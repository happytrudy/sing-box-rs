use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use rustls::{ClientConfig, pki_types::ServerName};
use serde::Deserialize;
use sing_box_core::{
    Address, BoxStream, Inbound, InboundBuildContext, Lifecycle, Network, Registry, Router,
    Session, StartStage,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{Mutex, oneshot},
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::{
    discovery::discover_edges,
    parse_token,
    protocol::ConnectionType,
    quic::{DatagramHandler, QuicConnection, QuicHttpHandler, QuicOptions, QuicRequestStream},
    registration::{ConnectionOptions, PermanentRegistrationError, RetryableRegistrationError},
    transport::{ConfigurationHandler, Http2Connection, Http2Handler, Http2Options, StreamHandler},
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflaredInboundOptions {
    token: String,
    #[serde(default = "default_protocol")]
    protocol: String,
    #[serde(default)]
    edge_ip_version: u8,
    #[serde(default)]
    region: String,
    #[serde(default = "default_ha_connections")]
    ha_connections: usize,
    #[serde(default)]
    post_quantum: bool,
    #[serde(default = "default_datagram_version")]
    datagram_version: String,
    #[serde(default = "default_grace_period")]
    grace_period: String,
}

fn default_protocol() -> String {
    "http2".into()
}

fn default_ha_connections() -> usize {
    4
}

fn default_grace_period() -> String {
    "30s".into()
}

fn default_datagram_version() -> String {
    "v2".into()
}

struct CloudflaredInbound {
    tag: String,
    options: CloudflaredInboundOptions,
    router: Arc<Router>,
    configuration_handler: ConfigurationHandler,
    remote_config: RemoteConfigStore,
    http_handler: Http2Handler,
    running: Mutex<Option<Running>>,
}

struct Running {
    cancel: CancellationToken,
    threads: Vec<std::thread::JoinHandle<()>>,
}

enum CloudflaredTransport {
    Http2(Http2Connection),
    Quic(QuicConnection),
}

impl CloudflaredTransport {
    async fn run_with_shutdown(
        self,
        handler: StreamHandler,
        datagram_handler: Option<DatagramHandler>,
        shutdown: oneshot::Receiver<()>,
    ) -> Result<crate::RegistrationResult> {
        match self {
            Self::Http2(connection) => connection.run_with_shutdown(handler, shutdown).await,
            Self::Quic(connection) => {
                connection
                    .run_with_shutdown(handler, datagram_handler, shutdown)
                    .await
            }
        }
    }
}

#[async_trait]
impl Lifecycle for CloudflaredInbound {
    async fn start(&self, stage: StartStage) -> Result<()> {
        if stage != StartStage::Start || self.running.lock().await.is_some() {
            return Ok(());
        }
        anyhow::ensure!(
            matches!(
                self.options.protocol.as_str(),
                "http2" | "h2" | "auto" | "quic"
            ),
            "cloudflared protocol must be http2, h2, auto, or quic"
        );
        anyhow::ensure!(
            self.options.datagram_version.is_empty()
                || self.options.datagram_version == "v2"
                || self.options.datagram_version == "v3",
            "cloudflared datagram_version must be v2 or v3"
        );
        anyhow::ensure!(
            !(self.options.post_quantum
                && matches!(self.options.protocol.as_str(), "http2" | "h2")),
            "cloudflared post_quantum requires quic or auto protocol"
        );
        let credentials = parse_token(&self.options.token).context("parse cloudflared token")?;
        let grace_period = parse_grace_period(&self.options.grace_period)?;
        anyhow::ensure!(
            self.options.region.is_empty() || credentials.endpoint.is_empty(),
            "cloudflared region cannot be used with a token endpoint"
        );
        let edges = discover_edges(
            &credentials,
            &self.options.region,
            self.options.edge_ip_version,
        )
        .await?;
        let count = self.options.ha_connections.max(1);
        let mut registration = ConnectionOptions::default();
        if self.options.datagram_version == "v3" {
            registration.features.push("support_datagram_v3_2".into());
        }
        let cancel = CancellationToken::new();
        let edges = Arc::new(edges);
        let mut threads = Vec::with_capacity(count);
        for connection_index in 0..count {
            let tag = self.tag.clone();
            let protocol = self.options.protocol.clone();
            let datagram_version = self.options.datagram_version.clone();
            let post_quantum = self.options.post_quantum;
            let credentials = credentials.clone();
            let registration = registration.clone();
            let router = Arc::clone(&self.router);
            let configuration_handler = Arc::clone(&self.configuration_handler);
            let remote_config = Arc::clone(&self.remote_config);
            let http_handler = Arc::clone(&self.http_handler);
            let edges = Arc::clone(&edges);
            let connection_cancel = cancel.clone();
            let thread = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build cloudflared runtime");
                runtime.block_on(async move {
                    supervise_connection(
                        tag,
                        protocol,
                        datagram_version,
                        post_quantum,
                        grace_period,
                        credentials,
                        registration,
                        router,
                        configuration_handler,
                        remote_config,
                        http_handler,
                        edges,
                        connection_index as u8,
                        connection_cancel,
                    )
                    .await;
                });
            });
            threads.push(thread);
        }
        *self.running.lock().await = Some(Running { cancel, threads });
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        if let Some(running) = self.running.lock().await.take() {
            running.cancel.cancel();
            for thread in running.threads {
                tokio::task::spawn_blocking(move || thread.join())
                    .await
                    .context("join cloudflared thread")?
                    .map_err(|_| anyhow::anyhow!("cloudflared thread panicked"))?;
            }
        }
        Ok(())
    }
}

impl Inbound for CloudflaredInbound {
    fn kind(&self) -> &'static str {
        "cloudflared"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }
}

pub fn register(registry: &mut Registry) -> Result<()> {
    registry.register_inbound::<CloudflaredInboundOptions, _, _>(
        "cloudflared",
        |context: InboundBuildContext, tag, options| async move {
            anyhow::ensure!(
                !options.token.trim().is_empty(),
                "cloudflared token is empty"
            );
            let router = context.router;
            let (configuration_handler, remote_config) = configuration_store();
            let http_handler =
                http_router_handler(Arc::clone(&router), tag.clone(), Arc::clone(&remote_config));
            Ok(Arc::new(CloudflaredInbound {
                tag,
                options,
                router,
                configuration_handler,
                remote_config,
                http_handler,
                running: Mutex::new(None),
            }) as Arc<dyn Inbound>)
        },
    )?;
    Ok(())
}

type RemoteConfigStore = Arc<StdMutex<RemoteConfigState>>;

#[derive(Default)]
struct RemoteConfigState {
    version: i32,
    raw: Vec<u8>,
    ingress: Vec<RemoteIngressRule>,
}

#[derive(Clone, Debug, Deserialize)]
struct RemoteConfigBody {
    #[serde(default)]
    ingress: Vec<RemoteIngressRule>,
}

#[derive(Clone, Debug, Deserialize)]
struct RemoteIngressRule {
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    path: String,
    service: String,
}

fn configuration_store() -> (ConfigurationHandler, RemoteConfigStore) {
    let state = Arc::new(StdMutex::new(RemoteConfigState {
        version: -1,
        ..RemoteConfigState::default()
    }));
    let handler_state = Arc::clone(&state);
    (
        Arc::new(move |version: i32, config: Vec<u8>| {
            let parsed: RemoteConfigBody = serde_json::from_slice(&config)
                .context("parse Cloudflared remote ingress configuration")?;
            let mut state = handler_state
                .lock()
                .map_err(|_| anyhow::anyhow!("cloudflared configuration lock poisoned"))?;
            if version > state.version {
                state.version = version;
                state.raw = config;
                state.ingress = parsed.ingress;
                tracing::info!(version, "updated cloudflared remote configuration");
            }
            Ok(state.version)
        }) as ConfigurationHandler,
        state,
    )
}

#[allow(clippy::too_many_arguments)]
async fn supervise_connection(
    tag: String,
    configured_protocol: String,
    datagram_version: String,
    post_quantum: bool,
    grace_period: Duration,
    credentials: crate::Credentials,
    base_registration: ConnectionOptions,
    router: Arc<Router>,
    configuration_handler: ConfigurationHandler,
    remote_config: RemoteConfigStore,
    http_handler: Http2Handler,
    edges: Arc<Vec<crate::discovery::EdgeAddr>>,
    connection_index: u8,
    cancel: CancellationToken,
) {
    let mut edge_index = usize::from(connection_index) % edges.len();
    let mut protocol = if matches!(configured_protocol.as_str(), "http2" | "h2") {
        "http2"
    } else {
        "quic"
    };
    let mut retries = 0u8;
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let edge = edges[edge_index].clone();
        let mut registration = base_registration.clone();
        registration.num_previous_attempts = retries;
        let handler = router_handler(Arc::clone(&router), tag.clone());
        let datagram_handler =
            if protocol == "quic" && matches!(datagram_version.as_str(), "v2" | "v3") {
                Some(router_datagram_handler(Arc::clone(&router), tag.clone()))
            } else {
                None
            };
        let connection = if protocol == "quic" {
            CloudflaredTransport::Quic(QuicConnection::new(QuicOptions {
                edge,
                credentials: credentials.clone(),
                connection_index,
                registration,
                post_quantum,
                datagram_version: datagram_version.clone(),
                grace_period,
                configuration_handler: Some(Arc::clone(&configuration_handler)),
                http_handler: Some(quic_http_router_handler(
                    Arc::clone(&router),
                    tag.clone(),
                    Arc::clone(&remote_config),
                )),
            }))
        } else {
            CloudflaredTransport::Http2(Http2Connection::new(Http2Options {
                edge,
                credentials: credentials.clone(),
                connection_index,
                registration,
                grace_period,
                configuration_handler: Some(Arc::clone(&configuration_handler)),
                http_handler: Some(Arc::clone(&http_handler)),
            }))
        };
        tracing::info!(
            tag = %tag,
            connection = connection_index,
            %protocol,
            edge = %edges[edge_index].address,
            "connecting cloudflared tunnel"
        );
        let (shutdown, receiver) = oneshot::channel();
        let attempt_cancel = cancel.clone();
        let shutdown_task = tokio::spawn(async move {
            attempt_cancel.cancelled().await;
            let _ = shutdown.send(());
        });
        let attempt_started = std::time::Instant::now();
        let result = connection
            .run_with_shutdown(handler, datagram_handler, receiver)
            .await;
        shutdown_task.abort();
        if cancel.is_cancelled() {
            return;
        }
        let error = match result {
            Ok(result) => anyhow::anyhow!(
                "edge connection {} at {} closed",
                result.connection_id,
                result.location
            ),
            Err(error) => error,
        };
        if error.downcast_ref::<PermanentRegistrationError>().is_some() {
            tracing::error!(
                tag = %tag,
                connection = connection_index,
                %error,
                error_chain = ?error,
                "cloudflared connection failed permanently"
            );
            return;
        }
        if attempt_started.elapsed() >= Duration::from_secs(30) {
            retries = 0;
        }
        retries = retries.saturating_add(1);
        edge_index = (edge_index + 1) % edges.len();
        if configured_protocol == "auto" && !post_quantum && protocol == "quic" && retries >= 3 {
            protocol = "http2";
            retries = 0;
            tracing::warn!(
                tag = %tag,
                connection = connection_index,
                %error,
                "switching cloudflared connection to HTTP/2 fallback"
            );
        }
        let backoff = error
            .downcast_ref::<RetryableRegistrationError>()
            .map(|error| error.delay)
            .filter(|delay| !delay.is_zero())
            .unwrap_or_else(|| Duration::from_secs(1u64 << retries.min(7)));
        tracing::warn!(
            tag = %tag,
            connection = connection_index,
            %protocol,
            %error,
            error_chain = ?error,
            retry_seconds = backoff.as_secs(),
            "cloudflared connection failed"
        );
        tokio::select! {
            _ = cancel.cancelled() => return,
            () = tokio::time::sleep(backoff) => {}
        }
    }
}

fn parse_grace_period(value: &str) -> Result<Duration> {
    let (number, multiplier) = if let Some(value) = value.strip_suffix("ms") {
        (value, 1)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1_000)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60_000)
    } else if let Some(value) = value.strip_suffix('h') {
        (value, 3_600_000)
    } else {
        anyhow::bail!("cloudflared grace_period must use ms, s, m, or h")
    };
    let number: u64 = number.parse().context("parse cloudflared grace_period")?;
    Ok(Duration::from_millis(number.saturating_mul(multiplier)))
}

fn router_handler(router: Arc<Router>, tag: String) -> StreamHandler {
    Arc::new(move |request, stream| {
        let router = Arc::clone(&router);
        let tag = tag.clone();
        Box::pin(async move {
            let (network, destination) =
                destination_for_request(&request.destination, request.connection_type)?;
            let source = source_for_request(&request);
            let session = Session::inbound(network, source, destination, tag, "cloudflared", None);
            match network {
                Network::Tcp => router.route(session, stream).await,
                Network::Udp => anyhow::bail!("cloudflared HTTP/2 does not carry UDP streams"),
            }
        })
    })
}

fn router_datagram_handler(router: Arc<Router>, tag: String) -> DatagramHandler {
    Arc::new(move |destination, connection| {
        let router = Arc::clone(&router);
        let tag = tag.clone();
        Box::pin(async move {
            let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            let session =
                Session::inbound(Network::Udp, source, destination, tag, "cloudflared", None);
            router.route_packet(session, connection).await
        })
    })
}

fn http_router_handler(
    router: Arc<Router>,
    tag: String,
    remote_config: RemoteConfigStore,
) -> Http2Handler {
    Arc::new(move |request, mut stream| {
        let router = Arc::clone(&router);
        let tag = tag.clone();
        let remote_config = Arc::clone(&remote_config);
        Box::pin(async move {
            let result =
                serve_http_origin(&router, &tag, &remote_config, &request, &mut stream).await;
            if let Err(error) = &result
                && let Ok(mut writer) = stream
                    .send_response(
                        502,
                        &[("content-type".into(), "text/plain; charset=utf-8".into())],
                    )
                    .await
            {
                let _ = writer.write_all(error.to_string().as_bytes()).await;
                let _ = writer.shutdown().await;
            }
            result
        })
    })
}

fn quic_http_router_handler(
    router: Arc<Router>,
    tag: String,
    remote_config: RemoteConfigStore,
) -> QuicHttpHandler {
    Arc::new(move |request, stream| {
        let router = Arc::clone(&router);
        let tag = tag.clone();
        let remote_config = Arc::clone(&remote_config);
        Box::pin(async move {
            serve_quic_http_origin(&router, &tag, &remote_config, &request, stream).await
        })
    })
}

async fn serve_quic_http_origin(
    router: &Router,
    tag: &str,
    remote_config: &RemoteConfigStore,
    request: &crate::protocol::ConnectRequest,
    mut stream: QuicRequestStream,
) -> Result<()> {
    let (request, status_override) = resolve_remote_request(remote_config, request)?;
    if let Some(status) = status_override {
        stream
            .send_response(&crate::protocol::ConnectResponse {
                error: String::new(),
                metadata: vec![crate::protocol::Metadata {
                    key: "HttpStatus".into(),
                    value: status.to_string(),
                }],
            })
            .await?;
        stream.shutdown().await?;
        return Ok(());
    }
    let is_websocket = request.connection_type == ConnectionType::Websocket;
    let (mut origin, status, response_headers, response_body) =
        match prepare_origin_request(router, tag, &request, &mut stream).await {
            Ok(value) => value,
            Err(error) => {
                let _ = stream
                    .send_response(&crate::protocol::ConnectResponse {
                        error: error.to_string(),
                        metadata: Vec::new(),
                    })
                    .await;
                let _ = stream.shutdown().await;
                return Err(error);
            }
        };
    let mut metadata = vec![crate::protocol::Metadata {
        key: "HttpStatus".into(),
        value: status.to_string(),
    }];
    metadata.extend(
        response_headers
            .iter()
            .filter(|(name, _)| !is_hop_by_hop_header(name) || is_websocket_response_header(name))
            .map(|(name, value)| crate::protocol::Metadata {
                key: format!("HttpHeader:{name}"),
                value: value.clone(),
            }),
    );
    stream
        .send_response(&crate::protocol::ConnectResponse {
            error: String::new(),
            metadata,
        })
        .await?;
    if is_websocket && status == 101 {
        let (mut origin_reader, mut origin_writer) = tokio::io::split(origin);
        let (mut request_reader, mut response_writer) = stream.into_split();
        let request_to_origin = tokio::io::copy(&mut request_reader, &mut origin_writer);
        let origin_to_request =
            copy_websocket_response(&mut origin_reader, &mut response_writer, &response_body);
        tokio::try_join!(request_to_origin, origin_to_request)?;
        return Ok(());
    }
    copy_response_body(&mut origin, &mut stream, &response_body, &response_headers).await?;
    stream.shutdown().await?;
    Ok(())
}

fn resolve_remote_request(
    remote_config: &RemoteConfigStore,
    request: &crate::protocol::ConnectRequest,
) -> Result<(crate::protocol::ConnectRequest, Option<u16>)> {
    let state = remote_config
        .lock()
        .map_err(|_| anyhow::anyhow!("cloudflared configuration lock poisoned"))?;
    if state.ingress.is_empty() {
        return Ok((request.clone(), None));
    }
    let uri: http::Uri = request
        .destination
        .parse()
        .context("parse Cloudflared request URI")?;
    let host = metadata_value(request, "HttpHost")
        .or_else(|| uri.authority().map(|authority| authority.host().to_owned()))
        .map(|value| normalize_host(&value))
        .unwrap_or_default();
    let path = uri.path();
    let rule = state.ingress.iter().find(|rule| {
        let hostname = rule.hostname.to_ascii_lowercase();
        let host_match = hostname.is_empty()
            || hostname == "*"
            || hostname == host
            || (hostname.starts_with("*.") && host.ends_with(&hostname[1..]));
        let path_pattern = rule.path.trim_start_matches('^').trim_end_matches('$');
        host_match && (path_pattern.is_empty() || path.starts_with(path_pattern))
    });
    let rule = rule.context("no Cloudflared ingress rule matched request")?;
    if let Some(status) = rule.service.strip_prefix("http_status:") {
        return Ok((
            request.clone(),
            Some(status.parse().context("parse Cloudflared status service")?),
        ));
    }
    let service: http::Uri = rule
        .service
        .parse()
        .context("parse Cloudflared ingress service URL")?;
    anyhow::ensure!(
        matches!(service.scheme_str(), Some("http" | "https" | "ws" | "wss"))
            && service.authority().is_some(),
        "unsupported Cloudflared ingress service"
    );
    let service_path = service.path().trim_end_matches('/');
    let request_path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let joined_path = if service_path.is_empty() || service_path == "/" {
        request_path.to_owned()
    } else if request_path == "/" {
        service_path.to_owned()
    } else {
        format!("{service_path}{request_path}")
    };
    let destination = format!(
        "{}://{}{}",
        service.scheme_str().unwrap_or("http"),
        service.authority().expect("validated service authority"),
        joined_path
    );
    let mut request = request.clone();
    request.destination = destination;
    Ok((request, None))
}

fn normalize_host(value: &str) -> String {
    if let Some(value) = value.strip_prefix('[') {
        return value
            .split(']')
            .next()
            .unwrap_or(value)
            .to_ascii_lowercase();
    }
    if let Some((host, port)) = value.rsplit_once(':')
        && port.parse::<u16>().is_ok()
    {
        return host.to_ascii_lowercase();
    }
    value.to_ascii_lowercase()
}

const MAX_HTTP_REQUEST_BODY: usize = 16 * 1024 * 1024;
const MAX_HTTP_RESPONSE_HEADERS: usize = 64 * 1024;

async fn serve_http_origin(
    router: &Router,
    tag: &str,
    remote_config: &RemoteConfigStore,
    request: &crate::protocol::ConnectRequest,
    stream: &mut crate::transport::Http2RequestStream,
) -> Result<()> {
    let (request, status_override) = resolve_remote_request(remote_config, request)?;
    if let Some(status) = status_override {
        let mut writer = stream.send_response(status, &[]).await?;
        writer.shutdown().await?;
        return Ok(());
    }
    let is_websocket = request.connection_type == ConnectionType::Websocket;
    let (mut origin, status, response_headers, response_body) =
        prepare_origin_request(router, tag, &request, stream).await?;
    let response_status = if is_websocket && status == 101 {
        200
    } else {
        status
    };
    let user_headers = response_headers
        .iter()
        .filter(|(name, _)| !is_hop_by_hop_header(name) || is_websocket_response_header(name))
        .cloned()
        .collect::<Vec<_>>();
    let mut headers = vec![(
        "cf-cloudflared-response-meta".to_owned(),
        r#"{"src":"origin"}"#.to_owned(),
    )];
    if !user_headers.is_empty() {
        headers.push((
            "cf-cloudflared-response-headers".to_owned(),
            serialize_headers(&user_headers),
        ));
    }
    for (name, value) in user_headers
        .iter()
        .filter(|(name, _)| !is_hop_by_hop_header(name))
    {
        if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("content-type")
        {
            headers.push((name.clone(), value.clone()));
        }
    }
    let mut response_writer = stream.send_response(response_status, &headers).await?;

    if is_websocket && status == 101 {
        let (mut origin_reader, mut origin_writer) = tokio::io::split(origin);
        let request_to_origin = tokio::io::copy(stream, &mut origin_writer);
        let origin_to_request =
            copy_websocket_response(&mut origin_reader, &mut response_writer, &response_body);
        tokio::try_join!(request_to_origin, origin_to_request)?;
        response_writer.shutdown().await?;
        return Ok(());
    }

    copy_response_body(
        &mut origin,
        &mut response_writer,
        &response_body,
        &response_headers,
    )
    .await?;
    response_writer.shutdown().await?;
    Ok(())
}

async fn prepare_origin_request<R: AsyncRead + Unpin + ?Sized>(
    router: &Router,
    tag: &str,
    request: &crate::protocol::ConnectRequest,
    stream: &mut R,
) -> Result<(BoxStream, u16, Vec<(String, String)>, Vec<u8>)> {
    let (network, destination) =
        destination_for_request(&request.destination, request.connection_type)?;
    let uri: http::Uri = request
        .destination
        .parse()
        .context("parse Cloudflare origin URI")?;
    let is_websocket = request.connection_type == ConnectionType::Websocket;
    let scheme = uri.scheme_str().unwrap_or("http");
    let host = metadata_value(request, "HttpHost")
        .or_else(|| uri.authority().map(|authority| authority.host().to_owned()))
        .context("Cloudflare HTTP request has no host")?;
    let tls_host = uri
        .authority()
        .map(|authority| authority.host().to_owned())
        .unwrap_or_else(|| host.clone());
    let mut session = Session::inbound(
        network,
        source_for_request(request),
        destination,
        tag.to_owned(),
        "cloudflared",
        None,
    );
    let mut origin = router.connect(&mut session).await?;
    if matches!(scheme.to_ascii_lowercase().as_str(), "https" | "wss") {
        origin = tls_origin(origin, &tls_host).await?;
    }
    let body = if is_websocket {
        Vec::new()
    } else {
        read_http_request_body(request, stream).await?
    };
    let request_head = build_origin_request(request, &uri, &host, body.len(), is_websocket)?;
    origin.write_all(&request_head).await?;
    if !body.is_empty() {
        origin.write_all(&body).await?;
    }
    origin.flush().await?;
    let (status, response_headers, response_body) = read_http_response_head(&mut origin).await?;
    Ok((origin, status, response_headers, response_body))
}

async fn tls_origin(stream: BoxStream, host: &str) -> Result<BoxStream> {
    let roots = crate::ca::root_store().context("load Cloudflare root CAs")?;
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("configure origin TLS versions")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_owned()).context("build origin TLS name")?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
        .context("TLS handshake with Cloudflare origin")?;
    Ok(Box::new(stream))
}

async fn read_limited_generic<R: AsyncRead + Unpin + ?Sized>(
    stream: &mut R,
    limit: usize,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        if output.len().saturating_add(count) > limit {
            anyhow::bail!("Cloudflare HTTP request body exceeds {limit} bytes");
        }
        output.extend_from_slice(&buffer[..count]);
    }
    Ok(output)
}

async fn read_http_request_body<R: AsyncRead + Unpin + ?Sized>(
    request: &crate::protocol::ConnectRequest,
    stream: &mut R,
) -> Result<Vec<u8>> {
    let method = metadata_value(request, "HttpMethod").unwrap_or_else(|| "GET".into());
    let content_length = request
        .metadata
        .iter()
        .find(|entry| {
            entry.key.eq_ignore_ascii_case("HttpHeader:content-length")
                || entry.key.eq_ignore_ascii_case("HttpHeader:content_length")
        })
        .map(|entry| entry.value.parse::<usize>())
        .transpose()
        .context("parse Cloudflare HTTP content length")?;
    if content_length == Some(0)
        || (content_length.is_none()
            && matches!(
                method.to_ascii_uppercase().as_str(),
                "GET" | "HEAD" | "OPTIONS"
            ))
    {
        return Ok(Vec::new());
    }
    if let Some(length) = content_length {
        anyhow::ensure!(
            length <= MAX_HTTP_REQUEST_BODY,
            "Cloudflare HTTP request body exceeds {MAX_HTTP_REQUEST_BODY} bytes"
        );
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).await?;
        return Ok(body);
    }
    read_limited_generic(stream, MAX_HTTP_REQUEST_BODY).await
}

fn metadata_value(request: &crate::protocol::ConnectRequest, key: &str) -> Option<String> {
    request
        .metadata
        .iter()
        .find(|entry| entry.key == key)
        .map(|entry| entry.value.clone())
}

fn source_for_request(request: &crate::protocol::ConnectRequest) -> SocketAddr {
    for key in ["Cf-Connecting-IP", "X-Real-IP", "X-Forwarded-For"] {
        let value = metadata_value(request, key)
            .or_else(|| metadata_value(request, &format!("HttpHeader:{key}")));
        let Some(value) = value else {
            continue;
        };
        let value = value.split(',').next().map(str::trim).unwrap_or_default();
        if let Ok(ip) = value.parse::<IpAddr>() {
            return SocketAddr::new(ip, 0);
        }
    }
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

fn build_origin_request(
    request: &crate::protocol::ConnectRequest,
    uri: &http::Uri,
    host: &str,
    body_length: usize,
    websocket: bool,
) -> Result<Vec<u8>> {
    let method = metadata_value(request, "HttpMethod").unwrap_or_else(|| "GET".into());
    let path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("/");
    ensure_http_token(&method)?;
    ensure_http_value(host)?;
    ensure_http_value(path)?;
    let mut output = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n").into_bytes();
    for entry in request
        .metadata
        .iter()
        .filter(|entry| entry.key.starts_with("HttpHeader:"))
    {
        let name = entry.key.trim_start_matches("HttpHeader:");
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("cf-cloudflared-proxy-connection-upgrade")
            || (websocket
                && (name.eq_ignore_ascii_case("upgrade")
                    || name.eq_ignore_ascii_case("sec-websocket-version")))
        {
            continue;
        }
        if name.eq_ignore_ascii_case("upgrade") && !websocket {
            continue;
        }
        ensure_http_token(name)?;
        ensure_http_value(&entry.value)?;
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(entry.value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(format!("Content-Length: {body_length}\r\n").as_bytes());
    if websocket {
        output.extend_from_slice(b"Upgrade: websocket\r\n");
        output.extend_from_slice(b"Sec-WebSocket-Version: 13\r\n");
        output.extend_from_slice(b"Connection: Upgrade\r\n");
    } else {
        output.extend_from_slice(b"Connection: close\r\n");
    }
    output.extend_from_slice(b"\r\n");
    Ok(output)
}

fn ensure_http_token(value: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && !value
                .bytes()
                .any(|byte| byte <= 0x20 || byte >= 0x7f || byte == b':'),
        "invalid HTTP token"
    );
    Ok(())
}

fn ensure_http_value(value: &str) -> Result<()> {
    anyhow::ensure!(
        !value.contains('\r') && !value.contains('\n'),
        "invalid HTTP header value"
    );
    Ok(())
}

async fn read_http_response_head<R: AsyncRead + Unpin + ?Sized>(
    stream: &mut R,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    let end = loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            anyhow::bail!("origin closed before HTTP response headers");
        }
        data.extend_from_slice(&buffer[..count]);
        if data.len() > MAX_HTTP_RESPONSE_HEADERS {
            anyhow::bail!("origin response headers exceed {MAX_HTTP_RESPONSE_HEADERS} bytes");
        }
        if let Some(position) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
    };
    let head =
        std::str::from_utf8(&data[..end]).context("origin response headers are not UTF-8")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().context("origin response has no status line")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .context("origin response has no status code")?
        .parse::<u16>()
        .context("parse origin response status")?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .context("origin response header is malformed")?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    Ok((status, headers, data[end + 4..].to_vec()))
}

async fn copy_response_body<R: AsyncRead + Unpin + ?Sized, W: AsyncWrite + Unpin + ?Sized>(
    origin: &mut R,
    response: &mut W,
    already_read: &[u8],
    headers: &[(String, String)],
) -> Result<()> {
    if headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
    }) {
        return copy_chunked_response_body(origin, response, already_read).await;
    }

    response.write_all(already_read).await?;
    if let Some(length) = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
    {
        let remaining = length.saturating_sub(already_read.len());
        let mut limited = origin.take(remaining as u64);
        tokio::io::copy(&mut limited, response).await?;
    } else {
        tokio::io::copy(origin, response).await?;
    }
    Ok(())
}

async fn copy_websocket_response<R: AsyncRead + Unpin + ?Sized, W: AsyncWrite + Unpin + ?Sized>(
    origin: &mut R,
    response: &mut W,
    already_read: &[u8],
) -> std::io::Result<u64> {
    response.write_all(already_read).await?;
    tokio::io::copy(origin, response).await
}

async fn copy_chunked_response_body<
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
>(
    origin: &mut R,
    response: &mut W,
    already_read: &[u8],
) -> Result<()> {
    let initial = std::io::Cursor::new(already_read);
    let mut reader = BufReader::new(initial.chain(origin));
    loop {
        let mut size_line = String::new();
        anyhow::ensure!(
            reader.read_line(&mut size_line).await? != 0,
            "origin closed before chunk size"
        );
        let size = size_line
            .strip_suffix("\r\n")
            .context("origin chunk size is missing CRLF")?
            .split(';')
            .next()
            .expect("split always returns one item")
            .trim();
        let size = usize::from_str_radix(size, 16).context("parse origin chunk size")?;
        if size == 0 {
            loop {
                let mut trailer = String::new();
                anyhow::ensure!(
                    reader.read_line(&mut trailer).await? != 0,
                    "origin closed before chunk trailers"
                );
                if trailer == "\r\n" {
                    return Ok(());
                }
            }
        }

        let mut chunk = (&mut reader).take(size as u64);
        let copied = tokio::io::copy(&mut chunk, response).await?;
        anyhow::ensure!(copied == size as u64, "origin closed within chunk body");
        let mut terminator = [0u8; 2];
        reader.read_exact(&mut terminator).await?;
        anyhow::ensure!(terminator == *b"\r\n", "origin chunk is missing CRLF");
    }
}

fn is_hop_by_hop_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("transfer-encoding")
}

fn is_websocket_response_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("sec-websocket-accept")
}

fn serialize_headers(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .map(|(name, value)| {
            format!(
                "{}:{}",
                base64_encode(name.as_bytes()),
                base64_encode(value.as_bytes())
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn base64_encode(value: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(value.len().div_ceil(3) * 4);
    for chunk in value.chunks(3) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);
        output.push(TABLE[(first >> 2) as usize] as char);
        output.push(TABLE[((first & 3) << 4 | second >> 4) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((second & 15) << 2 | third >> 6) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(third & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn destination_for_request(destination: &str, kind: ConnectionType) -> Result<(Network, Address)> {
    if matches!(kind, ConnectionType::Http | ConnectionType::Websocket) {
        let uri: http::Uri = destination.parse().context("parse cloudflared HTTP URI")?;
        let authority = uri
            .authority()
            .context("cloudflared HTTP request has no authority")?;
        let port = authority.port_u16().unwrap_or_else(|| {
            if matches!(uri.scheme_str(), Some("https" | "wss")) {
                443
            } else {
                80
            }
        });
        return Ok((Network::Tcp, Address::new(authority.host(), port)?));
    }
    let (host, port) = split_host_port(destination)?;
    Ok((Network::Tcp, Address::new(host, port)?))
}

fn split_host_port(value: &str) -> Result<(String, u16)> {
    if let Some(value) = value.strip_prefix('[') {
        let (host, port) = value
            .split_once(']')
            .context("invalid bracketed cloudflared destination")?;
        let port = port
            .strip_prefix(':')
            .context("cloudflared destination is missing port")?
            .parse()
            .context("parse cloudflared destination port")?;
        return Ok((host.to_owned(), port));
    }
    let (host, port) = value
        .rsplit_once(':')
        .context("cloudflared destination is missing port")?;
    Ok((
        host.to_owned(),
        port.parse().context("parse cloudflared destination port")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(destination: &str) -> crate::protocol::ConnectRequest {
        crate::protocol::ConnectRequest {
            destination: destination.into(),
            connection_type: ConnectionType::Http,
            metadata: vec![
                crate::protocol::Metadata {
                    key: "HttpMethod".into(),
                    value: "GET".into(),
                },
                crate::protocol::Metadata {
                    key: "HttpHost".into(),
                    value: "www.example.com".into(),
                },
            ],
        }
    }

    #[test]
    fn remote_ingress_rewrites_origin_and_preserves_path() {
        let (handler, store) = configuration_store();
        handler(
            1,
            br#"{"ingress":[{"hostname":"www.example.com","path":"/api","service":"http://127.0.0.1:8080/base"}]}"#.to_vec(),
        )
        .unwrap();
        let (request, status) =
            resolve_remote_request(&store, &request("https://www.example.com/api/v1?q=1")).unwrap();
        assert_eq!(status, None);
        assert_eq!(request.destination, "http://127.0.0.1:8080/base/api/v1?q=1");
    }

    #[test]
    fn remote_ingress_supports_status_service() {
        let (handler, store) = configuration_store();
        handler(
            1,
            br#"{"ingress":[{"service":"http_status:404"}]}"#.to_vec(),
        )
        .unwrap();
        let (_, status) =
            resolve_remote_request(&store, &request("http://other.example/")).unwrap();
        assert_eq!(status, Some(404));
    }

    #[tokio::test]
    async fn decodes_chunked_compressed_response_body() {
        let headers = vec![
            ("Transfer-Encoding".into(), "chunked".into()),
            ("Content-Encoding".into(), "gzip".into()),
        ];
        let already_read = b"4\r\n\x1f\x8b";
        let mut origin = &b"\x08\x00\r\n3;ext=value\r\nabc\r\n0\r\nX-Trailer: done\r\n\r\n"[..];
        let mut response = Vec::new();

        copy_response_body(&mut origin, &mut response, already_read, &headers)
            .await
            .unwrap();

        assert_eq!(response, b"\x1f\x8b\x08\x00abc");
    }

    #[tokio::test]
    async fn preserves_websocket_data_read_with_upgrade_response() {
        let already_read = b"first-websocket-frame";
        let mut origin = &b"remaining-websocket-frames"[..];
        let mut response = Vec::new();

        copy_websocket_response(&mut origin, &mut response, already_read)
            .await
            .unwrap();

        assert_eq!(response, b"first-websocket-frameremaining-websocket-frames");
    }

    #[test]
    fn rebuilds_websocket_upgrade_headers_for_origin() {
        let mut request = request("https://www.example.com/assets/app.js");
        request.connection_type = ConnectionType::Websocket;
        request.metadata.extend([
            crate::protocol::Metadata {
                key: "HttpHeader:Upgrade".into(),
                value: "h2c".into(),
            },
            crate::protocol::Metadata {
                key: "HttpHeader:Sec-WebSocket-Version".into(),
                value: "12".into(),
            },
            crate::protocol::Metadata {
                key: "HttpHeader:Sec-WebSocket-Key".into(),
                value: "MDEyMzQ1Njc4OWFiY2RlZg==".into(),
            },
            crate::protocol::Metadata {
                key: "HttpHeader:Cf-Cloudflared-Proxy-Connection-Upgrade".into(),
                value: "websocket".into(),
            },
        ]);
        let uri = "http://127.0.0.1:60176/assets/app.js".parse().unwrap();

        let origin = build_origin_request(&request, &uri, "www.example.com", 0, true).unwrap();
        let origin = String::from_utf8(origin).unwrap();

        assert!(origin.starts_with("GET /assets/app.js HTTP/1.1\r\n"));
        assert_eq!(origin.matches("Upgrade: websocket\r\n").count(), 1);
        assert_eq!(origin.matches("Sec-WebSocket-Version: 13\r\n").count(), 1);
        assert!(origin.contains("Connection: Upgrade\r\n"));
        assert!(origin.contains("Sec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n"));
        assert!(!origin.contains("Cf-Cloudflared-Proxy-Connection-Upgrade"));
        assert!(!origin.contains("Upgrade: h2c"));
        assert!(!origin.contains("Sec-WebSocket-Version: 12"));
    }
}
