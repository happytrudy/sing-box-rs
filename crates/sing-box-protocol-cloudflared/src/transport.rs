use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Context as _, Result};
use bytes::{Buf, Bytes};
use capnp::message::ReaderOptions;
use capnp_rpc::{RpcSystem, rpc_twoparty_capnp::Side, twoparty::VatNetwork};
use h2::{RecvStream, SendStream};
use http::{Request, Response, StatusCode};
use rustls::{ClientConfig, pki_types::ServerName};
use sing_box_core::BoxStream;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::oneshot,
};
use tokio_rustls::TlsConnector;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tokio_util::sync::CancellationToken;

use crate::{
    Credentials,
    discovery::EdgeAddr,
    protocol::{self, ConnectRequest, ConnectResponse, ConnectionType, Metadata},
    registration::{self, ConnectionOptions, RegistrationResult},
    tunnelrpc_capnp,
};

pub const H2_EDGE_SNI: &str = "h2.cftunnel.com";
pub const H2_CONTROL_HEADER: &str = "Cf-Cloudflared-Proxy-Connection-Upgrade";
pub const H2_TCP_SOURCE_HEADER: &str = "Cf-Cloudflared-Proxy-Src";
pub const H2_RESPONSE_META_HEADER: &str = "Cf-Cloudflared-Response-Meta";
pub const H2_CONTROL_STREAM: &str = "control-stream";
pub const H2_WEBSOCKET_STREAM: &str = "websocket";
pub const H2_RESPONSE_META: &str = r#"{"src":"cloudflared"}"#;

pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;
pub type StreamHandler = Arc<dyn Fn(ConnectRequest, BoxStream) -> HandlerFuture + Send + Sync>;
pub type ConfigurationHandler = Arc<dyn Fn(i32, Vec<u8>) -> Result<i32> + Send + Sync>;
pub type Http2Handler =
    Arc<dyn Fn(ConnectRequest, Http2RequestStream) -> HandlerFuture + Send + Sync>;

#[derive(Clone)]
pub struct Http2Options {
    pub edge: EdgeAddr,
    pub credentials: Credentials,
    pub connection_index: u8,
    pub registration: ConnectionOptions,
    pub grace_period: Duration,
    pub configuration_handler: Option<ConfigurationHandler>,
    pub http_handler: Option<Http2Handler>,
}

pub struct Http2Connection {
    options: Http2Options,
}

impl Http2Connection {
    pub fn new(options: Http2Options) -> Self {
        Self { options }
    }

    /// Connects to an edge and serves Cloudflare-initiated HTTP/2 streams.
    pub async fn run(self, handler: StreamHandler) -> Result<RegistrationResult> {
        let (_shutdown, receiver) = oneshot::channel();
        self.run_with_shutdown(handler, receiver).await
    }

    pub async fn run_with_shutdown(
        self,
        handler: StreamHandler,
        shutdown: oneshot::Receiver<()>,
    ) -> Result<RegistrationResult> {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(self.run_local(handler, shutdown))
            .await
            .context("run Cloudflare HTTP/2 connection")
    }

    async fn run_local(
        self,
        handler: StreamHandler,
        mut shutdown: oneshot::Receiver<()>,
    ) -> Result<RegistrationResult> {
        let tls = connect_tls(self.options.edge.address).await?;
        let mut builder = h2::server::Builder::new();
        builder
            .initial_window_size(16 * 1024 * 1024)
            .initial_connection_window_size(16 * 1024 * 1024)
            .max_concurrent_streams(1024);
        let mut connection = builder
            .handshake(tls)
            .await
            .context("start Cloudflare HTTP/2 server")?;

        let registered = Arc::new(tokio::sync::Mutex::new(None));
        let control_cancel = CancellationToken::new();
        loop {
            let accepted = connection.accept();
            tokio::pin!(accepted);
            let item = tokio::select! {
                item = &mut accepted => item,
                _ = &mut shutdown => {
                    control_cancel.cancel();
                    if !self.options.grace_period.is_zero() {
                        tokio::time::sleep(self.options.grace_period).await;
                    }
                    return registered
                        .lock()
                        .await
                        .take()
                        .context("Cloudflare edge closed before registration");
                },
            };
            let Some(item) = item else {
                break;
            };
            let (request, respond) = item.context("accept Cloudflare HTTP/2 stream")?;
            let credentials = self.options.credentials.clone();
            let registration = self.options.registration.clone();
            let connection_index = self.options.connection_index;
            let registered_for_task = Arc::clone(&registered);
            let control_cancel_for_task = control_cancel.clone();
            let handler = Arc::clone(&handler);
            let configuration_handler = self.options.configuration_handler.clone();
            let http_handler = self.options.http_handler.clone();
            tokio::task::spawn_local(async move {
                if let Err(error) = handle_request(
                    request,
                    respond,
                    credentials,
                    registration,
                    connection_index,
                    registered_for_task,
                    control_cancel_for_task,
                    configuration_handler,
                    http_handler,
                    handler,
                )
                .await
                {
                    tracing::warn!(%error, "Cloudflare HTTP/2 stream failed");
                }
            });
        }

        registered
            .lock()
            .await
            .take()
            .context("Cloudflare edge closed before registration")
    }
}

async fn connect_tls(address: SocketAddr) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(address)
        .await
        .with_context(|| format!("connect Cloudflare edge {address}"))?;
    let roots = crate::ca::root_store().context("load Cloudflare root CAs")?;
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("configure Cloudflare HTTP/2 TLS versions")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols.push(b"h2".to_vec());
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(H2_EDGE_SNI.to_owned())
        .context("build Cloudflare HTTP/2 server name")?;
    connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake with Cloudflare edge")
}

#[allow(clippy::too_many_arguments)]
async fn handle_request(
    request: Request<RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    credentials: Credentials,
    registration: ConnectionOptions,
    connection_index: u8,
    registered: Arc<tokio::sync::Mutex<Option<RegistrationResult>>>,
    control_cancel: CancellationToken,
    configuration_handler: Option<ConfigurationHandler>,
    http_handler: Option<Http2Handler>,
    handler: StreamHandler,
) -> Result<()> {
    if request
        .headers()
        .get(H2_CONTROL_HEADER)
        .and_then(|value| value.to_str().ok())
        == Some(H2_CONTROL_STREAM)
    {
        return handle_control_stream(
            request.into_body(),
            respond,
            credentials,
            registration,
            connection_index,
            registered,
            control_cancel,
        )
        .await;
    }

    if request
        .headers()
        .get(H2_CONTROL_HEADER)
        .and_then(|value| value.to_str().ok())
        == Some("update-configuration")
    {
        return handle_configuration_update(request.into_body(), respond, configuration_handler)
            .await;
    }

    handle_data_stream(request, respond, handler, http_handler).await
}

async fn handle_control_stream(
    body: RecvStream,
    mut respond: h2::server::SendResponse<Bytes>,
    credentials: Credentials,
    registration: ConnectionOptions,
    connection_index: u8,
    registered: Arc<tokio::sync::Mutex<Option<RegistrationResult>>>,
    control_cancel: CancellationToken,
) -> Result<()> {
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(H2_RESPONSE_META_HEADER, H2_RESPONSE_META)
        .body(())?;
    let writer = respond.send_response(response, false)?;
    let reader = H2Reader::new(body);
    let writer = H2Writer::new(writer);
    let network = VatNetwork::new(
        reader.compat(),
        writer.compat_write(),
        Side::Client,
        ReaderOptions::default(),
    );
    let mut rpc = RpcSystem::new(Box::new(network), None);
    let client: tunnelrpc_capnp::registration_server::Client = rpc.bootstrap(Side::Server);
    let mut request = client.register_connection_request();
    registration::set_register_connection(
        &mut request.get(),
        &credentials,
        connection_index,
        &registration,
    );
    let promise = request.send();
    let mut rpc_task = tokio::task::spawn_local(rpc);
    let response = promise
        .promise
        .await
        .context("Cloudflare registration RPC")?;
    let result = registration::read_registration_result(response.get()?.get_result()?)?;
    anyhow::ensure!(
        result.tunnel_is_remotely_managed,
        "Cloudflared only supports remotely managed tunnels"
    );
    *registered.lock().await = Some(result);
    tokio::select! {
        result = &mut rpc_task => {
            result.context("Cloudflare registration RPC task")??;
        }
        _ = control_cancel.cancelled() => {
            let request = client.unregister_connection_request();
            match tokio::time::timeout(Duration::from_secs(5), request.send().promise).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => tracing::debug!(%error, "Cloudflare HTTP/2 unregister failed"),
                Err(error) => tracing::debug!(%error, "Cloudflare HTTP/2 unregister timed out"),
            }
            rpc_task.abort();
        }
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct ConfigurationUpdateBody {
    version: i32,
    config: serde_json::Value,
}

#[derive(serde::Serialize)]
struct ConfigurationUpdateResponse {
    #[serde(rename = "lastAppliedVersion")]
    last_applied_version: i32,
    err: Option<String>,
}

async fn handle_configuration_update(
    body: RecvStream,
    mut respond: h2::server::SendResponse<Bytes>,
    configuration_handler: Option<ConfigurationHandler>,
) -> Result<()> {
    let body = read_h2_body(body).await?;
    let update: ConfigurationUpdateBody =
        serde_json::from_slice(&body).context("decode Cloudflare configuration update")?;
    let result = match configuration_handler {
        Some(handler) => match handler(update.version, serde_json::to_vec(&update.config)?) {
            Ok(version) => ConfigurationUpdateResponse {
                last_applied_version: version,
                err: None,
            },
            Err(error) => ConfigurationUpdateResponse {
                last_applied_version: update.version,
                err: Some(error.to_string()),
            },
        },
        None => ConfigurationUpdateResponse {
            last_applied_version: update.version,
            err: Some("configuration handler is not installed".into()),
        },
    };
    let payload = Bytes::from(serde_json::to_vec(&result)?);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(H2_RESPONSE_META_HEADER, H2_RESPONSE_META)
        .header("content-type", "application/json")
        .body(())?;
    let mut stream = respond.send_response(response, false)?;
    stream.send_data(payload, true)?;
    Ok(())
}

async fn read_h2_body(mut body: RecvStream) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.context("read Cloudflare HTTP/2 body")?;
        body.flow_control()
            .release_capacity(chunk.len())
            .context("release Cloudflare HTTP/2 body capacity")?;
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

async fn handle_data_stream(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    handler: StreamHandler,
    http_handler: Option<Http2Handler>,
) -> Result<()> {
    let connect_request = build_connect_request(&request)?;
    if let Some(http_handler) = http_handler
        && matches!(
            connect_request.connection_type,
            ConnectionType::Http | ConnectionType::Websocket
        )
    {
        let stream = Http2RequestStream {
            reader: H2Reader::new(request.into_body()),
            respond: Some(respond),
        };
        return (http_handler)(connect_request, stream).await;
    }
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(H2_RESPONSE_META_HEADER, H2_RESPONSE_META)
        .body(())?;
    let mut stream = H2Stream::new(request.into_body(), respond.send_response(response, false)?);
    let response = protocol::encode_connect_response(&ConnectResponse {
        error: String::new(),
        metadata: Vec::new(),
    })?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, &response).await?;
    (handler)(connect_request, Box::new(stream)).await
}

fn build_connect_request(request: &Request<RecvStream>) -> Result<ConnectRequest> {
    let websocket = request
        .headers()
        .get(H2_CONTROL_HEADER)
        .and_then(|value| value.to_str().ok())
        == Some(H2_WEBSOCKET_STREAM);
    let tcp = request.headers().contains_key(H2_TCP_SOURCE_HEADER);
    let connection_type = if websocket {
        ConnectionType::Websocket
    } else if tcp {
        ConnectionType::Tcp
    } else {
        ConnectionType::Http
    };
    let destination = if connection_type == ConnectionType::Tcp {
        request
            .uri()
            .authority()
            .map(|authority| authority.as_str().to_owned())
            .or_else(|| {
                request
                    .headers()
                    .get("host")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            })
            .context("Cloudflare TCP stream has no destination")?
    } else {
        let uri = request.uri();
        if uri.scheme().is_some() && uri.authority().is_some() {
            uri.to_string()
        } else {
            let host = request
                .headers()
                .get("host")
                .and_then(|value| value.to_str().ok())
                .context("Cloudflare HTTP stream has no host")?;
            let path = uri
                .path_and_query()
                .map(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .unwrap_or("/");
            format!("http://{host}{path}")
        }
    };
    let mut metadata = Vec::new();
    metadata.push(Metadata {
        key: "HttpMethod".into(),
        value: request.method().to_string(),
    });
    if let Some(host) = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
    {
        metadata.push(Metadata {
            key: "HttpHost".into(),
            value: host.to_owned(),
        });
    }
    for (name, value) in request.headers() {
        if let Ok(value) = value.to_str() {
            metadata.push(Metadata {
                key: format!("HttpHeader:{name}"),
                value: value.to_owned(),
            });
        }
    }
    Ok(ConnectRequest {
        destination,
        connection_type,
        metadata,
    })
}

struct H2Stream {
    reader: H2Reader,
    writer: H2Writer,
}

pub struct Http2RequestStream {
    reader: H2Reader,
    respond: Option<h2::server::SendResponse<Bytes>>,
}

pub struct Http2BodyWriter {
    writer: H2Writer,
}

impl Http2RequestStream {
    pub async fn send_response(
        &mut self,
        status: u16,
        headers: &[(String, String)],
    ) -> Result<Http2BodyWriter> {
        let mut response = Response::builder().status(StatusCode::from_u16(status)?);
        for (name, value) in headers {
            response = response.header(name, value);
        }
        let mut sender = self
            .respond
            .take()
            .context("HTTP/2 response has already been sent")?;
        let stream = sender.send_response(response.body(())?, false)?;
        Ok(Http2BodyWriter {
            writer: H2Writer::new(stream),
        })
    }
}

impl AsyncRead for Http2RequestStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for Http2BodyWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

impl H2Stream {
    fn new(reader: RecvStream, writer: SendStream<Bytes>) -> Self {
        Self {
            reader: H2Reader::new(reader),
            writer: H2Writer::new(writer),
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

struct H2Reader {
    stream: RecvStream,
    pending: Bytes,
}

impl H2Reader {
    fn new(stream: RecvStream) -> Self {
        Self {
            stream,
            pending: Bytes::new(),
        }
    }
}

impl AsyncRead for H2Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.pending.is_empty() {
            let length = self.pending.len().min(buf.remaining());
            buf.put_slice(&self.pending[..length]);
            self.pending.advance(length);
            return Poll::Ready(Ok(()));
        }
        match self.stream.poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let _ = self.stream.flow_control().release_capacity(data.len());
                self.pending = data;
                self.poll_read(cx, buf)
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(std::io::Error::other(error))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct H2Writer {
    stream: Option<SendStream<Bytes>>,
}

impl H2Writer {
    fn new(stream: SendStream<Bytes>) -> Self {
        Self {
            stream: Some(stream),
        }
    }
}

impl AsyncWrite for H2Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let Some(stream) = self.stream.as_mut() else {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Cloudflare HTTP/2 stream is closed",
            )));
        };
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let capacity = match stream.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => capacity,
            Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(std::io::Error::other(error))),
            Poll::Ready(None) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "Cloudflare HTTP/2 stream is closed",
                )));
            }
            Poll::Pending => return Poll::Pending,
        };
        if capacity == 0 {
            return Poll::Pending;
        }
        let length = capacity.min(data.len());
        stream
            .send_data(Bytes::copy_from_slice(&data[..length]), false)
            .map(|()| Poll::Ready(Ok(length)))
            .unwrap_or_else(|error| Poll::Ready(Err(std::io::Error::other(error))))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Some(mut stream) = self.stream.take() {
            stream
                .send_data(Bytes::new(), true)
                .map_err(std::io::Error::other)?;
        }
        Poll::Ready(Ok(()))
    }
}
