use std::{
    collections::HashMap,
    io,
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context as TaskContext, Poll},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::Deserialize;
use sing_box_core::{
    Address, ConnectionTasks, Dialer, Inbound, InboundBuildContext, Lifecycle, Network, Registry,
    Router, Session, bind_tcp_listeners,
};
use sing_box_tls::{RealityAcceptor, RealityOptions, RealityServerConfig};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    task::JoinHandle,
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

const VLESS_VERSION: u8 = 0;
const VLESS_COMMAND_TCP: u8 = 1;
const MAX_HTTP_HEADER_SIZE: usize = 16 * 1024;
const MAX_WS_FRAME_SIZE: u64 = 16 * 1024 * 1024;
const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VlessInboundOptions {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default)]
    listen_port: u16,
    users: Vec<UserOptions>,
    transport: WebSocketOptions,
    #[serde(default)]
    tls: VlessTlsOptions,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct VlessTlsOptions {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    server_name: String,
    #[serde(default)]
    alpn: Vec<String>,
    #[serde(default)]
    reality: RealityOptions,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserOptions {
    uuid: String,
    #[serde(default)]
    name: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebSocketOptions {
    #[serde(rename = "type")]
    kind: String,
    path: String,
    #[serde(default)]
    early_data_header_name: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VlessOutboundOptions {
    server: String,
    #[serde(default = "default_vless_server_port")]
    server_port: u16,
    uuid: String,
    transport: WebSocketOutboundOptions,
    #[serde(default)]
    tls: VlessClientTlsOptions,
}

fn default_vless_server_port() -> u16 {
    443
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebSocketOutboundOptions {
    #[serde(rename = "type")]
    kind: String,
    path: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    max_early_data: usize,
    #[serde(default)]
    early_data_header_name: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct VlessClientTlsOptions {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    server_name: String,
    #[serde(default)]
    insecure: bool,
    #[serde(default)]
    certificate_path: String,
    #[serde(default)]
    alpn: Vec<String>,
}

fn default_listen() -> String {
    "127.0.0.1".to_owned()
}

struct Running {
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    connection_tasks: ConnectionTasks,
}

struct VlessInbound {
    tag: String,
    path: String,
    early_data_header_name: String,
    users: Arc<HashMap<[u8; 16], String>>,
    router: Arc<Router>,
    listen: String,
    listen_port: u16,
    running: Mutex<Option<Running>>,
    local_addr: RwLock<Option<SocketAddr>>,
    reality: Option<Arc<RealityAcceptor>>,
}

struct VlessOutbound {
    tag: String,
    server: String,
    server_port: u16,
    uuid: [u8; 16],
    path: String,
    headers: HashMap<String, String>,
    max_early_data: usize,
    early_data_header_name: String,
    tls: VlessClientTlsOptions,
    dialer: sing_box_core::SystemDialer,
}

#[async_trait]
impl Lifecycle for VlessInbound {
    async fn start(&self, stage: sing_box_core::StartStage) -> Result<()> {
        if stage != sing_box_core::StartStage::Start {
            return Ok(());
        }
        if self.running.lock().await.is_some() {
            return Ok(());
        }
        let listeners = bind_tcp_listeners(&self.listen, self.listen_port)
            .await
            .context("bind VLESS inbound")?;
        let local_addr = listeners[0].local_addr()?;
        *self.local_addr.write().expect("VLESS address lock") = Some(local_addr);
        let cancel = CancellationToken::new();
        let connection_tasks = ConnectionTasks::new();
        let mut tasks = Vec::with_capacity(listeners.len());
        for listener in listeners {
            let connection_tasks_for_listener = connection_tasks.clone();
            tasks.push(tokio::spawn(run_listener(
                listener,
                cancel.clone(),
                connection_tasks_for_listener,
                Arc::clone(&self.router),
                self.tag.clone(),
                self.path.clone(),
                self.early_data_header_name.clone(),
                Arc::clone(&self.users),
                self.reality.clone(),
            )));
        }
        *self.running.lock().await = Some(Running {
            cancel,
            tasks,
            connection_tasks,
        });
        tracing::info!(tag = %self.tag, %local_addr, "started VLESS WebSocket inbound");
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        if let Some(running) = self.running.lock().await.take() {
            running.cancel.cancel();
            for task in running.tasks {
                task.await?;
            }
            running.connection_tasks.join().await;
        }
        Ok(())
    }
}

impl Inbound for VlessInbound {
    fn kind(&self) -> &'static str {
        "vless"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.read().expect("VLESS address lock")
    }
}

impl Lifecycle for VlessOutbound {}

#[async_trait]
impl Dialer for VlessOutbound {
    async fn connect(&self, session: &Session) -> Result<sing_box_core::BoxStream> {
        anyhow::ensure!(
            session.network == Network::Tcp,
            "VLESS outbound only supports TCP"
        );
        let server = Address::new(self.server.clone(), self.server_port)?;
        let transport = self.dialer.connect(&Session::outbound(server)).await?;
        let stream = if self.tls.enabled {
            let config = build_vless_client_config(&self.tls).await?;
            let connector = TlsConnector::from(Arc::new(config));
            let server_name = if self.tls.server_name.is_empty() {
                self.server.clone()
            } else {
                self.tls.server_name.clone()
            };
            let server_name =
                ServerName::try_from(server_name).context("invalid VLESS server_name")?;
            Box::new(
                connector
                    .connect(server_name, transport)
                    .await
                    .context("VLESS TLS handshake")?,
            ) as sing_box_core::BoxStream
        } else {
            transport
        };
        let request = encode_vless_request(&self.uuid, &session.destination)?;
        let early_data = self.max_early_data > 0
            && !self.early_data_header_name.is_empty()
            && request.len() <= self.max_early_data;
        let key = websocket_key()?;
        let path = if self.path.starts_with('/') {
            self.path.clone()
        } else {
            format!("/{}", self.path)
        };
        let host = if self.tls.server_name.is_empty() {
            self.server.as_str()
        } else {
            self.tls.server_name.as_str()
        };
        let mut http = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n"
        );
        for (name, value) in &self.headers {
            if !matches!(
                name.to_ascii_lowercase().as_str(),
                "host" | "upgrade" | "connection" | "sec-websocket-version" | "sec-websocket-key"
            ) {
                http.push_str(name);
                http.push_str(": ");
                http.push_str(value);
                http.push_str("\r\n");
            }
        }
        if early_data {
            http.push_str(&self.early_data_header_name);
            http.push_str(": ");
            http.push_str(&encode_base64_url(&request));
            http.push_str("\r\n");
        }
        http.push_str("\r\n");
        let mut stream = stream;
        stream.write_all(http.as_bytes()).await?;
        stream.flush().await?;
        let response = read_http_response(&mut stream).await?;
        anyhow::ensure!(
            response.status == 101,
            "VLESS WebSocket server returned HTTP status {}",
            response.status
        );
        anyhow::ensure!(
            response
                .headers
                .get("sec-websocket-accept")
                .is_some_and(|value| value == &websocket_accept(&key)),
            "invalid VLESS WebSocket accept header"
        );
        let mut stream = WebSocketStream::new(stream, response.tail, Vec::new(), true);
        if !early_data {
            stream.write_all(&request).await?;
            stream.flush().await?;
        }
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        anyhow::ensure!(response == [VLESS_VERSION, 0], "invalid VLESS response");
        Ok(Box::new(stream))
    }
}

impl sing_box_core::Outbound for VlessOutbound {
    fn kind(&self) -> &'static str {
        "vless"
    }

    fn tag(&self) -> &str {
        &self.tag
    }
}

pub fn register(registry: &mut Registry) -> Result<()> {
    registry.register_outbound::<VlessOutboundOptions, _, _>(
        "vless",
        |context: sing_box_core::OutboundBuildContext, tag, options| async move {
            anyhow::ensure!(!options.server.is_empty(), "VLESS server cannot be empty");
            anyhow::ensure!(options.server_port != 0, "VLESS server_port cannot be zero");
            anyhow::ensure!(
                options.transport.kind == "ws",
                "VLESS only supports WebSocket transport"
            );
            anyhow::ensure!(
                !options.transport.path.is_empty(),
                "VLESS WebSocket path cannot be empty"
            );
            anyhow::ensure!(
                options.tls.alpn.len() <= 16,
                "VLESS TLS ALPN list is too large"
            );
            Ok(Arc::new(VlessOutbound {
                tag,
                server: options.server,
                server_port: options.server_port,
                uuid: parse_uuid(&options.uuid).context("parse VLESS outbound UUID")?,
                path: options.transport.path,
                headers: options.transport.headers,
                max_early_data: options.transport.max_early_data,
                early_data_header_name: options.transport.early_data_header_name,
                tls: options.tls,
                dialer: context.system_dialer,
            }) as Arc<dyn sing_box_core::Outbound>)
        },
    )?;
    registry.register_inbound::<VlessInboundOptions, _, _>(
        "vless",
        |context: InboundBuildContext, tag, options| async move {
            anyhow::ensure!(
                options.transport.kind == "ws",
                "VLESS only supports WebSocket transport"
            );
            anyhow::ensure!(!options.users.is_empty(), "VLESS users cannot be empty");
            anyhow::ensure!(
                !options.transport.path.is_empty(),
                "VLESS WebSocket path cannot be empty"
            );
            let path = if options.transport.path.starts_with('/') {
                options.transport.path
            } else {
                format!("/{}", options.transport.path)
            };
            let reality = if options.tls.enabled {
                anyhow::ensure!(
                    options.tls.reality.enabled,
                    "VLESS TLS currently requires Reality"
                );
                Some(Arc::new(RealityAcceptor::new(RealityServerConfig {
                    server_name: options.tls.server_name.clone(),
                    alpn: options.tls.alpn.clone(),
                    options: options.tls.reality.clone(),
                    system_dialer: context.system_dialer.clone(),
                })?))
            } else {
                None
            };
            let mut users = HashMap::with_capacity(options.users.len());
            for (index, user) in options.users.into_iter().enumerate() {
                let uuid = parse_uuid(&user.uuid)
                    .with_context(|| format!("parse VLESS user UUID at index {index}"))?;
                let name = if user.name.is_empty() {
                    index.to_string()
                } else {
                    user.name
                };
                anyhow::ensure!(
                    users.insert(uuid, name).is_none(),
                    "duplicate VLESS user UUID"
                );
            }
            Ok(Arc::new(VlessInbound {
                tag,
                path,
                early_data_header_name: options.transport.early_data_header_name,
                users: Arc::new(users),
                router: context.router,
                listen: options.listen,
                listen_port: options.listen_port,
                running: Mutex::new(None),
                local_addr: RwLock::new(None),
                reality,
            }) as Arc<dyn Inbound>)
        },
    )
}

#[allow(clippy::too_many_arguments)]
async fn run_listener(
    listener: TcpListener,
    cancel: CancellationToken,
    connection_tasks: ConnectionTasks,
    router: Arc<Router>,
    tag: String,
    path: String,
    early_data_header_name: String,
    users: Arc<HashMap<[u8; 16], String>>,
    reality: Option<Arc<RealityAcceptor>>,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, source)) => {
                    let router = Arc::clone(&router);
                    let users = Arc::clone(&users);
                    let tag = tag.clone();
                    let path = path.clone();
                    let early_data_header_name = early_data_header_name.clone();
                    let reality = reality.clone();
                    let connection_cancel = cancel.clone();
                    connection_tasks.spawn(async move {
                        tokio::select! {
                            _ = connection_cancel.cancelled() => {}
                            result = handle_connection(
                                stream,
                                source,
                                router,
                                tag,
                                path,
                                early_data_header_name,
                                users,
                                reality,
                            ) => {
                                if let Err(error) = result {
                                    tracing::debug!(%source, %error, "VLESS WebSocket connection closed");
                                }
                            }
                        }
                    });
                }
                Err(error) => {
                    tracing::error!(%error, "VLESS accept failed");
                    break;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: TcpStream,
    source: SocketAddr,
    router: Arc<Router>,
    tag: String,
    path: String,
    early_data_header_name: String,
    users: Arc<HashMap<[u8; 16], String>>,
    reality: Option<Arc<RealityAcceptor>>,
) -> Result<()> {
    configure_tcp_stream(&stream)?;
    if let Some(reality) = reality {
        let Some(stream) = reality.accept(stream).await? else {
            return Ok(());
        };
        return handle_connection_inner(
            stream,
            source,
            router,
            tag,
            path,
            early_data_header_name,
            users,
        )
        .await;
    }
    handle_connection_inner(
        stream,
        source,
        router,
        tag,
        path,
        early_data_header_name,
        users,
    )
    .await
}

fn configure_tcp_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)
}

async fn handle_connection_inner<S>(
    mut stream: S,
    source: SocketAddr,
    router: Arc<Router>,
    tag: String,
    path: String,
    early_data_header_name: String,
    users: Arc<HashMap<[u8; 16], String>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request = read_http_request(&mut stream).await?;
    if request.method != "GET" {
        write_http_error(&mut stream, 405, "Method Not Allowed").await?;
        return Ok(());
    }
    if request.path != path {
        write_http_error(&mut stream, 404, "Not Found").await?;
        return Ok(());
    }
    ensure_websocket_request(&request)?;
    let early_data = if early_data_header_name.is_empty() {
        Vec::new()
    } else {
        let value = request.header(&early_data_header_name).unwrap_or_default();
        decode_base64_url(value).context("decode VLESS WebSocket early data")?
    };
    anyhow::ensure!(
        early_data.len() <= MAX_WS_FRAME_SIZE as usize,
        "VLESS early data is too large"
    );
    let accept = websocket_accept(request.header("sec-websocket-key").expect("validated key"));
    stream
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    stream.flush().await?;

    let mut application = WebSocketStream::new(stream, request.tail, early_data, false);
    let (destination, user) = read_vless_request(&mut application, &users).await?;
    application.write_all(&[VLESS_VERSION, 0]).await?;
    let session = Session::inbound(Network::Tcp, source, destination, tag, "vless", Some(user));
    router.route(session, Box::new(application)).await
}

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    tail: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    tail: Vec<u8>,
}

async fn read_http_response<S>(stream: &mut S) -> Result<HttpResponse>
where
    S: AsyncRead + Unpin,
{
    let mut data = Vec::with_capacity(1024);
    let header_end = loop {
        if data.len() > MAX_HTTP_HEADER_SIZE {
            anyhow::bail!("VLESS WebSocket response headers are too large");
        }
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            anyhow::bail!("VLESS WebSocket server closed before response headers");
        }
        data.extend_from_slice(&chunk[..read]);
        if let Some(position) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let header_text = std::str::from_utf8(&data[..header_end - 4])?;
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("VLESS WebSocket response has no status code")?
        .parse::<u16>()
        .context("parse VLESS WebSocket response status")?;
    let mut headers = HashMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            anyhow::bail!("invalid VLESS WebSocket response header");
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    Ok(HttpResponse {
        status,
        headers,
        tail: data[header_end..].to_vec(),
    })
}

async fn read_http_request<S>(stream: &mut S) -> Result<HttpRequest>
where
    S: AsyncRead + Unpin,
{
    let mut data = Vec::with_capacity(1024);
    let header_end = loop {
        if data.len() > MAX_HTTP_HEADER_SIZE {
            anyhow::bail!("VLESS WebSocket HTTP headers are too large");
        }
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            anyhow::bail!("VLESS WebSocket connection closed before HTTP headers");
        }
        data.extend_from_slice(&chunk[..read]);
        if let Some(position) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let header_text = std::str::from_utf8(&data[..header_end - 4])?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().context("missing WebSocket request line")?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_owned();
    let target = request_parts.next().unwrap_or_default();
    let path = target.split('?').next().unwrap_or_default().to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            anyhow::bail!("invalid WebSocket HTTP header");
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    Ok(HttpRequest {
        method,
        path,
        headers,
        tail: data[header_end..].to_vec(),
    })
}

fn ensure_websocket_request(request: &HttpRequest) -> Result<()> {
    anyhow::ensure!(
        request
            .header("upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket")),
        "missing WebSocket upgrade header"
    );
    anyhow::ensure!(
        request.header("connection").is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        }),
        "missing WebSocket connection header"
    );
    let key = request.header("sec-websocket-key").unwrap_or_default();
    anyhow::ensure!(!key.is_empty(), "missing Sec-WebSocket-Key header");
    Ok(())
}

async fn write_http_error<S>(stream: &mut S, status: u16, reason: &str) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(
            format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
}

struct WebSocketReadFrame {
    opcode: u8,
    remaining: u64,
    mask: [u8; 4],
    mask_offset: usize,
    control_payload: Option<Vec<u8>>,
}

struct WebSocketStream<S> {
    inner: S,
    client_side: bool,
    input: Vec<u8>,
    input_offset: usize,
    early_data: Vec<u8>,
    early_offset: usize,
    read_frame: Option<WebSocketReadFrame>,
    fragmented: bool,
    read_closed: bool,
    write_buffer: Vec<u8>,
    write_offset: usize,
    pending_payload_len: Option<usize>,
    control_write_pending: bool,
    close_queued: bool,
}

impl<S> WebSocketStream<S> {
    fn new(inner: S, input: Vec<u8>, early_data: Vec<u8>, client_side: bool) -> Self {
        Self {
            inner,
            client_side,
            input,
            input_offset: 0,
            early_data,
            early_offset: 0,
            read_frame: None,
            fragmented: false,
            read_closed: false,
            write_buffer: Vec::with_capacity(32 * 1024 + 10),
            write_offset: 0,
            pending_payload_len: None,
            control_write_pending: false,
            close_queued: false,
        }
    }

    fn available_input(&self) -> &[u8] {
        &self.input[self.input_offset..]
    }

    fn compact_input(&mut self) {
        if self.input_offset == self.input.len() {
            self.input.clear();
            self.input_offset = 0;
        } else if self.input_offset >= 32 * 1024 {
            self.input.drain(..self.input_offset);
            self.input_offset = 0;
        }
    }

    fn start_frame(&mut self) -> io::Result<bool> {
        let input = self.available_input();
        if input.len() < 2 {
            return Ok(false);
        }
        let fin = input[0] & 0x80 != 0;
        if input[0] & 0x70 != 0 {
            return Err(invalid_websocket_data("WebSocket reserved bits are set"));
        }
        let opcode = input[0] & 0x0f;
        let length_tag = input[1] & 0x7f;
        let extended_length = match length_tag {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        let masked = input[1] & 0x80 != 0;
        if masked == self.client_side {
            return Err(invalid_websocket_data(
                "invalid WebSocket masking direction",
            ));
        }
        let header_length = 2 + extended_length + usize::from(masked) * 4;
        if input.len() < header_length {
            return Ok(false);
        }
        let payload_length = match length_tag {
            126 => u64::from(u16::from_be_bytes([input[2], input[3]])),
            127 => u64::from_be_bytes(input[2..10].try_into().expect("WebSocket length")),
            value => u64::from(value),
        };
        if payload_length > MAX_WS_FRAME_SIZE {
            return Err(invalid_websocket_data("WebSocket frame is too large"));
        }
        let is_control = opcode & 0x08 != 0;
        if is_control && (!fin || payload_length > 125) {
            return Err(invalid_websocket_data("invalid WebSocket control frame"));
        }
        let mask_offset = 2 + extended_length;
        let mask = if masked {
            input[mask_offset..mask_offset + 4]
                .try_into()
                .expect("WebSocket mask")
        } else {
            [0; 4]
        };
        match opcode {
            0x0 => {
                if !self.fragmented {
                    return Err(invalid_websocket_data(
                        "unexpected WebSocket continuation frame",
                    ));
                }
                self.fragmented = !fin;
            }
            0x2 => {
                if self.fragmented {
                    return Err(invalid_websocket_data("nested WebSocket fragmented frame"));
                }
                self.fragmented = !fin;
            }
            0x8..=0xA => {}
            _ => {
                return Err(invalid_websocket_data(format!(
                    "unsupported WebSocket opcode: {opcode}"
                )));
            }
        }
        self.input_offset += header_length;
        self.read_frame = Some(WebSocketReadFrame {
            opcode,
            remaining: payload_length,
            mask,
            mask_offset: 0,
            control_payload: is_control.then(|| Vec::with_capacity(payload_length as usize)),
        });
        Ok(true)
    }

    fn append_frame(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        if self.write_offset == self.write_buffer.len() {
            self.write_buffer.clear();
            self.write_offset = 0;
        }
        self.write_buffer.push(0x80 | opcode);
        let mask_bit = if self.client_side { 0x80 } else { 0 };
        match payload.len() {
            0..=125 => self.write_buffer.push(mask_bit | payload.len() as u8),
            126..=65_535 => {
                self.write_buffer.push(mask_bit | 126);
                self.write_buffer
                    .extend_from_slice(&(payload.len() as u16).to_be_bytes());
            }
            length => {
                self.write_buffer.push(mask_bit | 127);
                self.write_buffer
                    .extend_from_slice(&(length as u64).to_be_bytes());
            }
        }
        if self.client_side {
            let mut mask = [0u8; 4];
            SystemRandom::new()
                .fill(&mut mask)
                .map_err(|_| io::Error::other("generate WebSocket mask"))?;
            self.write_buffer.extend_from_slice(&mask);
            self.write_buffer.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ mask[index % 4]),
            );
        } else {
            self.write_buffer.extend_from_slice(payload);
        }
        Ok(())
    }

    fn finish_read_frame(&mut self) -> io::Result<()> {
        let frame = self.read_frame.take().expect("WebSocket read frame");
        match frame.opcode {
            0x8 => {
                self.append_frame(0x8, frame.control_payload.as_deref().unwrap_or_default())?;
                self.control_write_pending = true;
                self.close_queued = true;
                self.read_closed = true;
            }
            0x9 => {
                self.append_frame(0xA, frame.control_payload.as_deref().unwrap_or_default())?;
                self.control_write_pending = true;
            }
            _ => {}
        }
        Ok(())
    }
}

impl<S> WebSocketStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_fill_input(&mut self, context: &mut TaskContext<'_>) -> Poll<io::Result<bool>> {
        self.compact_input();
        let mut chunk = [0u8; 32 * 1024];
        let mut buffer = ReadBuf::new(&mut chunk);
        match Pin::new(&mut self.inner).poll_read(context, &mut buffer) {
            Poll::Ready(Ok(())) => {
                if buffer.filled().is_empty() {
                    Poll::Ready(Ok(false))
                } else {
                    self.input.extend_from_slice(buffer.filled());
                    Poll::Ready(Ok(true))
                }
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush_output(&mut self, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        while self.write_offset < self.write_buffer.len() {
            match Pin::new(&mut self.inner)
                .poll_write(context, &self.write_buffer[self.write_offset..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write WebSocket frame",
                    )));
                }
                Poll::Ready(Ok(written)) => self.write_offset += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_buffer.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for WebSocketStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.early_offset < this.early_data.len() {
            let count = (this.early_data.len() - this.early_offset).min(output.remaining());
            output.put_slice(&this.early_data[this.early_offset..this.early_offset + count]);
            this.early_offset += count;
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.control_write_pending {
                match this.poll_flush_output(context) {
                    Poll::Ready(Ok(())) => this.control_write_pending = false,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if this.read_closed || output.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if this.read_frame.is_none() && !this.start_frame()? {
                match this.poll_fill_input(context) {
                    Poll::Ready(Ok(true)) => continue,
                    Poll::Ready(Ok(false)) if this.available_input().is_empty() => {
                        this.read_closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Ok(false)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated WebSocket frame header",
                        )));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if this
                .read_frame
                .as_ref()
                .is_some_and(|frame| frame.remaining == 0)
            {
                this.finish_read_frame()?;
                continue;
            }
            if this.available_input().is_empty() {
                match this.poll_fill_input(context) {
                    Poll::Ready(Ok(true)) => {}
                    Poll::Ready(Ok(false)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated WebSocket frame payload",
                        )));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let frame = this.read_frame.as_ref().expect("WebSocket read frame");
            let is_control = frame.control_payload.is_some();
            let count = (frame.remaining as usize)
                .min(this.available_input().len())
                .min(if is_control {
                    usize::MAX
                } else {
                    output.remaining()
                });
            let mask = frame.mask;
            let mask_offset = frame.mask_offset;
            if is_control {
                let decoded = this.available_input()[..count]
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ mask[(mask_offset + index) % 4])
                    .collect::<Vec<_>>();
                this.read_frame
                    .as_mut()
                    .expect("WebSocket read frame")
                    .control_payload
                    .as_mut()
                    .expect("WebSocket control payload")
                    .extend_from_slice(&decoded);
            } else {
                let destination = output.initialize_unfilled_to(count);
                for (index, byte) in this.available_input()[..count].iter().enumerate() {
                    destination[index] = byte ^ mask[(mask_offset + index) % 4];
                }
                output.advance(count);
            }
            this.input_offset += count;
            let frame = this.read_frame.as_mut().expect("WebSocket read frame");
            frame.remaining -= count as u64;
            frame.mask_offset = (frame.mask_offset + count) % 4;
            this.compact_input();
            if !is_control {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<S> AsyncWrite for WebSocketStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(accepted) = this.pending_payload_len {
            return match this.poll_flush_output(context) {
                Poll::Ready(Ok(())) => {
                    this.pending_payload_len = None;
                    Poll::Ready(Ok(accepted))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            };
        }
        match this.poll_flush_output(context) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let accepted = data.len().min(MAX_WS_FRAME_SIZE as usize);
        this.append_frame(0x2, &data[..accepted])?;
        this.pending_payload_len = Some(accepted);
        match this.poll_flush_output(context) {
            Poll::Ready(Ok(())) => {
                this.pending_payload_len = None;
                Poll::Ready(Ok(accepted))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_output(context) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(context),
            result => result,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.close_queued {
            if let Err(error) = this.append_frame(0x8, &[]) {
                return Poll::Ready(Err(error));
            }
            this.close_queued = true;
        }
        match this.poll_flush_output(context) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(context),
            result => result,
        }
    }
}

fn invalid_websocket_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

async fn read_vless_request<S>(
    stream: &mut S,
    users: &HashMap<[u8; 16], String>,
) -> Result<(Address, String)>
where
    S: AsyncRead + Unpin,
{
    let mut version = [0u8; 1];
    stream.read_exact(&mut version).await?;
    anyhow::ensure!(version[0] == VLESS_VERSION, "unsupported VLESS version");
    let mut uuid = [0u8; 16];
    stream.read_exact(&mut uuid).await?;
    let user = users.get(&uuid).context("invalid VLESS user UUID")?.clone();
    let mut addons_len = [0u8; 1];
    stream.read_exact(&mut addons_len).await?;
    if addons_len[0] > 0 {
        let mut addons = vec![0u8; addons_len[0] as usize];
        stream.read_exact(&mut addons).await?;
    }
    let mut command = [0u8; 1];
    stream.read_exact(&mut command).await?;
    anyhow::ensure!(
        command[0] == VLESS_COMMAND_TCP,
        "VLESS UDP is not implemented"
    );
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    let mut address_type = [0u8; 1];
    stream.read_exact(&mut address_type).await?;
    let host = match address_type[0] {
        1 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address).await?;
            Ipv4Addr::from(address).to_string()
        }
        2 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let mut domain = vec![0u8; length[0] as usize];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain).context("VLESS domain is not UTF-8")?
        }
        3 => {
            let mut address = [0u8; 16];
            stream.read_exact(&mut address).await?;
            Ipv6Addr::from(address).to_string()
        }
        value => anyhow::bail!("unsupported VLESS address type: {value}"),
    };
    Ok((Address::new(host, port)?, user))
}

fn parse_uuid(value: &str) -> Result<[u8; 16]> {
    let mut hex = [0u8; 32];
    let mut length = 0;
    for byte in value.bytes() {
        if byte == b'-' {
            continue;
        }
        anyhow::ensure!(length < hex.len(), "VLESS UUID is too long");
        hex[length] = byte;
        length += 1;
    }
    anyhow::ensure!(
        length == hex.len(),
        "VLESS UUID must contain 32 hexadecimal digits"
    );
    let mut output = [0u8; 16];
    for (index, pair) in hex.chunks_exact(2).enumerate() {
        output[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Ok(output)
}

fn encode_vless_request(uuid: &[u8; 16], destination: &Address) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(64 + destination.host.len());
    output.push(VLESS_VERSION);
    output.extend_from_slice(uuid);
    output.push(0);
    output.push(VLESS_COMMAND_TCP);
    output.extend_from_slice(&destination.port.to_be_bytes());
    match destination.host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        Ok(std::net::IpAddr::V6(address)) => {
            output.push(3);
            output.extend_from_slice(&address.octets());
        }
        Err(_) => {
            anyhow::ensure!(
                destination.host.len() <= u8::MAX as usize,
                "VLESS domain is too long"
            );
            output.push(2);
            output.push(destination.host.len() as u8);
            output.extend_from_slice(destination.host.as_bytes());
        }
    }
    Ok(output)
}

fn websocket_key() -> Result<String> {
    let mut key = [0u8; 16];
    SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| anyhow::anyhow!("generate WebSocket key"))?;
    Ok(encode_base64(&key))
}

fn hex_value(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => anyhow::bail!("invalid hexadecimal digit in VLESS UUID"),
    }
}

fn websocket_accept(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + WS_GUID.len());
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(WS_GUID);
    encode_base64(&sha1(&input))
}

fn decode_base64_url(value: &str) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in value.bytes() {
        if byte == b'=' {
            break;
        }
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => anyhow::bail!("invalid URL base64 character"),
        };
        buffer = (buffer << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    anyhow::ensure!(bits < 6, "invalid URL base64 padding");
    Ok(output)
}

fn encode_base64(value: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(value.len().div_ceil(3) * 4);
    for chunk in value.chunks(3) {
        let first = chunk[0];
        output.push(TABLE[(first >> 2) as usize] as char);
        if chunk.len() == 1 {
            output.push(TABLE[((first & 3) << 4) as usize] as char);
            output.push('=');
            output.push('=');
            continue;
        }
        let second = chunk[1];
        output.push(TABLE[((first & 3) << 4 | second >> 4) as usize] as char);
        if chunk.len() == 2 {
            output.push(TABLE[((second & 15) << 2) as usize] as char);
            output.push('=');
            continue;
        }
        let third = chunk[2];
        output.push(TABLE[((second & 15) << 2 | third >> 6) as usize] as char);
        output.push(TABLE[(third & 63) as usize] as char);
    }
    output
}

fn encode_base64_url(value: &[u8]) -> String {
    encode_base64(value)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

fn sha1(message: &[u8]) -> [u8; 20] {
    let bit_length = (message.len() as u64) * 8;
    let mut data = message.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_length.to_be_bytes());
    let mut state = [
        0x67452301u32,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    ];
    for chunk in data.chunks_exact(64) {
        let mut words = [0u32; 80];
        for (index, word) in words[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes([
                chunk[index * 4],
                chunk[index * 4 + 1],
                chunk[index * 4 + 2],
                chunk[index * 4 + 3],
            ]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (index, word) in words.iter().enumerate() {
            let (function, constant) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(function)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
    let mut output = [0u8; 20];
    for (index, word) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

async fn build_vless_client_config(tls: &VlessClientTlsOptions) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    if tls.certificate_path.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    } else {
        let data = tokio::fs::read(&tls.certificate_path)
            .await
            .with_context(|| format!("read {}", tls.certificate_path))?;
        let mut reader = Cursor::new(data);
        for certificate in rustls_pemfile::certs(&mut reader) {
            roots.add(certificate?)?;
        }
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = if tls.insecure {
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(VlessNoVerifier))
            .with_no_client_auth()
    } else {
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    config.alpn_protocols = if tls.alpn.is_empty() {
        vec![b"http/1.1".to_vec()]
    } else {
        tls.alpn
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect()
    };
    Ok(config)
}

#[derive(Debug)]
struct VlessNoVerifier;

impl ServerCertVerifier for VlessNoVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use super::*;

    #[derive(Default)]
    struct CountingWriter {
        writes: usize,
        data: Vec<u8>,
    }

    #[derive(Default)]
    struct PartialWriter {
        polls: usize,
        data: Vec<u8>,
    }

    impl AsyncWrite for CountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes += 1;
            self.data.extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for CountingWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for PartialWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.polls += 1;
            if self.polls == 2 {
                context.waker().wake_by_ref();
                return Poll::Pending;
            }
            let written = data.len().min(2);
            self.data.extend_from_slice(&data[..written]);
            Poll::Ready(Ok(written))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for PartialWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn masked_frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mask = [1u8, 2, 3, 4];
        let mut frame = vec![
            (if fin { 0x80 } else { 0 }) | opcode,
            0x80 | payload.len() as u8,
        ];
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
        frame
    }

    async fn read_server_frame(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0] & 0x0f, 0x2);
        assert_eq!(header[1] & 0x80, 0);
        let length = match header[1] & 0x7f {
            126 => {
                let mut bytes = [0u8; 2];
                stream.read_exact(&mut bytes).await.unwrap();
                u16::from_be_bytes(bytes) as usize
            }
            127 => {
                let mut bytes = [0u8; 8];
                stream.read_exact(&mut bytes).await.unwrap();
                u64::from_be_bytes(bytes) as usize
            }
            length => length as usize,
        };
        let mut payload = vec![0u8; length];
        stream.read_exact(&mut payload).await.unwrap();
        payload
    }

    #[tokio::test]
    async fn configures_inbound_tcp_for_low_latency() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(TcpStream::connect(address));
        let (server, _) = listener.accept().await.unwrap();
        configure_tcp_stream(&server).unwrap();
        assert!(server.nodelay().unwrap());
        client.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn vless_websocket_outbound_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_address = listener.local_addr().unwrap();
        let uuid = parse_uuid("d4f2ad1c-f6db-481e-91de-9d551f8885c9").unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await.unwrap();
            assert_eq!(request.path, "/proxy");
            let accept = websocket_accept(request.header("sec-websocket-key").unwrap());
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut websocket = WebSocketStream::new(stream, request.tail, Vec::new(), false);
            let users = HashMap::from([(uuid, "test".to_owned())]);
            let (destination, _) = read_vless_request(&mut websocket, &users).await.unwrap();
            assert_eq!(destination, Address::new("example.com", 443).unwrap());
            websocket.write_all(&[VLESS_VERSION, 0]).await.unwrap();
            let mut payload = [0u8; 4];
            websocket.read_exact(&mut payload).await.unwrap();
            websocket.write_all(&payload).await.unwrap();
        });
        let outbound = VlessOutbound {
            tag: "vless-out".to_owned(),
            server: server_address.ip().to_string(),
            server_port: server_address.port(),
            uuid,
            path: "/proxy".to_owned(),
            headers: HashMap::new(),
            max_early_data: 0,
            early_data_header_name: String::new(),
            tls: VlessClientTlsOptions::default(),
            dialer: sing_box_core::SystemDialer::new(
                None,
                None,
                sing_box_core::DomainStrategy::AsIs,
            ),
        };
        let session = Session::outbound(Address::new("example.com", 443).unwrap());
        let mut stream = outbound.connect(&session).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn writes_websocket_header_and_payload_together() {
        let writer = CountingWriter::default();
        let mut stream = WebSocketStream::new(writer, Vec::new(), Vec::new(), false);

        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();

        assert_eq!(stream.inner.writes, 1);
        assert_eq!(stream.inner.data, [0x82, 4, b'p', b'i', b'n', b'g']);
    }

    #[tokio::test]
    async fn client_websocket_frames_are_masked() {
        let writer = CountingWriter::default();
        let mut stream = WebSocketStream::new(writer, Vec::new(), Vec::new(), true);

        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();

        let frame = &stream.inner.data;
        assert_eq!(frame[0], 0x82);
        assert_eq!(frame[1], 0x84);
        let mask: [u8; 4] = frame[2..6].try_into().unwrap();
        let payload = frame[6..]
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 4])
            .collect::<Vec<_>>();
        assert_eq!(payload, b"ping");
    }

    #[tokio::test]
    async fn preserves_a_frame_across_partial_socket_writes() {
        let writer = PartialWriter::default();
        let mut stream = WebSocketStream::new(writer, Vec::new(), Vec::new(), false);

        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();

        assert_eq!(stream.inner.data, [0x82, 4, b'p', b'i', b'n', b'g']);
    }

    #[tokio::test]
    async fn reads_masked_websocket_payload_without_a_bridge() {
        let (mut client, server) = tokio::io::duplex(128);
        let mut stream = WebSocketStream::new(server, Vec::new(), Vec::new(), false);
        let frame = masked_frame(0x2, true, b"ping");
        client.write_all(&frame).await.unwrap();

        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();

        assert_eq!(&payload, b"ping");
    }

    #[tokio::test]
    async fn client_reads_unmasked_websocket_payload() {
        let (mut server, client) = tokio::io::duplex(128);
        let mut stream = WebSocketStream::new(client, Vec::new(), Vec::new(), true);
        server
            .write_all(&[0x82, 4, b'p', b'i', b'n', b'g'])
            .await
            .unwrap();

        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();

        assert_eq!(&payload, b"ping");
    }

    #[tokio::test]
    async fn handles_fragmented_data_and_ping_without_background_tasks() {
        let (mut client, server) = tokio::io::duplex(256);
        let mut stream = WebSocketStream::new(server, Vec::new(), Vec::new(), false);
        let mut frames = masked_frame(0x2, false, b"pi");
        frames.extend_from_slice(&masked_frame(0x9, true, b"ok"));
        frames.extend_from_slice(&masked_frame(0x0, true, b"ng"));
        client.write_all(&frames).await.unwrap();

        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        let mut pong = [0u8; 4];
        client.read_exact(&mut pong).await.unwrap();

        assert_eq!(&payload, b"ping");
        assert_eq!(pong, [0x8A, 2, b'o', b'k']);
    }

    #[tokio::test]
    async fn routes_vless_websocket_tcp_without_a_duplex_bridge() {
        use sing_box_core::{Config, Engine, Registry, register_builtins};

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let (mut reader, mut writer) = stream.split();
            tokio::io::copy(&mut reader, &mut writer).await.unwrap();
        });
        let mut registry = Registry::new();
        register_builtins(&mut registry).unwrap();
        register(&mut registry).unwrap();
        let config: Config = serde_json::from_value(serde_json::json!({
            "inbounds": [{
                "type": "vless",
                "tag": "vless-in",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "users": [{"uuid": "d4f2ad1c-f6db-481e-91de-9d551f8885c9"}],
                "transport": {"type": "ws", "path": "/proxy"}
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"}
        }))
        .unwrap();
        let engine = Engine::new(config, registry).await.unwrap();
        engine.start().await.unwrap();
        let inbound_address = engine.inbound_addr("vless-in").await.unwrap();
        let mut client = TcpStream::connect(inbound_address).await.unwrap();
        client
            .write_all(
                b"GET /proxy HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            response.push(client.read_u8().await.unwrap());
        }
        assert!(response.starts_with(b"HTTP/1.1 101"));

        let uuid = parse_uuid("d4f2ad1c-f6db-481e-91de-9d551f8885c9").unwrap();
        let mut request = vec![VLESS_VERSION];
        request.extend_from_slice(&uuid);
        request.extend_from_slice(&[0, VLESS_COMMAND_TCP]);
        request.extend_from_slice(&echo_address.port().to_be_bytes());
        request.extend_from_slice(&[1, 127, 0, 0, 1]);
        request.extend_from_slice(b"ping");
        client
            .write_all(&masked_frame(0x2, true, &request))
            .await
            .unwrap();

        let mut application_data = Vec::new();
        while application_data.len() < 6 {
            application_data.extend_from_slice(&read_server_frame(&mut client).await);
        }
        assert_eq!(&application_data[..2], &[VLESS_VERSION, 0]);
        assert_eq!(&application_data[2..], b"ping");

        client.shutdown().await.unwrap();
        drop(client);
        engine.shutdown().await.unwrap();
        echo_task.await.unwrap();
    }

    #[tokio::test]
    async fn parses_official_version_zero_request() {
        let uuid = parse_uuid("d4f2ad1c-f6db-481e-91de-9d551f8885c9").unwrap();
        let mut users = HashMap::new();
        users.insert(uuid, "test-user".to_owned());
        let (mut client, mut server) = tokio::io::duplex(128);
        let mut request = vec![0];
        request.extend_from_slice(&uuid);
        request.extend_from_slice(&[0, VLESS_COMMAND_TCP]);
        request.extend_from_slice(&443u16.to_be_bytes());
        request.extend_from_slice(&[1, 127, 0, 0, 1]);
        client.write_all(&request).await.unwrap();

        let (destination, user) = read_vless_request(&mut server, &users).await.unwrap();

        assert_eq!(destination, Address::new("127.0.0.1", 443).unwrap());
        assert_eq!(user, "test-user");
    }

    #[test]
    fn parses_vless_uuid() {
        assert_eq!(
            parse_uuid("d4f2ad1c-f6db-481e-91de-9d551f8885c9").unwrap(),
            [
                0xd4, 0xf2, 0xad, 0x1c, 0xf6, 0xdb, 0x48, 0x1e, 0x91, 0xde, 0x9d, 0x55, 0x1f, 0x88,
                0x85, 0xc9
            ]
        );
    }

    #[test]
    fn computes_websocket_accept_key() {
        assert_eq!(
            websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn decodes_url_base64_without_padding() {
        assert_eq!(decode_base64_url("AQIDBA").unwrap(), [1, 2, 3, 4]);
    }
}
