use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use sing_box_core::{
    Address, Inbound, InboundBuildContext, Lifecycle, Network, Registry, Router, Session,
    bind_tcp_listeners,
};
use sing_box_tls::{RealityAcceptor, RealityOptions, RealityServerConfig};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const VLESS_VERSION: u8 = 0;
const VLESS_COMMAND_TCP: u8 = 1;
const MAX_HTTP_HEADER_SIZE: usize = 16 * 1024;
const MAX_WS_FRAME_SIZE: u64 = 16 * 1024 * 1024;
const BRIDGE_CAPACITY: usize = 1024 * 1024;
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

fn default_listen() -> String {
    "127.0.0.1".to_owned()
}

struct Running {
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
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
        let mut tasks = Vec::with_capacity(listeners.len());
        for listener in listeners {
            tasks.push(tokio::spawn(run_listener(
                listener,
                cancel.clone(),
                Arc::clone(&self.router),
                self.tag.clone(),
                self.path.clone(),
                self.early_data_header_name.clone(),
                Arc::clone(&self.users),
                self.reality.clone(),
            )));
        }
        *self.running.lock().await = Some(Running { cancel, tasks });
        tracing::info!(tag = %self.tag, %local_addr, "started VLESS WebSocket inbound");
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        if let Some(running) = self.running.lock().await.take() {
            running.cancel.cancel();
            for task in running.tasks {
                task.await?;
            }
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

pub fn register(registry: &mut Registry) -> Result<()> {
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
                    tokio::spawn(async move {
                        if let Err(error) = handle_connection(
                            stream,
                            source,
                            router,
                            tag,
                            path,
                            early_data_header_name,
                            users,
                            reality,
                        )
                        .await
                        {
                            tracing::debug!(%source, %error, "VLESS WebSocket connection closed");
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

    let (tcp_reader, tcp_writer) = tokio::io::split(stream);
    let (application, bridge) = tokio::io::duplex(BRIDGE_CAPACITY);
    let (bridge_reader, bridge_writer) = tokio::io::split(bridge);
    let (control_sender, control_receiver) = mpsc::unbounded_channel();
    let reader_task = tokio::spawn(websocket_reader(
        tcp_reader,
        request.tail,
        early_data,
        bridge_writer,
        control_sender,
    ));
    let writer_task = tokio::spawn(websocket_writer(
        tcp_writer,
        bridge_reader,
        control_receiver,
    ));

    let mut application = application;
    let result = async {
        let (destination, user) = read_vless_request(&mut application, &users).await?;
        application.write_all(&[VLESS_VERSION, 0]).await?;
        let session = Session::inbound(Network::Tcp, source, destination, tag, "vless", Some(user));
        router.route(session, Box::new(application)).await
    }
    .await;
    reader_task.abort();
    writer_task.abort();
    result
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

enum ControlFrame {
    Pong(Vec<u8>),
    Close,
}

async fn websocket_reader<R>(
    mut reader: R,
    mut prefix: Vec<u8>,
    early_data: Vec<u8>,
    mut destination: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    controls: mpsc::UnboundedSender<ControlFrame>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut offset = 0;
    if !early_data.is_empty() {
        destination.write_all(&early_data).await?;
    }
    let mut fragmented = false;
    loop {
        let mut header = [0u8; 2];
        read_prefixed(&mut reader, &mut prefix, &mut offset, &mut header).await?;
        let fin = header[0] & 0x80 != 0;
        anyhow::ensure!(header[0] & 0x70 == 0, "WebSocket reserved bits are set");
        let opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        anyhow::ensure!(masked, "client WebSocket frame is not masked");
        let mut payload_len = u64::from(header[1] & 0x7f);
        if payload_len == 126 {
            let mut bytes = [0u8; 2];
            read_prefixed(&mut reader, &mut prefix, &mut offset, &mut bytes).await?;
            payload_len = u64::from(u16::from_be_bytes(bytes));
        } else if payload_len == 127 {
            let mut bytes = [0u8; 8];
            read_prefixed(&mut reader, &mut prefix, &mut offset, &mut bytes).await?;
            payload_len = u64::from_be_bytes(bytes);
        }
        anyhow::ensure!(
            payload_len <= MAX_WS_FRAME_SIZE,
            "WebSocket frame is too large"
        );
        if opcode & 0x08 != 0 {
            anyhow::ensure!(fin && payload_len <= 125, "invalid WebSocket control frame");
        }
        let mut mask = [0u8; 4];
        read_prefixed(&mut reader, &mut prefix, &mut offset, &mut mask).await?;
        let mut payload = vec![0u8; payload_len as usize];
        read_prefixed(&mut reader, &mut prefix, &mut offset, &mut payload).await?;
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
        match opcode {
            0x0 => {
                anyhow::ensure!(fragmented, "unexpected WebSocket continuation frame");
                destination.write_all(&payload).await?;
                fragmented = !fin;
            }
            0x2 => {
                anyhow::ensure!(!fragmented, "nested WebSocket fragmented frame");
                destination.write_all(&payload).await?;
                fragmented = !fin;
            }
            0x8 => {
                let _ = controls.send(ControlFrame::Close);
                destination.shutdown().await?;
                return Ok(());
            }
            0x9 => {
                let _ = controls.send(ControlFrame::Pong(payload));
            }
            0xA => {}
            _ => anyhow::bail!("unsupported WebSocket opcode: {opcode}"),
        }
    }
}

async fn websocket_writer<W>(
    mut writer: W,
    mut source: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    mut controls: mpsc::UnboundedReceiver<ControlFrame>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            command = controls.recv() => match command {
                Some(ControlFrame::Pong(payload)) => write_frame(&mut writer, 0xA, &payload).await?,
                Some(ControlFrame::Close) | None => {
                    if command.is_some() {
                        write_frame(&mut writer, 0x8, &[]).await?;
                    }
                    return Ok(());
                }
            },
            read = source.read(&mut buffer) => {
                let read = read?;
                if read == 0 {
                    let _ = write_frame(&mut writer, 0x8, &[]).await;
                    return Ok(());
                }
                write_frame(&mut writer, 0x2, &buffer[..read]).await?;
            }
        }
    }
}

async fn write_frame<W>(writer: &mut W, opcode: u8, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header = Vec::with_capacity(10);
    header.push(0x80 | opcode);
    match payload.len() {
        0..=125 => header.push(payload.len() as u8),
        126..=65_535 => {
            header.push(126);
            header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        length => {
            header.push(127);
            header.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    writer.write_all(&header).await?;
    writer.write_all(payload).await
}

async fn read_prefixed<R>(
    reader: &mut R,
    prefix: &mut [u8],
    offset: &mut usize,
    output: &mut [u8],
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut written = 0;
    if *offset < prefix.len() {
        let available = (prefix.len() - *offset).min(output.len());
        output[..available].copy_from_slice(&prefix[*offset..*offset + available]);
        *offset += available;
        written = available;
    }
    if written < output.len() {
        reader.read_exact(&mut output[written..]).await?;
    }
    Ok(())
}

async fn read_vless_request(
    stream: &mut tokio::io::DuplexStream,
    users: &HashMap<[u8; 16], String>,
) -> Result<(Address, String)> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
