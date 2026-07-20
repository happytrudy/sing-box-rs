use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use capnp::{capability::Promise, message::ReaderOptions};
use capnp_rpc::{RpcSystem, rpc_twoparty_capnp::Side, twoparty::VatNetwork};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, crypto::rustls::QuicClientConfig};
use rustls::{ClientConfig as RustlsClientConfig, NamedGroup};
use sing_box_core::{Address, BoxPacketConnection, Packet, PacketConnection};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::oneshot,
};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use crate::{
    Credentials,
    discovery::EdgeAddr,
    protocol::{self, ConnectRequest, ConnectResponse, ConnectionType},
    registration::{self, ConnectionOptions, RegistrationResult},
    transport::{ConfigurationHandler, HandlerFuture, StreamHandler},
    tunnelrpc_capnp,
};

pub const QUIC_EDGE_SNI: &str = "quic.cftunnel.com";
pub const QUIC_EDGE_ALPN: &[u8] = b"argotunnel";
const MAX_CONNECT_MESSAGE: usize = 8 * 1024 * 1024;
const DATAGRAM_V3_REGISTRATION: u8 = 0;
const DATAGRAM_V3_PAYLOAD: u8 = 1;
const DATAGRAM_V3_REGISTRATION_RESPONSE: u8 = 3;
const DATAGRAM_V3_FLAG_IPV6: u8 = 0x01;
const DATAGRAM_V3_FLAG_BUNDLE: u8 = 0x04;
const DATAGRAM_V3_REQUEST_ID_LENGTH: usize = 16;
const DATAGRAM_V3_MAX_PAYLOAD: usize = 1280;
const DEFAULT_DATAGRAM_IDLE: Duration = Duration::from_secs(210);
const QUIC_INITIAL_MTU_IPV4: u16 = 1232;
const QUIC_INITIAL_MTU_IPV6: u16 = 1252;
const QUIC_MAX_CONCURRENT_STREAMS: u32 = 1024;

pub type DatagramHandler =
    Arc<dyn Fn(Address, BoxPacketConnection) -> crate::transport::HandlerFuture + Send + Sync>;
pub type QuicHttpHandler =
    Arc<dyn Fn(ConnectRequest, QuicRequestStream) -> HandlerFuture + Send + Sync>;

#[derive(Clone)]
pub struct QuicOptions {
    pub edge: EdgeAddr,
    pub credentials: Credentials,
    pub connection_index: u8,
    pub registration: ConnectionOptions,
    pub post_quantum: bool,
    pub datagram_version: String,
    pub grace_period: Duration,
    pub configuration_handler: Option<ConfigurationHandler>,
    pub http_handler: Option<QuicHttpHandler>,
}

pub struct QuicConnection {
    options: QuicOptions,
}

impl QuicConnection {
    pub fn new(options: QuicOptions) -> Self {
        Self { options }
    }

    pub async fn run(
        self,
        handler: StreamHandler,
        datagram_handler: Option<DatagramHandler>,
    ) -> Result<RegistrationResult> {
        let (_shutdown, receiver) = oneshot::channel();
        self.run_with_shutdown(handler, datagram_handler, receiver)
            .await
    }

    pub async fn run_with_shutdown(
        self,
        handler: StreamHandler,
        datagram_handler: Option<DatagramHandler>,
        mut shutdown: oneshot::Receiver<()>,
    ) -> Result<RegistrationResult> {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(self.run_local(handler, datagram_handler, &mut shutdown))
            .await
            .context("run Cloudflare QUIC connection")
    }

    async fn run_local(
        self,
        handler: StreamHandler,
        datagram_handler: Option<DatagramHandler>,
        shutdown: &mut oneshot::Receiver<()>,
    ) -> Result<RegistrationResult> {
        let endpoint = build_endpoint(
            self.options.post_quantum,
            self.options.edge.address.is_ipv4(),
        )?;
        let connecting = endpoint
            .connect(self.options.edge.address, QUIC_EDGE_SNI)
            .context("connect Cloudflare QUIC edge")?;
        let connection = connecting
            .await
            .context("QUIC handshake with Cloudflare edge")?;
        let (send, recv) = connection
            .open_bi()
            .await
            .context("open Cloudflare control stream")?;
        let mut registration = register_connection(
            QuicStream::new(send, recv),
            self.options.credentials.clone(),
            self.options.connection_index,
            self.options.registration.clone(),
        )
        .await?;
        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel(256);
        let mut sessions = HashMap::new();
        let mut cleanup = tokio::time::interval(Duration::from_secs(1));
        let v2_state = if self.options.datagram_version == "v2" {
            Some(V2State {
                sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                handler: datagram_handler.clone(),
                outbound: outbound_tx.clone(),
            })
        } else {
            None
        };

        loop {
            tokio::select! {
                accepted = connection.accept_bi() => {
                    let (send, recv) = accepted.context("accept Cloudflare QUIC stream")?;
                    let handler = Arc::clone(&handler);
                    let configuration_handler = self.options.configuration_handler.clone();
                    let http_handler = self.options.http_handler.clone();
                    let v2_state = v2_state.clone();
                    tokio::task::spawn_local(async move {
                        if let Err(error) = handle_stream(
                            send,
                            recv,
                            handler,
                            configuration_handler,
                            http_handler,
                            v2_state,
                        )
                        .await
                        {
                            tracing::warn!(%error, error_chain = ?error, "Cloudflare QUIC data stream failed");
                        }
                    });
                }
                datagram = connection.read_datagram(), if self.options.datagram_version == "v3" => {
                    handle_datagram(&connection, datagram.context("read Cloudflare QUIC datagram")?.as_ref(), &mut sessions, datagram_handler.as_ref(), &outbound_tx).await?;
                }
                datagram = connection.read_datagram(), if self.options.datagram_version == "v2" => {
                    handle_v2_datagram(datagram.context("read Cloudflare QUIC v2 datagram")?.as_ref(), v2_state.as_ref()).await?;
                }
                _ = cleanup.tick(), if matches!(self.options.datagram_version.as_str(), "v2" | "v3") => {
                    cleanup_sessions(&mut sessions);
                    if let Some(state) = &v2_state {
                        state.cleanup().await;
                    }
                }
                outbound = outbound_rx.recv(), if matches!(self.options.datagram_version.as_str(), "v2" | "v3") => {
                    let Some((request_id, payload)) = outbound else { continue; };
                    if payload.len() > DATAGRAM_V3_MAX_PAYLOAD { continue; }
                    if self.options.datagram_version == "v3" {
                        let mut datagram = Vec::with_capacity(1 + request_id.len() + payload.len());
                        datagram.push(DATAGRAM_V3_PAYLOAD);
                        datagram.extend_from_slice(&request_id);
                        datagram.extend_from_slice(&payload);
                        connection.send_datagram(datagram.into()).context("send Cloudflare QUIC datagram")?;
                    } else {
                        let mut datagram = Vec::with_capacity(payload.len() + 17);
                        datagram.extend_from_slice(&payload);
                        datagram.extend_from_slice(&request_id);
                        datagram.push(0);
                        connection.send_datagram(datagram.into()).context("send Cloudflare QUIC v2 datagram")?;
                    }
                }
                _ = &mut *shutdown => {
                    let result = registration.result.clone();
                    registration.unregister().await;
                    if !self.options.grace_period.is_zero() {
                        tokio::time::sleep(self.options.grace_period).await;
                    }
                    connection.close(0u32.into(), b"shutdown");
                    return Ok(result);
                }
            }
        }
    }
}

struct DatagramSession {
    incoming: tokio::sync::mpsc::Sender<Vec<u8>>,
    idle_timeout: Duration,
    last_activity: Arc<StdMutex<Instant>>,
}

#[derive(Clone)]
struct V2State {
    sessions: Arc<tokio::sync::Mutex<HashMap<[u8; 16], DatagramSession>>>,
    handler: Option<DatagramHandler>,
    outbound: tokio::sync::mpsc::Sender<([u8; 16], Vec<u8>)>,
}

impl V2State {
    fn register(
        &self,
        request_id: [u8; 16],
        destination: Address,
        idle_timeout: Duration,
    ) -> Result<()> {
        let mut sessions = self.sessions.blocking_lock();
        if sessions.contains_key(&request_id) {
            return Ok(());
        }
        let handler = self
            .handler
            .as_ref()
            .context("cloudflared UDP handler is not installed")?;
        let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(256);
        let last_activity = Arc::new(StdMutex::new(Instant::now()));
        let packet = Arc::new(QuicPacketConnection {
            request_id,
            destination: destination.clone(),
            incoming: tokio::sync::Mutex::new(incoming_rx),
            outgoing: self.outbound.clone(),
            last_activity: Arc::clone(&last_activity),
        });
        let handler = Arc::clone(handler);
        tokio::task::spawn_local(async move {
            if let Err(error) = handler(destination, packet).await {
                tracing::debug!(%error, "Cloudflare QUIC v2 UDP flow stopped");
            }
        });
        sessions.insert(
            request_id,
            DatagramSession {
                incoming: incoming_tx,
                idle_timeout,
                last_activity,
            },
        );
        Ok(())
    }

    async fn deliver(&self, request_id: [u8; 16], payload: Vec<u8>) {
        let sender = self
            .sessions
            .lock()
            .await
            .get(&request_id)
            .map(|session| session.incoming.clone());
        if let Some(sender) = sender {
            if let Some(session) = self.sessions.lock().await.get(&request_id) {
                mark_activity(&session.last_activity);
            }
            let _ = sender.send(payload).await;
        }
    }

    async fn cleanup(&self) {
        let now = Instant::now();
        self.sessions
            .lock()
            .await
            .retain(|_, session| !is_expired(&session.last_activity, session.idle_timeout, now));
    }

    fn unregister_sync(&self, request_id: &[u8; 16]) {
        self.sessions.blocking_lock().remove(request_id);
    }
}

struct QuicPacketConnection {
    request_id: [u8; DATAGRAM_V3_REQUEST_ID_LENGTH],
    destination: Address,
    incoming: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    outgoing: tokio::sync::mpsc::Sender<([u8; DATAGRAM_V3_REQUEST_ID_LENGTH], Vec<u8>)>,
    last_activity: Arc<StdMutex<Instant>>,
}

#[async_trait]
impl PacketConnection for QuicPacketConnection {
    async fn send(&self, packet: Packet) -> Result<()> {
        mark_activity(&self.last_activity);
        self.outgoing
            .send((self.request_id, packet.data))
            .await
            .context("queue Cloudflare QUIC datagram")?;
        Ok(())
    }

    async fn recv(&self) -> Result<Packet> {
        let mut incoming = self.incoming.lock().await;
        let data = incoming
            .recv()
            .await
            .context("Cloudflare QUIC UDP flow closed")?;
        mark_activity(&self.last_activity);
        Ok(Packet {
            data,
            destination: self.destination.clone(),
        })
    }
}

async fn handle_datagram(
    connection: &quinn::Connection,
    data: &[u8],
    sessions: &mut HashMap<[u8; DATAGRAM_V3_REQUEST_ID_LENGTH], DatagramSession>,
    handler: Option<&DatagramHandler>,
    outbound: &tokio::sync::mpsc::Sender<([u8; DATAGRAM_V3_REQUEST_ID_LENGTH], Vec<u8>)>,
) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    match data[0] {
        DATAGRAM_V3_REGISTRATION => {
            let (request_id, destination, payload, idle_timeout) = parse_registration(&data[1..])?;
            let Some(handler) = handler else {
                send_registration_response(connection, request_id, 2).await?;
                return Ok(());
            };
            if let std::collections::hash_map::Entry::Vacant(entry) = sessions.entry(request_id) {
                let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(256);
                let last_activity = Arc::new(StdMutex::new(Instant::now()));
                let packet = Arc::new(QuicPacketConnection {
                    request_id,
                    destination: destination.clone(),
                    incoming: tokio::sync::Mutex::new(incoming_rx),
                    outgoing: outbound.clone(),
                    last_activity: Arc::clone(&last_activity),
                });
                let handler = Arc::clone(handler);
                let handler_destination = destination.clone();
                tokio::task::spawn_local(async move {
                    if let Err(error) = handler(handler_destination, packet).await {
                        tracing::debug!(%error, "Cloudflare QUIC UDP flow stopped");
                    }
                });
                entry.insert(DatagramSession {
                    incoming: incoming_tx,
                    idle_timeout,
                    last_activity,
                });
            }
            send_registration_response(connection, request_id, 0).await?;
            if !payload.is_empty()
                && let Some(session) = sessions.get(&request_id)
            {
                mark_activity(&session.last_activity);
                let _ = session.incoming.send(payload).await;
            }
        }
        DATAGRAM_V3_PAYLOAD => {
            if data.len() < 1 + DATAGRAM_V3_REQUEST_ID_LENGTH
                || data.len() > 1 + DATAGRAM_V3_REQUEST_ID_LENGTH + DATAGRAM_V3_MAX_PAYLOAD
            {
                return Ok(());
            }
            let mut request_id = [0u8; DATAGRAM_V3_REQUEST_ID_LENGTH];
            request_id.copy_from_slice(&data[1..1 + DATAGRAM_V3_REQUEST_ID_LENGTH]);
            if let Some(session) = sessions.get(&request_id) {
                mark_activity(&session.last_activity);
                let _ = session
                    .incoming
                    .send(data[1 + DATAGRAM_V3_REQUEST_ID_LENGTH..].to_vec())
                    .await;
            }
        }
        _ => {}
    }
    Ok(())
}

async fn handle_v2_datagram(data: &[u8], state: Option<&V2State>) -> Result<()> {
    anyhow::ensure!(!data.is_empty(), "Cloudflare v2 datagram is empty");
    if data.len() > DATAGRAM_V3_MAX_PAYLOAD + DATAGRAM_V3_REQUEST_ID_LENGTH + 1 {
        return Ok(());
    }
    let Some(state) = state else {
        return Ok(());
    };
    let datagram_type = *data.last().context("Cloudflare v2 datagram type missing")?;
    if datagram_type != 0 || data.len() < 17 {
        return Ok(());
    }
    let id_start = data.len() - 17;
    let mut request_id = [0u8; 16];
    request_id.copy_from_slice(&data[id_start..id_start + 16]);
    state.deliver(request_id, data[..id_start].to_vec()).await;
    Ok(())
}

fn parse_registration(
    data: &[u8],
) -> Result<(
    [u8; DATAGRAM_V3_REQUEST_ID_LENGTH],
    Address,
    Vec<u8>,
    Duration,
)> {
    anyhow::ensure!(
        data.len() >= 5 + DATAGRAM_V3_REQUEST_ID_LENGTH,
        "Cloudflare UDP registration is too short"
    );
    let flags = data[0];
    let port = u16::from_be_bytes([data[1], data[2]]);
    let idle_seconds = u16::from_be_bytes([data[3], data[4]]);
    let idle_timeout = if idle_seconds == 0 {
        DEFAULT_DATAGRAM_IDLE
    } else {
        Duration::from_secs(u64::from(idle_seconds))
    };
    let mut request_id = [0u8; DATAGRAM_V3_REQUEST_ID_LENGTH];
    request_id.copy_from_slice(&data[5..5 + DATAGRAM_V3_REQUEST_ID_LENGTH]);
    let offset = 5 + DATAGRAM_V3_REQUEST_ID_LENGTH;
    let (host, address_len) = if flags & DATAGRAM_V3_FLAG_IPV6 != 0 {
        anyhow::ensure!(
            data.len() >= offset + 16,
            "Cloudflare IPv6 UDP registration is too short"
        );
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&data[offset..offset + 16]);
        (IpAddr::V6(Ipv6Addr::from(bytes)), 16)
    } else {
        anyhow::ensure!(
            data.len() >= offset + 4,
            "Cloudflare IPv4 UDP registration is too short"
        );
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&data[offset..offset + 4]);
        (IpAddr::V4(Ipv4Addr::from(bytes)), 4)
    };
    let destination = Address::new(host.to_string(), port)?;
    let payload_offset = offset + address_len;
    let payload = if flags & DATAGRAM_V3_FLAG_BUNDLE != 0 {
        data[payload_offset..].to_vec()
    } else {
        Vec::new()
    };
    Ok((request_id, destination, payload, idle_timeout))
}

fn mark_activity(activity: &Arc<StdMutex<Instant>>) {
    if let Ok(mut value) = activity.lock() {
        *value = Instant::now();
    }
}

fn is_expired(activity: &Arc<StdMutex<Instant>>, timeout: Duration, now: Instant) -> bool {
    activity
        .lock()
        .map(|last| now.saturating_duration_since(*last) >= timeout)
        .unwrap_or(true)
}

fn cleanup_sessions(sessions: &mut HashMap<[u8; DATAGRAM_V3_REQUEST_ID_LENGTH], DatagramSession>) {
    let now = Instant::now();
    sessions.retain(|_, session| !is_expired(&session.last_activity, session.idle_timeout, now));
}

async fn send_registration_response(
    connection: &quinn::Connection,
    request_id: [u8; DATAGRAM_V3_REQUEST_ID_LENGTH],
    response: u8,
) -> Result<()> {
    let mut data = Vec::with_capacity(1 + 1 + request_id.len() + 2);
    data.push(DATAGRAM_V3_REGISTRATION_RESPONSE);
    data.push(response);
    data.extend_from_slice(&request_id);
    data.extend_from_slice(&0u16.to_be_bytes());
    connection
        .send_datagram(data.into())
        .context("send Cloudflare UDP registration response")?;
    Ok(())
}

fn build_endpoint(post_quantum: bool, edge_is_ipv4: bool) -> Result<Endpoint> {
    let roots = crate::ca::root_store().context("load Cloudflare root CAs")?;
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if !post_quantum {
        provider.kx_groups.retain(|group| {
            !matches!(
                group.name(),
                NamedGroup::X25519MLKEM768
                    | NamedGroup::secp256r1MLKEM768
                    | NamedGroup::MLKEM512
                    | NamedGroup::MLKEM768
                    | NamedGroup::MLKEM1024
            )
        });
    }
    let mut tls = RustlsClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .context("configure Cloudflare QUIC TLS versions")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![QUIC_EDGE_ALPN.to_vec()];
    let crypto = QuicClientConfig::try_from(tls).context("build Cloudflare QUIC TLS config")?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport
        .initial_mtu(if edge_is_ipv4 {
            QUIC_INITIAL_MTU_IPV4
        } else {
            QUIC_INITIAL_MTU_IPV6
        })
        // Quinn allocates state for each remotely initiated stream while
        // constructing a connection, so an unbounded VarInt is not safe here.
        .max_concurrent_bidi_streams(QUIC_MAX_CONCURRENT_STREAMS.into())
        .max_concurrent_uni_streams(QUIC_MAX_CONCURRENT_STREAMS.into())
        .datagram_receive_buffer_size(Some(16 * 1024 * 1024));
    transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(
        std::time::Duration::from_secs(5),
    )?));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(1)));
    config.transport_config(Arc::new(transport));
    let bind_address = if edge_is_ipv4 { "0.0.0.0:0" } else { "[::]:0" };
    let endpoint = Endpoint::client(bind_address.parse()?)?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

struct RegistrationSession {
    result: RegistrationResult,
    client: tunnelrpc_capnp::registration_server::Client,
    rpc_task: tokio::task::JoinHandle<std::result::Result<(), capnp::Error>>,
}

impl RegistrationSession {
    async fn unregister(&mut self) {
        let request = self.client.unregister_connection_request();
        match tokio::time::timeout(Duration::from_secs(5), request.send().promise).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::debug!(%error, "Cloudflare QUIC unregister failed"),
            Err(error) => tracing::debug!(%error, "Cloudflare QUIC unregister timed out"),
        }
        self.rpc_task.abort();
    }
}

async fn register_connection(
    stream: QuicStream,
    credentials: Credentials,
    connection_index: u8,
    options: ConnectionOptions,
) -> Result<RegistrationSession> {
    let (reader, writer) = stream.split();
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
        &options,
    );
    let promise = request.send();
    let rpc_task = tokio::task::spawn_local(rpc);
    let response = promise
        .promise
        .await
        .context("Cloudflare QUIC registration RPC")?;
    let result = registration::read_registration_result(response.get()?.get_result()?)?;
    anyhow::ensure!(
        result.tunnel_is_remotely_managed,
        "Cloudflared only supports remotely managed tunnels"
    );
    Ok(RegistrationSession {
        result,
        client,
        rpc_task,
    })
}

async fn handle_data_stream(
    mut stream: QuicStream,
    handler: StreamHandler,
    http_handler: Option<QuicHttpHandler>,
) -> Result<()> {
    let frame = read_connect_frame(&mut stream).await?;
    let request = protocol::decode_connect_request(&frame)?;
    if let Some(http_handler) = http_handler
        && matches!(
            request.connection_type,
            ConnectionType::Http | ConnectionType::Websocket
        )
    {
        return (http_handler)(request, QuicRequestStream::new(stream)).await;
    }
    let response = protocol::encode_connect_response(&ConnectResponse {
        error: String::new(),
        metadata: Vec::new(),
    })?;
    stream.write_all(&response).await?;
    (handler)(request, Box::new(stream)).await
}

async fn handle_stream(
    send: SendStream,
    recv: RecvStream,
    handler: StreamHandler,
    configuration_handler: Option<ConfigurationHandler>,
    http_handler: Option<QuicHttpHandler>,
    v2_state: Option<V2State>,
) -> Result<()> {
    let mut stream = QuicStream::new(send, recv);
    let mut signature = [0u8; 6];
    stream.read_exact(&mut signature).await?;
    match protocol::classify_stream(signature)? {
        protocol::StreamType::Data => handle_data_stream(stream, handler, http_handler).await,
        protocol::StreamType::Rpc => {
            handle_rpc_stream_body(stream, configuration_handler, v2_state).await
        }
    }
}

struct CloudflaredRpcServer {
    configuration_handler: Option<ConfigurationHandler>,
    v2_state: Option<V2State>,
}

impl tunnelrpc_capnp::session_manager::Server for CloudflaredRpcServer {
    fn register_udp_session(
        &mut self,
        params: tunnelrpc_capnp::session_manager::RegisterUdpSessionParams,
        mut results: tunnelrpc_capnp::session_manager::RegisterUdpSessionResults,
    ) -> Promise<(), capnp::Error> {
        let mut result = results.get().init_result();
        result.set_spans(&[]);
        let error = match (&self.v2_state, params.get()) {
            (Some(state), Ok(params)) => {
                let id = match params.get_session_id() {
                    Ok(id) if id.len() == 16 => {
                        let mut id_array = [0u8; 16];
                        id_array.copy_from_slice(id);
                        id_array
                    }
                    _ => {
                        return Promise::err(capnp::Error::failed("invalid UDP session ID".into()));
                    }
                };
                let ip = match params.get_dst_ip() {
                    Ok(ip) if ip.len() == 4 => {
                        IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))
                    }
                    Ok(ip) if ip.len() == 16 => {
                        let mut bytes = [0u8; 16];
                        bytes.copy_from_slice(ip);
                        IpAddr::V6(Ipv6Addr::from(bytes))
                    }
                    _ => {
                        return Promise::err(capnp::Error::failed(
                            "invalid UDP destination IP".into(),
                        ));
                    }
                };
                let idle_hint = params.get_close_after_idle_hint();
                let idle_timeout = if idle_hint > 0 {
                    Duration::from_nanos(idle_hint as u64)
                } else {
                    DEFAULT_DATAGRAM_IDLE
                };
                match state.register(
                    id,
                    Address::new(ip.to_string(), params.get_dst_port()).unwrap(),
                    idle_timeout,
                ) {
                    Ok(()) => String::new(),
                    Err(error) => error.to_string(),
                }
            }
            (None, _) => "datagram v2 state is not installed".into(),
            (_, Err(error)) => return Promise::err(error),
        };
        result.set_err(&error);
        Promise::ok(())
    }

    fn unregister_udp_session(
        &mut self,
        _params: tunnelrpc_capnp::session_manager::UnregisterUdpSessionParams,
        _results: tunnelrpc_capnp::session_manager::UnregisterUdpSessionResults,
    ) -> Promise<(), capnp::Error> {
        if let Some(state) = &self.v2_state
            && let Ok(params) = _params.get()
            && let Ok(id) = params.get_session_id()
            && id.len() == 16
        {
            let mut request_id = [0u8; 16];
            request_id.copy_from_slice(id);
            state.unregister_sync(&request_id);
        }
        Promise::ok(())
    }
}

impl tunnelrpc_capnp::configuration_manager::Server for CloudflaredRpcServer {
    fn update_configuration(
        &mut self,
        params: tunnelrpc_capnp::configuration_manager::UpdateConfigurationParams,
        mut results: tunnelrpc_capnp::configuration_manager::UpdateConfigurationResults,
    ) -> Promise<(), capnp::Error> {
        let params = match params.get() {
            Ok(params) => params,
            Err(error) => return Promise::err(error),
        };
        let version = params.get_version();
        let config = match params.get_config() {
            Ok(config) => config.to_vec(),
            Err(error) => return Promise::err(error),
        };
        let (applied_version, error_message) = match &self.configuration_handler {
            Some(handler) => match handler(version, config) {
                Ok(version) => (version, String::new()),
                Err(error) => (version, error.to_string()),
            },
            None => (version, "configuration handler is not installed".into()),
        };
        let mut result = results.get().init_result();
        result.set_latest_applied_version(applied_version);
        result.set_err(&error_message);
        Promise::ok(())
    }
}

impl tunnelrpc_capnp::cloudflared_server::Server for CloudflaredRpcServer {}

async fn handle_rpc_stream_body(
    stream: QuicStream,
    configuration_handler: Option<ConfigurationHandler>,
    v2_state: Option<V2State>,
) -> Result<()> {
    let (reader, writer) = stream.split();
    let server: tunnelrpc_capnp::cloudflared_server::Client =
        capnp_rpc::new_client(CloudflaredRpcServer {
            configuration_handler,
            v2_state,
        });
    let network = VatNetwork::new(
        reader.compat(),
        writer.compat_write(),
        Side::Server,
        ReaderOptions::default(),
    );
    RpcSystem::new(Box::new(network), Some(server.client))
        .await
        .context("Cloudflare RPC stream")?;
    Ok(())
}

async fn read_connect_frame<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Vec<u8>> {
    let mut version = [0u8; 2];
    stream
        .read_exact(&mut version)
        .await
        .context("read Cloudflare data stream version")?;
    anyhow::ensure!(
        version == *protocol::PROTOCOL_VERSION,
        "unsupported Cloudflare data stream version"
    );
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await?;
    let segment_count = u32::from_le_bytes(header[0..4].try_into()?) as usize + 1;
    anyhow::ensure!(
        segment_count <= 512,
        "Cloudflare Cap'n Proto message has too many segments"
    );
    let header_size = (4 * (segment_count + 1)).next_multiple_of(8);
    anyhow::ensure!(header_size >= 8, "invalid Cloudflare Cap'n Proto header");
    let mut frame = Vec::with_capacity(header_size);
    frame.extend_from_slice(&header);
    frame.resize(header_size, 0);
    if header_size > 8 {
        stream.read_exact(&mut frame[8..]).await?;
    }
    let mut body_size = 0usize;
    for index in 0..segment_count {
        let offset = 4 + index * 4;
        let words = u32::from_le_bytes(frame[offset..offset + 4].try_into()?) as usize;
        body_size = body_size
            .checked_add(
                words
                    .checked_mul(8)
                    .context("Cloudflare Cap'n Proto size overflow")?,
            )
            .context("Cloudflare Cap'n Proto size overflow")?;
    }
    anyhow::ensure!(
        body_size <= MAX_CONNECT_MESSAGE,
        "Cloudflare connect request is too large"
    );
    frame.resize(header_size + body_size, 0);
    stream.read_exact(&mut frame[header_size..]).await?;
    let mut encoded = protocol::DATA_STREAM_SIGNATURE.to_vec();
    encoded.extend_from_slice(protocol::PROTOCOL_VERSION);
    encoded.extend_from_slice(&frame);
    Ok(encoded)
}

struct QuicStream {
    send: SendStream,
    recv: RecvStream,
}

pub struct QuicRequestStream {
    stream: QuicStream,
    response_sent: bool,
}

impl QuicRequestStream {
    fn new(stream: QuicStream) -> Self {
        Self {
            stream,
            response_sent: false,
        }
    }

    pub async fn send_response(&mut self, response: &ConnectResponse) -> Result<()> {
        anyhow::ensure!(!self.response_sent, "Cloudflare QUIC response already sent");
        let encoded = protocol::encode_connect_response(response)?;
        self.stream.write_all(&encoded).await?;
        self.response_sent = true;
        Ok(())
    }

    pub(crate) fn into_split(self) -> (QuicReader, QuicWriter) {
        self.stream.split()
    }
}

impl AsyncRead for QuicRequestStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicRequestStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl QuicStream {
    fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }

    fn split(self) -> (QuicReader, QuicWriter) {
        (
            QuicReader { recv: self.recv },
            QuicWriter {
                send: Some(self.send),
            },
        )
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, data)
            .map_err(std::io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

pub(crate) struct QuicReader {
    recv: RecvStream,
}
pub(crate) struct QuicWriter {
    send: Option<SendStream>,
}

impl AsyncRead for QuicReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let Some(send) = self.send.as_mut() else {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Cloudflare QUIC stream is closed",
            )));
        };
        Pin::new(send)
            .poll_write(cx, data)
            .map_err(std::io::Error::other)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let Some(send) = self.send.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        Pin::new(send).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let Some(send) = self.send.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        Pin::new(send).poll_shutdown(cx)
    }
}

#[allow(dead_code)]
fn _assert_future_send<T: Future + Send>(_: T) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_connect_frame_after_protocol_version() {
        let request = ConnectRequest {
            destination: "https://www.example.com/".into(),
            connection_type: ConnectionType::Http,
            metadata: Vec::new(),
        };
        let encoded = protocol::encode_connect_request(&request).unwrap();
        let mut stream = &encoded[protocol::DATA_STREAM_SIGNATURE.len()..];

        let frame = read_connect_frame(&mut stream).await.unwrap();

        assert_eq!(protocol::decode_connect_request(&frame).unwrap(), request);
    }

    #[tokio::test]
    async fn rejects_unsupported_data_stream_version() {
        let mut stream = &b"02"[..];

        let error = read_connect_frame(&mut stream).await.unwrap_err();

        assert_eq!(
            error.to_string(),
            "unsupported Cloudflare data stream version"
        );
    }

    #[test]
    fn limits_stream_state_allocation() {
        assert_eq!(QUIC_MAX_CONCURRENT_STREAMS, 1024);
        assert!(u64::from(QUIC_MAX_CONCURRENT_STREAMS) < quinn::VarInt::MAX.into_inner());
    }

    #[test]
    fn parses_v3_ipv4_registration_with_bundled_payload() {
        let request_id = [9u8; DATAGRAM_V3_REQUEST_ID_LENGTH];
        let mut data = vec![DATAGRAM_V3_FLAG_BUNDLE];
        data.extend_from_slice(&53u16.to_be_bytes());
        data.extend_from_slice(&30u16.to_be_bytes());
        data.extend_from_slice(&request_id);
        data.extend_from_slice(&[1, 1, 1, 1]);
        data.extend_from_slice(b"dns");
        let (actual_id, destination, payload, idle) = parse_registration(&data).unwrap();
        assert_eq!(actual_id, request_id);
        assert_eq!(destination, Address::new("1.1.1.1", 53).unwrap());
        assert_eq!(payload, b"dns");
        assert_eq!(idle, Duration::from_secs(30));
    }

    #[test]
    fn parses_v3_ipv6_registration() {
        let request_id = [7u8; DATAGRAM_V3_REQUEST_ID_LENGTH];
        let mut data = vec![DATAGRAM_V3_FLAG_IPV6];
        data.extend_from_slice(&443u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&request_id);
        data.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        let (_, destination, payload, idle) = parse_registration(&data).unwrap();
        assert_eq!(destination, Address::new("::1", 443).unwrap());
        assert!(payload.is_empty());
        assert_eq!(idle, DEFAULT_DATAGRAM_IDLE);
    }
}
