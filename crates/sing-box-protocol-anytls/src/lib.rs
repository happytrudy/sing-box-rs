use std::{
    collections::HashMap,
    io::Cursor,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use rcgen::generate_simple_self_signed;
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};
use serde::Deserialize;
use sing_box_core::{
    Address, BoxPacketConnection, BoxStream, Certificate, ConnectionTasks, Inbound,
    InboundBuildContext, Lifecycle, Network, Outbound, OutboundBuildContext, Packet,
    PacketConnection, Registry, Router, Session, StartStage, bind_tcp_listeners,
};
use sing_box_tls::{RealityAcceptor, RealityOptions, RealityServerConfig};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Notify, RwLock, mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEARTBEAT_REQUEST: u8 = 8;
const CMD_HEARTBEAT_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;
const MAX_FRAME_SIZE: usize = u16::MAX as usize;
const DUPLEX_CAPACITY: usize = 1024 * 1024;
const AUTH_PADDING: usize = 30;
const STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UOT_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";
const UOT_MAX_PACKET: usize = u16::MAX as usize;
const MAX_PADDING_SIZE: usize = 1024 * 1024;
const DEFAULT_PADDING_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

#[derive(Clone, Debug)]
enum PaddingInstruction {
    Range { min: usize, max: usize },
    Check,
}

#[derive(Clone, Debug)]
struct PaddingScheme {
    stop: usize,
    rules: HashMap<usize, Vec<PaddingInstruction>>,
    source: String,
}

impl PaddingScheme {
    fn parse(source: &str) -> Result<Self> {
        let source = if source.trim().is_empty() {
            DEFAULT_PADDING_SCHEME
        } else {
            source
        };
        let mut scheme = Self {
            stop: 8,
            rules: HashMap::new(),
            source: source.to_owned(),
        };
        for item in source.split_whitespace() {
            let (key, value) = item
                .split_once('=')
                .with_context(|| format!("invalid AnyTLS padding item: {item}"))?;
            if key == "stop" {
                scheme.stop = value.parse()?;
                continue;
            }
            let index: usize = key.parse()?;
            let mut rules: Vec<PaddingInstruction> = Vec::new();
            for part in value.split(',') {
                if part == "c" {
                    rules.push(PaddingInstruction::Check);
                    continue;
                }
                let (min, max) = part
                    .split_once('-')
                    .with_context(|| format!("invalid AnyTLS padding range: {part}"))?;
                let min: usize = min.parse()?;
                let max: usize = max.parse()?;
                anyhow::ensure!(min <= max, "AnyTLS padding range is reversed");
                anyhow::ensure!(max <= MAX_PADDING_SIZE, "AnyTLS padding range is too large");
                rules.push(PaddingInstruction::Range { min, max });
            }
            anyhow::ensure!(!rules.is_empty(), "AnyTLS padding rule is empty");
            scheme.rules.insert(index, rules);
        }
        anyhow::ensure!(scheme.stop > 0, "AnyTLS padding stop must be positive");
        Ok(scheme)
    }

    fn auth_padding_len(&self) -> usize {
        self.rules
            .get(&0)
            .and_then(|rules| {
                rules.iter().find_map(|rule| match rule {
                    PaddingInstruction::Range { min, max } => Some(random_range(*min, *max)),
                    PaddingInstruction::Check => None,
                })
            })
            .unwrap_or(0)
    }

    fn md5_hex(&self) -> String {
        md5_hex(self.source.as_bytes())
    }
}

fn random_range(min: usize, max: usize) -> usize {
    if min >= max {
        return min;
    }
    let mut random = [0u8; 8];
    if SystemRandom::new().fill(&mut random).is_err() {
        return min;
    }
    min + (u64::from_le_bytes(random) as usize % (max - min))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnyTlsOutboundOptions {
    server: String,
    #[serde(default = "default_server_port")]
    server_port: u16,
    password: String,
    #[serde(default)]
    tls: ClientTlsOptions,
    #[serde(default = "default_idle_interval")]
    idle_session_check_interval: String,
    #[serde(default = "default_idle_timeout")]
    idle_session_timeout: String,
    #[serde(default)]
    min_idle_session: usize,
}

fn default_server_port() -> u16 {
    443
}
fn default_idle_interval() -> String {
    "30s".to_owned()
}
fn default_idle_timeout() -> String {
    "30s".to_owned()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientTlsOptions {
    #[serde(default = "default_true", alias = "enable")]
    enabled: bool,
    #[serde(default)]
    server_name: String,
    #[serde(default)]
    insecure: bool,
    #[serde(default)]
    certificate_path: String,
    #[serde(default)]
    enable_jls: bool,
    #[serde(default)]
    jls_username: String,
    #[serde(default)]
    jls_password: String,
}

impl Default for ClientTlsOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            server_name: String::new(),
            insecure: false,
            certificate_path: String::new(),
            enable_jls: false,
            jls_username: String::new(),
            jls_password: String::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnyTlsInboundOptions {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default)]
    listen_port: u16,
    users: Vec<UserOptions>,
    #[serde(default)]
    tls: ServerTlsOptions,
    #[serde(default)]
    padding_scheme: PaddingSchemeConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum PaddingSchemeConfig {
    String(String),
    Lines(Vec<String>),
}

impl Default for PaddingSchemeConfig {
    fn default() -> Self {
        Self::String(String::new())
    }
}

impl PaddingSchemeConfig {
    fn source(self) -> String {
        match self {
            Self::String(source) => source,
            Self::Lines(lines) => lines.join("\n"),
        }
    }
}

fn default_listen() -> String {
    "127.0.0.1".to_owned()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserOptions {
    password: String,
    #[serde(default)]
    name: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerTlsOptions {
    #[serde(default = "default_true", alias = "enable")]
    enabled: bool,
    #[serde(default)]
    server_name: String,
    #[serde(default)]
    certificate_provider: String,
    #[serde(default)]
    certificate_path: String,
    #[serde(default)]
    key_path: String,
    #[serde(default)]
    alpn: Vec<String>,
    #[serde(default)]
    reality: RealityOptions,
    #[serde(default)]
    enable_jls: bool,
    #[serde(default)]
    jls_username: String,
    #[serde(default)]
    jls_password: String,
}

impl Default for ServerTlsOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            server_name: String::new(),
            certificate_provider: String::new(),
            certificate_path: String::new(),
            key_path: String::new(),
            alpn: Vec::new(),
            reality: RealityOptions::default(),
            enable_jls: false,
            jls_username: String::new(),
            jls_password: String::new(),
        }
    }
}

enum CertificateSource {
    Static(Arc<Certificate>),
    Provider(tokio::sync::watch::Receiver<Option<Arc<Certificate>>>),
}

#[derive(Clone)]
enum ServerAcceptor {
    Standard(Arc<TlsAcceptor>),
    Reality(Arc<RealityAcceptor>),
}

struct RunningInbound {
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    connection_tasks: ConnectionTasks,
}

struct AnyTlsInbound {
    tag: String,
    listen: String,
    listen_port: u16,
    users: Arc<HashMap<[u8; 32], String>>,
    certificate: Mutex<Option<CertificateSource>>,
    reality: Option<Arc<RealityAcceptor>>,
    tls: ServerTlsOptions,
    padding_scheme: PaddingScheme,
    router: Arc<Router>,
    running: Mutex<Option<RunningInbound>>,
    local_addr: std::sync::RwLock<Option<SocketAddr>>,
}

struct AnyTlsOutbound {
    tag: String,
    server: String,
    server_port: u16,
    password: String,
    tls: ClientTlsOptions,
    idle_session_check_interval: Duration,
    idle_session_timeout: Duration,
    min_idle_session: usize,
    system_dialer: sing_box_core::SystemDialer,
    sessions: Arc<Mutex<Vec<Arc<ClientSession>>>>,
    running: Mutex<Option<RunningOutbound>>,
    padding: Arc<RwLock<PaddingScheme>>,
}

struct RunningOutbound {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

struct Frame {
    command: u8,
    stream_id: u32,
    data: Vec<u8>,
}

struct ClientStream {
    incoming: mpsc::Sender<Vec<u8>>,
    synack: Option<oneshot::Sender<Result<()>>>,
    cancel: CancellationToken,
}

struct ServerStream {
    incoming: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
}

struct ClientSession {
    tx: mpsc::Sender<Frame>,
    streams: Arc<Mutex<HashMap<u32, ClientStream>>>,
    next_stream_id: AtomicU32,
    active: AtomicUsize,
    closed: AtomicBool,
    cancel: CancellationToken,
    done: Notify,
    supports_v2: AtomicBool,
    last_used: Mutex<Instant>,
    padding: Arc<RwLock<PaddingScheme>>,
}

#[async_trait]
impl Lifecycle for AnyTlsOutbound {
    async fn start(&self, stage: StartStage) -> Result<()> {
        if stage != StartStage::Start {
            return Ok(());
        }
        let interval = self.idle_session_check_interval;
        let timeout = self.idle_session_timeout;
        if self.running.lock().await.is_some() {
            return Ok(());
        }
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let sessions = Arc::clone(&self.sessions);
        let min_idle = self.min_idle_session;
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        let now = Instant::now();
                        let mut sessions = sessions.lock().await;
                        let mut idle = sessions.iter().filter(|session| session.active.load(Ordering::Acquire) == 0).count();
                        let mut retired = Vec::new();
                        sessions.retain(|session| {
                            if session.closed.load(Ordering::Acquire) {
                                return false;
                            }
                            if session.active.load(Ordering::Acquire) != 0 || idle <= min_idle {
                                return true;
                            }
                            let keep = session.last_used.try_lock().map(|last| now.duration_since(*last) <= timeout).unwrap_or(true);
                            if !keep {
                                idle -= 1;
                                retired.push(Arc::clone(session));
                            }
                            keep
                        });
                        drop(sessions);
                        for session in retired {
                            session.close();
                            session.clear_streams().await;
                        }
                    }
                }
            }
        });
        *self.running.lock().await = Some(RunningOutbound { cancel, task });
        tracing::debug!(tag = %self.tag, ?interval, ?timeout, min_idle = self.min_idle_session, "AnyTLS outbound ready");
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        if let Some(running) = self.running.lock().await.take() {
            running.cancel.cancel();
            running.task.await?;
        }
        let sessions = self.sessions.lock().await.drain(..).collect::<Vec<_>>();
        for session in sessions {
            session.close();
            session.clear_streams().await;
            session.done.notified().await;
        }
        Ok(())
    }
}

#[async_trait]
impl sing_box_core::Dialer for AnyTlsOutbound {
    async fn connect(&self, session: &Session) -> Result<BoxStream> {
        anyhow::ensure!(
            session.network == Network::Tcp,
            "AnyTLS TCP dialer received a non-TCP session"
        );
        anyhow::ensure!(self.tls.enabled, "AnyTLS requires TLS to be enabled");
        let client = self.acquire_session().await?;
        Ok(Box::new(client.open_stream(&session.destination).await?))
    }
}

impl AnyTlsOutbound {
    async fn acquire_session(&self) -> Result<Arc<ClientSession>> {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|candidate| !candidate.closed.load(Ordering::Acquire));
        if let Some(client) = sessions
            .iter()
            .rev()
            .find(|candidate| candidate.try_reserve())
            .cloned()
        {
            return Ok(client);
        }
        drop(sessions);
        let client = ClientSession::connect(
            &self.server,
            self.server_port,
            &self.password,
            &self.tls,
            &self.system_dialer,
            Arc::clone(&self.padding),
        )
        .await?;
        anyhow::ensure!(client.try_reserve(), "new AnyTLS session is not idle");
        self.sessions.lock().await.push(Arc::clone(&client));
        Ok(client)
    }
}

#[async_trait]
impl Outbound for AnyTlsOutbound {
    fn kind(&self) -> &'static str {
        "anytls"
    }
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect_packet(&self, session: &Session) -> Result<BoxPacketConnection> {
        anyhow::ensure!(
            session.network == Network::Udp,
            "AnyTLS packet dialer received a non-UDP session"
        );
        anyhow::ensure!(self.tls.enabled, "AnyTLS requires TLS to be enabled");
        let client = self.acquire_session().await?;
        let stream = client.open_stream(&Address::new(UOT_MAGIC, 0)?).await?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(Arc::new(UotPacketConnection::new(reader, writer)))
    }
}

#[async_trait]
impl Lifecycle for AnyTlsInbound {
    async fn start(&self, stage: StartStage) -> Result<()> {
        if stage != StartStage::Start {
            return Ok(());
        }
        if self.running.lock().await.is_some() {
            return Ok(());
        }
        anyhow::ensure!(self.tls.enabled, "AnyTLS requires TLS to be enabled");
        let (acceptor_value, certificate_updates) = if let Some(reality) = &self.reality {
            (ServerAcceptor::Reality(Arc::clone(reality)), None)
        } else {
            let source = self
                .certificate
                .lock()
                .await
                .take()
                .context("AnyTLS inbound cannot be restarted")?;
            let (certificate, certificate_updates) = match source {
                CertificateSource::Static(certificate) => (certificate, None),
                CertificateSource::Provider(receiver) => {
                    let certificate = receiver
                        .borrow()
                        .clone()
                        .context("certificate provider is not ready")?;
                    (certificate, Some(receiver))
                }
            };
            let config = build_server_config(&certificate, &self.tls)?;
            (
                ServerAcceptor::Standard(Arc::new(TlsAcceptor::from(Arc::new(config)))),
                certificate_updates,
            )
        };
        let listeners = bind_tcp_listeners(&self.listen, self.listen_port)
            .await
            .context("bind AnyTLS inbound")?;
        let local_addr = listeners[0].local_addr()?;
        *self.local_addr.write().expect("AnyTLS address lock") = Some(local_addr);
        let cancel = CancellationToken::new();
        let connection_tasks = ConnectionTasks::new();
        let acceptor = Arc::new(RwLock::new(acceptor_value));
        let mut tasks = Vec::with_capacity(listeners.len());
        for listener in listeners {
            tasks.push(tokio::spawn(run_inbound_listener(
                listener,
                cancel.clone(),
                connection_tasks.clone(),
                Arc::clone(&self.router),
                self.tag.clone(),
                Arc::clone(&self.users),
                Arc::clone(&acceptor),
                self.padding_scheme.clone(),
            )));
        }
        if let Some(receiver) = certificate_updates {
            tasks.push(tokio::spawn(watch_certificate_updates(
                acceptor,
                receiver,
                self.tls.clone(),
                cancel.clone(),
            )));
        }
        *self.running.lock().await = Some(RunningInbound {
            cancel,
            tasks,
            connection_tasks,
        });
        tracing::info!(tag = %self.tag, %local_addr, "started AnyTLS inbound");
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

impl Inbound for AnyTlsInbound {
    fn kind(&self) -> &'static str {
        "anytls"
    }
    fn tag(&self) -> &str {
        &self.tag
    }
    fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.read().expect("AnyTLS address lock")
    }
}

pub fn register(registry: &mut Registry) -> Result<()> {
    registry.register_outbound::<AnyTlsOutboundOptions, _, _>(
        "anytls",
        |context: OutboundBuildContext, tag, options| async move {
            anyhow::ensure!(!options.server.is_empty(), "AnyTLS server cannot be empty");
            anyhow::ensure!(
                !options.password.is_empty(),
                "AnyTLS password cannot be empty"
            );
            anyhow::ensure!(
                options.server_port != 0,
                "AnyTLS server_port cannot be zero"
            );
            Ok(Arc::new(AnyTlsOutbound {
                tag,
                server: options.server,
                server_port: options.server_port,
                password: options.password,
                tls: options.tls,
                idle_session_check_interval: parse_duration(&options.idle_session_check_interval)
                    .context("parse AnyTLS idle_session_check_interval")?,
                idle_session_timeout: parse_duration(&options.idle_session_timeout)
                    .context("parse AnyTLS idle_session_timeout")?,
                min_idle_session: options.min_idle_session,
                system_dialer: context.system_dialer,
                sessions: Arc::new(Mutex::new(Vec::new())),
                running: Mutex::new(None),
                padding: Arc::new(RwLock::new(PaddingScheme::parse("")?)),
            }) as Arc<dyn Outbound>)
        },
    )?;
    registry.register_inbound::<AnyTlsInboundOptions, _, _>(
        "anytls",
        |context: InboundBuildContext, tag, options| async move {
            anyhow::ensure!(!options.users.is_empty(), "AnyTLS users cannot be empty");
            let padding_scheme = PaddingScheme::parse(&options.padding_scheme.source())?;
            let mut users = HashMap::with_capacity(options.users.len());
            for (index, user) in options.users.into_iter().enumerate() {
                anyhow::ensure!(
                    !user.password.is_empty(),
                    "AnyTLS user password cannot be empty"
                );
                let key = password_digest(&user.password);
                let name = if user.name.is_empty() {
                    index.to_string()
                } else {
                    user.name
                };
                anyhow::ensure!(
                    users.insert(key, name).is_none(),
                    "duplicate AnyTLS user password"
                );
            }
            let (certificate, reality) = if options.tls.reality.enabled {
                anyhow::ensure!(!options.tls.enable_jls, "AnyTLS JLS conflicts with Reality");
                anyhow::ensure!(
                    options.tls.certificate_provider.is_empty(),
                    "AnyTLS Reality conflicts with certificate_provider"
                );
                anyhow::ensure!(
                    options.tls.certificate_path.is_empty() && options.tls.key_path.is_empty(),
                    "AnyTLS Reality conflicts with certificate_path/key_path"
                );
                let reality = RealityAcceptor::new(RealityServerConfig {
                    server_name: options.tls.server_name.clone(),
                    alpn: options.tls.alpn.clone(),
                    options: options.tls.reality.clone(),
                    system_dialer: context.system_dialer.clone(),
                })?;
                (None, Some(Arc::new(reality)))
            } else if options.tls.certificate_provider.is_empty()
                && options.tls.certificate_path.is_empty()
                && options.tls.key_path.is_empty()
            {
                anyhow::ensure!(
                    options.tls.enable_jls,
                    "AnyTLS TLS requires certificate_provider or certificate_path/key_path"
                );
                (
                    Some(CertificateSource::Static(Arc::new(
                        generate_jls_certificate()?,
                    ))),
                    None,
                )
            } else if options.tls.certificate_provider.is_empty() {
                anyhow::ensure!(
                    !options.tls.certificate_path.is_empty() && !options.tls.key_path.is_empty(),
                    "AnyTLS TLS requires certificate_provider or certificate_path/key_path"
                );
                let cert_data = tokio::fs::read(&options.tls.certificate_path)
                    .await
                    .with_context(|| format!("read {}", options.tls.certificate_path))?;
                let key_data = tokio::fs::read(&options.tls.key_path)
                    .await
                    .with_context(|| format!("read {}", options.tls.key_path))?;
                (
                    Some(CertificateSource::Static(Arc::new(Certificate::new(
                        parse_certificates(&cert_data)?,
                        parse_private_key(&key_data)?,
                    )?))),
                    None,
                )
            } else {
                anyhow::ensure!(
                    options.tls.certificate_path.is_empty() && options.tls.key_path.is_empty(),
                    "AnyTLS certificate_provider conflicts with certificate_path/key_path"
                );
                (
                    Some(CertificateSource::Provider(
                        context
                            .certificate_providers
                            .subscribe(&options.tls.certificate_provider, &options.tls.server_name)
                            .await?,
                    )),
                    None,
                )
            };
            Ok(Arc::new(AnyTlsInbound {
                tag,
                listen: options.listen,
                listen_port: options.listen_port,
                users: Arc::new(users),
                certificate: Mutex::new(certificate),
                reality,
                tls: options.tls,
                padding_scheme,
                router: context.router,
                running: Mutex::new(None),
                local_addr: std::sync::RwLock::new(None),
            }) as Arc<dyn Inbound>)
        },
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_inbound_listener(
    listener: TcpListener,
    cancel: CancellationToken,
    connection_tasks: ConnectionTasks,
    router: Arc<Router>,
    tag: String,
    users: Arc<HashMap<[u8; 32], String>>,
    acceptor: Arc<RwLock<ServerAcceptor>>,
    padding_scheme: PaddingScheme,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, source)) => {
                    let router = Arc::clone(&router);
                    let users = Arc::clone(&users);
                    let acceptor = Arc::new(acceptor.read().await.clone());
                    let tag = tag.clone();
                    let padding_scheme = padding_scheme.clone();
                    let connection_cancel = cancel.child_token();
                    connection_tasks.spawn(async move {
                        tokio::select! {
                            _ = connection_cancel.cancelled() => {}
                            result = handle_inbound_connection(stream, source, router, tag, users, acceptor, padding_scheme, connection_cancel.clone()) => {
                                connection_cancel.cancel();
                                if let Err(error) = result {
                                    tracing::debug!(%source, %error, error_chain = ?error, "AnyTLS connection closed");
                                }
                            }
                        }
                    });
                }
                Err(error) => { tracing::error!(%error, "AnyTLS accept failed"); break; }
            }
        }
    }
}

async fn watch_certificate_updates(
    acceptor: Arc<RwLock<ServerAcceptor>>,
    mut receiver: tokio::sync::watch::Receiver<Option<Arc<Certificate>>>,
    tls: ServerTlsOptions,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            changed = receiver.changed() => {
                if changed.is_err() { break; }
                let Some(certificate) = receiver.borrow().clone() else { continue; };
                match build_server_config(&certificate, &tls) {
                    Ok(config) => {
                        *acceptor.write().await = ServerAcceptor::Standard(Arc::new(TlsAcceptor::from(Arc::new(config))));
                    }
                    Err(error) => tracing::error!(%error, "reload AnyTLS certificate failed"),
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_inbound_connection(
    stream: TcpStream,
    source: SocketAddr,
    router: Arc<Router>,
    tag: String,
    users: Arc<HashMap<[u8; 32], String>>,
    acceptor: Arc<ServerAcceptor>,
    padding_scheme: PaddingScheme,
    cancel: CancellationToken,
) -> Result<()> {
    let Some(mut stream) = (match acceptor.as_ref() {
        ServerAcceptor::Standard(acceptor) => {
            let stream = acceptor
                .accept(stream)
                .await
                .context("AnyTLS TLS handshake")?;
            verify_jls_state(stream.get_ref().1.jls_state())?;
            Some(tokio_rustls::TlsStream::Server(stream))
        }
        ServerAcceptor::Reality(acceptor) => acceptor.accept(stream).await?,
    }) else {
        return Ok(());
    };
    let mut password_hash = [0u8; 32];
    stream.read_exact(&mut password_hash).await?;
    let user = users
        .get(&password_hash)
        .cloned()
        .context("AnyTLS authentication failed")?;
    let padding_len = stream.read_u16().await? as usize;
    let mut padding = vec![0u8; padding_len];
    stream.read_exact(&mut padding).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<Frame>(64);
    let padding_scheme_for_writer = Arc::new(RwLock::new(padding_scheme.clone()));
    let writer_cancel = cancel.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = writer_cancel.cancelled() => {}
            _ = async {
                let mut packet_index = 1usize;
                while let Some(frame) = rx.recv().await {
                    if write_padded_frame(
                        &mut writer,
                        frame,
                        &padding_scheme_for_writer,
                        &mut packet_index,
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
            } => {}
        }
    });
    let streams: Arc<Mutex<HashMap<u32, ServerStream>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut settings_received = false;
    loop {
        let frame = tokio::select! {
            _ = cancel.cancelled() => break,
            result = read_frame(&mut reader) => result?,
        };
        match frame.command {
            CMD_SETTINGS => {
                settings_received = true;
                let _ = tx
                    .send(Frame {
                        command: CMD_SERVER_SETTINGS,
                        stream_id: 0,
                        data: b"v=2\n".to_vec(),
                    })
                    .await;
                let client_padding = setting_value(&frame.data, "padding-md5");
                let server_padding = padding_scheme.md5_hex();
                if client_padding.as_deref() != Some(server_padding.as_str()) {
                    let _ = tx
                        .send(Frame {
                            command: CMD_UPDATE_PADDING,
                            stream_id: 0,
                            data: padding_scheme.source.as_bytes().to_vec(),
                        })
                        .await;
                }
            }
            CMD_SYN => {
                anyhow::ensure!(settings_received, "AnyTLS SYN received before settings");
                anyhow::ensure!(frame.stream_id != 0, "AnyTLS stream id cannot be zero");
                let mut stream_map = streams.lock().await;
                anyhow::ensure!(
                    !stream_map.contains_key(&frame.stream_id),
                    "AnyTLS duplicate stream id"
                );
                let (local, remote) = tokio::io::duplex(DUPLEX_CAPACITY);
                let (remote_read, remote_write) = tokio::io::split(remote);
                let (incoming_tx, mut incoming_rx) = mpsc::channel::<Vec<u8>>(32);
                let stream_cancel = cancel.child_token();
                stream_map.insert(
                    frame.stream_id,
                    ServerStream {
                        incoming: incoming_tx,
                        cancel: stream_cancel.clone(),
                    },
                );
                drop(stream_map);
                let writer_cancel = stream_cancel.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = writer_cancel.cancelled() => {}
                        _ = async {
                            let mut remote_write = remote_write;
                            while let Some(data) = incoming_rx.recv().await {
                                if remote_write.write_all(&data).await.is_err() {
                                    break;
                                }
                            }
                            let _ = remote_write.shutdown().await;
                        } => {}
                    }
                });
                let pump_cancel = stream_cancel.clone();
                let tx_for_pump = tx.clone();
                let streams_for_pump = Arc::clone(&streams);
                tokio::spawn(async move {
                    let mut remote_read = remote_read;
                    let mut buffer = vec![0u8; MAX_FRAME_SIZE];
                    'read: loop {
                        let result = tokio::select! {
                            _ = pump_cancel.cancelled() => break 'read,
                            result = remote_read.read(&mut buffer) => result,
                        };
                        match result {
                            Ok(0) | Err(_) => break,
                            Ok(size) => {
                                if tx_for_pump
                                    .send(Frame {
                                        command: CMD_PSH,
                                        stream_id: frame.stream_id,
                                        data: buffer[..size].to_vec(),
                                    })
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    if let Some(stream) = streams_for_pump.lock().await.remove(&frame.stream_id) {
                        stream.cancel.cancel();
                    }
                    let _ = tx_for_pump
                        .send(Frame {
                            command: CMD_FIN,
                            stream_id: frame.stream_id,
                            data: Vec::new(),
                        })
                        .await;
                });
                let tx_for_stream = tx.clone();
                let streams_for_stream = Arc::clone(&streams);
                let tag_for_stream = tag.clone();
                let user_for_stream = user.clone();
                let router_for_stream = Arc::clone(&router);
                let stream_cancel = stream_cancel.clone();
                tokio::spawn(async move {
                    let result = tokio::select! {
                        _ = stream_cancel.cancelled() => Ok(()),
                        result = handle_server_stream(
                            local,
                            frame.stream_id,
                            source,
                            tag_for_stream,
                            user_for_stream,
                            router_for_stream,
                            tx_for_stream.clone(),
                        ) => result,
                    };
                    if let Err(error) = result {
                        tracing::debug!(%error, "AnyTLS stream routing failed");
                    }
                    if let Some(stream) = streams_for_stream.lock().await.remove(&frame.stream_id) {
                        stream.cancel.cancel();
                    }
                    let _ = tx_for_stream
                        .send(Frame {
                            command: CMD_FIN,
                            stream_id: frame.stream_id,
                            data: Vec::new(),
                        })
                        .await;
                });
            }
            CMD_PSH => {
                if let Some(sender) = streams
                    .lock()
                    .await
                    .get(&frame.stream_id)
                    .map(|stream| stream.incoming.clone())
                {
                    let _ = sender.send(frame.data).await;
                }
            }
            CMD_FIN => {
                if let Some(stream) = streams.lock().await.remove(&frame.stream_id) {
                    stream.cancel.cancel();
                }
            }
            CMD_HEARTBEAT_REQUEST => {
                let _ = tx
                    .send(Frame {
                        command: CMD_HEARTBEAT_RESPONSE,
                        stream_id: 0,
                        data: frame.data,
                    })
                    .await;
            }
            CMD_WASTE | CMD_UPDATE_PADDING | CMD_SERVER_SETTINGS => {}
            CMD_ALERT => anyhow::bail!("AnyTLS peer sent an alert"),
            command => anyhow::bail!("unsupported AnyTLS command {command}"),
        }
    }
    Ok(())
}

async fn handle_server_stream(
    mut inbound: DuplexStream,
    stream_id: u32,
    source: SocketAddr,
    tag: String,
    user: String,
    router: Arc<Router>,
    tx: mpsc::Sender<Frame>,
) -> Result<()> {
    let destination = read_socks_address(&mut inbound).await?;
    if destination.host == UOT_MAGIC {
        return handle_server_udp_stream(inbound, stream_id, source, tag, user, router, tx).await;
    }
    let mut session =
        Session::inbound(Network::Tcp, source, destination, tag, "anytls", Some(user));
    match router.connect(&mut session).await {
        Ok(outbound) => {
            tx.send(Frame {
                command: CMD_SYNACK,
                stream_id,
                data: Vec::new(),
            })
            .await
            .ok();
            router.relay(session, Box::new(inbound), outbound).await
        }
        Err(error) => {
            tx.send(Frame {
                command: CMD_SYNACK,
                stream_id,
                data: error.to_string().into_bytes(),
            })
            .await
            .ok();
            Err(error)
        }
    }
}

async fn handle_server_udp_stream(
    mut inbound: DuplexStream,
    stream_id: u32,
    source: SocketAddr,
    tag: String,
    user: String,
    router: Arc<Router>,
    tx: mpsc::Sender<Frame>,
) -> Result<()> {
    read_uot_request(&mut inbound).await?;
    let mut session = Session::inbound(
        Network::Udp,
        source,
        Address::new(UOT_MAGIC, 0)?,
        tag,
        "anytls",
        Some(user),
    );
    let outbound = router.connect_packet(&mut session).await?;
    tx.send(Frame {
        command: CMD_SYNACK,
        stream_id,
        data: Vec::new(),
    })
    .await
    .ok();
    let (reader, writer) = tokio::io::split(inbound);
    let inbound = Arc::new(UotPacketConnection::new(reader, writer));
    router.relay_packet(session, inbound, outbound).await
}

impl ClientSession {
    fn try_reserve(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
            && self
                .active
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }

    async fn connect(
        server: &str,
        port: u16,
        password: &str,
        tls: &ClientTlsOptions,
        dialer: &sing_box_core::SystemDialer,
        padding: Arc<RwLock<PaddingScheme>>,
    ) -> Result<Arc<Self>> {
        let addresses = dialer.resolve(server, port).await?;
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    let result =
                        Self::connect_stream(stream, server, password, tls, Arc::clone(&padding))
                            .await;
                    match result {
                        Ok(session) => return Ok(session),
                        Err(error) => last_error = Some(error),
                    }
                }
                Err(error) => last_error = Some(error.into()),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("AnyTLS server did not resolve")))
    }

    async fn connect_stream(
        stream: TcpStream,
        server: &str,
        password: &str,
        tls: &ClientTlsOptions,
        padding: Arc<RwLock<PaddingScheme>>,
    ) -> Result<Arc<Self>> {
        let config = build_client_config(tls).await?;
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = if tls.server_name.is_empty() {
            server
        } else {
            &tls.server_name
        };
        let server_name =
            ServerName::try_from(server_name.to_owned()).context("invalid AnyTLS server_name")?;
        let mut stream = connector
            .connect(server_name, stream)
            .await
            .context("AnyTLS TLS handshake")?;
        if tls.enable_jls {
            verify_jls_state(stream.get_ref().1.jls_state())?;
        }
        let auth_padding = padding.read().await.auth_padding_len();
        let auth_padding = if auth_padding == 0 {
            AUTH_PADDING
        } else {
            auth_padding
        };
        anyhow::ensure!(
            auth_padding <= u16::MAX as usize,
            "AnyTLS authentication padding is too large"
        );
        let mut auth = Vec::with_capacity(34 + auth_padding);
        auth.extend_from_slice(password_digest(password).as_ref());
        auth.extend_from_slice(&(auth_padding as u16).to_be_bytes());
        auth.resize(auth.len() + auth_padding, 0);
        stream.write_all(&auth).await?;
        let (reader, writer) = tokio::io::split(stream);
        let (tx, rx) = mpsc::channel::<Frame>(64);
        let cancel = CancellationToken::new();
        let writer_cancel = cancel.clone();
        tokio::spawn(frame_writer(
            writer,
            rx,
            Arc::clone(&padding),
            writer_cancel,
        ));
        let session = Arc::new(Self {
            tx: tx.clone(),
            streams: Arc::new(Mutex::new(HashMap::new())),
            next_stream_id: AtomicU32::new(1),
            active: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            cancel: cancel.clone(),
            done: Notify::new(),
            supports_v2: AtomicBool::new(false),
            last_used: Mutex::new(Instant::now()),
            padding: Arc::clone(&padding),
        });
        let reader_session = Arc::clone(&session);
        let reader_cancel = cancel.clone();
        tokio::spawn(async move {
            if let Err(error) = client_reader(reader, reader_session.clone(), reader_cancel).await {
                tracing::debug!(%error, "AnyTLS client session closed");
            }
            reader_session.close();
            reader_session.clear_streams().await;
            reader_session.done.notify_one();
        });
        if let Err(error) = tx
            .send(Frame {
                command: CMD_SETTINGS,
                stream_id: 0,
                data: format!(
                    "v=2\nclient=sing-box-rs\npadding-md5={}\n",
                    padding.read().await.md5_hex()
                )
                .into_bytes(),
            })
            .await
        {
            session.close();
            return Err(error.into());
        }
        Ok(session)
    }

    async fn open_stream(self: &Arc<Self>, destination: &Address) -> Result<DuplexStream> {
        anyhow::ensure!(
            !self.closed.load(Ordering::Acquire),
            "AnyTLS session is closed"
        );
        let id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        let (local, remote) = tokio::io::duplex(DUPLEX_CAPACITY);
        let (remote_read, remote_write) = tokio::io::split(remote);
        let (incoming_tx, mut incoming_rx) = mpsc::channel::<Vec<u8>>(32);
        let (synack_tx, synack_rx) = oneshot::channel();
        self.streams.lock().await.insert(
            id,
            ClientStream {
                incoming: incoming_tx,
                synack: Some(synack_tx),
                cancel: CancellationToken::new(),
            },
        );
        *self.last_used.lock().await = Instant::now();
        let stream_cancel = self
            .streams
            .lock()
            .await
            .get(&id)
            .map(|stream| stream.cancel.clone())
            .expect("inserted AnyTLS stream");
        let writer_cancel = stream_cancel.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = writer_cancel.cancelled() => {}
                _ = async {
                    let mut remote_write = remote_write;
                    while let Some(data) = incoming_rx.recv().await {
                        if remote_write.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    let _ = remote_write.shutdown().await;
                } => {}
            }
        });
        let pump_cancel = stream_cancel.clone();
        let pump_session = Arc::clone(self);
        tokio::spawn(async move {
            let mut remote_read = remote_read;
            let mut buffer = vec![0u8; MAX_FRAME_SIZE];
            'read: loop {
                let result = tokio::select! {
                    _ = pump_cancel.cancelled() => break 'read,
                    result = remote_read.read(&mut buffer) => result,
                };
                match result {
                    Ok(0) | Err(_) => break,
                    Ok(size) => {
                        if pump_session
                            .tx
                            .send(Frame {
                                command: CMD_PSH,
                                stream_id: id,
                                data: buffer[..size].to_vec(),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            let _ = pump_session
                .tx
                .send(Frame {
                    command: CMD_FIN,
                    stream_id: id,
                    data: Vec::new(),
                })
                .await;
            pump_session.remove_stream(id).await;
        });
        let mut local = local;
        let result = async {
            self.tx
                .send(Frame {
                    command: CMD_SYN,
                    stream_id: id,
                    data: Vec::new(),
                })
                .await?;
            let address = encode_socks_address(destination)?;
            local.write_all(&address).await?;
            if destination.host == UOT_MAGIC {
                write_uot_request(&mut local).await?;
            }
            if self.supports_v2.load(Ordering::Acquire) {
                match timeout(STREAM_CONNECT_TIMEOUT, synack_rx).await {
                    Ok(Ok(result)) => result?,
                    Ok(Err(_)) => anyhow::bail!("AnyTLS SYNACK channel closed"),
                    Err(_) => anyhow::bail!("AnyTLS stream connect timed out"),
                }
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            self.remove_stream(id).await;
            return Err(error);
        }
        Ok(local)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.cancel.cancel();
    }

    async fn clear_streams(&self) {
        let streams = self
            .streams
            .lock()
            .await
            .drain()
            .map(|(_, stream)| stream)
            .collect::<Vec<_>>();
        for stream in streams {
            stream.cancel.cancel();
        }
        self.active.store(0, Ordering::Release);
    }

    async fn remove_stream(&self, id: u32) {
        if let Some(stream) = self.streams.lock().await.remove(&id) {
            stream.cancel.cancel();
            self.active.fetch_sub(1, Ordering::AcqRel);
            *self.last_used.lock().await = Instant::now();
        }
    }
}

async fn client_reader<R: AsyncRead + Unpin>(
    mut reader: R,
    session: Arc<ClientSession>,
    cancel: CancellationToken,
) -> Result<()> {
    loop {
        let frame = tokio::select! {
            _ = cancel.cancelled() => break,
            result = read_frame(&mut reader) => result?,
        };
        match frame.command {
            CMD_PSH => {
                if let Some(stream) = session
                    .streams
                    .lock()
                    .await
                    .get(&frame.stream_id)
                    .map(|stream| stream.incoming.clone())
                {
                    let _ = stream.send(frame.data).await;
                }
            }
            CMD_SYNACK => {
                if let Some(stream) = session.streams.lock().await.get_mut(&frame.stream_id)
                    && let Some(ack) = stream.synack.take()
                {
                    let result = if frame.data.is_empty() {
                        Ok(())
                    } else {
                        Err(anyhow::anyhow!(
                            "AnyTLS remote connection rejected: {}",
                            String::from_utf8_lossy(&frame.data)
                        ))
                    };
                    let _ = ack.send(result);
                }
            }
            CMD_FIN => {
                session.remove_stream(frame.stream_id).await;
            }
            CMD_HEARTBEAT_REQUEST => {
                let _ = session
                    .tx
                    .send(Frame {
                        command: CMD_HEARTBEAT_RESPONSE,
                        stream_id: 0,
                        data: frame.data,
                    })
                    .await;
            }
            CMD_SETTINGS | CMD_WASTE | CMD_HEARTBEAT_RESPONSE => {}
            CMD_UPDATE_PADDING => {
                let scheme = PaddingScheme::parse(std::str::from_utf8(&frame.data)?)?;
                *session.padding.write().await = scheme;
            }
            CMD_SERVER_SETTINGS => {
                session.supports_v2.store(true, Ordering::Release);
            }
            CMD_ALERT => anyhow::bail!("AnyTLS server sent an alert"),
            command => anyhow::bail!("unsupported AnyTLS command {command}"),
        }
    }
    Ok(())
}

async fn frame_writer<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut rx: mpsc::Receiver<Frame>,
    padding: Arc<RwLock<PaddingScheme>>,
    cancel: CancellationToken,
) {
    let mut packet_index = 1usize;
    loop {
        let frame = tokio::select! {
            _ = cancel.cancelled() => break,
            frame = rx.recv() => {
                let Some(frame) = frame else { break; };
                frame
            }
        };
        if write_padded_frame(&mut writer, frame, &padding, &mut packet_index)
            .await
            .is_err()
        {
            cancel.cancel();
            break;
        }
    }
}

async fn write_padded_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: Frame,
    padding: &Arc<RwLock<PaddingScheme>>,
    packet_index: &mut usize,
) -> std::io::Result<()> {
    let scheme = padding.read().await.clone();
    let mut packet = Vec::with_capacity(frame.data.len() + 7);
    encode_frame(&mut packet, &frame)?;
    let index = *packet_index;
    *packet_index += 1;
    let Some(instructions) = (index < scheme.stop)
        .then(|| scheme.rules.get(&index))
        .flatten()
    else {
        return writer.write_all(&packet).await;
    };
    let mut offset = 0usize;
    for instruction in instructions {
        match instruction {
            PaddingInstruction::Check => {
                if offset == packet.len() {
                    return Ok(());
                }
            }
            PaddingInstruction::Range { min, max } => {
                let target = random_range(*min, *max);
                let remaining = packet.len() - offset;
                let take = remaining.min(target);
                let mut record = Vec::with_capacity(target);
                record.extend_from_slice(&packet[offset..offset + take]);
                offset += take;
                append_waste(&mut record, target)?;
                writer.write_all(&record).await?;
            }
        }
    }
    if offset < packet.len() {
        writer.write_all(&packet[offset..]).await?;
    }
    Ok(())
}

fn append_waste(record: &mut Vec<u8>, target: usize) -> std::io::Result<()> {
    while record.len() + 7 <= target {
        let length = (target - record.len() - 7).min(MAX_FRAME_SIZE);
        encode_frame(
            record,
            &Frame {
                command: CMD_WASTE,
                stream_id: 0,
                data: vec![0; length],
            },
        )?;
    }
    Ok(())
}

fn encode_frame(packet: &mut Vec<u8>, frame: &Frame) -> std::io::Result<()> {
    if frame.data.len() > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "AnyTLS frame is too large",
        ));
    }
    packet.push(frame.command);
    packet.extend_from_slice(&frame.stream_id.to_be_bytes());
    packet.extend_from_slice(&(frame.data.len() as u16).to_be_bytes());
    packet.extend_from_slice(&frame.data);
    Ok(())
}

fn setting_value(data: &[u8], key: &str) -> Option<String> {
    std::str::from_utf8(data).ok()?.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name == key).then(|| value.to_owned())
    })
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame> {
    let command = reader.read_u8().await?;
    let stream_id = reader.read_u32().await?;
    let length = reader.read_u16().await? as usize;
    let mut data = vec![0u8; length];
    reader.read_exact(&mut data).await?;
    Ok(Frame {
        command,
        stream_id,
        data,
    })
}

async fn read_socks_address<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Address> {
    let kind = reader.read_u8().await?;
    let host = match kind {
        1 => {
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes).await?;
            IpAddr::from(bytes).to_string()
        }
        3 => {
            let length = reader.read_u8().await? as usize;
            let mut bytes = vec![0u8; length];
            reader.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).context("AnyTLS domain is not UTF-8")?
        }
        4 => {
            let mut bytes = [0u8; 16];
            reader.read_exact(&mut bytes).await?;
            IpAddr::from(bytes).to_string()
        }
        other => anyhow::bail!("unsupported AnyTLS address type {other}"),
    };
    Address::new(host, reader.read_u16().await?)
}

fn encode_socks_address(address: &Address) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(32);
    match address.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            output.push(4);
            output.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            anyhow::ensure!(
                address.host.len() <= u8::MAX as usize,
                "AnyTLS domain is too long"
            );
            output.push(3);
            output.push(address.host.len() as u8);
            output.extend_from_slice(address.host.as_bytes());
        }
    }
    output.extend_from_slice(&address.port.to_be_bytes());
    Ok(output)
}

struct UotPacketConnection<R, W> {
    reader: Mutex<R>,
    writer: Mutex<W>,
}

impl<R, W> UotPacketConnection<R, W> {
    fn new(reader: R, writer: W) -> Self {
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        }
    }
}

#[async_trait]
impl<R, W> PacketConnection for UotPacketConnection<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    async fn send(&self, packet: Packet) -> Result<()> {
        anyhow::ensure!(
            packet.data.len() <= UOT_MAX_PACKET,
            "AnyTLS UDP packet is too large"
        );
        let mut writer = self.writer.lock().await;
        write_uot_address(&mut *writer, &packet.destination).await?;
        writer.write_u16(packet.data.len() as u16).await?;
        writer.write_all(&packet.data).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn recv(&self) -> Result<Packet> {
        let mut reader = self.reader.lock().await;
        let destination = read_uot_address(&mut *reader).await?;
        let length = reader.read_u16().await? as usize;
        anyhow::ensure!(length <= UOT_MAX_PACKET, "AnyTLS UDP packet is too large");
        let mut data = vec![0u8; length];
        reader.read_exact(&mut data).await?;
        Ok(Packet::new(data, destination))
    }
}

async fn write_uot_request<W: AsyncWrite + Unpin>(writer: &mut W) -> Result<()> {
    writer.write_u8(0).await?;
    write_uot_address(writer, &Address::new(UOT_MAGIC, 0)?).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_uot_address<W: AsyncWrite + Unpin>(writer: &mut W, address: &Address) -> Result<()> {
    match address.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            writer.write_u8(0).await?;
            writer.write_all(&ip.octets()).await?;
        }
        Ok(IpAddr::V6(ip)) => {
            writer.write_u8(1).await?;
            writer.write_all(&ip.octets()).await?;
        }
        Err(_) => {
            anyhow::ensure!(
                address.host.len() <= u8::MAX as usize,
                "AnyTLS UDP domain is too long"
            );
            writer.write_u8(2).await?;
            writer.write_u8(address.host.len() as u8).await?;
            writer.write_all(address.host.as_bytes()).await?;
        }
    }
    writer.write_u16(address.port).await?;
    Ok(())
}

async fn read_uot_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let is_connect = reader.read_u8().await?;
    anyhow::ensure!(
        is_connect == 0,
        "AnyTLS UDP connect streams are not supported"
    );
    let _ = read_uot_address(reader).await?;
    Ok(())
}

async fn read_uot_address<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Address> {
    let kind = reader.read_u8().await?;
    let host = match kind {
        0 => {
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes).await?;
            IpAddr::from(bytes).to_string()
        }
        1 => {
            let mut bytes = [0u8; 16];
            reader.read_exact(&mut bytes).await?;
            IpAddr::from(bytes).to_string()
        }
        2 => {
            let length = reader.read_u8().await? as usize;
            let mut bytes = vec![0u8; length];
            reader.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).context("AnyTLS UDP domain is not UTF-8")?
        }
        other => anyhow::bail!("unsupported AnyTLS UDP address type {other}"),
    };
    Address::new(host, reader.read_u16().await?)
}

fn password_digest(password: &str) -> [u8; 32] {
    let digest = digest(&SHA256, password.as_bytes());
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_ref());
    output
}

fn md5_hex(input: &[u8]) -> String {
    const SHIFT: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const CONSTANTS: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];
    let bit_len = (input.len() as u64) * 8;
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_le_bytes());
    let mut state = [0x6745_2301u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    for chunk in message.chunks_exact(64) {
        let mut words = [0u32; 16];
        for (index, word) in words.iter_mut().enumerate() {
            let offset = index * 4;
            *word = u32::from_le_bytes(chunk[offset..offset + 4].try_into().expect("MD5 word"));
        }
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        for index in 0..64 {
            let (function, word_index) = match index {
                0..=15 => ((b & c) | (!b & d), index),
                16..=31 => ((d & b) | (!d & c), (5 * index + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * index + 5) % 16),
                _ => (c ^ (b | !d), (7 * index) % 16),
            };
            let next = a
                .wrapping_add(function)
                .wrapping_add(CONSTANTS[index])
                .wrapping_add(words[word_index])
                .rotate_left(SHIFT[index]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(next);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
    state
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_duration(value: &str) -> Result<Duration> {
    let value = value.trim();
    anyhow::ensure!(!value.is_empty(), "duration is empty");
    let mut total = 0.0f64;
    let mut position = 0;
    while position < value.len() {
        let number_start = position;
        while position < value.len()
            && (value.as_bytes()[position].is_ascii_digit() || value.as_bytes()[position] == b'.')
        {
            position += 1;
        }
        anyhow::ensure!(position > number_start, "invalid duration: {value}");
        let number: f64 = value[number_start..position].parse()?;
        let unit_start = position;
        while position < value.len() && value.as_bytes()[position].is_ascii_alphabetic() {
            position += 1;
        }
        let unit = &value[unit_start..position];
        let multiplier = match unit {
            "ns" => 1e-9,
            "us" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "d" => 86400.0,
            _ => anyhow::bail!("invalid duration unit: {unit}"),
        };
        total += number * multiplier;
    }
    anyhow::ensure!(total > 0.0, "duration must be positive");
    Duration::try_from_secs_f64(total).context("duration is too large")
}

fn build_server_config(certificate: &Certificate, tls: &ServerTlsOptions) -> Result<ServerConfig> {
    let chain = certificate
        .certificate_chain
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    let key = PrivateKeyDer::try_from(certificate.private_key.clone())
        .map_err(|_| anyhow::anyhow!("invalid AnyTLS private key"))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    config.alpn_protocols = tls
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    if tls.enable_jls {
        anyhow::ensure!(
            !tls.jls_username.is_empty() && !tls.jls_password.is_empty(),
            "AnyTLS JLS requires jls_username and jls_password"
        );
        let mut jls = rustls::jls::JlsServerConfig::default()
            .enable(true)
            .add_user(tls.jls_password.clone(), tls.jls_username.clone());
        if !tls.server_name.is_empty() {
            jls = jls.with_server_name(tls.server_name.clone());
        }
        config.jls_config = Arc::new(jls);
    }
    Ok(config)
}

async fn build_client_config(tls: &ClientTlsOptions) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    if tls.certificate_path.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    } else {
        let data = tokio::fs::read(&tls.certificate_path)
            .await
            .with_context(|| format!("read {}", tls.certificate_path))?;
        let mut reader = Cursor::new(data);
        for cert in rustls_pemfile::certs(&mut reader) {
            roots.add(cert?)?;
        }
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = if tls.insecure {
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![b"anytls".to_vec()];
    if tls.enable_jls {
        anyhow::ensure!(
            !tls.jls_username.is_empty() && !tls.jls_password.is_empty(),
            "AnyTLS JLS requires jls_username and jls_password"
        );
        config.jls_config = rustls::jls::JlsClientConfig::new(&tls.jls_password, &tls.jls_username);
    }
    Ok(config)
}

fn verify_jls_state(state: rustls::jls::JlsState) -> Result<()> {
    anyhow::ensure!(
        matches!(
            state,
            rustls::jls::JlsState::AuthSuccess(_) | rustls::jls::JlsState::Disabled
        ),
        "AnyTLS JLS authentication failed"
    );
    Ok(())
}

fn generate_jls_certificate() -> Result<Certificate> {
    let certificate = generate_simple_self_signed(vec!["localhost".to_owned()])
        .context("generate AnyTLS JLS certificate")?;
    Certificate::new(
        vec![certificate.cert.der().to_vec()],
        certificate.signing_key.serialize_der(),
    )
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
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
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        None
    }
}

fn parse_certificates(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut reader = Cursor::new(data);
    let certificates: Vec<Vec<u8>> = rustls_pemfile::certs(&mut reader)
        .map(|item| item.map(|certificate| certificate.as_ref().to_vec()))
        .collect::<std::io::Result<_>>()?;
    if certificates.is_empty() {
        Ok(vec![data.to_vec()])
    } else {
        Ok(certificates)
    }
}

fn parse_private_key(data: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Cursor::new(data);
    if let Some(key) = rustls_pemfile::private_key(&mut reader)? {
        Ok(key.secret_der().to_vec())
    } else if data.is_empty() {
        anyhow::bail!("private key is empty")
    } else {
        Ok(data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_is_sha256() {
        assert_eq!(
            hex(password_digest("password")),
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        );
    }

    #[test]
    fn parses_protocol_durations() {
        assert_eq!(parse_duration("2m30s").unwrap(), Duration::from_secs(150));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert!(parse_duration("999999999999999999999999999s").is_err());
    }

    #[test]
    fn parses_default_padding_and_md5() {
        let scheme = PaddingScheme::parse("").unwrap();
        assert_eq!(scheme.auth_padding_len(), 30);
        assert_eq!(scheme.stop, 8);
        assert_eq!(scheme.md5_hex(), "75cff2ad89aadf5e257059ee571ebe11");
    }

    #[test]
    fn accepts_padding_scheme_line_array() {
        let options: AnyTlsInboundOptions = serde_json::from_str(
            r#"{
                "users": [{"password": "test"}],
                "padding_scheme": ["stop=2", "0=30-30", "1=100-100"],
                "tls": {}
            }"#,
        )
        .unwrap();
        let scheme = PaddingScheme::parse(&options.padding_scheme.source()).unwrap();
        assert_eq!(scheme.stop, 2);
        assert_eq!(scheme.auth_padding_len(), 30);
    }

    #[test]
    fn rejects_unbounded_padding_ranges() {
        assert!(PaddingScheme::parse("0=0-1048577").is_err());
    }

    #[test]
    fn parses_quicproxy_jls_tls_fields() {
        let options: AnyTlsInboundOptions = serde_json::from_str(
            r#"{
                "users": [{"password": "anytls-password"}],
                "tls": {
                    "enable": true,
                    "server_name": "localhost",
                    "enable_jls": true,
                    "jls_username": "jls-user",
                    "jls_password": "jls-password"
                }
            }"#,
        )
        .unwrap();
        assert!(options.tls.enabled);
        assert!(options.tls.enable_jls);
        assert_eq!(options.tls.jls_username, "jls-user");
        assert_eq!(options.tls.jls_password, "jls-password");
    }

    #[tokio::test]
    async fn anytls_jls_tls_handshake_authenticates() {
        let server_tls = ServerTlsOptions {
            enabled: true,
            server_name: "localhost".to_owned(),
            enable_jls: true,
            jls_username: "jls-user".to_owned(),
            jls_password: "jls-password".to_owned(),
            ..ServerTlsOptions::default()
        };
        let certificate = generate_jls_certificate().unwrap();
        let server_config = build_server_config(&certificate, &server_tls).unwrap();
        let client_tls = ClientTlsOptions {
            insecure: true,
            server_name: "localhost".to_owned(),
            enable_jls: true,
            jls_username: "jls-user".to_owned(),
            jls_password: "jls-password".to_owned(),
            ..ClientTlsOptions::default()
        };
        let client_config = build_client_config(&client_tls).await.unwrap();
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            TlsAcceptor::from(Arc::new(server_config))
                .accept(server_io)
                .await
                .unwrap()
        });
        let server_name = ServerName::try_from("localhost".to_owned()).unwrap();
        let client = TlsConnector::from(Arc::new(client_config))
            .connect(server_name, client_io)
            .await
            .unwrap();
        let server = server.await.unwrap();
        assert!(matches!(
            client.get_ref().1.jls_state(),
            rustls::jls::JlsState::AuthSuccess(_)
        ));
        assert!(matches!(
            server.get_ref().1.jls_state(),
            rustls::jls::JlsState::AuthSuccess(_)
        ));
    }

    #[tokio::test]
    async fn client_session_close_cancels_reader() {
        let (reader, _peer) = tokio::io::duplex(1024);
        let (tx, _rx) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        let session = Arc::new(ClientSession {
            tx,
            streams: Arc::new(Mutex::new(HashMap::new())),
            next_stream_id: AtomicU32::new(1),
            active: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            cancel: cancel.clone(),
            done: Notify::new(),
            supports_v2: AtomicBool::new(false),
            last_used: Mutex::new(Instant::now()),
            padding: Arc::new(RwLock::new(PaddingScheme::parse("").unwrap())),
        });
        let reader_session = Arc::clone(&session);
        tokio::spawn(async move {
            let _ = client_reader(reader, reader_session.clone(), cancel).await;
            reader_session.close();
            reader_session.clear_streams().await;
            reader_session.done.notify_one();
        });

        let done = session.done.notified();
        session.close();
        timeout(Duration::from_secs(1), done)
            .await
            .expect("AnyTLS reader did not stop after session close");
    }

    #[test]
    fn active_client_session_is_not_reserved_twice() {
        let (tx, _rx) = mpsc::channel(1);
        let session = ClientSession {
            tx,
            streams: Arc::new(Mutex::new(HashMap::new())),
            next_stream_id: AtomicU32::new(1),
            active: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            cancel: CancellationToken::new(),
            done: Notify::new(),
            supports_v2: AtomicBool::new(false),
            last_used: Mutex::new(Instant::now()),
            padding: Arc::new(RwLock::new(PaddingScheme::parse("").unwrap())),
        };

        assert!(session.try_reserve());
        assert!(!session.try_reserve());
        session.active.store(0, Ordering::Release);
        assert!(session.try_reserve());
    }

    #[test]
    fn md5_matches_standard_vector() {
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[tokio::test]
    async fn address_round_trip() {
        for address in [
            Address::new("127.0.0.1", 80).unwrap(),
            Address::new("example.com", 443).unwrap(),
            Address::new("2001:db8::1", 8443).unwrap(),
        ] {
            let (mut left, mut right) = tokio::io::duplex(128);
            let encoded = encode_socks_address(&address).unwrap();
            let writer = tokio::spawn(async move {
                left.write_all(&encoded).await.unwrap();
            });
            assert_eq!(read_socks_address(&mut right).await.unwrap(), address);
            writer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn udp_over_tcp_address_round_trip() {
        for address in [
            Address::new("192.0.2.1", 53).unwrap(),
            Address::new("2001:db8::1", 443).unwrap(),
            Address::new("example.com", 8443).unwrap(),
        ] {
            let (mut left, mut right) = tokio::io::duplex(256);
            let expected = address.clone();
            let writer = tokio::spawn(async move {
                write_uot_address(&mut left, &expected).await.unwrap();
            });
            assert_eq!(read_uot_address(&mut right).await.unwrap(), address);
            writer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn udp_over_tcp_packet_round_trip() {
        let (left, right) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(left);
        let connection = UotPacketConnection::new(reader, writer);
        let (mut peer_reader, mut peer_writer) = tokio::io::split(right);
        let outbound = Packet::new(b"hello".to_vec(), Address::new("example.com", 443).unwrap());
        let send = connection.send(outbound.clone());
        let read = async {
            let packet = read_uot_address(&mut peer_reader).await.unwrap();
            let length = peer_reader.read_u16().await.unwrap() as usize;
            let mut data = vec![0u8; length];
            peer_reader.read_exact(&mut data).await.unwrap();
            (packet, data)
        };
        let (send_result, (destination, data)) = tokio::join!(send, read);
        send_result.unwrap();
        assert_eq!(destination, outbound.destination);
        assert_eq!(data, outbound.data);
        write_uot_address(&mut peer_writer, &Address::new("192.0.2.1", 53).unwrap())
            .await
            .unwrap();
        peer_writer.write_u16(3).await.unwrap();
        peer_writer.write_all(b"dns").await.unwrap();
        assert_eq!(connection.recv().await.unwrap().data, b"dns");
    }

    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
