use std::{
    io::Cursor,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use sing_box_core::{
    Address, BoxPacketConnection, BoxStream, Certificate, Dialer, Inbound, InboundBuildContext,
    Lifecycle, Network, Outbound, OutboundBuildContext, Packet, PacketConnection, Registry, Router,
    Session, StartStage, listen_addresses,
};
use sing_quic::sunnyquic::{
    Accepted, Client, ClientOptions, CongestionConfig, Server, ServerOptions, ShadowQuicPacket,
    ShadowQuicPacketConnection, TransportOptions as SunnyQuicTransportOptions, User,
};
use tokio::{sync::Mutex, sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;

const DEFAULT_ZERO_RTT: bool = true;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SunnyQuicOutboundOptions {
    server: String,
    server_port: u16,
    username: String,
    password: String,
    #[serde(default)]
    over_stream: bool,
    #[serde(default = "default_zero_rtt")]
    zero_rtt: bool,
    #[serde(default)]
    congestion_control: CongestionControlOptions,
    tls: OutboundTlsOptions,
    #[serde(flatten)]
    quic: SunnyQuicQuicOptions,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutboundTlsOptions {
    server_name: String,
    #[serde(default)]
    certificate_path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SunnyQuicInboundOptions {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default)]
    listen_port: u16,
    users: Vec<UserOptions>,
    #[serde(default = "default_zero_rtt")]
    zero_rtt: bool,
    #[serde(default)]
    congestion_control: CongestionControlOptions,
    tls: InboundTlsOptions,
    #[serde(flatten)]
    quic: SunnyQuicQuicOptions,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SunnyQuicQuicOptions {
    #[serde(default = "default_initial_packet_size")]
    initial_packet_size: u16,
    #[serde(default = "default_max_concurrent_streams")]
    max_concurrent_streams: u64,
    #[serde(default = "default_connection_receive_window")]
    connection_receive_window: u64,
    #[serde(default = "default_stream_receive_window")]
    stream_receive_window: u64,
    #[serde(default)]
    keep_alive_period: String,
    #[serde(default = "default_idle_timeout")]
    idle_timeout: String,
    #[serde(default)]
    disable_path_mtu_discovery: bool,
}

impl SunnyQuicQuicOptions {
    fn into_protocol(self) -> Result<SunnyQuicTransportOptions> {
        Ok(SunnyQuicTransportOptions {
            initial_packet_size: self.initial_packet_size,
            max_concurrent_streams: self.max_concurrent_streams,
            connection_receive_window: self.connection_receive_window,
            stream_receive_window: self.stream_receive_window,
            keep_alive_period: parse_optional_duration(&self.keep_alive_period)?,
            idle_timeout: parse_optional_duration(&self.idle_timeout)?,
            disable_path_mtu_discovery: self.disable_path_mtu_discovery,
        })
    }
}

fn default_initial_packet_size() -> u16 {
    1_300
}
fn default_max_concurrent_streams() -> u64 {
    1_000
}
fn default_connection_receive_window() -> u64 {
    20 * 1024 * 1024
}
fn default_stream_receive_window() -> u64 {
    5_000_000
}
fn default_idle_timeout() -> String {
    "30s".into()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InboundTlsOptions {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    alpn: Vec<String>,
    server_name: String,
    #[serde(default)]
    certificate_provider: String,
    #[serde(default)]
    certificate_path: String,
    #[serde(default)]
    key_path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserOptions {
    #[serde(default)]
    name: String,
    password: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum CongestionControlOptions {
    #[default]
    Bbr,
    Brutal {
        bandwidth_mbps: u64,
        #[serde(default)]
        disable_loss_compensation: bool,
    },
}

impl CongestionControlOptions {
    fn into_protocol(self) -> Result<CongestionConfig> {
        match self {
            Self::Bbr => Ok(CongestionConfig::Bbr),
            Self::Brutal {
                bandwidth_mbps,
                disable_loss_compensation,
            } => {
                anyhow::ensure!(
                    bandwidth_mbps > 0,
                    "SunnyQUIC Brutal bandwidth must be positive"
                );
                Ok(CongestionConfig::Brutal {
                    bytes_per_second: bandwidth_mbps
                        .checked_mul(125_000)
                        .context("SunnyQUIC Brutal bandwidth is too large")?,
                    disable_loss_compensation,
                })
            }
        }
    }
}

fn default_listen() -> String {
    "127.0.0.1".into()
}

fn default_zero_rtt() -> bool {
    DEFAULT_ZERO_RTT
}

enum CertificateSource {
    Static(Arc<Certificate>),
    Provider(watch::Receiver<Option<Arc<Certificate>>>),
}

struct PreparedServer {
    listen: Vec<SocketAddr>,
    certificate: CertificateSource,
    users: Vec<User>,
    congestion: CongestionConfig,
    zero_rtt: bool,
    transport: SunnyQuicTransportOptions,
}

struct Running {
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    servers: Vec<Arc<Server>>,
}

struct SunnyQuicInbound {
    tag: String,
    prepared: Mutex<Option<PreparedServer>>,
    router: Arc<Router>,
    running: Mutex<Option<Running>>,
    local_addr: RwLock<Option<SocketAddr>>,
}

struct SunnyQuicOutbound {
    tag: String,
    client: Arc<Client>,
    over_stream: bool,
}

#[async_trait]
impl Lifecycle for SunnyQuicOutbound {
    async fn close(&self) -> Result<()> {
        self.client.close();
        Ok(())
    }
}

#[async_trait]
impl Dialer for SunnyQuicOutbound {
    async fn connect(&self, session: &Session) -> Result<BoxStream> {
        anyhow::ensure!(
            session.network == Network::Tcp,
            "SunnyQUIC UDP requires packet routing"
        );
        let destination =
            sing_quic::Address::new(session.destination.host.clone(), session.destination.port)?;
        Ok(Box::new(self.client.connect(destination).await?))
    }
}

#[async_trait]
impl Outbound for SunnyQuicOutbound {
    fn kind(&self) -> &'static str {
        "sunnyquic"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect_packet(&self, session: &Session) -> Result<BoxPacketConnection> {
        anyhow::ensure!(
            session.network == Network::Udp,
            "SunnyQUIC packet routing requires UDP"
        );
        let destination =
            sing_quic::Address::new(session.destination.host.clone(), session.destination.port)?;
        Ok(Arc::new(SunnyQuicPacketAdapter {
            inner: self.client.associate(destination, self.over_stream).await?,
        }))
    }
}

#[async_trait]
impl Lifecycle for SunnyQuicInbound {
    async fn start(&self, stage: StartStage) -> Result<()> {
        if stage != StartStage::Start || self.running.lock().await.is_some() {
            return Ok(());
        }
        let prepared = self
            .prepared
            .lock()
            .await
            .take()
            .context("SunnyQUIC inbound cannot be restarted after close")?;
        let PreparedServer {
            listen,
            certificate,
            users,
            congestion,
            zero_rtt,
            transport,
        } = prepared;
        let (certificate, certificate_updates) = match certificate {
            CertificateSource::Static(certificate) => (certificate, None),
            CertificateSource::Provider(receiver) => {
                let certificate = receiver
                    .borrow()
                    .clone()
                    .context("certificate provider is not ready")?;
                (certificate, Some(receiver))
            }
        };
        let ipv6_wildcard = listen[0].ip().is_unspecified() && listen[0].is_ipv6();
        let mut servers: Vec<Arc<Server>> = Vec::with_capacity(listen.len());
        let mut assigned_port = 0;
        for (index, mut address) in listen.into_iter().enumerate() {
            if index > 0 && address.port() == 0 {
                address.set_port(assigned_port);
            }
            let server = match Server::bind(ServerOptions {
                listen: address,
                users: users.clone(),
                certificate_chain: certificate.certificate_chain.clone(),
                private_key: certificate.private_key.clone(),
                congestion,
                zero_rtt,
                transport,
            }) {
                Ok(server) => Arc::new(server),
                Err(sing_quic::Error::Io(error))
                    if index > 0
                        && ipv6_wildcard
                        && error.kind() == std::io::ErrorKind::AddrInUse =>
                {
                    continue;
                }
                Err(error) => {
                    for server in &servers {
                        server.close().await;
                    }
                    return Err(error.into());
                }
            };
            if index == 0 {
                assigned_port = server.local_addr()?.port();
            }
            servers.push(server);
        }
        let local_addr = servers[0].local_addr()?;
        *self.local_addr.write().expect("SunnyQUIC address lock") = Some(local_addr);
        let cancel = CancellationToken::new();
        let mut tasks = servers
            .iter()
            .map(|server| {
                tokio::spawn(run_server(
                    Arc::clone(server),
                    cancel.clone(),
                    Arc::clone(&self.router),
                    self.tag.clone(),
                ))
            })
            .collect::<Vec<_>>();
        if let Some(receiver) = certificate_updates {
            tasks.push(tokio::spawn(watch_certificate_updates(
                servers.clone(),
                receiver,
                cancel.clone(),
                self.tag.clone(),
            )));
        }
        *self.running.lock().await = Some(Running {
            cancel,
            tasks,
            servers,
        });
        tracing::info!(tag = %self.tag, %local_addr, "started SunnyQUIC inbound");
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        if let Some(running) = self.running.lock().await.take() {
            running.cancel.cancel();
            for task in running.tasks {
                task.await?;
            }
            for server in running.servers {
                server.close().await;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Inbound for SunnyQuicInbound {
    fn kind(&self) -> &'static str {
        "sunnyquic"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.read().expect("SunnyQUIC address lock")
    }
}

async fn watch_certificate_updates(
    servers: Vec<Arc<Server>>,
    mut receiver: watch::Receiver<Option<Arc<Certificate>>>,
    cancel: CancellationToken,
    tag: String,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            changed = receiver.changed() => {
                if changed.is_err() { return; }
            }
        }
        let Some(certificate) = receiver.borrow_and_update().clone() else {
            continue;
        };
        for server in &servers {
            if let Err(error) = server.update_certificate(
                certificate.certificate_chain.clone(),
                certificate.private_key.clone(),
            ) {
                tracing::warn!(inbound = %tag, %error, "failed to apply SunnyQUIC certificate update");
            }
        }
        tracing::info!(inbound = %tag, "applied SunnyQUIC certificate provider update");
    }
}

async fn run_server(
    server: Arc<Server>,
    cancel: CancellationToken,
    router: Arc<Router>,
    tag: String,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = server.accept() => match accepted {
                Ok(Accepted::Stream(accepted)) => {
                    let router = Arc::clone(&router);
                    let tag = tag.clone();
                    tokio::spawn(async move {
                        let destination = match Address::new(accepted.destination.host(), accepted.destination.port()) {
                            Ok(destination) => destination,
                            Err(error) => { tracing::debug!(%error, "invalid SunnyQUIC TCP destination"); return; }
                        };
                        let session = Session::inbound(
                            Network::Tcp,
                            accepted.source,
                            destination,
                            tag,
                            "sunnyquic",
                            Some(accepted.user),
                        );
                        if let Err(error) = router.route(session, Box::new(accepted.stream)).await {
                            tracing::debug!(%error, "SunnyQUIC TCP session closed");
                        }
                    });
                }
                Ok(Accepted::Packet(accepted)) => {
                    let router = Arc::clone(&router);
                    let tag = tag.clone();
                    tokio::spawn(async move {
                        let destination = match Address::new(accepted.destination.host(), accepted.destination.port()) {
                            Ok(destination) => destination,
                            Err(error) => { tracing::debug!(%error, "invalid SunnyQUIC UDP destination"); return; }
                        };
                        let session = Session::inbound(
                            Network::Udp,
                            accepted.source,
                            destination,
                            tag,
                            "sunnyquic",
                            Some(accepted.user),
                        );
                        let connection = Arc::clone(&accepted.connection);
                        let result = router.route_packet(
                            session,
                            Arc::new(SunnyQuicPacketAdapter { inner: accepted.connection }),
                        ).await;
                        if let Err(error) = result {
                            tracing::debug!(%error, "SunnyQUIC UDP session closed");
                        }
                        drop(connection);
                    });
                }
                Err(error) => {
                    tracing::debug!(%error, "SunnyQUIC accept stopped");
                    break;
                }
            }
        }
    }
}

struct SunnyQuicPacketAdapter {
    inner: Arc<ShadowQuicPacketConnection>,
}

#[async_trait]
impl PacketConnection for SunnyQuicPacketAdapter {
    async fn send(&self, packet: Packet) -> Result<()> {
        self.inner
            .send(ShadowQuicPacket {
                data: packet.data,
                destination: sing_quic::Address::new(
                    packet.destination.host,
                    packet.destination.port,
                )?,
            })
            .await?;
        Ok(())
    }

    async fn recv(&self) -> Result<Packet> {
        let packet = self.inner.recv().await?;
        Ok(Packet {
            data: packet.data,
            destination: Address::new(packet.destination.host(), packet.destination.port())?,
        })
    }
}

pub fn register(registry: &mut Registry) -> Result<()> {
    registry.register_outbound::<SunnyQuicOutboundOptions, _, _>(
        "sunnyquic",
        |context: OutboundBuildContext, tag, options| async move {
            let server = context
                .system_dialer
                .resolve(&options.server, options.server_port)
                .await?
                .into_iter()
                .next()
                .with_context(|| {
                    format!(
                        "no address found for {}:{}",
                        options.server, options.server_port
                    )
                })?;
            let ca_certificates = if options.tls.certificate_path.is_empty() {
                Vec::new()
            } else {
                let data = tokio::fs::read(&options.tls.certificate_path)
                    .await
                    .with_context(|| format!("read {}", options.tls.certificate_path))?;
                parse_certificates(&data)?
            };
            let client = Client::new(ClientOptions {
                server,
                server_name: options.tls.server_name,
                username: options.username,
                password: options.password,
                ca_certificates,
                congestion: options.congestion_control.into_protocol()?,
                zero_rtt: options.zero_rtt,
                transport: options.quic.into_protocol()?,
            })?;
            Ok(Arc::new(SunnyQuicOutbound {
                tag,
                client: Arc::new(client),
                over_stream: options.over_stream,
            }) as Arc<dyn Outbound>)
        },
    )?;

    registry.register_inbound::<SunnyQuicInboundOptions, _, _>(
        "sunnyquic",
        |context: InboundBuildContext, tag, options| async move {
            anyhow::ensure!(!options.users.is_empty(), "SunnyQUIC users cannot be empty");
            anyhow::ensure!(
                !options.tls.server_name.is_empty(),
                "SunnyQUIC TLS server_name cannot be empty"
            );
            anyhow::ensure!(
                options.tls.alpn.is_empty()
                    || options.tls.alpn.iter().any(|protocol| protocol == "h3"),
                "SunnyQUIC TLS ALPN must include h3"
            );
            let _ = options.tls.enabled;
            let listen = listen_addresses(&options.listen, options.listen_port)?;
            let certificate = if options.tls.certificate_provider.is_empty() {
                anyhow::ensure!(
                    !options.tls.certificate_path.is_empty() && !options.tls.key_path.is_empty(),
                    "SunnyQUIC TLS requires certificate_provider or certificate_path/key_path"
                );
                let certificate_data = tokio::fs::read(&options.tls.certificate_path)
                    .await
                    .with_context(|| format!("read {}", options.tls.certificate_path))?;
                let key_data = tokio::fs::read(&options.tls.key_path)
                    .await
                    .with_context(|| format!("read {}", options.tls.key_path))?;
                CertificateSource::Static(Arc::new(Certificate::new(
                    parse_certificates(&certificate_data)?,
                    parse_private_key(&key_data)?,
                )?))
            } else {
                anyhow::ensure!(
                    options.tls.certificate_path.is_empty() && options.tls.key_path.is_empty(),
                    "SunnyQUIC certificate_provider conflicts with certificate_path/key_path"
                );
                CertificateSource::Provider(
                    context
                        .certificate_providers
                        .subscribe(&options.tls.certificate_provider, &options.tls.server_name)
                        .await?,
                )
            };
            let users = options
                .users
                .into_iter()
                .map(|user| User {
                    name: user.name,
                    password: user.password,
                })
                .collect();
            Ok(Arc::new(SunnyQuicInbound {
                tag,
                prepared: Mutex::new(Some(PreparedServer {
                    listen,
                    certificate,
                    users,
                    congestion: options.congestion_control.into_protocol()?,
                    zero_rtt: options.zero_rtt,
                    transport: options.quic.into_protocol()?,
                })),
                router: context.router,
                running: Mutex::new(None),
                local_addr: RwLock::new(None),
            }) as Arc<dyn Inbound>)
        },
    )?;
    Ok(())
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

fn parse_optional_duration(value: &str) -> Result<Option<Duration>> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    let duration = parse_duration(value)?;
    Ok((!duration.is_zero()).then_some(duration))
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
        let multiplier = match &value[unit_start..position] {
            "ns" => 1e-9,
            "us" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "d" => 86400.0,
            unit => anyhow::bail!("invalid duration unit: {unit}"),
        };
        total += number * multiplier;
    }
    Ok(Duration::from_secs_f64(total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_brutal_bandwidth() {
        let config = CongestionControlOptions::Brutal {
            bandwidth_mbps: 100,
            disable_loss_compensation: false,
        };
        assert_eq!(
            config.into_protocol().unwrap(),
            CongestionConfig::Brutal {
                bytes_per_second: 12_500_000,
                disable_loss_compensation: false,
            }
        );
    }

    #[test]
    fn parses_sunnyquic_transport_options() {
        let options: SunnyQuicOutboundOptions = serde_json::from_str(
            r#"{
                "server": "sunny.example.com",
                "server_port": 443,
                "username": "demo",
                "password": "secret",
                "initial_packet_size": 1380,
                "max_concurrent_streams": 256,
                "connection_receive_window": 25000000,
                "stream_receive_window": 5500000,
                "keep_alive_period": "4s",
                "idle_timeout": "40s",
                "disable_path_mtu_discovery": true,
                "tls": {"server_name": "sunny.example.com"}
            }"#,
        )
        .unwrap();
        let transport = options.quic.into_protocol().unwrap();
        assert_eq!(transport.initial_packet_size, 1380);
        assert_eq!(transport.max_concurrent_streams, 256);
        assert_eq!(transport.keep_alive_period, Some(Duration::from_secs(4)));
        assert_eq!(transport.idle_timeout, Some(Duration::from_secs(40)));
        assert!(transport.disable_path_mtu_discovery);
    }
}
