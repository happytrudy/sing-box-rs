use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use sing_box_core::{
    Address, BoxStream, Dialer, Inbound, InboundBuildContext, Lifecycle, Network, Outbound,
    OutboundBuildContext, Packet, PacketConnection, Registry, Router, Session, StartStage,
    listen_addresses,
};
use sing_quic::shadowquic::{
    Accepted, Client, ClientOptions, CongestionConfig as ShadowQuicCongestionConfig, Server,
    ServerOptions, ShadowQuicPacket, ShadowQuicPacketConnection,
    TransportOptions as ShadowQuicTransportOptions, User as ShadowQuicUser,
};
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowQuicOutboundOptions {
    server: String,
    server_port: u16,
    username: String,
    password: String,
    server_name: String,
    #[serde(default)]
    congestion_control: CongestionControlOptions,
    #[serde(default = "default_zero_rtt")]
    zero_rtt: bool,
    #[serde(flatten)]
    quic: ShadowQuicQuicOptions,
}

fn default_zero_rtt() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowQuicQuicOptions {
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

impl ShadowQuicQuicOptions {
    fn into_protocol(self) -> Result<ShadowQuicTransportOptions> {
        Ok(ShadowQuicTransportOptions {
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
    fn into_protocol(self) -> Result<ShadowQuicCongestionConfig> {
        match self {
            Self::Bbr => Ok(ShadowQuicCongestionConfig::Bbr),
            Self::Brutal {
                bandwidth_mbps,
                disable_loss_compensation,
            } => {
                anyhow::ensure!(
                    bandwidth_mbps > 0,
                    "ShadowQuic Brutal bandwidth must be positive"
                );
                let bytes_per_second = bandwidth_mbps
                    .checked_mul(125_000)
                    .context("ShadowQuic Brutal bandwidth is too large")?;
                Ok(ShadowQuicCongestionConfig::Brutal {
                    bytes_per_second,
                    disable_loss_compensation,
                })
            }
        }
    }
}

struct ShadowQuicOutbound {
    tag: String,
    client: Arc<Client>,
}

#[async_trait]
impl Lifecycle for ShadowQuicOutbound {
    async fn close(&self) -> Result<()> {
        self.client.close();
        Ok(())
    }
}

#[async_trait]
impl Dialer for ShadowQuicOutbound {
    async fn connect(&self, session: &Session) -> Result<BoxStream> {
        anyhow::ensure!(
            session.network == Network::Tcp,
            "ShadowQuic UDP is not implemented"
        );
        let destination =
            sing_quic::Address::new(session.destination.host.clone(), session.destination.port)?;
        Ok(Box::new(self.client.connect(destination).await?))
    }
}

#[async_trait]
impl Outbound for ShadowQuicOutbound {
    fn kind(&self) -> &'static str {
        "shadowquic"
    }

    fn tag(&self) -> &str {
        &self.tag
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowQuicInboundOptions {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default)]
    listen_port: u16,
    #[serde(default)]
    server_name: String,
    #[serde(default)]
    jls_upstream: Option<JlsUpstreamOptions>,
    #[serde(default = "default_zero_rtt")]
    zero_rtt: bool,
    #[serde(default)]
    congestion_control: CongestionControlOptions,
    users: Vec<UserOptions>,
    #[serde(flatten)]
    quic: ShadowQuicQuicOptions,
}

fn default_listen() -> String {
    "127.0.0.1".to_owned()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JlsUpstreamOptions {
    addr: String,
    #[serde(default)]
    rate_limit: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserOptions {
    #[serde(default)]
    name: String,
    password: String,
}

struct PreparedServer {
    listen: Vec<SocketAddr>,
    protocol: ServerProtocolOptions,
}

#[derive(Clone)]
struct ServerProtocolOptions {
    users: Vec<ShadowQuicUser>,
    server_name: Option<String>,
    jls_upstream_addr: Option<String>,
    jls_rate_limit: u64,
    congestion: ShadowQuicCongestionConfig,
    zero_rtt: bool,
    transport: ShadowQuicTransportOptions,
}

struct Running {
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    servers: Vec<Arc<Server>>,
}

struct ShadowQuicInbound {
    tag: String,
    prepared: Mutex<Option<PreparedServer>>,
    router: Arc<Router>,
    running: Mutex<Option<Running>>,
    local_addr: RwLock<Option<SocketAddr>>,
}

#[async_trait]
impl Lifecycle for ShadowQuicInbound {
    async fn start(&self, stage: StartStage) -> Result<()> {
        if stage != StartStage::Start || self.running.lock().await.is_some() {
            return Ok(());
        }
        let prepared = self
            .prepared
            .lock()
            .await
            .take()
            .context("ShadowQuic inbound cannot be restarted after close")?;
        let PreparedServer { listen, protocol } = prepared;
        let ipv6_wildcard = listen[0].ip().is_unspecified() && listen[0].is_ipv6();
        let mut servers: Vec<Arc<Server>> = Vec::with_capacity(listen.len());
        let mut assigned_port = 0;
        for (index, mut address) in listen.into_iter().enumerate() {
            if index > 0 && address.port() == 0 {
                address.set_port(assigned_port);
            }
            let server = match Server::bind(ServerOptions {
                listen: address,
                users: protocol.users.clone(),
                server_name: protocol.server_name.clone(),
                jls_upstream_addr: protocol.jls_upstream_addr.clone(),
                jls_rate_limit: protocol.jls_rate_limit,
                congestion: protocol.congestion,
                zero_rtt: protocol.zero_rtt,
                transport: protocol.transport,
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
        *self.local_addr.write().expect("ShadowQuic address lock") = Some(local_addr);
        let cancel = CancellationToken::new();
        let tasks = servers
            .iter()
            .map(|server| {
                tokio::spawn(run_server(
                    Arc::clone(server),
                    cancel.clone(),
                    Arc::clone(&self.router),
                    self.tag.clone(),
                ))
            })
            .collect();
        *self.running.lock().await = Some(Running {
            cancel,
            tasks,
            servers,
        });
        tracing::info!(tag = %self.tag, %local_addr, "started ShadowQuic inbound");
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
                Ok(accepted) => {
                    let router = Arc::clone(&router);
                    let tag = tag.clone();
                    tokio::spawn(async move {
                        let result: Result<()> = async {
                            match accepted {
                            Accepted::Stream(accepted) => {
                                let destination = Address::new(
                                    accepted.destination.host(),
                                    accepted.destination.port(),
                                )?;
                                let session = Session::inbound(
                                    Network::Tcp,
                                    accepted.source,
                                    destination,
                                    tag,
                                    "shadowquic",
                                    Some(accepted.user),
                                );
                                router.route(session, Box::new(accepted.stream)).await
                            }
                            Accepted::Packet(accepted) => {
                                let destination = Address::new(
                                    accepted.destination.host(),
                                    accepted.destination.port(),
                                )?;
                                let session = Session::inbound(
                                    Network::Udp,
                                    accepted.source,
                                    destination,
                                    tag,
                                    "shadowquic",
                                    Some(accepted.user),
                                );
                                router
                                    .route_packet(
                                        session,
                                        Arc::new(ShadowQuicPacketAdapter {
                                            inner: accepted.connection,
                                        }),
                                    )
                                    .await
                            }
                            }
                        }
                        .await;
                        if let Err(error) = result {
                            tracing::debug!(%error, "ShadowQuic routed session closed");
                        }
                    });
                }
                Err(error) => { tracing::debug!(%error, "ShadowQuic accept stopped"); break; }
            }
        }
    }
}

struct ShadowQuicPacketAdapter {
    inner: Arc<ShadowQuicPacketConnection>,
}

#[async_trait]
impl PacketConnection for ShadowQuicPacketAdapter {
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

#[async_trait]
impl Inbound for ShadowQuicInbound {
    fn kind(&self) -> &'static str {
        "shadowquic"
    }
    fn tag(&self) -> &str {
        &self.tag
    }
    fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.read().expect("ShadowQuic address lock")
    }
}

pub fn register(registry: &mut Registry) -> Result<()> {
    registry.register_outbound::<ShadowQuicOutboundOptions, _, _>(
        "shadowquic",
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
            let client = Client::new(ClientOptions {
                server,
                server_name: options.server_name,
                username: options.username,
                password: options.password,
                congestion: options.congestion_control.into_protocol()?,
                zero_rtt: options.zero_rtt,
                transport: options.quic.into_protocol()?,
            })?;
            Ok(Arc::new(ShadowQuicOutbound {
                tag,
                client: Arc::new(client),
            }) as Arc<dyn Outbound>)
        },
    )?;
    registry.register_inbound::<ShadowQuicInboundOptions, _, _>(
        "shadowquic",
        |context: InboundBuildContext, tag, options| async move {
            anyhow::ensure!(
                !options.users.is_empty(),
                "ShadowQuic users cannot be empty"
            );
            let listen = listen_addresses(&options.listen, options.listen_port)?;
            let users = options
                .users
                .into_iter()
                .map(|user| ShadowQuicUser {
                    name: user.name,
                    password: user.password,
                })
                .collect();
            let server_name = (!options.server_name.is_empty()).then_some(options.server_name);
            let (jls_upstream_addr, jls_rate_limit) = options
                .jls_upstream
                .map(|upstream| {
                    (
                        Some(upstream.addr),
                        if upstream.rate_limit == 0 {
                            u64::MAX
                        } else {
                            upstream.rate_limit
                        },
                    )
                })
                .unwrap_or((None, u64::MAX));
            let congestion = options.congestion_control.into_protocol()?;
            let transport = options.quic.into_protocol()?;
            Ok(Arc::new(ShadowQuicInbound {
                tag,
                prepared: Mutex::new(Some(PreparedServer {
                    listen,
                    protocol: ServerProtocolOptions {
                        users,
                        server_name,
                        jls_upstream_addr,
                        jls_rate_limit,
                        congestion,
                        zero_rtt: options.zero_rtt,
                        transport,
                    },
                })),
                router: context.router,
                running: Mutex::new(None),
                local_addr: RwLock::new(None),
            }) as Arc<dyn Inbound>)
        },
    )?;
    Ok(())
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
    fn converts_brutal_megabits_to_bytes_per_second() {
        let congestion = CongestionControlOptions::Brutal {
            bandwidth_mbps: 100,
            disable_loss_compensation: false,
        }
        .into_protocol()
        .unwrap();

        assert_eq!(
            congestion,
            ShadowQuicCongestionConfig::Brutal {
                bytes_per_second: 12_500_000,
                disable_loss_compensation: false,
            }
        );
    }

    #[test]
    fn rejects_zero_brutal_bandwidth() {
        let error = CongestionControlOptions::Brutal {
            bandwidth_mbps: 0,
            disable_loss_compensation: false,
        }
        .into_protocol()
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "ShadowQuic Brutal bandwidth must be positive"
        );
    }

    #[test]
    fn parses_shadowquic_transport_options() {
        let options: ShadowQuicInboundOptions = serde_json::from_str(
            r#"{
                "listen": "::",
                "listen_port": 443,
                "initial_packet_size": 1400,
                "max_concurrent_streams": 512,
                "connection_receive_window": 30000000,
                "stream_receive_window": 6000000,
                "keep_alive_period": "5s",
                "idle_timeout": "45s",
                "disable_path_mtu_discovery": true,
                "users": [{"name": "demo", "password": "secret"}]
            }"#,
        )
        .unwrap();
        let transport = options.quic.into_protocol().unwrap();
        assert_eq!(transport.initial_packet_size, 1400);
        assert_eq!(transport.max_concurrent_streams, 512);
        assert_eq!(transport.keep_alive_period, Some(Duration::from_secs(5)));
        assert_eq!(transport.idle_timeout, Some(Duration::from_secs(45)));
        assert!(transport.disable_path_mtu_discovery);
    }
}
