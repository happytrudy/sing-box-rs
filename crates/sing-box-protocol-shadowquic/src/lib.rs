use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use sing_box_core::{
    Address, BoxStream, Dialer, Inbound, InboundBuildContext, Lifecycle, Network, Outbound,
    OutboundBuildContext, Registry, Router, Session, StartStage, listen_addresses,
};
use sing_quic::shadowquic::{
    Client, ClientOptions, CongestionConfig as ShadowQuicCongestionConfig, Server, ServerOptions,
    User as ShadowQuicUser,
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
}

fn default_zero_rtt() -> bool {
    true
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
                        let destination = Address::new(accepted.destination.host(), accepted.destination.port())?;
                        let session = Session::inbound(
                            Network::Tcp,
                            accepted.source,
                            destination,
                            tag,
                            "shadowquic",
                            Some(accepted.user),
                        );
                        router.route(session, Box::new(accepted.stream)).await
                    });
                }
                Err(error) => { tracing::debug!(%error, "ShadowQuic accept stopped"); break; }
            }
        }
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
                .map(|upstream| (Some(upstream.addr), upstream.rate_limit))
                .unwrap_or((None, u64::MAX));
            let congestion = options.congestion_control.into_protocol()?;
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
}
