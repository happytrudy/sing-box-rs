use std::{
    io::Cursor,
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
use sing_quic::Error as SingQuicError;
use sing_quic::hysteria2::{
    Client, ClientBandwidth, ClientOptions, Server, ServerBandwidth, ServerOptions,
    User as Hysteria2User,
};
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hysteria2OutboundOptions {
    server: String,
    server_port: u16,
    password: String,
    #[serde(default)]
    up_mbps: u64,
    #[serde(default)]
    down_mbps: u64,
    tls: OutboundTlsOptions,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutboundTlsOptions {
    server_name: String,
    certificate_path: String,
}

struct Hysteria2Outbound {
    tag: String,
    client: Arc<Client>,
}

#[async_trait]
impl Lifecycle for Hysteria2Outbound {
    async fn close(&self) -> Result<()> {
        self.client.close();
        Ok(())
    }
}

#[async_trait]
impl Dialer for Hysteria2Outbound {
    async fn connect(&self, session: &Session) -> Result<BoxStream> {
        anyhow::ensure!(
            session.network == Network::Tcp,
            "Hysteria2 UDP is not implemented"
        );
        let destination =
            sing_quic::Address::new(session.destination.host.clone(), session.destination.port)?;
        Ok(Box::new(self.client.connect(destination).await?))
    }
}

#[async_trait]
impl Outbound for Hysteria2Outbound {
    fn kind(&self) -> &'static str {
        "hysteria2"
    }

    fn tag(&self) -> &str {
        &self.tag
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hysteria2InboundOptions {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default)]
    listen_port: u16,
    #[serde(default)]
    up_mbps: u64,
    #[serde(default)]
    down_mbps: u64,
    #[serde(default)]
    ignore_client_bandwidth: bool,
    tls: InboundTlsOptions,
    users: Vec<UserOptions>,
}

fn default_listen() -> String {
    "127.0.0.1".to_owned()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InboundTlsOptions {
    certificate_path: String,
    key_path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserOptions {
    name: String,
    password: String,
}

struct PreparedServer {
    listen: Vec<SocketAddr>,
    certificate_chain: Vec<Vec<u8>>,
    private_key: Vec<u8>,
    users: Vec<Hysteria2User>,
    bandwidth: ServerBandwidth,
}

struct Running {
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    servers: Vec<Arc<Server>>,
}

struct Hysteria2Inbound {
    tag: String,
    prepared: Mutex<Option<PreparedServer>>,
    router: Arc<Router>,
    running: Mutex<Option<Running>>,
    local_addr: RwLock<Option<SocketAddr>>,
}

#[async_trait]
impl Lifecycle for Hysteria2Inbound {
    async fn start(&self, stage: StartStage) -> Result<()> {
        if stage != StartStage::Start {
            return Ok(());
        }
        if self.running.lock().await.is_some() {
            return Ok(());
        }
        let prepared = self
            .prepared
            .lock()
            .await
            .take()
            .context("Hysteria2 inbound cannot be restarted after close")?;
        let PreparedServer {
            listen,
            certificate_chain,
            private_key,
            users,
            bandwidth,
        } = prepared;
        let ipv6_wildcard = listen[0].ip().is_unspecified() && listen[0].is_ipv6();
        let mut servers: Vec<Arc<Server>> = Vec::with_capacity(listen.len());
        let mut assigned_port = 0;
        for (index, mut address) in listen.into_iter().enumerate() {
            if index > 0 && address.port() == 0 {
                address.set_port(assigned_port);
            }
            let server = match Server::bind_with_bandwidth(
                ServerOptions {
                    listen: address,
                    certificate_chain: certificate_chain.clone(),
                    private_key: private_key.clone(),
                    users: users.clone(),
                },
                bandwidth,
            ) {
                Ok(server) => Arc::new(server),
                Err(SingQuicError::Io(error))
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
        *self.local_addr.write().expect("Hysteria2 address lock") = Some(local_addr);
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
        tracing::info!(tag = %self.tag, %local_addr, "started Hysteria2 inbound");
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
                        let destination = match Address::new(
                            accepted.destination.host(),
                            accepted.destination.port(),
                        ) {
                            Ok(destination) => destination,
                            Err(error) => {
                                tracing::debug!(%error, "invalid Hysteria2 destination");
                                return;
                            }
                        };
                        let session = Session {
                            network: Network::Tcp,
                            source: Some(accepted.source),
                            destination,
                            inbound: tag,
                            inbound_type: "hysteria2".to_owned(),
                            outbound: None,
                            user: Some(accepted.user),
                        };
                        if let Err(error) = router.route(session, Box::new(accepted.stream)).await {
                            tracing::debug!(%error, "Hysteria2 stream closed");
                        }
                    });
                }
                Err(error) => {
                    tracing::debug!(%error, "Hysteria2 accept stopped");
                    break;
                }
            }
        }
    }
}

#[async_trait]
impl Inbound for Hysteria2Inbound {
    fn kind(&self) -> &'static str {
        "hysteria2"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.read().expect("Hysteria2 address lock")
    }
}

pub fn register(registry: &mut Registry) -> Result<()> {
    registry.register_outbound::<Hysteria2OutboundOptions, _, _>(
        "hysteria2",
        |_context: OutboundBuildContext, tag, options| async move {
            let server = resolve_server(&options.server, options.server_port).await?;
            let certificate_data = tokio::fs::read(&options.tls.certificate_path)
                .await
                .with_context(|| format!("read {}", options.tls.certificate_path))?;
            let certificates = parse_certificates(&certificate_data)?;
            let client = Client::new_with_bandwidth(
                ClientOptions {
                    server,
                    server_name: options.tls.server_name,
                    password: options.password,
                    ca_certificates: certificates,
                },
                ClientBandwidth {
                    send_bps: mbps_to_bps(options.up_mbps)?,
                    receive_bps: mbps_to_bps(options.down_mbps)?,
                },
            )?;
            Ok(Arc::new(Hysteria2Outbound {
                tag,
                client: Arc::new(client),
            }) as Arc<dyn Outbound>)
        },
    )?;

    registry.register_inbound::<Hysteria2InboundOptions, _, _>(
        "hysteria2",
        |context: InboundBuildContext, tag, options| async move {
            anyhow::ensure!(!options.users.is_empty(), "Hysteria2 users cannot be empty");
            let listen = listen_addresses(&options.listen, options.listen_port)?;
            let certificate_data = tokio::fs::read(&options.tls.certificate_path)
                .await
                .with_context(|| format!("read {}", options.tls.certificate_path))?;
            let key_data = tokio::fs::read(&options.tls.key_path)
                .await
                .with_context(|| format!("read {}", options.tls.key_path))?;
            let prepared = PreparedServer {
                listen,
                certificate_chain: parse_certificates(&certificate_data)?,
                private_key: parse_private_key(&key_data)?,
                users: options
                    .users
                    .into_iter()
                    .map(|user| Hysteria2User {
                        name: user.name,
                        password: user.password,
                    })
                    .collect(),
                bandwidth: ServerBandwidth {
                    send_bps: mbps_to_bps(options.up_mbps)?,
                    receive_bps: mbps_to_bps(options.down_mbps)?,
                    ignore_client_bandwidth: options.ignore_client_bandwidth,
                },
            };
            Ok(Arc::new(Hysteria2Inbound {
                tag,
                prepared: Mutex::new(Some(prepared)),
                router: context.router,
                running: Mutex::new(None),
                local_addr: RwLock::new(None),
            }) as Arc<dyn Inbound>)
        },
    )?;
    Ok(())
}

fn mbps_to_bps(mbps: u64) -> Result<u64> {
    mbps.checked_mul(125_000)
        .context("Hysteria2 bandwidth is too large")
}

async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr> {
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .with_context(|| format!("no address found for {host}:{port}"))
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
