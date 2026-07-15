use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use sing_box_core::{
    Address, BoxStream, Dialer, Inbound, InboundBuildContext, Lifecycle, Network, Outbound,
    OutboundBuildContext, OutboundManagerDialer, Registry, Router, Session, StartStage,
    SystemDialer,
};
use sing_snell::{Address as SnellAddress, Client, ClientOptions, Server, ServerOptions, User};
use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnellOutboundOptions {
    server: String,
    server_port: u16,
    psk: String,
    #[serde(default)]
    user_key: String,
    #[serde(default = "default_client_version")]
    version: u8,
    #[serde(default)]
    detour: String,
}

fn default_client_version() -> u8 {
    4
}

struct SnellOutbound {
    tag: String,
    server: Address,
    client: Client,
    dialer: Arc<dyn Dialer>,
    dependencies: Vec<String>,
}

impl Lifecycle for SnellOutbound {}

#[async_trait]
impl Dialer for SnellOutbound {
    async fn connect(&self, session: &Session) -> Result<BoxStream> {
        anyhow::ensure!(
            session.network == Network::Tcp,
            "Snell UDP is not implemented"
        );
        let transport_session = Session::outbound(self.server.clone());
        let transport = self.dialer.connect(&transport_session).await?;
        let destination =
            SnellAddress::new(session.destination.host.clone(), session.destination.port)?;
        let stream = self.client.connect(transport, destination).await?;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl Outbound for SnellOutbound {
    fn kind(&self) -> &'static str {
        "snell"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn dependencies(&self) -> Vec<String> {
        self.dependencies.clone()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnellInboundOptions {
    #[serde(default = "default_listen")]
    listen: String,
    listen_port: u16,
    psk: String,
    #[serde(default = "default_server_version")]
    version: u8,
    #[serde(default)]
    users: Vec<SnellUserOptions>,
}

fn default_listen() -> String {
    "127.0.0.1".to_owned()
}

fn default_server_version() -> u8 {
    5
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnellUserOptions {
    name: String,
    user_key: String,
}

struct Running {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

struct SnellInbound {
    tag: String,
    listen: String,
    listen_port: u16,
    server: Server,
    router: Arc<Router>,
    running: Mutex<Option<Running>>,
    local_addr: RwLock<Option<SocketAddr>>,
}

#[async_trait]
impl Lifecycle for SnellInbound {
    async fn start(&self, stage: StartStage) -> Result<()> {
        if stage != StartStage::Start {
            return Ok(());
        }
        if self.running.lock().await.is_some() {
            return Ok(());
        }
        let listener = TcpListener::bind((self.listen.as_str(), self.listen_port))
            .await
            .context("bind Snell inbound")?;
        let local_addr = listener.local_addr()?;
        *self.local_addr.write().expect("Snell address lock") = Some(local_addr);
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let router = Arc::clone(&self.router);
        let tag = self.tag.clone();
        let server = self.server.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((stream, source)) => {
                            let router = Arc::clone(&router);
                            let server = server.clone();
                            let tag = tag.clone();
                            tokio::spawn(async move {
                                match server.accept(stream).await {
                                    Ok(accepted) => {
                                        let destination = match Address::new(
                                            accepted.destination.host(),
                                            accepted.destination.port(),
                                        ) {
                                            Ok(destination) => destination,
                                            Err(error) => {
                                                tracing::debug!(%source, %error, "invalid Snell destination");
                                                return;
                                            }
                                        };
                                        let session = Session {
                                            network: Network::Tcp,
                                            source: Some(source),
                                            destination,
                                            inbound: tag,
                                            inbound_type: "snell".to_owned(),
                                            outbound: None,
                                            user: accepted.user,
                                        };
                                        if let Err(error) = router.route(session, Box::new(accepted.stream)).await {
                                            tracing::debug!(%source, %error, "Snell connection closed");
                                        }
                                    }
                                    Err(error) => tracing::debug!(%source, %error, "Snell handshake failed"),
                                }
                            });
                        }
                        Err(error) => {
                            tracing::error!(%error, "Snell accept failed");
                            break;
                        }
                    }
                }
            }
        });
        *self.running.lock().await = Some(Running { cancel, task });
        tracing::info!(tag = %self.tag, %local_addr, "started Snell inbound");
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        if let Some(running) = self.running.lock().await.take() {
            running.cancel.cancel();
            running.task.await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Inbound for SnellInbound {
    fn kind(&self) -> &'static str {
        "snell"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.read().expect("Snell address lock")
    }
}

pub fn register(registry: &mut Registry) -> Result<()> {
    registry.register_outbound::<SnellOutboundOptions, _, _>(
        "snell",
        |context: OutboundBuildContext, tag, options| async move {
            anyhow::ensure!(
                options.version == 4,
                "sing-snell-rs currently supports Snell v4 outbound, got v{}",
                options.version
            );
            let server = Address::new(options.server, options.server_port)?;
            let client = Client::new(ClientOptions {
                psk: options.psk.into_bytes(),
                user_key: options.user_key.into_bytes(),
            })?;
            let (dialer, dependencies): (Arc<dyn Dialer>, Vec<String>) =
                if options.detour.is_empty() {
                    (Arc::new(SystemDialer), Vec::new())
                } else {
                    (
                        Arc::new(OutboundManagerDialer::new(
                            context.outbounds,
                            options.detour.clone(),
                        )),
                        vec![options.detour],
                    )
                };
            Ok(Arc::new(SnellOutbound {
                tag,
                server,
                client,
                dialer,
                dependencies,
            }) as Arc<dyn Outbound>)
        },
    )?;

    registry.register_inbound::<SnellInboundOptions, _, _>(
        "snell",
        |context: InboundBuildContext, tag, options| async move {
            anyhow::ensure!(
                options.version == 5,
                "sing-snell-rs currently supports Snell v5 inbound, got v{}",
                options.version
            );
            let users = options
                .users
                .into_iter()
                .map(|user| User {
                    name: user.name,
                    key: user.user_key.into_bytes(),
                })
                .collect();
            let server = Server::new(ServerOptions {
                psk: options.psk.into_bytes(),
                users,
            })?;
            Ok(Arc::new(SnellInbound {
                tag,
                listen: options.listen,
                listen_port: options.listen_port,
                server,
                router: context.router,
                running: Mutex::new(None),
                local_addr: RwLock::new(None),
            }) as Arc<dyn Inbound>)
        },
    )?;
    Ok(())
}
