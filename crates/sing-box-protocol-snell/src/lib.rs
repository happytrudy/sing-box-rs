use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use sing_box_core::{
    Address, BoxPacketConnection, BoxStream, ConnectionTasks, Dialer, Inbound, InboundBuildContext,
    Lifecycle, Network, Outbound, OutboundBuildContext, OutboundManagerDialer, Packet,
    PacketConnection, Registry, Router, Session, StartStage, bind_tcp_listeners,
};
use sing_snell::{
    AcceptedSession, Address as SnellAddress, Client, ClientOptions, ObfsMode, ObfsOptions,
    ReuseClientSession, Server, ServerOptions, User, V6Mode,
};
use tokio::{sync::Mutex, task::JoinHandle};
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
    #[serde(default)]
    obfs: String,
    #[serde(default)]
    obfs_host: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    reuse: bool,
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
    reuse: bool,
    reuse_sessions: Mutex<Vec<ReuseClientSession>>,
}

#[async_trait]
impl Lifecycle for SnellOutbound {
    async fn close(&self) -> Result<()> {
        for session in self.reuse_sessions.lock().await.drain(..) {
            session.close().await;
        }
        Ok(())
    }
}

#[async_trait]
impl Dialer for SnellOutbound {
    async fn connect(&self, session: &Session) -> Result<BoxStream> {
        anyhow::ensure!(session.network == Network::Tcp, "expected a TCP session");
        let destination =
            SnellAddress::new(session.destination.host.clone(), session.destination.port)?;
        if self.reuse {
            return self.connect_reuse(destination).await;
        }
        let transport_session = Session::outbound(self.server.clone());
        let transport = self.dialer.connect(&transport_session).await?;
        let stream = self.client.connect(transport, destination).await?;
        Ok(Box::new(stream))
    }
}

impl SnellOutbound {
    async fn connect_reuse(&self, destination: SnellAddress) -> Result<BoxStream> {
        let mut sessions = self.reuse_sessions.lock().await;
        sessions.retain(|session| !session.is_closed());
        if let Some(session) = sessions.iter().find(|session| !session.is_busy()) {
            return session
                .connect(destination)
                .await
                .map(|stream| Box::new(stream) as BoxStream)
                .map_err(Into::into);
        }

        let transport_session = Session::outbound(self.server.clone());
        let transport = self.dialer.connect(&transport_session).await?;
        let session = self.client.reuse_session(transport)?;
        let stream = session.connect(destination).await?;
        sessions.push(session);
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

    async fn connect_packet(&self, session: &Session) -> Result<BoxPacketConnection> {
        anyhow::ensure!(session.network == Network::Udp, "expected a UDP session");
        let transport_session = Session::outbound(self.server.clone());
        let transport = self.dialer.connect(&transport_session).await?;
        let connection = self.client.connect_udp(transport).await?;
        Ok(Arc::new(SnellPacketConnection { inner: connection }))
    }
}

struct SnellPacketConnection {
    inner: sing_snell::PacketConnection,
}

#[async_trait]
impl PacketConnection for SnellPacketConnection {
    async fn send(&self, mut packet: Packet) -> Result<()> {
        let destination =
            SnellAddress::new(packet.destination.host.clone(), packet.destination.port)?;
        self.inner.send(packet.take_data(), destination).await?;
        Ok(())
    }

    async fn recv(&self) -> Result<Packet> {
        let packet = self.inner.recv().await?;
        let destination = Address::new(packet.destination.host(), packet.destination.port())?;
        Ok(Packet::new(packet.data, destination))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnellInboundOptions {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default)]
    listen_port: u16,
    psk: String,
    #[serde(default = "default_server_version")]
    version: u8,
    #[serde(default)]
    users: Vec<SnellUserOptions>,
    #[serde(default)]
    obfs: String,
    #[serde(default)]
    obfs_host: String,
    #[serde(default)]
    mode: String,
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
    tasks: Vec<JoinHandle<()>>,
    connection_tasks: ConnectionTasks,
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
        let listeners = bind_tcp_listeners(&self.listen, self.listen_port)
            .await
            .context("bind Snell inbound")?;
        let local_addr = listeners[0].local_addr()?;
        *self.local_addr.write().expect("Snell address lock") = Some(local_addr);
        let cancel = CancellationToken::new();
        let connection_tasks = ConnectionTasks::new();
        let mut tasks = Vec::with_capacity(listeners.len());
        for listener in listeners {
            let task_cancel = cancel.clone();
            let connection_tasks_for_listener = connection_tasks.clone();
            let router = Arc::clone(&self.router);
            let tag = self.tag.clone();
            let server = self.server.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = task_cancel.cancelled() => break,
                        accepted = listener.accept() => match accepted {
                            Ok((stream, source)) => {
                                let router = Arc::clone(&router);
                                let server = server.clone();
                                let tag = tag.clone();
                                let connection_cancel = task_cancel.clone();
                                connection_tasks_for_listener.spawn(async move {
                                    tokio::select! {
                                        _ = connection_cancel.cancelled() => {}
                                        _ = async {
                                            let mut sessions = server.accept_sessions(stream);
                                            while let Some(accepted) = sessions.recv().await {
                                                match accepted {
                                                    Ok(accepted) => {
                                                        if let Err(error) = route_accepted(
                                                            accepted,
                                                            source,
                                                            tag.clone(),
                                                            Arc::clone(&router),
                                                        )
                                                        .await
                                                        {
                                                            tracing::debug!(%source, %error, "Snell session closed");
                                                        }
                                                    }
                                                    Err(error) => {
                                                        tracing::debug!(%source, %error, "Snell handshake failed");
                                                        break;
                                                    }
                                                }
                                            }
                                        } => {}
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
            }));
        }
        *self.running.lock().await = Some(Running {
            cancel,
            tasks,
            connection_tasks,
        });
        tracing::info!(tag = %self.tag, %local_addr, "started Snell inbound");
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

async fn route_accepted(
    accepted: AcceptedSession,
    source: SocketAddr,
    tag: String,
    router: Arc<Router>,
) -> Result<()> {
    match accepted {
        AcceptedSession::Stream(accepted) => {
            let destination =
                Address::new(accepted.destination.host(), accepted.destination.port())?;
            let session = Session::inbound(
                Network::Tcp,
                source,
                destination,
                tag,
                "snell",
                accepted.user,
            );
            router.route(session, Box::new(accepted.stream)).await
        }
        AcceptedSession::Packet(accepted) => {
            let session = Session::inbound(
                Network::Udp,
                source,
                Address::new("0.0.0.0", 0)?,
                tag,
                "snell",
                accepted.user,
            );
            router
                .route_packet(
                    session,
                    Arc::new(SnellPacketConnection {
                        inner: accepted.connection,
                    }),
                )
                .await
        }
        AcceptedSession::Pong => Ok(()),
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
                options.version == 4 || options.version == 6,
                "Snell outbound version must be 4 or 6, got v{}",
                options.version
            );
            let server = Address::new(options.server, options.server_port)?;
            let obfs = parse_obfs(&options.obfs, options.obfs_host)?;
            let mut client = Client::new(ClientOptions {
                psk: options.psk.into_bytes(),
                user_key: options.user_key.into_bytes(),
            })?
            .with_obfs(obfs);
            if options.version == 6 {
                client = client.with_v6_mode(parse_v6_mode(&options.mode)?)?;
            } else {
                anyhow::ensure!(options.mode.is_empty(), "Snell mode requires version 6");
            }
            let (dialer, dependencies): (Arc<dyn Dialer>, Vec<String>) =
                if options.detour.is_empty() {
                    (Arc::new(context.system_dialer), Vec::new())
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
                reuse: options.reuse,
                reuse_sessions: Mutex::new(Vec::new()),
            }) as Arc<dyn Outbound>)
        },
    )?;

    registry.register_inbound::<SnellInboundOptions, _, _>(
        "snell",
        |context: InboundBuildContext, tag, options| async move {
            anyhow::ensure!(
                options.version == 5 || options.version == 6,
                "Snell inbound version must be 5 or 6, got v{}",
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
            let obfs = parse_obfs(&options.obfs, options.obfs_host)?;
            let mut server = Server::new(ServerOptions {
                psk: options.psk.into_bytes(),
                users,
            })?
            .with_obfs(obfs);
            if options.version == 6 {
                server = server.with_v6_mode(parse_v6_mode(&options.mode)?)?;
            } else {
                anyhow::ensure!(options.mode.is_empty(), "Snell mode requires version 6");
            }
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

fn parse_obfs(mode: &str, host: String) -> Result<ObfsOptions> {
    let mode = match mode {
        "" | "none" => ObfsMode::None,
        "http" => ObfsMode::Http,
        "tls" => ObfsMode::Tls,
        other => anyhow::bail!("unsupported Snell obfs mode: {other}"),
    };
    Ok(ObfsOptions { mode, host })
}

fn parse_v6_mode(mode: &str) -> Result<V6Mode> {
    match mode {
        "" | "default" => Ok(V6Mode::Default),
        "unshaped" => Ok(V6Mode::Unshaped),
        "unsafe-raw" => Ok(V6Mode::UnsafeRaw),
        other => anyhow::bail!("unsupported Snell v6 mode: {other}"),
    }
}
