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
    OutboundBuildContext, Registry, Router, Session, StartStage,
};
use sing_quic::hysteria2::{Client, ClientOptions, Server, ServerOptions, User as Hysteria2User};
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hysteria2OutboundOptions {
    server: String,
    server_port: u16,
    password: String,
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
    listen_port: u16,
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
    listen: SocketAddr,
    certificate_chain: Vec<Vec<u8>>,
    private_key: Vec<u8>,
    users: Vec<Hysteria2User>,
}

struct Running {
    cancel: CancellationToken,
    task: JoinHandle<()>,
    server: Arc<Server>,
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
        let server = Arc::new(Server::bind(ServerOptions {
            listen: prepared.listen,
            certificate_chain: prepared.certificate_chain,
            private_key: prepared.private_key,
            users: prepared.users,
        })?);
        let local_addr = server.local_addr()?;
        *self.local_addr.write().expect("Hysteria2 address lock") = Some(local_addr);
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task_server = Arc::clone(&server);
        let router = Arc::clone(&self.router);
        let tag = self.tag.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    accepted = task_server.accept() => match accepted {
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
        });
        *self.running.lock().await = Some(Running {
            cancel,
            task,
            server,
        });
        tracing::info!(tag = %self.tag, %local_addr, "started Hysteria2 inbound");
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        if let Some(running) = self.running.lock().await.take() {
            running.cancel.cancel();
            running.task.await?;
            running.server.close().await;
        }
        Ok(())
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
            let client = Client::new(ClientOptions {
                server,
                server_name: options.tls.server_name,
                password: options.password,
                ca_certificates: certificates,
            })?;
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
            let listen: SocketAddr = format!("{}:{}", options.listen, options.listen_port)
                .parse()
                .context("parse Hysteria2 listen address")?;
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
