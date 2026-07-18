use std::{
    io::Cursor,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use sing_box_core::{
    Address, BoxStream, Certificate, Dialer, Inbound, InboundBuildContext, Lifecycle, Network,
    Outbound, OutboundBuildContext, Registry, Router, Session, StartStage, listen_addresses,
};
use sing_quic::shadowquic::{Client, ClientOptions, Server, ServerOptions, User as ShadowQuicUser};
use tokio::{sync::Mutex, sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowQuicOutboundOptions {
    server: String,
    server_port: u16,
    username: String,
    password: String,
    tls: OutboundTlsOptions,
    #[serde(default = "default_zero_rtt")]
    zero_rtt: bool,
}

fn default_zero_rtt() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutboundTlsOptions {
    server_name: String,
    certificate_path: String,
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
    tls: InboundTlsOptions,
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
struct InboundTlsOptions {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    alpn: Vec<String>,
    #[serde(default)]
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

enum CertificateSource {
    Static(Arc<Certificate>),
    Provider(watch::Receiver<Option<Arc<Certificate>>>),
}

struct PreparedServer {
    listen: Vec<SocketAddr>,
    certificate: CertificateSource,
    protocol: ServerProtocolOptions,
}

#[derive(Clone)]
struct ServerProtocolOptions {
    users: Vec<ShadowQuicUser>,
    server_name: Option<String>,
    jls_upstream_addr: Option<String>,
    jls_rate_limit: u64,
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
        let PreparedServer {
            listen,
            certificate,
            protocol,
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
                certificate_chain: certificate.certificate_chain.clone(),
                private_key: certificate.private_key.clone(),
                users: protocol.users.clone(),
                server_name: protocol.server_name.clone(),
                jls_upstream_addr: protocol.jls_upstream_addr.clone(),
                jls_rate_limit: protocol.jls_rate_limit,
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
        if let Some(receiver) = certificate_updates {
            let running = self.running.lock().await;
            let servers = running
                .as_ref()
                .map(|running| running.servers.clone())
                .unwrap_or_default();
            let cancel = running
                .as_ref()
                .map(|running| running.cancel.clone())
                .expect("running state");
            drop(running);
            tokio::spawn(watch_certificate_updates(
                servers,
                receiver,
                cancel,
                protocol,
                self.tag.clone(),
            ));
        }
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

async fn watch_certificate_updates(
    servers: Vec<Arc<Server>>,
    mut receiver: watch::Receiver<Option<Arc<Certificate>>>,
    cancel: CancellationToken,
    protocol: ServerProtocolOptions,
    tag: String,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            changed = receiver.changed() => if changed.is_err() { return; },
        }
        let Some(certificate) = receiver.borrow_and_update().clone() else {
            continue;
        };
        for server in &servers {
            if let Err(error) = server.update_config(ServerOptions {
                listen: server
                    .local_addr()
                    .expect("bound ShadowQuic server address"),
                certificate_chain: certificate.certificate_chain.clone(),
                private_key: certificate.private_key.clone(),
                users: protocol.users.clone(),
                server_name: protocol.server_name.clone(),
                jls_upstream_addr: protocol.jls_upstream_addr.clone(),
                jls_rate_limit: protocol.jls_rate_limit,
                zero_rtt: protocol.zero_rtt,
            }) {
                tracing::warn!(inbound = %tag, %error, "failed to apply ShadowQuic certificate update");
            }
        }
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
            let certificate_data = tokio::fs::read(&options.tls.certificate_path)
                .await
                .with_context(|| format!("read {}", options.tls.certificate_path))?;
            let client = Client::new(ClientOptions {
                server,
                server_name: options.tls.server_name,
                username: options.username,
                password: options.password,
                ca_certificates: parse_certificates(&certificate_data)?,
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
            anyhow::ensure!(
                options.tls.alpn.is_empty()
                    || options.tls.alpn.iter().any(|protocol| protocol == "h3"),
                "ShadowQuic TLS ALPN must include h3"
            );
            let _ = options.tls.enabled;
            let certificate = if options.tls.certificate_provider.is_empty() {
                anyhow::ensure!(
                    !options.tls.certificate_path.is_empty() && !options.tls.key_path.is_empty(),
                    "ShadowQuic TLS requires certificate_provider or certificate_path/key_path"
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
                .map(|user| ShadowQuicUser {
                    name: user.name,
                    password: user.password,
                })
                .collect();
            let server_name = if !options.server_name.is_empty() {
                Some(options.server_name)
            } else if !options.tls.server_name.is_empty() {
                Some(options.tls.server_name)
            } else {
                None
            };
            let (jls_upstream_addr, jls_rate_limit) = options
                .jls_upstream
                .map(|upstream| (Some(upstream.addr), upstream.rate_limit))
                .unwrap_or((None, u64::MAX));
            Ok(Arc::new(ShadowQuicInbound {
                tag,
                prepared: Mutex::new(Some(PreparedServer {
                    listen,
                    certificate,
                    protocol: ServerProtocolOptions {
                        users,
                        server_name,
                        jls_upstream_addr,
                        jls_rate_limit,
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
