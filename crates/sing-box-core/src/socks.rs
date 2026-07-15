use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    Address, Inbound, InboundBuildContext, Lifecycle, Network, Registry, Router, Session,
    StartStage,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SocksOptions {
    #[serde(default = "default_listen")]
    listen: String,
    listen_port: u16,
}

fn default_listen() -> String {
    "127.0.0.1".to_owned()
}

struct Running {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

struct SocksInbound {
    tag: String,
    options: SocksOptions,
    router: Arc<Router>,
    running: Mutex<Option<Running>>,
    local_addr: RwLock<Option<SocketAddr>>,
}

#[async_trait]
impl Lifecycle for SocksInbound {
    async fn start(&self, stage: StartStage) -> Result<()> {
        if stage != StartStage::Start {
            return Ok(());
        }
        if self.running.lock().await.is_some() {
            return Ok(());
        }
        let listener = TcpListener::bind((self.options.listen.as_str(), self.options.listen_port))
            .await
            .context("bind SOCKS inbound")?;
        let local_addr = listener.local_addr()?;
        *self.local_addr.write().expect("SOCKS address lock") = Some(local_addr);
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let router = Arc::clone(&self.router);
        let tag = self.tag.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((stream, source)) => {
                            let router = Arc::clone(&router);
                            let tag = tag.clone();
                            tokio::spawn(async move {
                                if let Err(error) = handle_connection(stream, source, tag, router).await {
                                    tracing::debug!(%source, %error, "SOCKS connection closed");
                                }
                            });
                        }
                        Err(error) => {
                            tracing::error!(%error, "SOCKS accept failed");
                            break;
                        }
                    }
                }
            }
        });
        *self.running.lock().await = Some(Running { cancel, task });
        tracing::info!(tag = %self.tag, %local_addr, "started SOCKS inbound");
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
impl Inbound for SocksInbound {
    fn kind(&self) -> &'static str {
        "socks"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.read().expect("SOCKS address lock")
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    source: SocketAddr,
    tag: String,
    router: Arc<Router>,
) -> Result<()> {
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    anyhow::ensure!(greeting[0] == 5, "unsupported SOCKS version");
    let mut methods = vec![0u8; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;
    anyhow::ensure!(
        methods.contains(&0),
        "SOCKS client did not offer no-auth method"
    );
    stream.write_all(&[5, 0]).await?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    anyhow::ensure!(
        request[0] == 5 && request[1] == 1,
        "only SOCKS5 CONNECT is supported"
    );
    let host = match request[3] {
        1 => {
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).await?;
            IpAddr::from(bytes).to_string()
        }
        3 => {
            let length = stream.read_u8().await? as usize;
            let mut bytes = vec![0u8; length];
            stream.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).context("SOCKS domain is not UTF-8")?
        }
        4 => {
            let mut bytes = [0u8; 16];
            stream.read_exact(&mut bytes).await?;
            IpAddr::from(bytes).to_string()
        }
        address_type => anyhow::bail!("unsupported SOCKS address type {address_type}"),
    };
    let port = stream.read_u16().await?;
    let mut session = Session {
        network: Network::Tcp,
        source: Some(source),
        destination: Address::new(host, port)?,
        inbound: tag,
        inbound_type: "socks".to_owned(),
        outbound: None,
        user: None,
    };

    match router.connect(&mut session).await {
        Ok(outbound) => {
            let bound = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            let mut reply = vec![5, 0, 0, 1];
            if let IpAddr::V4(address) = bound.ip() {
                reply.extend_from_slice(&address.octets());
            }
            reply.extend_from_slice(&bound.port().to_be_bytes());
            stream.write_all(&reply).await?;
            router.relay(session, Box::new(stream), outbound).await
        }
        Err(error) => {
            let _ = stream.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            Err(error)
        }
    }
}

pub(crate) fn register(registry: &mut Registry) -> Result<()> {
    registry.register_inbound::<SocksOptions, _, _>(
        "socks",
        |context: InboundBuildContext, tag, options| async move {
            Ok(Arc::new(SocksInbound {
                tag,
                options,
                router: context.router,
                running: Mutex::new(None),
                local_addr: RwLock::new(None),
            }) as Arc<dyn Inbound>)
        },
    )
}
