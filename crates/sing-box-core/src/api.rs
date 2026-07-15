use std::{fmt, net::SocketAddr};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxStream = Box<dyn ProxyStream>;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Address {
    pub host: String,
    pub port: u16,
}

impl Address {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self> {
        let host = host.into();
        anyhow::ensure!(!host.is_empty(), "address host cannot be empty");
        Ok(Self { host, port })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub network: Network,
    pub source: Option<SocketAddr>,
    pub destination: Address,
    pub inbound: String,
    pub inbound_type: String,
    pub outbound: Option<String>,
    pub user: Option<String>,
}

impl Session {
    pub fn outbound(destination: Address) -> Self {
        Self {
            network: Network::Tcp,
            source: None,
            destination,
            inbound: String::new(),
            inbound_type: String::new(),
            outbound: None,
            user: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StartStage {
    Initialize,
    Start,
    PostStart,
    Started,
}

pub const START_STAGES: [StartStage; 4] = [
    StartStage::Initialize,
    StartStage::Start,
    StartStage::PostStart,
    StartStage::Started,
];

#[async_trait]
pub trait Lifecycle: Send + Sync {
    async fn start(&self, _stage: StartStage) -> Result<()> {
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
pub trait Dialer: Send + Sync {
    async fn connect(&self, session: &Session) -> Result<BoxStream>;
}

#[async_trait]
pub trait Outbound: Lifecycle + Dialer {
    fn kind(&self) -> &'static str;
    fn tag(&self) -> &str;

    fn dependencies(&self) -> Vec<String> {
        Vec::new()
    }
}

#[async_trait]
pub trait Inbound: Lifecycle {
    fn kind(&self) -> &'static str;
    fn tag(&self) -> &str;
    fn local_addr(&self) -> Option<SocketAddr>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDialer;

#[async_trait]
impl Dialer for SystemDialer {
    async fn connect(&self, session: &Session) -> Result<BoxStream> {
        anyhow::ensure!(
            session.network == Network::Tcp,
            "system UDP dialer is not implemented"
        );
        let stream =
            TcpStream::connect((session.destination.host.as_str(), session.destination.port))
                .await?;
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }
}
