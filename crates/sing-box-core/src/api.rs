use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, lookup_host},
    sync::watch,
};

use crate::{DomainStrategy, buffer::PacketBufferPool};

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxStream = Box<dyn ProxyStream>;

pub struct Packet {
    pub data: Vec<u8>,
    pub destination: Address,
    recycle_pool: Option<PacketBufferPool>,
}

impl Packet {
    pub fn new(data: Vec<u8>, destination: Address) -> Self {
        Self {
            data,
            destination,
            recycle_pool: None,
        }
    }

    pub(crate) fn from_pool(
        mut data: Vec<u8>,
        length: usize,
        destination: Address,
        recycle_pool: PacketBufferPool,
    ) -> Self {
        data.truncate(length);
        Self {
            data,
            destination,
            recycle_pool: Some(recycle_pool),
        }
    }

    pub fn take_data(&mut self) -> Vec<u8> {
        self.recycle_pool = None;
        std::mem::take(&mut self.data)
    }
}

impl Clone for Packet {
    fn clone(&self) -> Self {
        Self::new(self.data.clone(), self.destination.clone())
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("data", &self.data)
            .field("destination", &self.destination)
            .finish()
    }
}

impl PartialEq for Packet {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.destination == other.destination
    }
}

impl Eq for Packet {}

impl Drop for Packet {
    fn drop(&mut self) {
        if let Some(pool) = self.recycle_pool.take() {
            pool.recycle(std::mem::take(&mut self.data));
        }
    }
}

#[async_trait]
pub trait PacketConnection: Send + Sync {
    async fn send(&self, packet: Packet) -> Result<()>;
    async fn recv(&self) -> Result<Packet>;
}

pub type BoxPacketConnection = Arc<dyn PacketConnection>;

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

pub fn normalize_socket_addr(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(address) => address
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), address.port()))
            .unwrap_or(SocketAddr::V6(address)),
        address => address,
    }
}

impl Session {
    /// Creates the routing context reported by an inbound protocol.
    ///
    /// Inbounds must pass the transport peer unchanged. Address-family
    /// normalization and all source-based policy decisions belong to Router.
    pub fn inbound(
        network: Network,
        source: SocketAddr,
        destination: Address,
        inbound: impl Into<String>,
        inbound_type: impl Into<String>,
        user: Option<String>,
    ) -> Self {
        Self {
            network,
            source: Some(source),
            destination,
            inbound: inbound.into(),
            inbound_type: inbound_type.into(),
            outbound: None,
            user,
        }
    }

    pub fn source_ip(&self) -> Option<IpAddr> {
        self.source
            .map(normalize_socket_addr)
            .map(|source| source.ip())
    }

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

    async fn connect_packet(&self, _session: &Session) -> Result<BoxPacketConnection> {
        anyhow::bail!("outbound {} does not support UDP", self.tag())
    }
}

#[async_trait]
pub trait Inbound: Lifecycle {
    fn kind(&self) -> &'static str;
    fn tag(&self) -> &str;
    fn local_addr(&self) -> Option<SocketAddr>;
}

pub struct Certificate {
    pub certificate_chain: Vec<Vec<u8>>,
    pub private_key: Vec<u8>,
}

impl Certificate {
    pub fn new(certificate_chain: Vec<Vec<u8>>, private_key: Vec<u8>) -> Result<Self> {
        anyhow::ensure!(!certificate_chain.is_empty(), "certificate chain is empty");
        anyhow::ensure!(!private_key.is_empty(), "certificate private key is empty");
        Ok(Self {
            certificate_chain,
            private_key,
        })
    }
}

pub trait CertificateProvider: Lifecycle {
    fn kind(&self) -> &'static str;
    fn tag(&self) -> &str;

    fn subscribe(&self, server_name: &str) -> Result<watch::Receiver<Option<Arc<Certificate>>>>;
}

#[async_trait]
pub trait DomainResolver: Send + Sync {
    async fn lookup(
        &self,
        server: Option<&str>,
        host: &str,
        strategy: DomainStrategy,
    ) -> Result<Vec<IpAddr>>;

    fn contains_server(&self, tag: &str) -> bool;
}

#[derive(Clone, Default)]
pub struct SystemDialer {
    resolver: Option<Arc<dyn DomainResolver>>,
    resolver_server: Option<String>,
    strategy: DomainStrategy,
}

impl SystemDialer {
    pub fn new(
        resolver: Option<Arc<dyn DomainResolver>>,
        resolver_server: Option<String>,
        strategy: DomainStrategy,
    ) -> Self {
        Self {
            resolver,
            resolver_server,
            strategy,
        }
    }

    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        if let Some(resolver) = &self.resolver {
            return Ok(resolver
                .lookup(self.resolver_server.as_deref(), host, self.strategy)
                .await?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect());
        }
        Ok(lookup_host((host, port)).await?.collect())
    }
}

#[async_trait]
impl Dialer for SystemDialer {
    async fn connect(&self, session: &Session) -> Result<BoxStream> {
        anyhow::ensure!(
            session.network == Network::Tcp,
            "system UDP dialer is not implemented"
        );
        let addresses = self
            .resolve(&session.destination.host, session.destination.port)
            .await?;
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    return Ok(Box::new(stream));
                }
                Err(error) => last_error = Some(error),
            }
        }
        match last_error {
            Some(error) => Err(error.into()),
            None => anyhow::bail!("destination did not resolve: {}", session.destination),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestResolver;

    #[async_trait]
    impl DomainResolver for TestResolver {
        async fn lookup(
            &self,
            server: Option<&str>,
            host: &str,
            strategy: DomainStrategy,
        ) -> Result<Vec<IpAddr>> {
            assert_eq!(server, Some("test"));
            assert_eq!(host, "resolver.test");
            assert_eq!(strategy, DomainStrategy::Ipv4Only);
            Ok(vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)])
        }

        fn contains_server(&self, tag: &str) -> bool {
            tag == "test"
        }
    }

    #[tokio::test]
    async fn system_dialer_uses_injected_resolver() {
        let dialer = SystemDialer::new(
            Some(Arc::new(TestResolver)),
            Some("test".into()),
            DomainStrategy::Ipv4Only,
        );
        assert_eq!(
            dialer.resolve("resolver.test", 443).await.unwrap(),
            ["127.0.0.1:443".parse().unwrap()]
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let session = Session::outbound(
            Address::new("resolver.test", listener.local_addr().unwrap().port()).unwrap(),
        );
        let (connected, accepted) = tokio::join!(dialer.connect(&session), listener.accept());
        connected.unwrap();
        accepted.unwrap();
    }

    #[test]
    fn normalizes_ipv4_mapped_socket_address() {
        assert_eq!(
            normalize_socket_addr("[::ffff:192.0.2.1]:443".parse().unwrap()),
            "192.0.2.1:443".parse().unwrap()
        );
    }
}
