mod api;
mod block;
mod certificate;
mod config;
mod direct;
mod engine;
mod json;
mod listen;
mod manager;
mod ntp;
mod registry;
mod router;
mod socks;
mod srs;
mod tasks;

pub use api::{
    Address, BoxPacketConnection, BoxStream, Certificate, CertificateProvider, Dialer,
    DomainResolver, Inbound, Lifecycle, Network, Outbound, Packet, PacketConnection, ProxyStream,
    START_STAGES, Session, StartStage, SystemDialer, normalize_socket_addr,
};
pub use certificate::CertificateProviderManager;
pub use config::{
    Config, DnsConfig, DomainStrategy, LogConfig, NtpConfig, RawComponent, RouteConfig,
};
pub use engine::Engine;
pub use json::{parse_extended_json, strip_json_comments};
pub use listen::{bind_tcp_listeners, listen_addresses};
pub use manager::{InboundManager, OutboundManager, OutboundManagerDialer};
pub use registry::{
    CertificateProviderBuildContext, InboundBuildContext, OutboundBuildContext, Registry,
};
pub use router::{Router, RuleSetFetchResult, RuleSetFetcher};
pub use tasks::ConnectionTasks;

pub fn register_builtins(registry: &mut Registry) -> anyhow::Result<()> {
    block::register(registry)?;
    direct::register(registry)?;
    socks::register(registry)?;
    Ok(())
}
