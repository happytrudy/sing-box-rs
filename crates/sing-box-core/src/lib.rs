mod api;
mod config;
mod direct;
mod engine;
mod listen;
mod manager;
mod registry;
mod router;
mod socks;

pub use api::{
    Address, BoxPacketConnection, BoxStream, Dialer, Inbound, Lifecycle, Network, Outbound, Packet,
    PacketConnection, ProxyStream, START_STAGES, Session, StartStage, SystemDialer,
};
pub use config::{Config, RawComponent, RouteConfig};
pub use engine::Engine;
pub use listen::{bind_tcp_listeners, listen_addresses};
pub use manager::{InboundManager, OutboundManager, OutboundManagerDialer};
pub use registry::{InboundBuildContext, OutboundBuildContext, Registry};
pub use router::Router;

pub fn register_builtins(registry: &mut Registry) -> anyhow::Result<()> {
    direct::register(registry)?;
    socks::register(registry)?;
    Ok(())
}
