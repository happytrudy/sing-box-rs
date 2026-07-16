use std::{net::IpAddr, sync::Arc};

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use tokio::net::{UdpSocket, lookup_host};

use crate::{
    Address, BoxPacketConnection, BoxStream, Dialer, Lifecycle, Outbound, OutboundBuildContext,
    Packet, PacketConnection, Registry, Session, SystemDialer,
};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectOptions {}

struct DirectOutbound {
    tag: String,
}

impl Lifecycle for DirectOutbound {}

#[async_trait]
impl Dialer for DirectOutbound {
    async fn connect(&self, session: &Session) -> Result<BoxStream> {
        SystemDialer.connect(session).await
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn kind(&self) -> &'static str {
        "direct"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect_packet(&self, _session: &Session) -> Result<BoxPacketConnection> {
        let ipv4 = UdpSocket::bind("0.0.0.0:0").await?;
        let ipv6 = UdpSocket::bind("[::]:0").await.ok();
        Ok(Arc::new(DirectPacketConnection { ipv4, ipv6 }))
    }
}

struct DirectPacketConnection {
    ipv4: UdpSocket,
    ipv6: Option<UdpSocket>,
}

#[async_trait]
impl PacketConnection for DirectPacketConnection {
    async fn send(&self, packet: Packet) -> Result<()> {
        let addresses =
            lookup_host((packet.destination.host.as_str(), packet.destination.port)).await?;
        let mut last_error = None;
        for destination in addresses {
            let socket = match destination {
                std::net::SocketAddr::V4(_) => &self.ipv4,
                std::net::SocketAddr::V6(_) => {
                    let Some(socket) = &self.ipv6 else {
                        continue;
                    };
                    socket
                }
            };
            match socket.send_to(&packet.data, destination).await {
                Ok(_) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }
        match last_error {
            Some(error) => Err(error.into()),
            None => anyhow::bail!("destination did not resolve: {}", packet.destination),
        }
    }

    async fn recv(&self) -> Result<Packet> {
        let (mut buffer, length, source) = if let Some(ipv6) = &self.ipv6 {
            let mut ipv4_buffer = vec![0u8; u16::MAX as usize];
            let mut ipv6_buffer = vec![0u8; u16::MAX as usize];
            tokio::select! {
                result = self.ipv4.recv_from(&mut ipv4_buffer) => {
                    let (length, source) = result?;
                    (ipv4_buffer, length, source)
                }
                result = ipv6.recv_from(&mut ipv6_buffer) => {
                    let (length, source) = result?;
                    (ipv6_buffer, length, source)
                }
            }
        } else {
            let mut buffer = vec![0u8; u16::MAX as usize];
            let (length, source) = self.ipv4.recv_from(&mut buffer).await?;
            (buffer, length, source)
        };
        buffer.truncate(length);
        let source_ip = match source.ip() {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(ip)),
            ip => ip,
        };
        Ok(Packet {
            data: buffer,
            destination: Address::new(source_ip.to_string(), source.port())?,
        })
    }
}

pub(crate) fn register(registry: &mut Registry) -> Result<()> {
    registry.register_outbound::<DirectOptions, _, _>(
        "direct",
        |_context: OutboundBuildContext, tag, _options| async move {
            Ok(Arc::new(DirectOutbound { tag }) as Arc<dyn Outbound>)
        },
    )
}
