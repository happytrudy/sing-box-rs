use std::{net::IpAddr, sync::Arc};

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use tokio::net::UdpSocket;

use crate::{
    Address, BoxPacketConnection, BoxStream, Dialer, Lifecycle, Outbound, OutboundBuildContext,
    Packet, PacketConnection, Registry, Session, SystemDialer,
    buffer::{PacketBufferPool, shared_packet_buffer_pool},
};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectOptions {}

struct DirectOutbound {
    tag: String,
    dialer: SystemDialer,
}

impl Lifecycle for DirectOutbound {}

#[async_trait]
impl Dialer for DirectOutbound {
    async fn connect(&self, session: &Session) -> Result<BoxStream> {
        self.dialer.connect(session).await
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
        Ok(Arc::new(DirectPacketConnection {
            ipv4,
            ipv6,
            buffer_pool: shared_packet_buffer_pool(),
            dialer: self.dialer.clone(),
        }))
    }
}

struct DirectPacketConnection {
    ipv4: UdpSocket,
    ipv6: Option<UdpSocket>,
    buffer_pool: PacketBufferPool,
    dialer: SystemDialer,
}

#[async_trait]
impl PacketConnection for DirectPacketConnection {
    async fn send(&self, packet: Packet) -> Result<()> {
        let addresses = self
            .dialer
            .resolve(&packet.destination.host, packet.destination.port)
            .await?;
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
        let (buffer, length, source) = if let Some(ipv6) = &self.ipv6 {
            let mut ipv4_buffer = self.buffer_pool.acquire();
            let mut ipv6_buffer = self.buffer_pool.acquire();
            tokio::select! {
                result = self.ipv4.recv_from(ipv4_buffer.as_mut_slice()) => {
                    let (length, source) = result?;
                    (ipv4_buffer, length, source)
                }
                result = ipv6.recv_from(ipv6_buffer.as_mut_slice()) => {
                    let (length, source) = result?;
                    (ipv6_buffer, length, source)
                }
            }
        } else {
            let mut buffer = self.buffer_pool.acquire();
            let (length, source) = self.ipv4.recv_from(buffer.as_mut_slice()).await?;
            (buffer, length, source)
        };
        let source_ip = match source.ip() {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(ip)),
            ip => ip,
        };
        let destination = Address::new(source_ip.to_string(), source.port())?;
        Ok(Packet::from_pool(
            buffer.into_vec(),
            length,
            destination,
            self.buffer_pool.clone(),
        ))
    }
}

pub(crate) fn register(registry: &mut Registry) -> Result<()> {
    registry.register_outbound::<DirectOptions, _, _>(
        "direct",
        |context: OutboundBuildContext, tag, _options| async move {
            Ok(Arc::new(DirectOutbound {
                tag,
                dialer: context.system_dialer,
            }) as Arc<dyn Outbound>)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DomainStrategy;

    #[tokio::test]
    async fn recv_returns_the_buffer_to_the_shared_pool() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = socket.local_addr().unwrap();
        let buffer_pool = PacketBufferPool::new();
        let connection = DirectPacketConnection {
            ipv4: socket,
            ipv6: None,
            buffer_pool: buffer_pool.clone(),
            dialer: SystemDialer::new(None, None, DomainStrategy::AsIs),
        };

        peer.send_to(b"packet", destination).await.unwrap();
        let packet = connection.recv().await.unwrap();
        assert_eq!(packet.data, b"packet");
        let first_allocation = packet.data.as_ptr();
        assert_eq!(buffer_pool.available(), 0);
        drop(packet);
        assert_eq!(buffer_pool.available(), 1);

        let second_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_destination = second_socket.local_addr().unwrap();
        let second_connection = DirectPacketConnection {
            ipv4: second_socket,
            ipv6: None,
            buffer_pool: buffer_pool.clone(),
            dialer: SystemDialer::new(None, None, DomainStrategy::AsIs),
        };
        peer.send_to(b"second", second_destination).await.unwrap();
        let second_packet = second_connection.recv().await.unwrap();
        assert_eq!(second_packet.data, b"second");
        assert_eq!(second_packet.data.as_ptr(), first_allocation);
    }
}
