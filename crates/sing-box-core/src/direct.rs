use std::{net::IpAddr, sync::Arc};

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use tokio::{net::UdpSocket, sync::Mutex};

use crate::{
    Address, BoxPacketConnection, BoxStream, Dialer, Lifecycle, Outbound, OutboundBuildContext,
    Packet, PacketConnection, Registry, Session, SystemDialer,
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
        let has_ipv6 = ipv6.is_some();
        Ok(Arc::new(DirectPacketConnection {
            ipv4,
            ipv6,
            ipv4_buffer: Mutex::new(vec![0u8; u16::MAX as usize]),
            ipv6_buffer: has_ipv6.then(|| Mutex::new(vec![0u8; u16::MAX as usize])),
            dialer: self.dialer.clone(),
        }))
    }
}

struct DirectPacketConnection {
    ipv4: UdpSocket,
    ipv6: Option<UdpSocket>,
    ipv4_buffer: Mutex<Vec<u8>>,
    ipv6_buffer: Option<Mutex<Vec<u8>>>,
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
        let (buffer, source) =
            if let (Some(ipv6), Some(ipv6_buffer)) = (&self.ipv6, &self.ipv6_buffer) {
                let mut ipv4_buffer = self.ipv4_buffer.lock().await;
                let mut ipv6_buffer = ipv6_buffer.lock().await;
                tokio::select! {
                    result = self.ipv4.recv_from(&mut ipv4_buffer) => {
                        let (length, source) = result?;
                        (ipv4_buffer[..length].to_vec(), source)
                    }
                    result = ipv6.recv_from(&mut ipv6_buffer) => {
                        let (length, source) = result?;
                        (ipv6_buffer[..length].to_vec(), source)
                    }
                }
            } else {
                let mut buffer = self.ipv4_buffer.lock().await;
                let (length, source) = self.ipv4.recv_from(&mut buffer).await?;
                (buffer[..length].to_vec(), source)
            };
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
        |context: OutboundBuildContext, tag, _options| async move {
            Ok(Arc::new(DirectOutbound {
                tag,
                dialer: context.system_dialer,
            }) as Arc<dyn Outbound>)
        },
    )
}
