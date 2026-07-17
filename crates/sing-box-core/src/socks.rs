use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::Mutex,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    Address, Inbound, InboundBuildContext, Lifecycle, Network, Packet, PacketConnection, Registry,
    Router, Session, StartStage, bind_tcp_listeners,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SocksOptions {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default)]
    listen_port: u16,
}

fn default_listen() -> String {
    "127.0.0.1".to_owned()
}

struct Running {
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
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
        let listeners = bind_tcp_listeners(&self.options.listen, self.options.listen_port)
            .await
            .context("bind SOCKS inbound")?;
        let local_addr = listeners[0].local_addr()?;
        *self.local_addr.write().expect("SOCKS address lock") = Some(local_addr);
        let cancel = CancellationToken::new();
        let mut tasks = Vec::with_capacity(listeners.len());
        for listener in listeners {
            let task_cancel = cancel.clone();
            let router = Arc::clone(&self.router);
            let tag = self.tag.clone();
            tasks.push(tokio::spawn(async move {
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
            }));
        }
        *self.running.lock().await = Some(Running { cancel, tasks });
        tracing::info!(tag = %self.tag, %local_addr, "started SOCKS inbound");
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        if let Some(running) = self.running.lock().await.take() {
            running.cancel.cancel();
            for task in running.tasks {
                task.await?;
            }
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
    anyhow::ensure!(request[0] == 5 && request[2] == 0, "invalid SOCKS5 request");
    let destination = read_address(&mut stream, request[3]).await?;

    match request[1] {
        1 => handle_connect(stream, source, tag, router, destination).await,
        3 => handle_udp_associate(stream, source, tag, router, destination).await,
        command => {
            let _ = write_reply(&mut stream, 7, unspecified_address(source)).await;
            anyhow::bail!("unsupported SOCKS5 command {command}")
        }
    }
}

async fn read_address(stream: &mut TcpStream, address_type: u8) -> Result<Address> {
    let host = match address_type {
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
        other => anyhow::bail!("unsupported SOCKS address type {other}"),
    };
    let port = stream.read_u16().await?;
    Address::new(host, port)
}

async fn handle_connect(
    mut stream: TcpStream,
    source: SocketAddr,
    tag: String,
    router: Arc<Router>,
    destination: Address,
) -> Result<()> {
    let mut session = Session::inbound(Network::Tcp, source, destination, tag, "socks", None);

    match router.connect(&mut session).await {
        Ok(outbound) => {
            write_reply(&mut stream, 0, unspecified_address(source)).await?;
            router.relay(session, Box::new(stream), outbound).await
        }
        Err(error) => {
            let _ = stream.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            Err(error)
        }
    }
}

async fn handle_udp_associate(
    mut stream: TcpStream,
    source: SocketAddr,
    tag: String,
    router: Arc<Router>,
    destination: Address,
) -> Result<()> {
    let local_ip = stream.local_addr()?.ip();
    let socket = Arc::new(UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?);
    write_reply(&mut stream, 0, socket.local_addr()?).await?;
    let connection = Arc::new(SocksPacketConnection {
        socket,
        control_source_ip: source.ip(),
        peer: Mutex::new(None),
    });
    let session = Session::inbound(Network::Udp, source, destination, tag, "socks", None);

    tokio::select! {
        result = router.route_packet(session, connection) => result,
        result = async {
            let mut sink = tokio::io::sink();
            tokio::io::copy(&mut stream, &mut sink).await?;
            Ok::<(), anyhow::Error>(())
        } => result,
    }
}

struct SocksPacketConnection {
    socket: Arc<UdpSocket>,
    control_source_ip: IpAddr,
    peer: Mutex<Option<SocketAddr>>,
}

#[async_trait]
impl PacketConnection for SocksPacketConnection {
    async fn send(&self, packet: Packet) -> Result<()> {
        let peer = self
            .peer
            .lock()
            .await
            .ok_or_else(|| anyhow::anyhow!("SOCKS UDP client address is not known"))?;
        let mut output = vec![0, 0, 0];
        encode_address(&packet.destination, &mut output)?;
        output.extend_from_slice(&packet.data);
        self.socket.send_to(&output, peer).await?;
        Ok(())
    }

    async fn recv(&self) -> Result<Packet> {
        let mut buffer = vec![0u8; u16::MAX as usize];
        loop {
            let (length, source) = self.socket.recv_from(&mut buffer).await?;
            if source.ip() != self.control_source_ip {
                continue;
            }
            let current_peer = *self.peer.lock().await;
            if current_peer.is_some_and(|peer| peer != source) {
                continue;
            }
            anyhow::ensure!(length >= 4, "truncated SOCKS UDP datagram");
            anyhow::ensure!(buffer[0..2] == [0, 0], "invalid SOCKS UDP reserved bytes");
            anyhow::ensure!(buffer[2] == 0, "fragmented SOCKS UDP is not supported");
            let (destination, consumed) = decode_address(&buffer[3..length])?;
            *self.peer.lock().await = Some(source);
            return Ok(Packet {
                data: buffer[3 + consumed..length].to_vec(),
                destination,
            });
        }
    }
}

async fn write_reply(stream: &mut TcpStream, status: u8, bound: SocketAddr) -> Result<()> {
    let mut reply = vec![5, status, 0];
    encode_address(
        &Address::new(bound.ip().to_string(), bound.port())?,
        &mut reply,
    )?;
    stream.write_all(&reply).await?;
    Ok(())
}

fn encode_address(address: &Address, output: &mut Vec<u8>) -> Result<()> {
    match address.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            output.push(4);
            output.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            anyhow::ensure!(
                address.host.len() <= u8::MAX as usize,
                "SOCKS host is too long"
            );
            output.push(3);
            output.push(address.host.len() as u8);
            output.extend_from_slice(address.host.as_bytes());
        }
    }
    output.extend_from_slice(&address.port.to_be_bytes());
    Ok(())
}

fn decode_address(input: &[u8]) -> Result<(Address, usize)> {
    anyhow::ensure!(!input.is_empty(), "missing SOCKS UDP address");
    let (host, address_len) = match input[0] {
        1 => {
            anyhow::ensure!(input.len() >= 7, "truncated SOCKS IPv4 address");
            (
                IpAddr::from([input[1], input[2], input[3], input[4]]).to_string(),
                5,
            )
        }
        4 => {
            anyhow::ensure!(input.len() >= 19, "truncated SOCKS IPv6 address");
            let bytes: [u8; 16] = input[1..17].try_into().expect("IPv6 length checked");
            (IpAddr::from(bytes).to_string(), 17)
        }
        3 => {
            anyhow::ensure!(input.len() >= 2, "truncated SOCKS domain length");
            let length = input[1] as usize;
            anyhow::ensure!(input.len() >= 2 + length + 2, "truncated SOCKS domain");
            (
                String::from_utf8(input[2..2 + length].to_vec())
                    .context("SOCKS domain is not UTF-8")?,
                2 + length,
            )
        }
        other => anyhow::bail!("unsupported SOCKS address type {other}"),
    };
    anyhow::ensure!(input.len() >= address_len + 2, "missing SOCKS port");
    let port = u16::from_be_bytes([input[address_len], input[address_len + 1]]);
    Ok((Address::new(host, port)?, address_len + 2))
}

fn unspecified_address(source: SocketAddr) -> SocketAddr {
    match source {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
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
