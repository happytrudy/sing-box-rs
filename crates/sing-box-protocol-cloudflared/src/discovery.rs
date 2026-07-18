use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket, lookup_host},
    time::timeout,
};
use tokio_rustls::TlsConnector;

use crate::Credentials;

const EDGE_SRV_SERVICE: &str = "v2-origintunneld";
const EDGE_SRV_DOMAIN: &str = "argotunnel.com";
const DOT_SERVER_NAME: &str = "cloudflare-dns.com";
const DOT_SERVER_ADDRESS: &str = "1.1.1.1:853";
const DNS_TIMEOUT: Duration = Duration::from_secs(15);
const DNS_TYPE_SRV: u16 = 33;
static NEXT_DNS_ID: AtomicU16 = AtomicU16::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeAddr {
    pub address: SocketAddr,
    pub ip_version: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SrvRecord {
    priority: u16,
    weight: u16,
    port: u16,
    target: String,
}

/// Discovers Cloudflare Tunnel edge addresses using SRV and DoT fallback.
pub async fn discover_edges(
    credentials: &Credentials,
    region: &str,
    edge_ip_version: u8,
) -> Result<Vec<EdgeAddr>> {
    let effective_region = if credentials.endpoint.is_empty() {
        region
    } else {
        &credentials.endpoint
    };
    let service = if effective_region.is_empty() {
        EDGE_SRV_SERVICE.to_owned()
    } else {
        format!("{effective_region}-{EDGE_SRV_SERVICE}")
    };
    let name = format!("_{service}._tcp.{EDGE_SRV_DOMAIN}");
    let records = match lookup_srv_system(&name).await {
        Ok(records) if !records.is_empty() => records,
        system_result => lookup_srv_dot(&name)
            .await
            .with_context(|| match system_result {
                Ok(_) => format!("DoT SRV lookup returned no records for {name}"),
                Err(error) => format!("system SRV lookup failed for {name}: {error}"),
            })?,
    };

    let mut edges = Vec::new();
    for record in records {
        let addresses = lookup_host((record.target.trim_end_matches('.'), record.port))
            .await
            .with_context(|| format!("resolve Cloudflare edge {}", record.target))?;
        for address in addresses {
            let version = if address.is_ipv4() { 4 } else { 6 };
            if edge_ip_version == 0 || edge_ip_version == version {
                edges.push(EdgeAddr {
                    address,
                    ip_version: version,
                });
            }
        }
    }
    edges.sort_by_key(|edge| edge.address);
    edges.dedup_by_key(|edge| edge.address);
    anyhow::ensure!(
        !edges.is_empty(),
        "no Cloudflare edge addresses match edge_ip_version"
    );
    Ok(edges)
}

async fn lookup_srv_system(name: &str) -> Result<Vec<SrvRecord>> {
    let resolv = tokio::fs::read_to_string("/etc/resolv.conf")
        .await
        .context("read /etc/resolv.conf")?;
    let server = resolv
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("nameserver ").map(str::trim))
        .context("/etc/resolv.conf has no nameserver")?;
    let server = dns_server_address(server)?;
    let bind = if server.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind).await.context("bind DNS socket")?;
    let query = build_dns_query(name, DNS_TYPE_SRV)?;
    socket.send_to(&query, server).await?;
    let mut response = vec![0u8; 4096];
    let (length, source) = timeout(DNS_TIMEOUT, socket.recv_from(&mut response))
        .await
        .context("system SRV lookup timed out")??;
    anyhow::ensure!(source.ip() == server.ip(), "DNS response source mismatch");
    response.truncate(length);
    parse_srv_response(&response, u16::from_be_bytes([query[0], query[1]]))
}

async fn lookup_srv_dot(name: &str) -> Result<Vec<SrvRecord>> {
    let tcp = timeout(DNS_TIMEOUT, TcpStream::connect(DOT_SERVER_ADDRESS))
        .await
        .context("connect DoT server timed out")??;
    let roots = crate::ca::root_store().context("load Cloudflare root CAs")?;
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("configure Cloudflare DoT TLS versions")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(DOT_SERVER_NAME.to_owned())?;
    let mut tls = timeout(DNS_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .context("DoT TLS handshake timed out")??;
    let query = build_dns_query(name, DNS_TYPE_SRV)?;
    tls.write_all(&(query.len() as u16).to_be_bytes()).await?;
    tls.write_all(&query).await?;
    tls.flush().await?;
    let length = timeout(DNS_TIMEOUT, tls.read_u16())
        .await
        .context("DoT response timed out")?? as usize;
    let mut response = vec![0u8; length];
    timeout(DNS_TIMEOUT, tls.read_exact(&mut response))
        .await
        .context("DoT response body timed out")??;
    parse_srv_response(&response, u16::from_be_bytes([query[0], query[1]]))
}

fn dns_server_address(value: &str) -> Result<SocketAddr> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }
    let ip: IpAddr = value.parse().context("parse DNS nameserver")?;
    Ok(SocketAddr::new(ip, 53))
}

fn build_dns_query(name: &str, record_type: u16) -> Result<Vec<u8>> {
    let id = NEXT_DNS_ID.fetch_add(1, Ordering::Relaxed);
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    for label in name.trim_end_matches('.').split('.') {
        anyhow::ensure!(!label.is_empty() && label.len() <= 63, "invalid DNS label");
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&record_type.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    Ok(query)
}

fn parse_srv_response(packet: &[u8], expected_id: u16) -> Result<Vec<SrvRecord>> {
    anyhow::ensure!(packet.len() >= 12, "DNS response is too short");
    anyhow::ensure!(
        u16::from_be_bytes([packet[0], packet[1]]) == expected_id,
        "DNS response ID mismatch"
    );
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    anyhow::ensure!(flags & 0x8000 != 0, "DNS packet is not a response");
    anyhow::ensure!(
        flags & 0x000f == 0,
        "DNS server returned error code {}",
        flags & 0x000f
    );
    let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let answers = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        read_dns_name(packet, &mut offset)?;
        take(packet, &mut offset, 4)?;
    }
    let mut records = Vec::new();
    for _ in 0..answers {
        read_dns_name(packet, &mut offset)?;
        let header = take(packet, &mut offset, 10)?;
        let record_type = u16::from_be_bytes([header[0], header[1]]);
        let class = u16::from_be_bytes([header[2], header[3]]);
        let data_length = u16::from_be_bytes([header[8], header[9]]) as usize;
        let data_start = offset;
        let data_end = data_start
            .checked_add(data_length)
            .context("DNS record length overflow")?;
        anyhow::ensure!(data_end <= packet.len(), "truncated DNS record");
        if record_type == DNS_TYPE_SRV && class == 1 && data_length >= 7 {
            let priority = u16::from_be_bytes([packet[data_start], packet[data_start + 1]]);
            let weight = u16::from_be_bytes([packet[data_start + 2], packet[data_start + 3]]);
            let port = u16::from_be_bytes([packet[data_start + 4], packet[data_start + 5]]);
            let mut target_offset = data_start + 6;
            let target = read_dns_name(packet, &mut target_offset)?;
            records.push(SrvRecord {
                priority,
                weight,
                port,
                target,
            });
        }
        offset = data_end;
    }
    records.sort_by_key(|record| (record.priority, std::cmp::Reverse(record.weight)));
    Ok(records)
}

fn read_dns_name(packet: &[u8], offset: &mut usize) -> Result<String> {
    let mut cursor = *offset;
    let mut jumped = false;
    let mut labels = Vec::new();
    for _ in 0..128 {
        let length = *packet.get(cursor).context("truncated DNS name")?;
        if length & 0xc0 == 0xc0 {
            let next = *packet.get(cursor + 1).context("truncated DNS pointer")?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(next);
            anyhow::ensure!(pointer < packet.len(), "invalid DNS pointer");
            if !jumped {
                *offset = cursor + 2;
                jumped = true;
            }
            cursor = pointer;
            continue;
        }
        cursor += 1;
        if length == 0 {
            if !jumped {
                *offset = cursor;
            }
            return Ok(labels.join("."));
        }
        anyhow::ensure!(length <= 63, "invalid DNS label length");
        let end = cursor + usize::from(length);
        let label = std::str::from_utf8(packet.get(cursor..end).context("truncated DNS label")?)?;
        labels.push(label.to_owned());
        cursor = end;
    }
    anyhow::bail!("DNS name compression loop")
}

fn take<'a>(packet: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = offset.checked_add(length).context("DNS offset overflow")?;
    let value = packet.get(*offset..end).context("truncated DNS response")?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compressed_srv_response() {
        let query = build_dns_query("_test._tcp.example.com", DNS_TYPE_SRV).unwrap();
        let id = u16::from_be_bytes([query[0], query[1]]);
        let mut response = query;
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&DNS_TYPE_SRV.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&12u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&2u16.to_be_bytes());
        response.extend_from_slice(&7844u16.to_be_bytes());
        response.extend_from_slice(&[4, b'e', b'd', b'g', b'e', 0xc0, 0x17]);
        let records = parse_srv_response(&response, id).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].port, 7844);
        assert_eq!(records[0].target, "edge.example.com");
    }
}
