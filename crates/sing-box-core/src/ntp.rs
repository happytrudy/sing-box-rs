use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use tokio::{net::UdpSocket, time::timeout};

use crate::{NtpConfig, SystemDialer};

const NTP_PORT: u16 = 123;
const NTP_UNIX_EPOCH_DELTA: i128 = 2_208_988_800;
const NANOS_PER_SECOND: i128 = 1_000_000_000;

pub async fn synchronize(config: &NtpConfig, dialer: &SystemDialer) -> Result<i128> {
    anyhow::ensure!(!config.server.is_empty(), "NTP server is empty");
    let port = if config.server_port == 0 {
        NTP_PORT
    } else {
        config.server_port
    };
    let addresses = dialer.resolve(&config.server, port).await?;
    let mut last_error = None;
    for address in addresses {
        match query(address).await {
            Ok(offset) => return Ok(offset),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("NTP server did not resolve: {}", config.server)))
}

async fn query(server: SocketAddr) -> Result<i128> {
    let bind_address = if server.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind_address).await?;
    socket.connect(server).await?;
    let mut request = [0u8; 48];
    request[0] = 0x23;
    let client_send_time = SystemTime::now();
    let client_send = unix_nanos(client_send_time)?;
    request[40..48].copy_from_slice(&system_time_to_ntp(client_send_time)?);
    socket.send(&request).await?;
    let mut response = [0u8; 48];
    timeout(Duration::from_secs(5), socket.recv(&mut response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "NTP query timed out"))??;
    let client_receive = unix_nanos(SystemTime::now())?;
    anyhow::ensure!(response[0] & 0x07 == 4, "invalid NTP response mode");
    anyhow::ensure!(response[1] != 0, "NTP server is unsynchronized");
    let server_receive = ntp_timestamp(&response[32..40])?;
    let server_send = ntp_timestamp(&response[40..48])?;
    Ok(((server_receive - client_send) + (server_send - client_receive)) / 2)
}

fn unix_nanos(time: SystemTime) -> Result<i128> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    Ok(i128::from(duration.as_secs()) * NANOS_PER_SECOND + i128::from(duration.subsec_nanos()))
}

fn ntp_timestamp(input: &[u8]) -> Result<i128> {
    anyhow::ensure!(input.len() == 8, "invalid NTP timestamp");
    let seconds = u32::from_be_bytes(input[..4].try_into().expect("NTP seconds length"));
    let fraction = u32::from_be_bytes(input[4..].try_into().expect("NTP fraction length"));
    Ok(
        (i128::from(seconds) - NTP_UNIX_EPOCH_DELTA) * NANOS_PER_SECOND
            + ((i128::from(fraction) * NANOS_PER_SECOND) >> 32),
    )
}

fn system_time_to_ntp(time: SystemTime) -> Result<[u8; 8]> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    let seconds = duration
        .as_secs()
        .checked_add(NTP_UNIX_EPOCH_DELTA as u64)
        .context("NTP timestamp overflow")?;
    let seconds: u32 = seconds.try_into().context("NTP era overflow")?;
    let fraction = ((u64::from(duration.subsec_nanos()) << 32) / NANOS_PER_SECOND as u64) as u32;
    let mut output = [0u8; 8];
    output[..4].copy_from_slice(&seconds.to_be_bytes());
    output[4..].copy_from_slice(&fraction.to_be_bytes());
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_ntp_epoch_timestamp() {
        let seconds = (NTP_UNIX_EPOCH_DELTA + 1) as u32;
        let mut timestamp = [0u8; 8];
        timestamp[..4].copy_from_slice(&seconds.to_be_bytes());
        assert_eq!(ntp_timestamp(&timestamp).unwrap(), NANOS_PER_SECOND);
    }

    #[tokio::test]
    async fn measures_offset_from_an_ntp_server() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut request = [0u8; 48];
            let (_, source) = socket.recv_from(&mut request).await.unwrap();
            let now = system_time_to_ntp(SystemTime::now()).unwrap();
            let mut response = [0u8; 48];
            response[0] = 0x24;
            response[1] = 1;
            response[24..32].copy_from_slice(&request[40..48]);
            response[32..40].copy_from_slice(&now);
            response[40..48].copy_from_slice(&now);
            socket.send_to(&response, source).await.unwrap();
        });
        let offset = query(address).await.unwrap();
        assert!(offset.abs() < 100_000_000);
        server.await.unwrap();
    }
}
