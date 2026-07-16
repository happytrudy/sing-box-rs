use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use anyhow::{Context, Result};
use tokio::net::TcpListener;

/// Expands the project-wide inbound listen semantics into socket addresses.
pub fn listen_addresses(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let (ip, port) = if let Ok(address) = host.parse::<SocketAddr>() {
        anyhow::ensure!(
            port == 0 || port == address.port(),
            "listen port {port} conflicts with address port {}",
            address.port()
        );
        (address.ip(), address.port())
    } else {
        let ip: IpAddr = host
            .parse()
            .with_context(|| format!("parse inbound listen address {host}"))?;
        (ip, port)
    };
    let mut addresses = vec![SocketAddr::new(ip, port)];
    if ip == IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
        addresses.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    } else if ip.is_loopback() && ip.is_ipv6() {
        addresses.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    Ok(addresses)
}

/// Binds all TCP sockets required by [`listen_addresses`].
pub async fn bind_tcp_listeners(host: &str, port: u16) -> Result<Vec<TcpListener>> {
    let mut listeners = Vec::new();
    let addresses = listen_addresses(host, port)?;
    let ipv6_wildcard = addresses[0].ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    let ephemeral = addresses[0].port() == 0;
    let mut assigned_port = addresses[0].port();
    for (index, mut address) in addresses.into_iter().enumerate() {
        if index > 0 && ephemeral {
            address.set_port(assigned_port);
        }
        let listener = match TcpListener::bind(address).await {
            Ok(listener) => listener,
            Err(error) if index > 0 && ipv6_wildcard && error.kind() == ErrorKind::AddrInUse => {
                continue;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("bind inbound listener {address}"));
            }
        };
        if index == 0 && ephemeral {
            assigned_port = listener.local_addr()?.port();
        }
        listeners.push(listener);
    }
    Ok(listeners)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use tokio::net::TcpStream;

    #[test]
    fn expands_inbound_listen_addresses() {
        assert_eq!(
            listen_addresses("0.0.0.0", 443).unwrap(),
            vec![SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                443
            ))]
        );
        assert_eq!(
            listen_addresses("::", 443).unwrap(),
            vec![
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 443, 0, 0)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 443)),
            ]
        );
        assert_eq!(
            listen_addresses("::1", 443).unwrap(),
            vec![
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443)),
            ]
        );
        assert_eq!(
            listen_addresses("127.0.0.1:443", 0).unwrap(),
            vec!["127.0.0.1:443".parse().unwrap()]
        );
        assert_eq!(
            listen_addresses("[::1]:443", 0).unwrap(),
            vec![
                "[::1]:443".parse().unwrap(),
                "127.0.0.1:443".parse().unwrap()
            ]
        );
        assert!(listen_addresses("127.0.0.1:443", 8443).is_err());
    }

    #[tokio::test]
    async fn loopback_pair_uses_one_ephemeral_port() {
        let listeners = bind_tcp_listeners("::1", 0).await.unwrap();
        assert_eq!(listeners.len(), 2);
        let port = listeners[0].local_addr().unwrap().port();
        assert_eq!(listeners[1].local_addr().unwrap().port(), port);

        let ipv4 = TcpStream::connect((Ipv4Addr::LOCALHOST, port));
        let ipv6 = TcpStream::connect((Ipv6Addr::LOCALHOST, port));
        let (ipv4, ipv6) = tokio::join!(ipv4, ipv6);
        ipv4.unwrap();
        ipv6.unwrap();
        listeners[0].accept().await.unwrap();
        listeners[1].accept().await.unwrap();
    }

    #[tokio::test]
    async fn wildcard_accepts_ipv4_and_ipv6() {
        let listeners = bind_tcp_listeners("::", 0).await.unwrap();
        let port = listeners[0].local_addr().unwrap().port();
        assert!(listeners.iter().all(|listener| {
            listener
                .local_addr()
                .is_ok_and(|address| address.port() == port)
        }));

        let ipv4 = TcpStream::connect((Ipv4Addr::LOCALHOST, port));
        let ipv6 = TcpStream::connect((Ipv6Addr::LOCALHOST, port));
        let (ipv4, ipv6) = tokio::join!(ipv4, ipv6);
        ipv4.unwrap();
        ipv6.unwrap();
        listeners[0].accept().await.unwrap();
        listeners[listeners.len() - 1].accept().await.unwrap();
    }
}
