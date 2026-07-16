use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use sing_box_core::{Config, Engine, Registry, register_builtins};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Duration, timeout},
};

#[tokio::test]
async fn socks_to_snell_to_direct_echo() -> Result<()> {
    let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = echo_listener.accept().await?;
            let (mut reader, mut writer) = stream.split();
            tokio::io::copy(&mut reader, &mut writer).await?;
        }
        Ok::<_, std::io::Error>(())
    });

    let mut registry = Registry::new();
    register_builtins(&mut registry)?;
    sing_box_protocol_snell::register(&mut registry)?;

    let server_config: Config = serde_json::from_value(serde_json::json!({
        "inbounds": [{
            "type": "snell",
            "tag": "snell-in",
            "listen": "127.0.0.1",
            "listen_port": 0,
            "version": 6,
            "mode": "default",
            "psk": "correct horse battery staple",
            "users": [{"name": "alice", "user_key": "secret"}]
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final_outbound": "direct"}
    }))?;
    let server = Engine::new(server_config, registry.clone()).await?;
    server.start().await?;
    let snell_addr = server.inbound_addr("snell-in").await.unwrap();

    let client_config: Config = serde_json::from_value(serde_json::json!({
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": 0
        }],
        "outbounds": [{
            "type": "snell",
            "tag": "snell-out",
            "server": snell_addr.ip().to_string(),
            "server_port": snell_addr.port(),
            "version": 6,
            "mode": "default",
            "psk": "correct horse battery staple",
            "user_key": "secret",
            "reuse": true
        }],
        "route": {"final_outbound": "snell-out"}
    }))?;
    let client = Engine::new(client_config, registry).await?;
    client.start().await?;
    let socks_addr = client.inbound_addr("socks-in").await.unwrap();

    let IpAddr::V4(echo_ip) = echo_addr.ip() else {
        panic!("test echo listener unexpectedly used IPv6")
    };
    for sequence in 0..2 {
        let mut stream = TcpStream::connect(socks_addr).await?;
        stream.write_all(&[5, 1, 0]).await?;
        let mut method_reply = [0u8; 2];
        stream.read_exact(&mut method_reply).await?;
        assert_eq!(method_reply, [5, 0]);

        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&echo_ip.octets());
        request.extend_from_slice(&echo_addr.port().to_be_bytes());
        stream.write_all(&request).await?;
        let mut connect_reply = [0u8; 10];
        stream.read_exact(&mut connect_reply).await?;
        assert_eq!(&connect_reply[..2], &[5, 0]);

        let payload = format!("socks -> reused snell -> direct #{sequence}");
        stream.write_all(payload.as_bytes()).await?;
        let mut response = vec![0u8; payload.len()];
        stream.read_exact(&mut response).await?;
        assert_eq!(response, payload.as_bytes());
        stream.shutdown().await?;
    }

    client.shutdown().await?;
    server.shutdown().await?;
    echo_task.await??;
    Ok(())
}

#[tokio::test]
async fn socks_udp_to_snell_tls_obfs_to_direct_echo() -> Result<()> {
    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let echo_addr = echo.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        let (length, source) = echo.recv_from(&mut buffer).await?;
        echo.send_to(&buffer[..length], source).await?;
        Ok::<_, std::io::Error>(())
    });

    let mut registry = Registry::new();
    register_builtins(&mut registry)?;
    sing_box_protocol_snell::register(&mut registry)?;

    let server_config: Config = serde_json::from_value(serde_json::json!({
        "inbounds": [{
            "type": "snell",
            "tag": "snell-in",
            "listen": "127.0.0.1",
            "listen_port": 0,
            "version": 5,
            "psk": "correct horse battery staple",
            "users": [{"name": "alice", "user_key": "secret"}],
            "obfs": "tls",
            "obfs_host": "example.com"
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final_outbound": "direct"}
    }))?;
    let server = Engine::new(server_config, registry.clone()).await?;
    server.start().await?;
    let snell_addr = server.inbound_addr("snell-in").await.unwrap();

    let client_config: Config = serde_json::from_value(serde_json::json!({
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": 0
        }],
        "outbounds": [{
            "type": "snell",
            "tag": "snell-out",
            "server": snell_addr.ip().to_string(),
            "server_port": snell_addr.port(),
            "version": 4,
            "psk": "correct horse battery staple",
            "user_key": "secret",
            "obfs": "tls",
            "obfs_host": "example.com"
        }],
        "route": {"final_outbound": "snell-out"}
    }))?;
    let client = Engine::new(client_config, registry).await?;
    client.start().await?;
    let socks_addr = client.inbound_addr("socks-in").await.unwrap();

    let mut control = TcpStream::connect(socks_addr).await?;
    control.write_all(&[5, 1, 0]).await?;
    let mut method_reply = [0u8; 2];
    control.read_exact(&mut method_reply).await?;
    assert_eq!(method_reply, [5, 0]);
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut associate_reply = [0u8; 10];
    control.read_exact(&mut associate_reply).await?;
    assert_eq!(&associate_reply[..4], &[5, 0, 0, 1]);
    let relay_addr = std::net::SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&associate_reply[4..8])?)),
        u16::from_be_bytes([associate_reply[8], associate_reply[9]]),
    );

    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let payload = b"socks udp -> snell -> direct";
    let IpAddr::V4(echo_ip) = echo_addr.ip() else {
        panic!("test echo socket unexpectedly used IPv6")
    };
    let mut datagram = vec![0, 0, 0, 1];
    datagram.extend_from_slice(&echo_ip.octets());
    datagram.extend_from_slice(&echo_addr.port().to_be_bytes());
    datagram.extend_from_slice(payload);
    udp.send_to(&datagram, relay_addr).await?;

    let mut response = [0u8; 2048];
    let (length, _) = timeout(Duration::from_secs(5), udp.recv_from(&mut response)).await??;
    assert_eq!(&response[..4], &[0, 0, 0, 1]);
    assert_eq!(&response[4..8], &echo_ip.octets());
    assert_eq!(
        u16::from_be_bytes([response[8], response[9]]),
        echo_addr.port()
    );
    assert_eq!(&response[10..length], payload);

    drop(control);
    client.shutdown().await?;
    server.shutdown().await?;
    echo_task.await??;
    Ok(())
}
