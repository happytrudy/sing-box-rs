use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use sing_box_core::{Config, Engine, Registry, register_builtins};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::test]
async fn socks_to_snell_to_direct_echo() -> Result<()> {
    let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await?;
        let (mut reader, mut writer) = stream.split();
        tokio::io::copy(&mut reader, &mut writer).await?;
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
            "version": 4,
            "psk": "correct horse battery staple",
            "user_key": "secret"
        }],
        "route": {"final_outbound": "snell-out"}
    }))?;
    let client = Engine::new(client_config, registry).await?;
    client.start().await?;
    let socks_addr = client.inbound_addr("socks-in").await.unwrap();

    let mut stream = TcpStream::connect(socks_addr).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method_reply = [0u8; 2];
    stream.read_exact(&mut method_reply).await?;
    assert_eq!(method_reply, [5, 0]);

    let IpAddr::V4(echo_ip) = echo_addr.ip() else {
        panic!("test echo listener unexpectedly used IPv6")
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&echo_ip.octets());
    request.extend_from_slice(&echo_addr.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut connect_reply = [0u8; 10];
    stream.read_exact(&mut connect_reply).await?;
    assert_eq!(&connect_reply[..2], &[5, 0]);

    let payload = b"socks -> snell -> direct";
    stream.write_all(payload).await?;
    let mut response = vec![0u8; payload.len()];
    stream.read_exact(&mut response).await?;
    assert_eq!(response, payload);
    stream.shutdown().await?;

    client.shutdown().await?;
    server.shutdown().await?;
    echo_task.await??;
    Ok(())
}
