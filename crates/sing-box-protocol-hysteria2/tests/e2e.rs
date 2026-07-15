use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use rcgen::generate_simple_self_signed;
use sing_box_core::{Config, Engine, Registry, register_builtins};
use tempfile::tempdir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::test]
async fn socks_to_hysteria2_to_direct_echo() -> Result<()> {
    let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await?;
        let (mut reader, mut writer) = stream.split();
        tokio::io::copy(&mut reader, &mut writer).await?;
        Ok::<_, std::io::Error>(())
    });

    let certificate = generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate_der = certificate.cert.der().to_vec();
    let private_key_der = certificate.signing_key.serialize_der();
    let directory = tempdir()?;
    let certificate_path = directory.path().join("certificate.der");
    let private_key_path = directory.path().join("private-key.der");
    std::fs::write(&certificate_path, certificate_der)?;
    std::fs::write(&private_key_path, private_key_der)?;

    let mut registry = Registry::new();
    register_builtins(&mut registry)?;
    sing_box_protocol_hysteria2::register(&mut registry)?;

    let server_config: Config = serde_json::from_value(serde_json::json!({
        "inbounds": [{
            "type": "hysteria2",
            "tag": "hy2-in",
            "listen": "127.0.0.1",
            "listen_port": 0,
            "tls": {
                "certificate_path": certificate_path,
                "key_path": private_key_path
            },
            "users": [{"name": "alice", "password": "secret"}]
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final_outbound": "direct"}
    }))?;
    let server = Engine::new(server_config, registry.clone()).await?;
    server.start().await?;
    let hysteria2_addr = server.inbound_addr("hy2-in").await.unwrap();

    let client_config: Config = serde_json::from_value(serde_json::json!({
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": 0
        }],
        "outbounds": [{
            "type": "hysteria2",
            "tag": "hy2-out",
            "server": hysteria2_addr.ip().to_string(),
            "server_port": hysteria2_addr.port(),
            "password": "secret",
            "tls": {
                "server_name": "localhost",
                "certificate_path": certificate_path
            }
        }],
        "route": {"final_outbound": "hy2-out"}
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

    let payload = b"socks -> Hysteria2 -> direct";
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
