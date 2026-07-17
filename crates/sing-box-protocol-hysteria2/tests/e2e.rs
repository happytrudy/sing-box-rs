use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use async_trait::async_trait;
use rcgen::generate_simple_self_signed;
use serde::Deserialize;
use sing_box_core::{
    Certificate, CertificateProvider, Config, Engine, Lifecycle, Registry, register_builtins,
};
use tempfile::tempdir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestProviderOptions {}

struct TestProvider {
    tag: String,
    sender: watch::Sender<Option<Arc<Certificate>>>,
}

#[async_trait]
impl Lifecycle for TestProvider {}

impl CertificateProvider for TestProvider {
    fn kind(&self) -> &'static str {
        "test"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn subscribe(&self, _server_name: &str) -> Result<watch::Receiver<Option<Arc<Certificate>>>> {
        Ok(self.sender.subscribe())
    }
}

#[tokio::test]
async fn hysteria2_source_whitelist_hot_reload_is_fail_closed() -> Result<()> {
    let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_connections = Arc::new(AtomicUsize::new(0));
    let echo_connections_task = Arc::clone(&echo_connections);
    let echo_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = echo_listener.accept().await?;
            echo_connections_task.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    });

    let certificate = generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate_der = certificate.cert.der().to_vec();
    let private_key_der = certificate.signing_key.serialize_der();
    let directory = tempdir()?;
    let certificate_path = directory.path().join("certificate.der");
    let private_key_path = directory.path().join("private-key.der");
    let rule_set_path = directory.path().join("client-whitelist.json");
    std::fs::write(&certificate_path, &certificate_der)?;
    std::fs::write(&private_key_path, &private_key_der)?;
    std::fs::write(
        &rule_set_path,
        r#"{
            "version": 5,
            "rules": [{"source_ip_cidr": ["127.0.0.1/32"]}]
        }"#,
    )?;

    let mut registry = Registry::new();
    register_builtins(&mut registry)?;
    let provided_certificate = Arc::new(Certificate::new(vec![certificate_der], private_key_der)?);
    registry.register_certificate_provider::<TestProviderOptions, _, _>(
        "test",
        move |_context, tag, _options| {
            let certificate = Arc::clone(&provided_certificate);
            async move {
                let (sender, _) = watch::channel(Some(certificate));
                Ok(Arc::new(TestProvider { tag, sender }) as Arc<dyn CertificateProvider>)
            }
        },
    )?;
    sing_box_protocol_hysteria2::register(&mut registry)?;

    let server_config: Config = serde_json::from_value(serde_json::json!({
        "certificate_providers": [{
            "type": "test",
            "tag": "shared-test-certificate"
        }],
        "inbounds": [{
            "type": "hysteria2",
            "tag": "hy2-in",
            "listen": "::1",
            "listen_port": 0,
            "up_mbps": 100,
            "down_mbps": 100,
            "masquerade": {
                "type": "string",
                "status_code": 200,
                "headers": {"content-type": "text/plain"},
                "content": "decoy"
            },
            "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "server_name": "localhost",
                "certificate_provider": "shared-test-certificate"
            },
            "users": [{"name": "alice", "password": "secret"}]
        }],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "rule_set": [{
                "type": "local",
                "tag": "client-whitelist",
                "format": "source",
                "path": rule_set_path
            }],
            "rules": [
                {
                    "inbound": "hy2-in",
                    "rule_set": "client-whitelist",
                    "action": "route",
                    "outbound": "direct"
                },
                {
                    "inbound": "hy2-in",
                    "action": "reject",
                    "method": "drop"
                }
            ],
            "final": "direct"
        }
    }))?;
    let server = Engine::new(server_config, registry.clone()).await?;
    server.start().await?;
    let hysteria2_addr = server.inbound_addr("hy2-in").await.unwrap();

    let client_config: Config = serde_json::from_value(serde_json::json!({
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "::1",
            "listen_port": 0
        }],
        "outbounds": [{
            "type": "hysteria2",
            "tag": "hy2-out",
            "server": "127.0.0.1",
            "server_port": hysteria2_addr.port(),
            "password": "secret",
            "up_mbps": 100,
            "down_mbps": 100,
            "tls": {
                "server_name": "localhost",
                "certificate_path": certificate_path
            }
        }],
        "route": {"final": "hy2-out"}
    }))?;
    let client = Engine::new(client_config, registry).await?;
    client.start().await?;
    let socks_port = client.inbound_addr("socks-in").await.unwrap().port();
    let socks_addr = (Ipv4Addr::LOCALHOST, socks_port);

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
    assert_eq!(echo_connections.load(Ordering::SeqCst), 1);

    std::fs::write(
        &rule_set_path,
        r#"{
            "version": 1,
            "rules": []
        }"#,
    )?;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut denied = TcpStream::connect(socks_addr).await?;
    denied.write_all(&[5, 1, 0]).await?;
    denied.read_exact(&mut method_reply).await?;
    assert_eq!(method_reply, [5, 0]);
    denied.write_all(&request).await?;

    // Hysteria2 can acknowledge the proxy stream before the server-side router
    // closes it. The authoritative assertion is that no second connection
    // reaches the direct target after the whitelist becomes empty.
    let mut denied_reply = [0u8; 10];
    let _ =
        tokio::time::timeout(Duration::from_secs(1), denied.read_exact(&mut denied_reply)).await;
    let _ = denied.write_all(b"must not reach direct").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        echo_connections.load(Ordering::SeqCst),
        1,
        "empty client whitelist must not fall through to route.final"
    );

    client.shutdown().await?;
    server.shutdown().await?;
    echo_task.abort();
    let _ = echo_task.await;
    Ok(())
}
