//! Protocol-neutral server TLS support.
//!
//! Reality authentication is performed before the normal rustls handshake.
//! The accepted connection is then resumed by the same rustls state machine,
//! so protocol implementations only need to consume a regular TLS stream.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use aws_lc_rs::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    agreement::{self, X25519},
    hkdf,
    hmac::{self, Key as HmacKey},
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use rustls::{NamedGroup, ServerConfig, pki_types::PrivateKeyDer};
use serde::Deserialize;
use sing_box_core::SystemDialer;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{LazyConfigAcceptor, TlsStream};

const REALITY_INFO: &[u8] = b"REALITY";
const REALITY_SESSION_ID_LEN: usize = 32;
const REALITY_PAYLOAD_LEN: usize = 16;
const REALITY_KEY_LEN: usize = 32;
const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];

/// Generate a REALITY X25519 keypair in the format used by sing-box.
pub fn generate_reality_keypair() -> Result<(String, String)> {
    let mut private_bytes = [0u8; REALITY_KEY_LEN];
    SystemRandom::new()
        .fill(&mut private_bytes)
        .map_err(|_| anyhow::anyhow!("generate Reality private key"))?;
    let private_key = agreement::PrivateKey::from_private_key(&X25519, &private_bytes)
        .map_err(|_| anyhow::anyhow!("generate Reality X25519 keypair"))?;
    let public_key = private_key
        .compute_public_key()
        .map_err(|_| anyhow::anyhow!("compute Reality public key"))?;
    Ok((
        encode_base64_url(&private_bytes),
        encode_base64_url(public_key.as_ref()),
    ))
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RealityHandshake {
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub server_port: u16,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RealityOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub handshake: RealityHandshake,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub short_id: RealityShortId,
    #[serde(default)]
    pub max_time_difference: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum RealityShortId {
    One(String),
    Many(Vec<String>),
}

impl Default for RealityShortId {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl RealityShortId {
    fn values(&self) -> impl Iterator<Item = &str> {
        match self {
            Self::One(value) => std::slice::from_ref(value).iter().map(String::as_str),
            Self::Many(values) => values.iter().map(String::as_str),
        }
    }
}

#[derive(Clone)]
pub struct RealityServerConfig {
    pub server_name: String,
    pub alpn: Vec<String>,
    pub options: RealityOptions,
    pub system_dialer: SystemDialer,
}

pub struct RealityAcceptor {
    server_name: String,
    alpn: Vec<String>,
    private_key: agreement::PrivateKey,
    handshake_server: String,
    handshake_port: u16,
    short_ids: Vec<[u8; 8]>,
    max_time_difference: Option<Duration>,
    signer_pkcs8: Arc<Vec<u8>>,
    signer_public_key: [u8; 32],
    system_dialer: SystemDialer,
}

impl RealityAcceptor {
    pub fn new(config: RealityServerConfig) -> Result<Self> {
        anyhow::ensure!(config.options.enabled, "Reality is not enabled");
        anyhow::ensure!(
            !config.server_name.is_empty(),
            "Reality server_name is empty"
        );
        anyhow::ensure!(
            !config.options.private_key.is_empty(),
            "Reality private_key is empty"
        );
        anyhow::ensure!(
            !config.options.handshake.server.is_empty(),
            "Reality handshake.server is empty"
        );
        anyhow::ensure!(
            config.options.handshake.server_port != 0,
            "Reality handshake.server_port is zero"
        );

        let private_bytes = decode_private_key(&config.options.private_key)?;
        let private_key = agreement::PrivateKey::from_private_key(&X25519, &private_bytes)
            .map_err(|_| anyhow::anyhow!("invalid Reality X25519 private key"))?;
        let short_ids = config
            .options
            .short_id
            .values()
            .map(parse_short_id)
            .collect::<Result<Vec<_>>>()?;
        anyhow::ensure!(!short_ids.is_empty(), "Reality short_id is empty");
        let max_time_difference = if config.options.max_time_difference.trim().is_empty() {
            None
        } else {
            let duration = parse_duration(&config.options.max_time_difference)?;
            (duration != Duration::ZERO).then_some(duration)
        };

        let rng = SystemRandom::new();
        let signer_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow::anyhow!("generate Reality signing key"))?;
        let signer = Ed25519KeyPair::from_pkcs8(signer_pkcs8.as_ref())
            .map_err(|_| anyhow::anyhow!("parse Reality signing key"))?;
        let signer_public_key = signer.public_key().as_ref().try_into().unwrap();

        Ok(Self {
            server_name: config.server_name,
            alpn: config.alpn,
            private_key,
            handshake_server: config.options.handshake.server,
            handshake_port: config.options.handshake.server_port,
            short_ids,
            max_time_difference,
            signer_pkcs8: Arc::new(signer_pkcs8.as_ref().to_vec()),
            signer_public_key,
            system_dialer: config.system_dialer,
        })
    }

    /// Authenticate and resume a TLS connection. Invalid REALITY clients are
    /// relayed to the configured handshake server and return `Ok(None)`.
    pub async fn accept<IO>(&self, stream: IO) -> Result<Option<TlsStream<IO>>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let mut start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
            .await
            .context("read Reality ClientHello")?;
        let Some(auth_key) = self.authenticate(&start.accepted) else {
            self.relay_invalid(start).await?;
            return Ok(None);
        };
        start.accepted.reality_enable_ed25519();
        let config = self.server_config(&auth_key)?;
        let tls = start
            .into_stream(config)
            .await
            .context("Reality TLS handshake")?;
        Ok(Some(tokio_rustls::TlsStream::Server(tls)))
    }

    fn authenticate(&self, accepted: &rustls::server::Accepted) -> Option<[u8; 32]> {
        let hello = accepted.reality_client_hello();
        if hello.session_id().len() != REALITY_SESSION_ID_LEN {
            return None;
        }
        if accepted.client_hello().server_name() != Some(self.server_name.as_str()) {
            return None;
        }
        let peer_key = hello.key_share(NamedGroup::X25519)?;
        if peer_key.len() != REALITY_KEY_LEN {
            return None;
        }
        let peer_key = agreement::UnparsedPublicKey::new(&X25519, peer_key);
        let Ok(auth_key) = agreement::agree(&self.private_key, peer_key, (), |shared| {
            let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &hello.random()[..20]);
            let prk = salt.extract(shared);
            let okm = prk
                .expand(&[REALITY_INFO], hkdf::HKDF_SHA256)
                .map_err(|_| ())?;
            let mut key = [0u8; REALITY_KEY_LEN];
            okm.fill(&mut key).map_err(|_| ())?;
            Ok::<_, ()>(key)
        }) else {
            return None;
        };
        let mut ciphertext = hello.session_id().to_vec();
        let mut aad = hello.encoded().to_vec();
        if aad.len() < 71 {
            return None;
        }
        aad[39..71].fill(0);
        let Ok(unbound) = UnboundKey::new(&aead::AES_256_GCM, &auth_key) else {
            return None;
        };
        let key = LessSafeKey::new(unbound);
        let Ok(nonce) = Nonce::try_assume_unique_for_key(&hello.random()[20..32]) else {
            return None;
        };
        let Ok(plain) = key.open_in_place(nonce, Aad::from(aad.as_slice()), &mut ciphertext) else {
            return None;
        };
        if plain.len() < REALITY_PAYLOAD_LEN {
            return None;
        }
        let mut short_id = [0u8; 8];
        short_id.copy_from_slice(&plain[8..16]);
        if !self
            .short_ids
            .iter()
            .any(|candidate| candidate == &short_id)
        {
            return None;
        }
        if let Some(max_difference) = self.max_time_difference {
            let timestamp = u32::from_be_bytes(plain[4..8].try_into().unwrap()) as u64;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now.abs_diff(timestamp) > max_difference.as_secs() {
                return None;
            }
        }
        Some(auth_key)
    }

    fn server_config(&self, auth_key: &[u8; 32]) -> Result<Arc<ServerConfig>> {
        let signature = hmac::sign(
            &HmacKey::new(hmac::HMAC_SHA512, auth_key),
            &self.signer_public_key,
        );
        let certificate = build_reality_certificate(&self.signer_public_key, signature.as_ref());
        let key = PrivateKeyDer::Pkcs8(self.signer_pkcs8.as_ref().clone().into());
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let mut config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(certificate)],
                key,
            )?;
        if !self.alpn.is_empty() {
            config.alpn_protocols = self
                .alpn
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect();
        }
        Ok(Arc::new(config))
    }

    async fn relay_invalid<IO>(&self, start: tokio_rustls::StartHandshake<IO>) -> Result<()>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let addresses = self
            .system_dialer
            .resolve(&self.handshake_server, self.handshake_port)
            .await?;
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(mut upstream) => {
                    let encoded = start.accepted.reality_client_hello().encoded();
                    anyhow::ensure!(
                        encoded.len() <= u16::MAX as usize,
                        "Reality ClientHello is too large"
                    );
                    let mut record = Vec::with_capacity(encoded.len() + 5);
                    record.extend_from_slice(&[
                        22,
                        3,
                        1,
                        (encoded.len() >> 8) as u8,
                        encoded.len() as u8,
                    ]);
                    record.extend_from_slice(encoded);
                    upstream.write_all(&record).await?;
                    let mut client = start.io;
                    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error
            .context("connect Reality handshake server")?
            .into())
    }
}

fn parse_short_id(value: &str) -> Result<[u8; 8]> {
    let value = value.trim();
    anyhow::ensure!(
        !value.is_empty() && value.len() <= 16,
        "invalid Reality short_id"
    );
    anyhow::ensure!(
        value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid Reality short_id"
    );
    let mut output = [0u8; 8];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        output[index] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(output)
}

fn decode_private_key(value: &str) -> Result<[u8; 32]> {
    let bytes = decode_base64_url(value)?;
    if bytes.len() != 32 {
        bail!("Reality private_key must decode to 32 bytes");
    }
    Ok(bytes.try_into().unwrap())
}

fn decode_base64_url(value: &str) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in value.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => break,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => bail!("invalid base64 Reality private_key"),
        } as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(output)
}

fn encode_base64_url(value: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(value.len().div_ceil(3) * 4);
    let mut index = 0;
    while index < value.len() {
        let remaining = value.len() - index;
        let first = value[index];
        let second = if remaining > 1 { value[index + 1] } else { 0 };
        let third = if remaining > 2 { value[index + 2] } else { 0 };
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[((first & 0x03) << 4 | second >> 4) as usize] as char);
        if remaining > 1 {
            output.push(ALPHABET[((second & 0x0f) << 2 | third >> 6) as usize] as char);
        }
        if remaining > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        }
        index += 3;
    }
    output
}

fn parse_duration(value: &str) -> Result<Duration> {
    let value = value.trim();
    if let Some(value) = value.strip_suffix('s') {
        return Ok(Duration::from_secs(value.parse()?));
    }
    if let Some(value) = value.strip_suffix('m') {
        return Ok(Duration::from_secs(value.parse::<u64>()? * 60));
    }
    bail!("invalid duration: {value}")
}

fn build_reality_certificate(public_key: &[u8; 32], signature: &[u8]) -> Vec<u8> {
    let algorithm = der_sequence(&[der_oid(ED25519_OID)]);
    let version = der_context_explicit(0, &der_integer(&[2]));
    let serial = der_integer(&[1]);
    let common_name = der_sequence(&[der_oid(&[0x55, 0x04, 0x03]), der_utf8("REALITY")]);
    let name = der_sequence(&[der_set(&[common_name])]);
    let validity = der_sequence(&[
        der_generalized_time("20200101000000Z"),
        der_generalized_time("20500101000000Z"),
    ]);
    let spki = der_sequence(&[algorithm.clone(), der_bit_string(public_key)]);
    let tbs = der_sequence(&[
        version,
        serial,
        algorithm.clone(),
        name.clone(),
        validity,
        name,
        spki,
    ]);
    der_sequence(&[tbs, algorithm, der_bit_string(signature)])
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        return vec![len as u8];
    }
    let bytes = (len as u64).to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap();
    let body = &bytes[first..];
    let mut out = vec![0x80 | body.len() as u8];
    out.extend_from_slice(body);
    out
}
fn der_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}
fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    der_tag(
        0x30,
        &parts
            .iter()
            .flat_map(|part| part.clone())
            .collect::<Vec<_>>(),
    )
}
fn der_set(parts: &[Vec<u8>]) -> Vec<u8> {
    der_tag(
        0x31,
        &parts
            .iter()
            .flat_map(|part| part.clone())
            .collect::<Vec<_>>(),
    )
}
fn der_integer(value: &[u8]) -> Vec<u8> {
    der_tag(0x02, value)
}
fn der_oid(value: &[u8]) -> Vec<u8> {
    der_tag(0x06, value)
}
fn der_utf8(value: &str) -> Vec<u8> {
    der_tag(0x0c, value.as_bytes())
}
fn der_generalized_time(value: &str) -> Vec<u8> {
    der_tag(0x18, value.as_bytes())
}
fn der_bit_string(value: &[u8]) -> Vec<u8> {
    let mut content = vec![0];
    content.extend_from_slice(value);
    der_tag(0x03, &content)
}
fn der_context_explicit(tag: u8, value: &[u8]) -> Vec<u8> {
    der_tag(0xa0 | tag, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reality_private_key_and_short_id() {
        let private = decode_private_key("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").unwrap();
        assert_eq!(
            private,
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ]
        );
        assert_eq!(
            parse_short_id("1123456789abcdef").unwrap(),
            [0x11, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,]
        );
    }

    #[test]
    fn reality_certificate_matches_signing_key() {
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
        let public_key: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
        let signature = hmac::sign(&HmacKey::new(hmac::HMAC_SHA512, &[7u8; 32]), &public_key);
        let certificate = build_reality_certificate(&public_key, signature.as_ref());
        let config = ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(certificate)],
            PrivateKeyDer::Pkcs8(key.as_ref().to_vec().into()),
        );
        assert!(config.is_ok());
    }

    #[test]
    fn generated_keypair_uses_raw_url_base64() {
        let (private_key, public_key) = generate_reality_keypair().unwrap();
        assert_eq!(private_key.len(), 43);
        assert_eq!(public_key.len(), 43);
        assert_eq!(decode_base64_url(&private_key).unwrap().len(), 32);
        assert_eq!(decode_base64_url(&public_key).unwrap().len(), 32);
        assert!(!private_key.contains('='));
        assert!(!public_key.contains('='));
    }
}
