//! Cloudflare Tunnel protocol support.
//!
//! The implementation is split into protocol-neutral credentials and
//! registration data, followed by HTTP/2 and QUIC transports. Keeping the
//! token model here lets both transports share the same authentication path.

mod ca;
use anyhow::{Context, Result};
use serde::Deserialize;
use uuid::Uuid;

pub mod discovery;
pub(crate) mod inbound;
pub mod protocol;
pub mod quic;
#[allow(dead_code)]
pub(crate) mod registration;
pub mod transport;

pub use registration::{ConnectionOptions, RegistrationResult};

pub fn register(registry: &mut sing_box_core::Registry) -> anyhow::Result<()> {
    inbound::register(registry)
}
#[allow(clippy::all, dead_code, unused_parens, unused_variables)]
pub(crate) mod tunnelrpc_capnp;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Credentials {
    pub account_tag: String,
    #[serde(deserialize_with = "deserialize_bytes")]
    pub tunnel_secret: Vec<u8>,
    pub tunnel_id: Uuid,
    #[serde(default)]
    pub endpoint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct TunnelToken {
    #[serde(rename = "a")]
    account_tag: String,
    #[serde(rename = "s", deserialize_with = "deserialize_bytes")]
    tunnel_secret: Vec<u8>,
    #[serde(rename = "t")]
    tunnel_id: Uuid,
    #[serde(default, rename = "e")]
    endpoint: String,
}

impl From<TunnelToken> for Credentials {
    fn from(token: TunnelToken) -> Self {
        Self {
            account_tag: token.account_tag,
            tunnel_secret: token.tunnel_secret,
            tunnel_id: token.tunnel_id,
            endpoint: token.endpoint,
        }
    }
}

/// Decodes a remote-managed Cloudflare Tunnel token.
pub fn parse_token(token: &str) -> Result<Credentials> {
    anyhow::ensure!(!token.trim().is_empty(), "cloudflared token is empty");
    let encoded = decode_base64(token.trim()).context("decode cloudflared token")?;
    let token: TunnelToken = serde_json::from_slice(&encoded).context("parse cloudflared token")?;
    anyhow::ensure!(
        !token.account_tag.is_empty(),
        "cloudflared account tag is empty"
    );
    anyhow::ensure!(
        !token.tunnel_secret.is_empty(),
        "cloudflared tunnel secret is empty"
    );
    Ok(token.into())
}

fn deserialize_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    decode_base64(&value).map_err(serde::de::Error::custom)
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in value.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            break;
        }
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => anyhow::bail!("invalid base64 character"),
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    anyhow::ensure!(bits < 6, "invalid base64 padding");
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_remote_managed_token() {
        let payload =
            br#"{"a":"account","s":"AQID","t":"d4f2ad1c-f6db-481e-91de-9d551f8885c9","e":""}"#;
        let token = encode_base64(payload);
        let credentials = parse_token(&token).unwrap();
        assert_eq!(credentials.account_tag, "account");
        assert_eq!(credentials.tunnel_secret, [1, 2, 3]);
        assert_eq!(
            credentials.tunnel_id,
            Uuid::parse_str("d4f2ad1c-f6db-481e-91de-9d551f8885c9").unwrap()
        );
    }

    #[test]
    fn accepts_url_safe_base64() {
        let payload = br#"{"a":"account","s":"AQI_","t":"d4f2ad1c-f6db-481e-91de-9d551f8885c9"}"#;
        let token = encode_base64(payload).replace('+', "-").replace('/', "_");
        assert!(parse_token(&token).is_ok());
    }

    fn encode_base64(value: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::with_capacity(value.len().div_ceil(3) * 4);
        for chunk in value.chunks(3) {
            let first = chunk[0];
            output.push(TABLE[(first >> 2) as usize] as char);
            if chunk.len() == 1 {
                output.push(TABLE[((first & 3) << 4) as usize] as char);
                output.push_str("==");
            } else {
                let second = chunk[1];
                output.push(TABLE[((first & 3) << 4 | second >> 4) as usize] as char);
                if chunk.len() == 2 {
                    output.push(TABLE[((second & 15) << 2) as usize] as char);
                    output.push('=');
                } else {
                    let third = chunk[2];
                    output.push(TABLE[((second & 15) << 2 | third >> 6) as usize] as char);
                    output.push(TABLE[(third & 63) as usize] as char);
                }
            }
        }
        output
    }
}
