use std::{net::IpAddr, time::Duration};

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::{Credentials, tunnelrpc_capnp};

pub const CLIENT_VERSION: &str = "sing-cloudflared";

pub const DEFAULT_FEATURES: &[&str] = &[
    "serialized_headers",
    "support_datagram_v2",
    "support_quic_eof",
    "allow_remote_config",
];

#[derive(Clone, Debug)]
pub struct ConnectionOptions {
    pub connector_id: Uuid,
    pub features: Vec<String>,
    pub origin_local_ip: Option<IpAddr>,
    pub replace_existing: bool,
    pub compression_quality: u8,
    pub num_previous_attempts: u8,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            connector_id: Uuid::new_v4(),
            features: DEFAULT_FEATURES
                .iter()
                .map(|feature| (*feature).into())
                .collect(),
            origin_local_ip: None,
            replace_existing: false,
            compression_quality: 0,
            num_previous_attempts: 0,
        }
    }
}

/// Fills the Cap'n Proto registration parameters shared by HTTP/2 and QUIC.
pub fn set_register_connection(
    params: &mut tunnelrpc_capnp::registration_server::register_connection_params::Builder<'_>,
    credentials: &Credentials,
    conn_index: u8,
    options: &ConnectionOptions,
) {
    let mut auth = params.reborrow().init_auth();
    auth.set_account_tag(&credentials.account_tag);
    auth.set_tunnel_secret(credentials.tunnel_secret.as_slice());

    params.set_tunnel_id(credentials.tunnel_id.as_bytes());
    params.set_conn_index(conn_index);

    let mut connection_options = params.reborrow().init_options();
    let mut client = connection_options.reborrow().init_client();
    client.set_client_id(options.connector_id.as_bytes());
    let mut features = client
        .reborrow()
        .init_features(options.features.len() as u32);
    for (index, feature) in options.features.iter().enumerate() {
        features.set(index as u32, feature);
    }
    client.set_version(CLIENT_VERSION);
    client.set_arch(format!(
        "{}_{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    ));

    connection_options.set_replace_existing(options.replace_existing);
    connection_options.set_compression_quality(options.compression_quality);
    connection_options.set_num_previous_attempts(options.num_previous_attempts);
    if let Some(address) = options.origin_local_ip {
        let bytes = match address {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(address) => address.octets().to_vec(),
        };
        connection_options.set_origin_local_ip(bytes.as_slice());
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationResult {
    pub connection_id: Uuid,
    pub location: String,
    pub tunnel_is_remotely_managed: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("Cloudflare registration is retryable: {cause}")]
pub struct RetryableRegistrationError {
    pub cause: String,
    pub delay: Duration,
}

#[derive(Debug, thiserror::Error)]
#[error("Cloudflare registration rejected: {cause}")]
pub struct PermanentRegistrationError {
    pub cause: String,
}

/// Decodes the result returned by `registration_server.registerConnection`.
pub fn read_registration_result(
    response: tunnelrpc_capnp::connection_response::Reader<'_>,
) -> Result<RegistrationResult> {
    let result = response.get_result();
    match result
        .which()
        .context("read Cloudflare registration result")?
    {
        tunnelrpc_capnp::connection_response::result::WhichReader::Error(error) => {
            let error = error.context("read Cloudflare registration error")?;
            let cause = error.get_cause()?.to_str()?.to_owned();
            if error.get_should_retry() {
                let retry_after = error.get_retry_after().max(0) as u64;
                return Err(RetryableRegistrationError {
                    cause,
                    delay: Duration::from_nanos(retry_after),
                }
                .into());
            }
            Err(PermanentRegistrationError { cause }.into())
        }
        tunnelrpc_capnp::connection_response::result::WhichReader::ConnectionDetails(details) => {
            let details = details.context("read Cloudflare connection details")?;
            let uuid_bytes = details.get_uuid()?;
            let connection_id =
                Uuid::from_slice(uuid_bytes).context("parse Cloudflare connection UUID")?;
            let location = details.get_location_name()?.to_str()?.to_owned();
            Ok(RegistrationResult {
                connection_id,
                location,
                tunnel_is_remotely_managed: details.get_tunnel_is_remotely_managed(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fills_registration_parameters() {
        let credentials = Credentials {
            account_tag: "account".into(),
            tunnel_secret: vec![1, 2, 3],
            tunnel_id: Uuid::from_bytes([7; 16]),
            endpoint: String::new(),
        };
        let options = ConnectionOptions::default();
        let mut message = capnp::message::Builder::new_default();
        let mut params = message
            .init_root::<tunnelrpc_capnp::registration_server::register_connection_params::Builder>(
        );
        set_register_connection(&mut params, &credentials, 2, &options);
        let reader = message
            .get_root_as_reader::<tunnelrpc_capnp::registration_server::register_connection_params::Reader>()
            .unwrap();
        assert_eq!(
            reader
                .get_auth()
                .unwrap()
                .get_account_tag()
                .unwrap()
                .to_str()
                .unwrap(),
            "account"
        );
        assert_eq!(reader.get_tunnel_id().unwrap(), &[7; 16]);
        assert_eq!(reader.get_conn_index(), 2);
        assert_eq!(
            reader
                .get_options()
                .unwrap()
                .get_client()
                .unwrap()
                .get_version()
                .unwrap()
                .to_str()
                .unwrap(),
            CLIENT_VERSION
        );
    }
}
