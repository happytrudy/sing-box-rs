use std::io::Cursor;

use anyhow::{Context, Result};
use capnp::{message::ReaderOptions, serialize};

use crate::tunnelrpc_capnp;

pub const DATA_STREAM_SIGNATURE: [u8; 6] = [0x0A, 0x36, 0xCD, 0x12, 0xA1, 0x3E];
pub const RPC_STREAM_SIGNATURE: [u8; 6] = [0x52, 0xBB, 0x82, 0x5C, 0xDB, 0x65];
pub const PROTOCOL_VERSION: &[u8; 2] = b"01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamType {
    Data,
    Rpc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionType {
    Http,
    Websocket,
    Tcp,
}

impl From<ConnectionType> for tunnelrpc_capnp::ConnectionType {
    fn from(value: ConnectionType) -> Self {
        match value {
            ConnectionType::Http => Self::Http,
            ConnectionType::Websocket => Self::Websocket,
            ConnectionType::Tcp => Self::Tcp,
        }
    }
}

impl TryFrom<tunnelrpc_capnp::ConnectionType> for ConnectionType {
    type Error = anyhow::Error;

    fn try_from(value: tunnelrpc_capnp::ConnectionType) -> Result<Self> {
        Ok(match value {
            tunnelrpc_capnp::ConnectionType::Http => Self::Http,
            tunnelrpc_capnp::ConnectionType::Websocket => Self::Websocket,
            tunnelrpc_capnp::ConnectionType::Tcp => Self::Tcp,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectRequest {
    pub destination: String,
    pub connection_type: ConnectionType,
    pub metadata: Vec<Metadata>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectResponse {
    pub error: String,
    pub metadata: Vec<Metadata>,
}

pub fn classify_stream(signature: [u8; 6]) -> Result<StreamType> {
    match signature {
        DATA_STREAM_SIGNATURE => Ok(StreamType::Data),
        RPC_STREAM_SIGNATURE => Ok(StreamType::Rpc),
        _ => anyhow::bail!("unknown Cloudflare Tunnel stream signature"),
    }
}

pub fn encode_connect_request(request: &ConnectRequest) -> Result<Vec<u8>> {
    let mut message = capnp::message::Builder::new_default();
    let mut root = message.init_root::<tunnelrpc_capnp::connect_request::Builder>();
    root.set_dest(&request.destination);
    root.set_type(request.connection_type.into());
    let mut metadata = root.init_metadata(request.metadata.len() as u32);
    for (index, entry) in request.metadata.iter().enumerate() {
        let mut item = metadata.reborrow().get(index as u32);
        item.set_key(&entry.key);
        item.set_val(&entry.value);
    }
    let mut output = DATA_STREAM_SIGNATURE.to_vec();
    output.extend_from_slice(PROTOCOL_VERSION);
    serialize::write_message(&mut output, &message).context("encode Cloudflare connect request")?;
    Ok(output)
}

pub fn decode_connect_request(data: &[u8]) -> Result<ConnectRequest> {
    anyhow::ensure!(data.len() >= DATA_STREAM_SIGNATURE.len() + PROTOCOL_VERSION.len());
    anyhow::ensure!(
        data[..DATA_STREAM_SIGNATURE.len()] == DATA_STREAM_SIGNATURE,
        "invalid Cloudflare data stream signature"
    );
    anyhow::ensure!(
        data[DATA_STREAM_SIGNATURE.len()..DATA_STREAM_SIGNATURE.len() + 2] == *PROTOCOL_VERSION,
        "unsupported Cloudflare data stream version"
    );
    let mut cursor = Cursor::new(&data[8..]);
    let message = serialize::read_message(&mut cursor, ReaderOptions::default())?;
    let root = message
        .get_root::<tunnelrpc_capnp::connect_request::Reader>()
        .context("read Cloudflare connect request")?;
    let destination = root.get_dest()?.to_str()?.to_owned();
    let connection_type = root.get_type()?.try_into()?;
    let metadata_reader = root.get_metadata()?;
    let mut metadata = Vec::with_capacity(metadata_reader.len() as usize);
    for index in 0..metadata_reader.len() {
        let entry = metadata_reader.get(index);
        metadata.push(Metadata {
            key: entry.get_key()?.to_str()?.to_owned(),
            value: entry.get_val()?.to_str()?.to_owned(),
        });
    }
    Ok(ConnectRequest {
        destination,
        connection_type,
        metadata,
    })
}

pub fn encode_connect_response(response: &ConnectResponse) -> Result<Vec<u8>> {
    let mut message = capnp::message::Builder::new_default();
    let mut root = message.init_root::<tunnelrpc_capnp::connect_response::Builder>();
    root.set_error(&response.error);
    let mut metadata = root.init_metadata(response.metadata.len() as u32);
    for (index, entry) in response.metadata.iter().enumerate() {
        let mut item = metadata.reborrow().get(index as u32);
        item.set_key(&entry.key);
        item.set_val(&entry.value);
    }
    let mut output = DATA_STREAM_SIGNATURE.to_vec();
    output.extend_from_slice(PROTOCOL_VERSION);
    serialize::write_message(&mut output, &message)
        .context("encode Cloudflare connect response")?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_round_trip() {
        let request = ConnectRequest {
            destination: "example.com:443".into(),
            connection_type: ConnectionType::Tcp,
            metadata: vec![Metadata {
                key: "Cf-Cloudflared-Proxy-Src".into(),
                value: "tcp".into(),
            }],
        };
        let encoded = encode_connect_request(&request).unwrap();
        assert_eq!(decode_connect_request(&encoded).unwrap(), request);
    }

    #[test]
    fn classifies_stream_signatures() {
        assert_eq!(
            classify_stream(DATA_STREAM_SIGNATURE).unwrap(),
            StreamType::Data
        );
        assert_eq!(
            classify_stream(RPC_STREAM_SIGNATURE).unwrap(),
            StreamType::Rpc
        );
        assert!(classify_stream([0; 6]).is_err());
    }
}
