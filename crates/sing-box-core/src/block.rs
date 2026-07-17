use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;

use crate::{
    BoxPacketConnection, BoxStream, Dialer, Lifecycle, Outbound, OutboundBuildContext, Registry,
    Session,
};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockOptions {}

struct BlockOutbound {
    tag: String,
}

impl Lifecycle for BlockOutbound {}

#[async_trait]
impl Dialer for BlockOutbound {
    async fn connect(&self, _session: &Session) -> Result<BoxStream> {
        anyhow::bail!("connection blocked by outbound {}", self.tag)
    }
}

#[async_trait]
impl Outbound for BlockOutbound {
    fn kind(&self) -> &'static str {
        "block"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect_packet(&self, _session: &Session) -> Result<BoxPacketConnection> {
        anyhow::bail!("packet connection blocked by outbound {}", self.tag)
    }
}

pub(crate) fn register(registry: &mut Registry) -> Result<()> {
    registry.register_outbound::<BlockOptions, _, _>(
        "block",
        |_context: OutboundBuildContext, tag, _options| async move {
            Ok(Arc::new(BlockOutbound { tag }) as Arc<dyn Outbound>)
        },
    )
}
