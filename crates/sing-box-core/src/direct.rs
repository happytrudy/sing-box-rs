use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;

use crate::{
    BoxStream, Dialer, Lifecycle, Outbound, OutboundBuildContext, Registry, Session, SystemDialer,
};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectOptions {}

struct DirectOutbound {
    tag: String,
}

impl Lifecycle for DirectOutbound {}

#[async_trait]
impl Dialer for DirectOutbound {
    async fn connect(&self, session: &Session) -> Result<BoxStream> {
        SystemDialer.connect(session).await
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn kind(&self) -> &'static str {
        "direct"
    }

    fn tag(&self) -> &str {
        &self.tag
    }
}

pub(crate) fn register(registry: &mut Registry) -> Result<()> {
    registry.register_outbound::<DirectOptions, _, _>(
        "direct",
        |_context: OutboundBuildContext, tag, _options| async move {
            Ok(Arc::new(DirectOutbound { tag }) as Arc<dyn Outbound>)
        },
    )
}
