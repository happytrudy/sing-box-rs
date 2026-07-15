use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};

use crate::{
    Config, InboundBuildContext, InboundManager, OutboundBuildContext, OutboundManager, Registry,
    Router, START_STAGES,
};

pub struct Engine {
    outbounds: Arc<OutboundManager>,
    inbounds: Arc<InboundManager>,
}

impl Engine {
    pub async fn new(config: Config, registry: Registry) -> Result<Self> {
        let outbounds = Arc::new(OutboundManager::new());
        for (index, raw) in config.outbounds.iter().enumerate() {
            let tag = component_tag(&raw.tag, &raw.kind, index);
            let outbound = registry
                .create_outbound(
                    OutboundBuildContext {
                        outbounds: Arc::clone(&outbounds),
                    },
                    &raw.kind,
                    tag,
                    raw.options_value(),
                )
                .await
                .with_context(|| format!("create outbound/{}", raw.kind))?;
            outbounds.add(outbound).await?;
        }
        outbounds.ordered().await?;
        anyhow::ensure!(
            outbounds.get(&config.route.final_outbound).await.is_some(),
            "final outbound not found: {}",
            config.route.final_outbound
        );

        let router = Arc::new(Router::new(
            Arc::clone(&outbounds),
            config.route.final_outbound,
        ));
        let inbounds = Arc::new(InboundManager::new());
        for (index, raw) in config.inbounds.iter().enumerate() {
            let tag = component_tag(&raw.tag, &raw.kind, index);
            let inbound = registry
                .create_inbound(
                    InboundBuildContext {
                        router: Arc::clone(&router),
                    },
                    &raw.kind,
                    tag,
                    raw.options_value(),
                )
                .await
                .with_context(|| format!("create inbound/{}", raw.kind))?;
            inbounds.add(inbound).await?;
        }
        Ok(Self {
            outbounds,
            inbounds,
        })
    }

    pub async fn start(&self) -> Result<()> {
        for stage in START_STAGES {
            if let Err(error) = self.outbounds.start(stage).await {
                let _ = self.shutdown().await;
                return Err(error);
            }
            if let Err(error) = self.inbounds.start(stage).await {
                let _ = self.shutdown().await;
                return Err(error);
            }
        }
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        let inbound_result = self.inbounds.close().await;
        let outbound_result = self.outbounds.close().await;
        inbound_result?;
        outbound_result
    }

    pub async fn inbound_addr(&self, tag: &str) -> Option<SocketAddr> {
        self.inbounds
            .get(tag)
            .await
            .and_then(|inbound| inbound.local_addr())
    }
}

fn component_tag(tag: &str, kind: &str, index: usize) -> String {
    if tag.is_empty() {
        format!("{kind}-{index}")
    } else {
        tag.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::register_builtins;

    #[tokio::test]
    async fn rejects_unknown_protocol_during_typed_decode() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "inbounds": [],
            "outbounds": [{"type": "missing", "tag": "x"}],
            "route": {"final_outbound": "x"}
        }))
        .unwrap();
        let mut registry = Registry::new();
        register_builtins(&mut registry).unwrap();
        let error = match Engine::new(config, registry).await {
            Ok(_) => panic!("unknown protocol unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("unknown outbound type"));
    }
}
