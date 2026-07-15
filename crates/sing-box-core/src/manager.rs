use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{BoxStream, Dialer, Inbound, Outbound, Session, StartStage};

#[derive(Default)]
pub struct OutboundManager {
    entries: RwLock<HashMap<String, Arc<dyn Outbound>>>,
    insertion_order: RwLock<Vec<String>>,
}

impl OutboundManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn add(&self, outbound: Arc<dyn Outbound>) -> Result<()> {
        let tag = outbound.tag().to_owned();
        anyhow::ensure!(!tag.is_empty(), "outbound tag cannot be empty");
        {
            let mut entries = self.entries.write().await;
            anyhow::ensure!(!entries.contains_key(&tag), "duplicate outbound tag: {tag}");
            entries.insert(tag.clone(), outbound);
        }
        self.insertion_order.write().await.push(tag);
        Ok(())
    }

    pub async fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.entries.read().await.get(tag).cloned()
    }

    pub async fn ordered(&self) -> Result<Vec<Arc<dyn Outbound>>> {
        let entries = self.entries.read().await.clone();
        let order = self.insertion_order.read().await.clone();
        let mut remaining: HashSet<String> = order.iter().cloned().collect();
        let mut resolved = HashSet::new();
        let mut result = Vec::with_capacity(order.len());

        while !remaining.is_empty() {
            let mut progressed = false;
            for tag in &order {
                if !remaining.contains(tag) {
                    continue;
                }
                let outbound = entries.get(tag).expect("manager maps stay consistent");
                let dependencies = outbound.dependencies();
                for dependency in &dependencies {
                    anyhow::ensure!(
                        entries.contains_key(dependency),
                        "dependency [{dependency}] not found for outbound [{tag}]"
                    );
                }
                if dependencies.iter().all(|item| resolved.contains(item)) {
                    result.push(Arc::clone(outbound));
                    resolved.insert(tag.clone());
                    remaining.remove(tag);
                    progressed = true;
                }
            }
            anyhow::ensure!(
                progressed,
                "circular outbound dependency involving {remaining:?}"
            );
        }
        Ok(result)
    }

    pub async fn start(&self, stage: StartStage) -> Result<()> {
        for outbound in self.ordered().await? {
            outbound.start(stage).await.with_context(|| {
                format!("start outbound/{}[{}]", outbound.kind(), outbound.tag())
            })?;
        }
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        let mut first_error = None;
        let mut entries = self.ordered().await?;
        entries.reverse();
        for outbound in entries {
            if let Err(error) = outbound.close().await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[derive(Clone)]
pub struct OutboundManagerDialer {
    manager: Arc<OutboundManager>,
    tag: String,
}

impl OutboundManagerDialer {
    pub fn new(manager: Arc<OutboundManager>, tag: impl Into<String>) -> Self {
        Self {
            manager,
            tag: tag.into(),
        }
    }
}

#[async_trait]
impl Dialer for OutboundManagerDialer {
    async fn connect(&self, session: &Session) -> Result<BoxStream> {
        let outbound = self
            .manager
            .get(&self.tag)
            .await
            .with_context(|| format!("detour outbound not found: {}", self.tag))?;
        outbound.connect(session).await
    }
}

#[derive(Default)]
pub struct InboundManager {
    entries: RwLock<HashMap<String, Arc<dyn Inbound>>>,
    insertion_order: RwLock<Vec<String>>,
}

impl InboundManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn add(&self, inbound: Arc<dyn Inbound>) -> Result<()> {
        let tag = inbound.tag().to_owned();
        anyhow::ensure!(!tag.is_empty(), "inbound tag cannot be empty");
        {
            let mut entries = self.entries.write().await;
            anyhow::ensure!(!entries.contains_key(&tag), "duplicate inbound tag: {tag}");
            entries.insert(tag.clone(), inbound);
        }
        self.insertion_order.write().await.push(tag);
        Ok(())
    }

    async fn ordered(&self) -> Vec<Arc<dyn Inbound>> {
        let entries = self.entries.read().await.clone();
        let order = self.insertion_order.read().await.clone();
        order
            .iter()
            .filter_map(|tag| entries.get(tag).cloned())
            .collect()
    }

    pub async fn get(&self, tag: &str) -> Option<Arc<dyn Inbound>> {
        self.entries.read().await.get(tag).cloned()
    }

    pub async fn start(&self, stage: StartStage) -> Result<()> {
        for inbound in self.ordered().await {
            inbound
                .start(stage)
                .await
                .with_context(|| format!("start inbound/{}[{}]", inbound.kind(), inbound.tag()))?;
        }
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        let mut first_error = None;
        let mut entries = self.ordered().await;
        entries.reverse();
        for inbound in entries {
            if let Err(error) = inbound.close().await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}
