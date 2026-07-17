use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, Result};
use tokio::sync::{RwLock, watch};

use crate::{Certificate, CertificateProvider, StartStage};

#[derive(Default)]
struct ProviderState {
    ordered: Vec<Arc<dyn CertificateProvider>>,
    by_tag: HashMap<String, Arc<dyn CertificateProvider>>,
}

#[derive(Default)]
pub struct CertificateProviderManager {
    state: RwLock<ProviderState>,
}

impl CertificateProviderManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn add(&self, provider: Arc<dyn CertificateProvider>) -> Result<()> {
        let tag = provider.tag().to_owned();
        anyhow::ensure!(!tag.is_empty(), "certificate provider tag cannot be empty");
        let mut state = self.state.write().await;
        anyhow::ensure!(
            !state.by_tag.contains_key(&tag),
            "duplicate certificate provider tag: {tag}"
        );
        state.ordered.push(Arc::clone(&provider));
        state.by_tag.insert(tag, provider);
        Ok(())
    }

    pub async fn get(&self, tag: &str) -> Option<Arc<dyn CertificateProvider>> {
        self.state.read().await.by_tag.get(tag).cloned()
    }

    pub async fn subscribe(
        &self,
        tag: &str,
        server_name: &str,
    ) -> Result<watch::Receiver<Option<Arc<Certificate>>>> {
        self.get(tag)
            .await
            .with_context(|| format!("certificate provider not found: {tag}"))?
            .subscribe(server_name)
    }

    pub async fn start(&self, stage: StartStage) -> Result<()> {
        let providers = self.state.read().await.ordered.clone();
        for provider in providers {
            provider.start(stage).await.with_context(|| {
                format!(
                    "{stage:?} certificate-provider/{}[{}]",
                    provider.kind(),
                    provider.tag()
                )
            })?;
        }
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        let providers = self.state.read().await.ordered.clone();
        let mut first_error = None;
        for provider in providers.into_iter().rev() {
            if let Err(error) = provider.close().await.with_context(|| {
                format!(
                    "close certificate-provider/{}[{}]",
                    provider.kind(),
                    provider.tag()
                )
            }) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct StaticProvider {
        sender: watch::Sender<Option<Arc<Certificate>>>,
    }

    #[async_trait]
    impl crate::Lifecycle for StaticProvider {}

    impl CertificateProvider for StaticProvider {
        fn kind(&self) -> &'static str {
            "static"
        }

        fn tag(&self) -> &str {
            "test"
        }

        fn subscribe(
            &self,
            _server_name: &str,
        ) -> Result<watch::Receiver<Option<Arc<Certificate>>>> {
            Ok(self.sender.subscribe())
        }
    }

    #[tokio::test]
    async fn resolves_shared_provider_by_tag() {
        let (sender, _) = watch::channel(Some(Arc::new(
            Certificate::new(vec![vec![1]], vec![2]).unwrap(),
        )));
        let manager = CertificateProviderManager::new();
        manager
            .add(Arc::new(StaticProvider { sender }))
            .await
            .unwrap();
        let receiver = manager.subscribe("test", "example.com").await.unwrap();
        assert_eq!(
            receiver.borrow().as_ref().unwrap().certificate_chain[0],
            vec![1]
        );
        assert!(manager.subscribe("missing", "example.com").await.is_err());
    }
}
