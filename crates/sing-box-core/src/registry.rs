use std::{collections::HashMap, future::Future, sync::Arc};

use anyhow::{Context, Result};
use futures::future::BoxFuture;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{
    CertificateProvider, CertificateProviderManager, Inbound, Outbound, OutboundManager, Router,
    SystemDialer,
};

#[derive(Clone)]
pub struct CertificateProviderBuildContext {
    pub system_dialer: SystemDialer,
}

#[derive(Clone)]
pub struct OutboundBuildContext {
    pub outbounds: Arc<OutboundManager>,
    pub system_dialer: SystemDialer,
    pub certificate_providers: Arc<CertificateProviderManager>,
}

#[derive(Clone)]
pub struct InboundBuildContext {
    pub router: Arc<Router>,
    pub system_dialer: SystemDialer,
    pub certificate_providers: Arc<CertificateProviderManager>,
}

type CertificateProviderFactory = Arc<
    dyn Fn(
            CertificateProviderBuildContext,
            String,
            Value,
        ) -> BoxFuture<'static, Result<Arc<dyn CertificateProvider>>>
        + Send
        + Sync,
>;

type OutboundFactory = Arc<
    dyn Fn(OutboundBuildContext, String, Value) -> BoxFuture<'static, Result<Arc<dyn Outbound>>>
        + Send
        + Sync,
>;
type InboundFactory = Arc<
    dyn Fn(InboundBuildContext, String, Value) -> BoxFuture<'static, Result<Arc<dyn Inbound>>>
        + Send
        + Sync,
>;

#[derive(Clone, Default)]
pub struct Registry {
    certificate_provider: HashMap<String, CertificateProviderFactory>,
    outbound: HashMap<String, OutboundFactory>,
    inbound: HashMap<String, InboundFactory>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_certificate_provider<C, F, Fut>(
        &mut self,
        kind: &str,
        constructor: F,
    ) -> Result<()>
    where
        C: DeserializeOwned + Send + 'static,
        F: Fn(CertificateProviderBuildContext, String, C) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Arc<dyn CertificateProvider>>> + Send + 'static,
    {
        anyhow::ensure!(
            !self.certificate_provider.contains_key(kind),
            "certificate provider type already registered: {kind}"
        );
        let constructor = Arc::new(constructor);
        self.certificate_provider.insert(
            kind.to_owned(),
            Arc::new(move |context, tag, raw| {
                let constructor = Arc::clone(&constructor);
                Box::pin(async move {
                    let config = serde_json::from_value(raw)
                        .context("decode certificate provider options")?;
                    constructor(context, tag, config).await
                })
            }),
        );
        Ok(())
    }

    pub fn register_outbound<C, F, Fut>(&mut self, kind: &str, constructor: F) -> Result<()>
    where
        C: DeserializeOwned + Send + 'static,
        F: Fn(OutboundBuildContext, String, C) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Arc<dyn Outbound>>> + Send + 'static,
    {
        anyhow::ensure!(
            !self.outbound.contains_key(kind),
            "outbound type already registered: {kind}"
        );
        let constructor = Arc::new(constructor);
        self.outbound.insert(
            kind.to_owned(),
            Arc::new(move |context, tag, raw| {
                let constructor = Arc::clone(&constructor);
                Box::pin(async move {
                    let config = serde_json::from_value(raw)
                        .context("decode protocol-specific outbound options")?;
                    constructor(context, tag, config).await
                })
            }),
        );
        Ok(())
    }

    pub fn register_inbound<C, F, Fut>(&mut self, kind: &str, constructor: F) -> Result<()>
    where
        C: DeserializeOwned + Send + 'static,
        F: Fn(InboundBuildContext, String, C) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Arc<dyn Inbound>>> + Send + 'static,
    {
        anyhow::ensure!(
            !self.inbound.contains_key(kind),
            "inbound type already registered: {kind}"
        );
        let constructor = Arc::new(constructor);
        self.inbound.insert(
            kind.to_owned(),
            Arc::new(move |context, tag, raw| {
                let constructor = Arc::clone(&constructor);
                Box::pin(async move {
                    let config = serde_json::from_value(raw)
                        .context("decode protocol-specific inbound options")?;
                    constructor(context, tag, config).await
                })
            }),
        );
        Ok(())
    }

    pub async fn create_outbound(
        &self,
        context: OutboundBuildContext,
        kind: &str,
        tag: String,
        options: Value,
    ) -> Result<Arc<dyn Outbound>> {
        let factory = self
            .outbound
            .get(kind)
            .with_context(|| format!("unknown outbound type: {kind}"))?
            .clone();
        factory(context, tag, options).await
    }

    pub async fn create_certificate_provider(
        &self,
        context: CertificateProviderBuildContext,
        kind: &str,
        tag: String,
        options: Value,
    ) -> Result<Arc<dyn CertificateProvider>> {
        let factory = self
            .certificate_provider
            .get(kind)
            .with_context(|| format!("unknown certificate provider type: {kind}"))?
            .clone();
        factory(context, tag, options).await
    }

    pub async fn create_inbound(
        &self,
        context: InboundBuildContext,
        kind: &str,
        tag: String,
        options: Value,
    ) -> Result<Arc<dyn Inbound>> {
        let factory = self
            .inbound
            .get(kind)
            .with_context(|| format!("unknown inbound type: {kind}"))?
            .clone();
        factory(context, tag, options).await
    }
}
