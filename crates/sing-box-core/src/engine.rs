use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};

use crate::{
    CertificateProviderBuildContext, CertificateProviderManager, Config, DomainResolver,
    InboundBuildContext, InboundManager, OutboundBuildContext, OutboundManager, Registry, Router,
    RuleSetFetcher, START_STAGES, SystemDialer,
};

pub struct Engine {
    outbounds: Arc<OutboundManager>,
    inbounds: Arc<InboundManager>,
    certificate_providers: Arc<CertificateProviderManager>,
    router: Arc<Router>,
    ntp_offset_nanos: Option<i128>,
}

impl Engine {
    pub async fn new(config: Config, registry: Registry) -> Result<Self> {
        Self::new_with_resolver(config, registry, None).await
    }

    pub async fn new_with_resolver(
        config: Config,
        registry: Registry,
        resolver: Option<Arc<dyn DomainResolver>>,
    ) -> Result<Self> {
        Self::new_with_services(config, registry, resolver, None).await
    }

    pub async fn new_with_services(
        config: Config,
        registry: Registry,
        resolver: Option<Arc<dyn DomainResolver>>,
        rule_set_fetcher: Option<Arc<dyn RuleSetFetcher>>,
    ) -> Result<Self> {
        let default_outbound = config
            .outbounds
            .first()
            .map(|raw| component_tag(&raw.tag, &raw.kind, 0))
            .unwrap_or_default();
        let resolver_server = config
            .route
            .default_domain_resolver
            .as_ref()
            .map(|resolver| resolver.server().to_owned());
        if let Some(server) = &resolver_server {
            let resolver = resolver
                .as_ref()
                .context("default_domain_resolver requires DNS configuration")?;
            anyhow::ensure!(
                resolver.contains_server(server),
                "default DNS server not found: {server}"
            );
        }
        let strategy = config
            .dns
            .as_ref()
            .map_or_else(Default::default, |dns| dns.strategy);
        let system_dialer = SystemDialer::new(resolver, resolver_server, strategy);
        let ntp_offset_nanos = if config.ntp.as_ref().is_some_and(|ntp| ntp.enabled) {
            match crate::ntp::synchronize(config.ntp.as_ref().expect("NTP enabled"), &system_dialer)
                .await
            {
                Ok(offset) => {
                    tracing::info!(offset_ms = offset / 1_000_000, "synchronized NTP clock");
                    Some(offset)
                }
                Err(error) => {
                    tracing::warn!(%error, "NTP synchronization failed");
                    None
                }
            }
        } else {
            None
        };
        let certificate_providers = Arc::new(CertificateProviderManager::new());
        for (index, raw) in config.certificate_providers.iter().enumerate() {
            let tag = component_tag(&raw.tag, &raw.kind, index);
            let provider = registry
                .create_certificate_provider(
                    CertificateProviderBuildContext {
                        system_dialer: system_dialer.clone(),
                    },
                    &raw.kind,
                    tag,
                    raw.options_value(),
                )
                .await
                .with_context(|| format!("create certificate-provider/{}", raw.kind))?;
            certificate_providers.add(provider).await?;
        }
        let outbounds = Arc::new(OutboundManager::new());
        for (index, raw) in config.outbounds.iter().enumerate() {
            let tag = component_tag(&raw.tag, &raw.kind, index);
            let outbound = registry
                .create_outbound(
                    OutboundBuildContext {
                        outbounds: Arc::clone(&outbounds),
                        system_dialer: system_dialer.clone(),
                        certificate_providers: Arc::clone(&certificate_providers),
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
        let router = Arc::new(
            Router::build_with_fetcher(
                Arc::clone(&outbounds),
                config.route,
                default_outbound,
                rule_set_fetcher,
            )
            .await?,
        );
        let inbounds = Arc::new(InboundManager::new());
        for (index, raw) in config.inbounds.iter().enumerate() {
            let tag = component_tag(&raw.tag, &raw.kind, index);
            let inbound = registry
                .create_inbound(
                    InboundBuildContext {
                        router: Arc::clone(&router),
                        system_dialer: system_dialer.clone(),
                        certificate_providers: Arc::clone(&certificate_providers),
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
            certificate_providers,
            router,
            ntp_offset_nanos,
        })
    }

    pub async fn start(&self) -> Result<()> {
        self.router.start().await;
        for stage in START_STAGES {
            if let Err(error) = self.certificate_providers.start(stage).await {
                let _ = self.shutdown().await;
                return Err(error);
            }
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
        let router_result = self.router.close().await;
        let outbound_result = self.outbounds.close().await;
        let certificate_provider_result = self.certificate_providers.close().await;
        inbound_result?;
        router_result?;
        outbound_result?;
        certificate_provider_result
    }

    pub async fn inbound_addr(&self, tag: &str) -> Option<SocketAddr> {
        self.inbounds
            .get(tag)
            .await
            .and_then(|inbound| inbound.local_addr())
    }

    pub fn ntp_offset_nanos(&self) -> Option<i128> {
        self.ntp_offset_nanos
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
    use std::time::SystemTime;

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

    #[tokio::test]
    async fn loads_local_source_rule_set() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sing-box-rs-rule-set-{unique}.json"));
        std::fs::write(
            &path,
            r#"{
                "version": 5,
                "rules": [{"source_ip_cidr": ["192.0.2.0/24"]}]
            }"#,
        )
        .unwrap();
        let config: Config = serde_json::from_value(serde_json::json!({
            "inbounds": [],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"}
            ],
            "route": {
                "rule_set": [{
                    "type": "local",
                    "tag": "allow",
                    "format": "source",
                    "path": path
                }],
                "rules": [{
                    "rule_set": "allow",
                    "action": "route",
                    "outbound": "direct"
                }],
                "final": "block"
            }
        }))
        .unwrap();
        let mut registry = Registry::new();
        register_builtins(&mut registry).unwrap();
        let result = Engine::new(config, registry).await;
        let _ = std::fs::remove_file(path);
        result.unwrap();
    }
}
