use std::{net::IpAddr, sync::Arc};

use anyhow::{Context, Result};
use async_trait::async_trait;
use sing_box_core::{DnsConfig, DomainResolver, DomainStrategy};
use sing_dns::{Resolver, ResolverConfig, Strategy, UdpServer, default_dns_port};

pub fn build(config: Option<&DnsConfig>) -> Result<Option<Arc<dyn DomainResolver>>> {
    let Some(config) = config else {
        return Ok(None);
    };
    let mut servers = Vec::with_capacity(config.servers.len());
    for server in &config.servers {
        anyhow::ensure!(
            server.kind == "udp",
            "unsupported DNS type: {}",
            server.kind
        );
        let address: IpAddr = server
            .server
            .parse()
            .with_context(|| format!("DNS server must be an IP address: {}", server.server))?;
        servers.push(UdpServer {
            tag: server.tag.clone(),
            address: (address, default_dns_port(server.server_port)).into(),
        });
    }
    let resolver = Resolver::new(ResolverConfig {
        servers,
        final_server: config.final_server.clone(),
        strategy: convert_strategy(config.strategy),
        disable_cache: config.disable_cache,
        disable_expire: config.disable_expire,
    })?;
    Ok(Some(Arc::new(ResolverAdapter(resolver))))
}

struct ResolverAdapter(Resolver);

#[async_trait]
impl DomainResolver for ResolverAdapter {
    async fn lookup(
        &self,
        server: Option<&str>,
        host: &str,
        strategy: DomainStrategy,
    ) -> Result<Vec<IpAddr>> {
        Ok(match server {
            Some(server) => {
                self.0
                    .lookup_with(server, host, convert_strategy(strategy))
                    .await?
            }
            None => self.0.lookup(host).await?,
        })
    }

    fn contains_server(&self, tag: &str) -> bool {
        self.0.contains_server(tag)
    }
}

fn convert_strategy(strategy: DomainStrategy) -> Strategy {
    match strategy {
        DomainStrategy::AsIs => Strategy::AsIs,
        DomainStrategy::PreferIpv4 => Strategy::PreferIpv4,
        DomainStrategy::PreferIpv6 => Strategy::PreferIpv6,
        DomainStrategy::Ipv4Only => Strategy::Ipv4Only,
        DomainStrategy::Ipv6Only => Strategy::Ipv6Only,
    }
}
