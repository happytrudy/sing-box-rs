use std::{env, sync::Arc};

use anyhow::Result;
use sing_box_core::{Engine, Registry, RuleSetFetcher, register_builtins};

mod acme;
mod config_loader;
mod dns_adapter;
mod logging;
mod rule_set_fetcher;

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let sources = match config_loader::parse_args(env::args().skip(1))? {
        config_loader::CliAction::Run(sources) => sources,
        config_loader::CliAction::Help => {
            print!("{}", config_loader::HELP);
            return Ok(());
        }
        config_loader::CliAction::Version => {
            println!("sing-box-rs {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        config_loader::CliAction::GenerateRealityKeypair => {
            let (private_key, public_key) = sing_box_tls::generate_reality_keypair()?;
            println!("PrivateKey: {private_key}");
            println!("PublicKey: {public_key}");
            return Ok(());
        }
    };
    let loaded = config_loader::load(sources).await?;
    logging::init(loaded.config.log.as_ref())?;
    tracing::info!(files = loaded.paths.len(), "loaded configuration");
    let resolver = dns_adapter::build(loaded.config.dns.as_ref())?;

    let mut registry = Registry::new();
    register_builtins(&mut registry)?;
    let http_client = Arc::new(rule_set_fetcher::HttpClient::new());
    acme::register(&mut registry, Arc::clone(&http_client))?;
    sing_box_protocol_snell::register(&mut registry)?;
    sing_box_protocol_hysteria2::register(&mut registry)?;
    sing_box_protocol_shadowquic::register(&mut registry)?;
    sing_box_protocol_sunnyquic::register(&mut registry)?;
    sing_box_protocol_cloudflared::register(&mut registry)?;
    sing_box_protocol_vless::register(&mut registry)?;
    sing_box_protocol_anytls::register(&mut registry)?;

    let rule_set_fetcher = Arc::new(rule_set_fetcher::HttpRuleSetFetcher::with_client(
        http_client,
    )) as Arc<dyn RuleSetFetcher>;
    let engine =
        Engine::new_with_services(loaded.config, registry, resolver, Some(rule_set_fetcher))
            .await?;
    engine.start().await?;
    tracing::info!("sing-box-rs started");
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    engine.shutdown().await
}
