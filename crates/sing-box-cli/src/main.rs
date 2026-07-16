use std::env;

use anyhow::Result;
use sing_box_core::{Engine, Registry, register_builtins};
use tracing_subscriber::EnvFilter;

mod config_loader;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

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
    };
    let loaded = config_loader::load(sources).await?;
    tracing::info!(files = loaded.paths.len(), "loaded configuration");

    let mut registry = Registry::new();
    register_builtins(&mut registry)?;
    sing_box_protocol_snell::register(&mut registry)?;
    sing_box_protocol_hysteria2::register(&mut registry)?;

    let engine = Engine::new(loaded.config, registry).await?;
    engine.start().await?;
    tracing::info!("sing-box-rs started");
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    engine.shutdown().await
}
