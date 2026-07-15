use std::{env, path::PathBuf};

use anyhow::{Context, Result};
use sing_box_core::{Config, Engine, Registry, register_builtins};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config_path = config_path()?;
    let content = tokio::fs::read_to_string(&config_path)
        .await
        .with_context(|| format!("read config {}", config_path.display()))?;
    let config: Config = serde_json::from_str(&content)
        .with_context(|| format!("decode config {}", config_path.display()))?;

    let mut registry = Registry::new();
    register_builtins(&mut registry)?;
    sing_box_protocol_snell::register(&mut registry)?;
    sing_box_protocol_hysteria2::register(&mut registry)?;

    let engine = Engine::new(config, registry).await?;
    engine.start().await?;
    tracing::info!("sing-box-rs started");
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    engine.shutdown().await
}

fn config_path() -> Result<PathBuf> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let index = usize::from(arguments.first().is_some_and(|item| item == "run"));
    match &arguments[index..] {
        [option, value] if option == "-c" || option == "--config" => Ok(PathBuf::from(value)),
        [value] if !value.starts_with('-') => Ok(PathBuf::from(value)),
        [option, ..] if option.starts_with('-') => anyhow::bail!("unknown option: {option}"),
        _ => anyhow::bail!("usage: sing-box-rs run -c <config.json>"),
    }
}
