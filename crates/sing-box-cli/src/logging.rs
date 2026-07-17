use std::{fs::OpenOptions, sync::Arc};

use anyhow::{Context, Result};
use sing_box_core::LogConfig;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub fn init(config: Option<&LogConfig>) -> Result<()> {
    if config.is_some_and(|config| config.disabled) {
        return Ok(());
    }
    let configured_level = config
        .map(|config| config.level.as_str())
        .filter(|level| !level.is_empty());
    let level = configured_level.unwrap_or("info");
    anyhow::ensure!(
        matches!(level, "trace" | "debug" | "info" | "warn" | "error"),
        "unknown log level: {level}"
    );
    let filter = match configured_level {
        Some(level) => EnvFilter::try_new(level),
        None => EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(level)),
    }
    .context("create log filter")?;
    let timestamp = config.is_some_and(|config| config.timestamp);
    let output = config.map_or("", |config| config.output.as_str());
    if output.is_empty() {
        if timestamp {
            fmt().with_env_filter(filter).finish().try_init()?;
        } else {
            fmt()
                .with_env_filter(filter)
                .without_time()
                .finish()
                .try_init()?;
        }
    } else {
        let file = Arc::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(output)
                .with_context(|| format!("open log output {output}"))?,
        );
        let writer = move || file.try_clone().expect("clone log file");
        if timestamp {
            fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_writer(writer)
                .finish()
                .try_init()?;
        } else {
            fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .without_time()
                .with_writer(writer)
                .finish()
                .try_init()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn writes_logs_to_the_configured_file() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sing-box-rs-log-{unique}.log"));
        init(Some(&LogConfig {
            disabled: false,
            output: path.to_string_lossy().into_owned(),
            level: "info".into(),
            timestamp: false,
        }))
        .unwrap();
        tracing::info!("configured file logger test");
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert!(content.contains("configured file logger test"));
        assert!(!content.starts_with("20"));
    }
}
