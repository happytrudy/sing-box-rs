use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::Value;
use sing_box_core::{Config, parse_extended_json};

pub struct ConfigSources {
    files: Vec<PathBuf>,
    directories: Vec<PathBuf>,
}

pub struct LoadedConfig {
    pub config: Config,
    pub paths: Vec<PathBuf>,
}

pub enum CliAction {
    Run(ConfigSources),
    Help,
    Version,
}

pub const HELP: &str = r#"sing-box-rs - A modular proxy platform

Usage: sing-box-rs [run] [OPTIONS] [CONFIG]

Options:
  -c, --config <PATH>              Load a JSON configuration file (repeatable)
  -C, --config-directory <PATH>    Load all .json files in a directory (repeatable)
  -v, --version                    Print version information
  -h, --help                       Print help information

If no configuration source is specified, config.json is loaded. Configuration
files from -c and -C are sorted by path and merged before validation. Arrays are
appended in order, which allows protocol inbounds to live in separate files.
"#;

pub fn parse_args(arguments: impl IntoIterator<Item = String>) -> Result<CliAction> {
    let mut files = Vec::new();
    let mut directories = Vec::new();
    let mut bare_path = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "run" => {}
            "-h" | "--help" => return Ok(CliAction::Help),
            "-v" | "--version" => return Ok(CliAction::Version),
            "-c" | "--config" => files.push(PathBuf::from(
                arguments
                    .next()
                    .with_context(|| format!("missing value for {argument}"))?,
            )),
            "-C" | "--config-directory" => directories.push(PathBuf::from(
                arguments
                    .next()
                    .with_context(|| format!("missing value for {argument}"))?,
            )),
            _ if argument.starts_with("--config=") => {
                files.push(PathBuf::from(&argument["--config=".len()..]));
            }
            _ if argument.starts_with("--config-directory=") => {
                directories.push(PathBuf::from(&argument["--config-directory=".len()..]));
            }
            _ if argument.starts_with('-') => anyhow::bail!("unknown option: {argument}"),
            _ if bare_path.is_none() && files.is_empty() && directories.is_empty() => {
                bare_path = Some(PathBuf::from(argument));
            }
            _ => anyhow::bail!("unexpected argument: {argument}"),
        }
    }
    if let Some(path) = bare_path {
        files.push(path);
    }
    if files.is_empty() && directories.is_empty() {
        files.push(PathBuf::from("config.json"));
    }
    Ok(CliAction::Run(ConfigSources { files, directories }))
}

pub async fn load(sources: ConfigSources) -> Result<LoadedConfig> {
    let paths = collect_paths(sources).await?;
    anyhow::ensure!(!paths.is_empty(), "no JSON configuration files found");
    let mut merged = None;
    for path in &paths {
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("read config {}", path.display()))?;
        let source: Value = parse_extended_json(&content)
            .with_context(|| format!("decode config {}", path.display()))?;
        merged = Some(match merged {
            Some(destination) => merge_value(source, destination)
                .with_context(|| format!("merge config {}", path.display()))?,
            None => source,
        });
    }
    let config = serde_json::from_value(merged.expect("configuration paths checked"))
        .context("decode merged configuration")?;
    Ok(LoadedConfig { config, paths })
}

async fn collect_paths(sources: ConfigSources) -> Result<Vec<PathBuf>> {
    let mut paths = sources.files;
    for directory in sources.directories {
        let mut entries = tokio::fs::read_dir(&directory)
            .await
            .with_context(|| format!("read config directory {}", directory.display()))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .with_context(|| format!("read config directory {}", directory.display()))?
        {
            let file_type = entry
                .file_type()
                .await
                .with_context(|| format!("read config file type {}", entry.path().display()))?;
            if !file_type.is_file() || entry.path().extension().is_none_or(|value| value != "json")
            {
                continue;
            }
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn merge_value(source: Value, destination: Value) -> Result<Value> {
    if source.is_null() {
        return Ok(destination);
    }
    if destination.is_null() {
        return Ok(source);
    }
    match destination {
        Value::Array(mut destination) => {
            match source {
                Value::Array(mut source) => destination.append(&mut source),
                source => destination.push(source),
            }
            Ok(Value::Array(destination))
        }
        Value::Object(mut destination) => {
            let Value::Object(source) = source else {
                anyhow::bail!("cannot merge a non-object value into an object");
            };
            for (key, source_value) in source {
                let value = match destination.remove(&key) {
                    Some(destination_value) => merge_value(source_value, destination_value)
                        .with_context(|| format!("merge object field {key}"))?,
                    None => source_value,
                };
                destination.insert(key, value);
            }
            Ok(Value::Object(destination))
        }
        destination => Ok(destination),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, time::SystemTime};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "sing-box-rs-config-loader-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parses_repeated_config_sources() {
        let CliAction::Run(sources) = parse_args([
            "run".to_owned(),
            "-c".to_owned(),
            "config.json".to_owned(),
            "-C".to_owned(),
            "conf".to_owned(),
            "--config=extra.json".to_owned(),
        ])
        .unwrap() else {
            panic!("expected run action")
        };
        assert_eq!(
            sources.files,
            [PathBuf::from("config.json"), PathBuf::from("extra.json")]
        );
        assert_eq!(sources.directories, [PathBuf::from("conf")]);
    }

    #[test]
    fn parses_help_and_version_actions() {
        assert!(matches!(
            parse_args(["--help".to_owned()]).unwrap(),
            CliAction::Help
        ));
        assert!(matches!(
            parse_args(["run".to_owned(), "-v".to_owned()]).unwrap(),
            CliAction::Version
        ));
        assert!(HELP.contains("--config-directory"));
    }

    #[test]
    fn merge_appends_arrays_and_preserves_earlier_scalars() {
        let destination = serde_json::json!({
            "inbounds": [{"tag": "first"}],
            "route": {"final_outbound": "direct"}
        });
        let source = serde_json::json!({
            "inbounds": [{"tag": "second"}],
            "route": {"final_outbound": "other"},
            "outbounds": [{"tag": "direct"}]
        });
        assert_eq!(
            merge_value(source, destination).unwrap(),
            serde_json::json!({
                "inbounds": [{"tag": "first"}, {"tag": "second"}],
                "outbounds": [{"tag": "direct"}],
                "route": {"final_outbound": "direct"}
            })
        );
    }

    #[tokio::test]
    async fn loads_partial_files_from_a_directory() {
        let root = TestDirectory::new();
        let directory = root.0.join("conf");
        fs::create_dir(&directory).unwrap();
        let base = root.0.join("config.json");
        fs::write(
            &base,
            r#"{
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {"final_outbound": "direct"}
            }"#,
        )
        .unwrap();
        fs::write(
            directory.join("10-socks.json"),
            r#"{"inbounds": [{"type": "socks", "tag": "a", "listen_port": 1001}]}"#,
        )
        .unwrap();
        fs::write(
            directory.join("20-socks.json"),
            r#"{"inbounds": [{"type": "socks", "tag": "b", "listen_port": 1002}]}"#,
        )
        .unwrap();
        fs::write(directory.join("ignored.jsonc"), "{}").unwrap();

        let loaded = load(ConfigSources {
            files: vec![base],
            directories: vec![directory],
        })
        .await
        .unwrap();
        assert_eq!(loaded.paths.len(), 3);
        assert_eq!(loaded.config.inbounds.len(), 2);
        assert_eq!(loaded.config.inbounds[0].tag, "a");
        assert_eq!(loaded.config.inbounds[1].tag, "b");
        assert_eq!(loaded.config.outbounds.len(), 1);
        assert_eq!(loaded.config.route.final_outbound, "direct");
    }

    #[tokio::test]
    async fn loads_complete_modular_example() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let action = parse_args([
            "-c".to_owned(),
            root.join("examples/modular/config.json")
                .display()
                .to_string(),
            "-C".to_owned(),
            root.join("examples/modular/conf").display().to_string(),
        ])
        .unwrap();
        let CliAction::Run(sources) = action else {
            panic!("expected run action")
        };
        let loaded = load(sources).await.unwrap();
        assert_eq!(loaded.config.inbounds.len(), 1);
        assert_eq!(loaded.config.outbounds.len(), 2);
        assert!(
            loaded
                .config
                .route
                .rule_set
                .iter()
                .any(|rule_set| rule_set.tag == "my-client-whitelist")
        );
        assert!(loaded.config.route.rules.iter().any(|rule| {
            rule.action == "reject" && rule.inbound.as_slice().iter().any(|tag| tag == "hy2-in")
        }));
        assert_eq!(loaded.config.route.final_outbound, "direct");
        assert!(loaded.config.dns.is_some());
        assert!(loaded.config.ntp.is_some());
    }
}
