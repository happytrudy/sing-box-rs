use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, rename = "$schema")]
    pub schema: String,
    #[serde(default)]
    pub log: Option<LogConfig>,
    #[serde(default)]
    pub dns: Option<DnsConfig>,
    #[serde(default)]
    pub ntp: Option<NtpConfig>,
    #[serde(default)]
    pub certificate_providers: Vec<RawComponent>,
    #[serde(default)]
    pub inbounds: Vec<RawComponent>,
    #[serde(default)]
    pub outbounds: Vec<RawComponent>,
    pub route: RouteConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RawComponent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub tag: String,
    #[serde(flatten)]
    pub options: Map<String, Value>,
}

impl RawComponent {
    pub fn options_value(&self) -> Value {
        Value::Object(self.options.clone())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub output: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub timestamp: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default)]
    pub servers: Vec<DnsServerConfig>,
    #[serde(default, rename = "final")]
    pub final_server: String,
    #[serde(default)]
    pub strategy: DomainStrategy,
    #[serde(default)]
    pub disable_cache: bool,
    #[serde(default)]
    pub disable_expire: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsServerConfig {
    #[serde(rename = "type")]
    pub kind: String,
    pub tag: String,
    pub server: String,
    #[serde(default)]
    pub server_port: u16,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DomainStrategy {
    #[default]
    AsIs,
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub server_port: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    #[serde(default)]
    pub default_domain_resolver: Option<DomainResolverConfig>,
    #[serde(default)]
    pub rule_set: Vec<RuleSetConfig>,
    #[serde(default)]
    pub rules: Vec<RouteRuleConfig>,
    #[serde(default, rename = "final", alias = "final_outbound")]
    pub final_outbound: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum DomainResolverConfig {
    Tag(String),
    Options { server: String },
}

impl DomainResolverConfig {
    pub fn server(&self) -> &str {
        match self {
            Self::Tag(server) | Self::Options { server } => server,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSetConfig {
    #[serde(default, rename = "type")]
    pub kind: String,
    pub tag: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub update_interval: String,
    #[serde(default)]
    pub download_detour: String,
    #[serde(default)]
    pub http_client: Option<Value>,
    #[serde(default)]
    pub rules: Vec<HeadlessRuleConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSetSource {
    pub version: u8,
    pub rules: Vec<HeadlessRuleConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRuleConfig {
    #[serde(default)]
    pub inbound: Listable<String>,
    #[serde(default)]
    pub network: Listable<String>,
    #[serde(default)]
    pub auth_user: Listable<String>,
    #[serde(default)]
    pub domain: Listable<String>,
    #[serde(default)]
    pub domain_suffix: Listable<String>,
    #[serde(default)]
    pub domain_keyword: Listable<String>,
    #[serde(default)]
    pub source_ip_cidr: Listable<String>,
    #[serde(default)]
    pub source_ip_is_private: Option<bool>,
    #[serde(default)]
    pub ip_cidr: Listable<String>,
    #[serde(default)]
    pub ip_is_private: Option<bool>,
    #[serde(default)]
    pub source_port: Listable<u16>,
    #[serde(default)]
    pub source_port_range: Listable<String>,
    #[serde(default)]
    pub port: Listable<u16>,
    #[serde(default)]
    pub port_range: Listable<String>,
    #[serde(default)]
    pub rule_set: Listable<String>,
    #[serde(default)]
    pub invert: bool,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub outbound: String,
    #[serde(default)]
    pub override_address: String,
    #[serde(default)]
    pub override_port: u16,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub no_drop: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadlessRuleConfig {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub rules: Vec<HeadlessRuleConfig>,
    #[serde(default)]
    pub network: Listable<String>,
    #[serde(default)]
    pub domain: Listable<String>,
    #[serde(default)]
    pub domain_suffix: Listable<String>,
    #[serde(default)]
    pub domain_keyword: Listable<String>,
    #[serde(default)]
    pub source_ip_cidr: Listable<String>,
    #[serde(default)]
    pub ip_cidr: Listable<String>,
    #[serde(default)]
    pub source_port: Listable<u16>,
    #[serde(default)]
    pub source_port_range: Listable<String>,
    #[serde(default)]
    pub port: Listable<u16>,
    #[serde(default)]
    pub port_range: Listable<String>,
    #[serde(default)]
    pub invert: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Listable<T>(pub Vec<T>);

impl<T> Listable<T> {
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de, T> Deserialize<'de> for Listable<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany<T> {
            One(T),
            Many(Vec<T>),
        }

        Ok(Self(match OneOrMany::deserialize(deserializer)? {
            OneOrMany::One(value) => vec![value],
            OneOrMany::Many(values) => values,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_extended_json;

    #[test]
    fn parses_sing_box_style_configuration() {
        let config: Config = parse_extended_json(
            r#"{
                "log": {"disabled": true, "output": "/tmp/access.log", "level": "warn", "timestamp": true},
                "dns": {
                    "servers": [
                        {"tag": "google", "type": "udp", "server": "2001:4860:4860::8888", "server_port": 53},
                        {"tag": "cf", "type": "udp", "server": "1.1.1.1", "server_port": 53}
                    ],
                    "final": "google",
                    "strategy": "prefer_ipv6",
                    "disable_cache": false,
                    "disable_expire": false
                },
                "route": {
                    "default_domain_resolver": {"server": "google"},
                    "rule_set": [{"tag": "whitelist", "type": "local", "format": "source", "path": "/tmp/whitelist.json"}],
                    // route options continue to the next matching rule
                    "rules": [
                        {"port": 53, "outbound": "direct"},
                        {"inbound": "tunnel", "action": "route-options", "override_address": "127.0.0.1"},
                        {"inbound": "tunnel", "action": "route", "outbound": "direct"},
                        {"inbound": "hy2", "rule_set": "whitelist", "action": "route", "outbound": "direct"},
                        {"inbound": "hy2", "action": "reject", "method": "drop"}
                    ],
                    "final": "direct"
                },
                "ntp": {"enabled": true, "server": "time.apple.com"},
                "outbounds": [
                    {"tag": "direct", "type": "direct"},
                    {"tag": "block", "type": "block"}
                ]
            }"#,
        )
        .unwrap();
        assert!(config.log.unwrap().disabled);
        assert_eq!(config.dns.unwrap().final_server, "google");
        assert_eq!(config.route.rules.len(), 5);
        assert_eq!(config.route.rules[0].port.as_slice(), &[53]);
        assert_eq!(config.route.final_outbound, "direct");
        assert!(config.ntp.unwrap().enabled);
    }

    #[test]
    fn parses_remote_binary_rule_set() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "route": {
                "rule_set": [{
                    "type": "remote",
                    "tag": "remote",
                    "format": "binary",
                    "url": "https://example.com/rules.srs",
                    "update_interval": "6h"
                }],
                "final": "direct"
            },
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .unwrap();
        let rule_set = &config.route.rule_set[0];
        assert_eq!(rule_set.url, "https://example.com/rules.srs");
        assert_eq!(rule_set.update_interval, "6h");
    }
}
