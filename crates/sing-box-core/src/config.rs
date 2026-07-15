use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub final_outbound: String,
}
