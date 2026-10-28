use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

const HOST_KEYS: &[&str] = &["enabled", "priority", "store"];

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct Config {
    pub rules_file: Option<PathBuf>,
    pub disabled_rules: Vec<String>,
    pub allow: Vec<String>,
    pub notice: Option<bool>,
    #[serde(flatten)]
    rest: BTreeMap<String, serde_json::Value>,
}

impl Config {
    pub fn parse(yaml: &[u8]) -> Result<Self, String> {
        if yaml.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self::default());
        }
        serde_saphyr::from_slice(yaml).map_err(|error| error.to_string())
    }

    pub fn notice(&self) -> bool {
        self.notice.unwrap_or(true)
    }

    pub fn unknown_keys(&self) -> impl Iterator<Item = &str> {
        self.rest
            .keys()
            .map(String::as_str)
            .filter(|key| !HOST_KEYS.contains(key))
    }
}
