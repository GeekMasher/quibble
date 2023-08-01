use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs::File, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Config is where all of the settings for Quibble is stored.
pub struct Config {
    #[serde(default = "default_registries")]
    /// Registries that are allowed
    pub registries: Vec<String>,

    #[serde(default = "default_severity")]
    /// Severity
    pub severity: String,

    #[serde(default, rename = "disable-rules")]
    pub disable_rules: bool,

    #[serde(default)]
    pub rules: HashMap<String, RuleConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            registries: default_registries(),
            severity: default_severity(),
            disable_rules: false,
            rules: HashMap::new(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        if let Some(ext) = path.extension() {
            let file = match File::open(path) {
                Ok(f) => f,
                Err(_) => {
                    // by default
                    return Ok(Config::default());
                }
            };

            match ext.to_str() {
                Some("yml") | Some("yaml") => {
                    return Ok(serde_yaml::from_reader(file)?);
                }
                Some("json") => {
                    return Ok(serde_json::from_reader(file)?);
                }
                Some("toml") => {
                    return Err(anyhow!("Toml file is currently not supported"));
                }
                _ => {
                    return Err(anyhow!("Unknown extension"));
                }
            }
        }
        Ok(Config::default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleConfig {
    pub enabled: Option<bool>,
    pub severity: Option<String>,
}

// Default severity
fn default_severity() -> String {
    String::from("Medium")
}

fn default_registries() -> Vec<String> {
    // Default registries
    let registries: Vec<String> = vec![
        // Docker
        "docker.io".to_string(),
        // GitHub
        "ghcr.io".to_string(),
        // Microsoft
        "mcr.microsoft.com".to_string(),
        // Google
        "gcr.io".to_string(),
    ];
    registries
}
