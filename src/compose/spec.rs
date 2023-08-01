use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Display};

use crate::containers::ContainerImage;

#[derive(Debug, Serialize, Deserialize)]
/// Based on the current spec
/// https://github.com/compose-spec/compose-spec/blob/master/schema/compose-spec.json
pub struct ComposeSpec {
    // Version being used
    pub version: Option<String>,
    // Name of the compose project
    pub name: Option<String>,
    /// Compose Services
    pub services: HashMap<String, Service>,
}

impl Display for ComposeSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut output = String::new();
        output.push_str("Compose(");

        if let Some(v) = &self.version {
            output += format!("'{v}'").as_str();
        }
        if let Some(n) = &self.name {
            output += format!("'{n}'").as_str();
        }
        output.push(')');

        write!(f, "{output}")
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Service {
    // Using external container
    pub image: Option<String>,

    // Manually building container
    pub build: Option<StringOrBuild>,

    // Container name
    pub container_name: Option<String>,

    // DNS server settings
    pub dns: Option<StringOrList>,

    // Environment files
    pub env_file: Option<StringOrList>,

    // Environment
    pub environment: Option<ListOrHashMap>,

    // Exposed ports
    pub expose: Option<Vec<StringOrNumber>>,

    // Ports
    pub ports: Option<Vec<StringOrNumber>>,

    // Volumes
    pub volumes: Option<Vec<String>>,

    /// Compose Service labels
    pub labels: Option<ListOrHashMap>,

    /// Compose security options
    pub security_opt: Option<Vec<String>>,

    /// Compose service restart policy
    pub restart: Option<String>,

    /// Compose sysctls
    pub sysctls: Option<ListOrHashMap>,

    /// Compose cap_add
    pub cap_add: Option<Vec<String>>,

    /// Compose service is running as privileged
    pub privileged: Option<bool>,
}

impl Service {
    pub fn parse_image(&self) -> Result<ContainerImage> {
        match &self.image {
            Some(i) => ContainerImage::parse(i.to_string()),
            None => Err(anyhow!("Failed to parse `image`")),
        }
    }
}

impl Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(name) = &self.container_name {
            write!(f, "{name}")
        } else if let Ok(image) = &self.parse_image() {
            write!(f, "{}", image.name)
        } else {
            write!(f, "unknown")
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Build {
    pub context: Option<String>,
    pub dockerfile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrBuild {
    Build(Build),
    Str(String),
}

// Serde Generic Enums

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrNumber {
    Num(usize),
    Str(String),
    None,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrList {
    VecStr(Vec<String>),
    Str(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ListOrHashMap {
    Hash(HashMap<String, StringOrNumber>),
    Vec(Vec<StringOrNumber>),
}
