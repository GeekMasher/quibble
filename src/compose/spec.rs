use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Display, path::Path};

use crate::containers::ContainerImage;

#[derive(Debug, Serialize, Deserialize)]
/// Based on the current spec
/// https://github.com/compose-spec/compose-spec/blob/master/schema/compose-spec.json
pub struct ComposeSpec {
    // Version being used
    pub version: String,
    // Name of the compose project
    pub name: Option<String>,

    // HashMap of services
    pub services: HashMap<String, Service>,
}

impl ComposeSpec {
    pub fn parse(path: &Path) -> Result<ComposeSpec> {
        let file = std::fs::File::open(path)?;
        let data: ComposeSpec = serde_yaml::from_reader(file)?;
        Ok(data)
    }
}

impl Display for ComposeSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.name {
            Some(name) => write!(f, "Compose('{}', '{}')", self.version, name),
            None => write!(f, "Compose('{}')", self.version),
        }
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
    pub environment: Option<Vec<String>>,

    // Exposed ports
    pub expose: Option<Vec<StringOrNumber>>,

    // Ports
    pub ports: Option<Vec<StringOrNumber>>,

    // Volumes
    pub volumes: Option<Vec<String>>,

    // Lables
    pub lables: Option<ListOrHashMap>,

    pub security_opt: Option<Vec<String>>,

    pub restart: Option<String>,

    pub sysctls: Option<ListOrHashMap>,

    pub cap_add: Option<Vec<String>>,

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
    Hash(HashMap<String, String>),
    Vec(Vec<String>),
}
