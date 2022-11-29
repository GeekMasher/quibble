
use std::{path::Path, collections::HashMap, fmt::Display};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};

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
    pub services: HashMap<String, Service>
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
            None => write!(f, "Compose('{}')", self.version)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Service {
    // Using external container
    pub image: Option<String>,
    // Container name
    pub container_name: Option<String>,
    // DNS server settings
    pub dns: Option<Vec<String>>,
    // TODO: string or vec
    pub env_file: Option<String>,
    // Environment
    pub environment: Option<Vec<String>>,
    // Exposed ports
    pub expose: Option<Vec<String>>,
    // Ports
    pub ports: Option<Vec<String>>,
    // Volumes
    pub volumes: Option<Vec<String>>,
    // Lables
    pub lables: Option<Vec<String>>,

    pub security_opt: Option<Vec<String>>,

    pub restart: Option<String>,

    pub sysctls: Option<Vec<String>>,

    pub cap_add: Option<Vec<String>>,
}

impl Service {
    pub fn parse_image(&self) -> Result<ContainerImage> {
        match &self.image {
            Some(i) => {
                ContainerImage::parse(i.to_string())
            },
            None => {
                Err(anyhow!("Failed to parse `image`"))
            }
        }
    }
}


