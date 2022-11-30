use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub registries: Option<Vec<String>>,
}

impl Default for Config {
    fn default() -> Self {
        let registries: Vec<String> = vec![
            "docker.io".to_string(),
            "ghdr.io".to_string()
        ];

        Config {
            registries: Some(registries)
        }
    }
}

