use std::fmt::Display;

use anyhow::{anyhow, Result};
use log::warn;

#[derive(Debug)]
/// Container Image
pub struct ContainerImage {
    /// Namespace / User
    pub namespace: String,
    /// Name
    pub name: String,
    /// Instance
    pub instance: String,
    /// Tag
    pub tag: String,
    /// Digest
    pub digest: Option<String>,
    /// Signature
    pub signature: Option<String>,
}

impl ContainerImage {
    pub fn new() -> Self {
        ContainerImage {
            ..Default::default()
        }
    }

    pub fn parse(container: String) -> Result<Self> {
        let mut slash_split: Vec<&str> = container.split('/').collect();
        let mut result = ContainerImage::new();

        if slash_split.len() == 1 {
            result.name = slash_split.pop().unwrap_or("").to_string();
        } else if slash_split.len() == 2 {
            result.name = slash_split.pop().unwrap_or("").to_string();
            result.namespace = slash_split.pop().unwrap_or("").to_string();
        } else if slash_split.len() == 3 {
            result.name = slash_split.pop().unwrap_or("").to_string();
            result.namespace = slash_split.pop().unwrap_or("").to_string();
            result.instance = slash_split.pop().unwrap_or("").to_string();
        } else {
            warn!("Unsupported container syntax, please report as an Issue");
            return Err(anyhow!("Unsupported container splitting:"));
        }

        if let Some((start, end)) = result.name.split_once(':') {
            result.tag = end.to_string();
            result.name = start.to_string();
        }

        Ok(result)
    }
}

impl Default for ContainerImage {
    fn default() -> Self {
        ContainerImage {
            namespace: String::from("_"),
            name: String::new(),
            instance: String::from("docker.io"),
            tag: String::from("latest"),
            digest: None,
            signature: None,
        }
    }
}

impl Display for ContainerImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}/{}:{}",
            self.instance, self.namespace, self.name, self.tag
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::containers::ContainerImage;

    #[test]
    fn parse_name() {
        let container = String::from("gitea:latest");
        let image = ContainerImage::parse(container).unwrap();

        assert_eq!(image.namespace, String::from(""));
        assert_eq!(image.name, String::from("gitea"));
        assert_eq!(image.instance, String::from("docker.io"));
        assert_eq!(image.tag, String::from("latest"));
    }
    #[test]
    fn parse_namespace() {
        let container = String::from("gitea/gitea");
        let image = ContainerImage::parse(container).unwrap();

        assert_eq!(image.namespace, String::from("gitea"));
        assert_eq!(image.name, String::from("gitea"));
        assert_eq!(image.instance, String::from("docker.io"));
        assert_eq!(image.tag, String::from("latest"));
    }

    #[test]
    fn parse_tag() {
        let container = String::from("gitea/gitea:1.20");
        let image = ContainerImage::parse(container).unwrap();

        assert_eq!(image.namespace, String::from("gitea"));
        assert_eq!(image.name, String::from("gitea"));
        assert_eq!(image.instance, String::from("docker.io"));
        assert_eq!(image.tag, String::from("1.20"));
    }

    #[test]
    fn parse_instance() {
        let container = String::from("ghcr.io/gitea/gitea");
        let image = ContainerImage::parse(container).unwrap();

        assert_eq!(image.namespace, String::from("gitea"));
        assert_eq!(image.name, String::from("gitea"));
        assert_eq!(image.instance, String::from("ghcr.io"));
        assert_eq!(image.tag, String::from("latest"));
    }
}
