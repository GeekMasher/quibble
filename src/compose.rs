use anyhow::{anyhow, Result};
use log::{debug, warn};
use std::{
    collections::HashMap,
    fmt::Display,
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
};

pub mod rules;
pub mod spec;

pub use rules::*;
pub use spec::*;
use walkdir::WalkDir;

use crate::compose::ComposeSpec;

pub struct ComposeFile {
    /// Path to the file
    pub path: PathBuf,
    /// Compose Spec
    pub compose: ComposeSpec,
    /// Key line mappings
    pub mappings: HashMap<String, i32>,
}

pub fn find(path: &Path) -> Result<Vec<ComposeFile>> {
    let mut compose_files: Vec<ComposeFile> = Vec::new();

    if path.is_file() {
        debug!("Path is a file, parsing compose file");

        match ComposeFile::parse(path) {
            Ok(c) => compose_files.push(c),
            Err(err) => return Err(err),
        }
    } else if path.is_dir() {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            let subpath = &entry.into_path();
            // TODO: This check should be better

            let filter = match subpath.extension() {
                Some(p) => p == "yml" || p == "yaml",
                None => false,
            };

            if subpath.is_file() && filter {
                debug!("Compose file: {:?}", subpath);

                match ComposeFile::parse(subpath) {
                    Ok(c) => {
                        compose_files.push(c);
                    }
                    Err(err) => {
                        debug!("Docker Compose file unable to parse: {:?}", subpath);
                        debug!("Error processing: {}", err);
                    }
                }
            }
        }
    } else {
        return Err(anyhow!("Unknown path type..."));
    }

    if compose_files.is_empty() {
        warn!("No compose file were found: {}", path.display());
    }

    Ok(compose_files)
}

impl Display for ComposeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ComposeFile('{}')", self.path.display())
    }
}

impl ComposeFile {
    pub fn parse(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new().read(true).open(path)?;
        let mut data = String::new();
        file.read_to_string(&mut data)?;

        let mappings = ComposeFile::mappings(&data)?;

        let cs: ComposeSpec = serde_yaml::from_str(data.as_str())?;

        Ok(ComposeFile {
            path: path.to_path_buf(),
            compose: cs,
            mappings,
        })
    }

    /// Generate mappings for the compose file keys. This allows us to
    /// point to a specific line in the file when we find a rule violation.
    pub fn mappings(data: &str) -> Result<HashMap<String, i32>> {
        let mut mappings: HashMap<String, i32> = HashMap::new();
        let mut stack: Vec<&str> = Vec::new();
        let mut current_index = 0;

        for (number, line) in data.split('\n').enumerate() {
            let number = number as i32;
            let index = line.matches("  ").count();
            let line = line.trim();

            // skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if current_index > index {
                let diff = current_index - index;
                for _ in 0..diff {
                    stack.pop();
                }
                current_index = index;
            }

            // key with no value
            if line.ends_with(':') {
                let key = line.trim_end_matches(':');

                let full_key = stack.join(".");
                if !full_key.is_empty() {
                    mappings.insert(format!("{}.{}", full_key, key), number);
                } else {
                    mappings.insert(key.to_string(), number);
                }

                stack.push(key);
                current_index = index;
                continue;
            }

            // arrays
            if line.starts_with('-') {
                let mut full_key = stack.join(".");
                let array_key = format!("[{}]", line.trim_start_matches("- "));

                full_key.push_str(array_key.as_str());

                mappings.insert(full_key, number);
                current_index = index;
                continue;
            }

            // key with value
            let key = line.split_once(':');
            if let Some((key, _)) = key {
                let mut full_key = stack.join(".");
                if !full_key.is_empty() {
                    full_key.push('.');
                }
                full_key.push_str(key);

                // println!("Key :: {}:{}", full_key, number);
                mappings.insert(full_key, number);
                current_index = index;
            }
        }

        Ok(mappings)
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn mappings() {
        let data = String::from(
            "version: \"3.9\"\n\nservices:\n  web:\n    image: nginx:latest\n    ports:\n      - \"80:80\"\n"
        );

        let mappings = super::ComposeFile::mappings(&data).unwrap();

        assert_eq!(mappings.len(), 6);
        assert_eq!(mappings.get("version").unwrap_or(&1), &0);
        assert_eq!(mappings.get("services").unwrap_or(&1), &2);
        assert_eq!(mappings.get("services.web").unwrap_or(&1), &3);
        assert_eq!(mappings.get("services.web.image").unwrap_or(&1), &4);
        assert_eq!(mappings.get("services.web.ports").unwrap_or(&1), &5);
        assert_eq!(
            mappings.get("services.web.ports[\"80:80\"]").unwrap_or(&1),
            &6
        );
    }

    #[test]
    fn mappings2() {
        let data = String::from(
            "version: \"3\"\nnetworks:\n  backend:\n    external: true\nservices:\n  web:\n    image: nginx:latest\n",
        );

        let mappings = super::ComposeFile::mappings(&data).unwrap();
        for (map, num) in mappings.iter() {
            println!("{}: {}", map, num);
        }

        assert_eq!(mappings.len(), 7);
        assert_eq!(mappings.get("version").unwrap_or(&1), &0);

        assert_eq!(mappings.get("networks").unwrap_or(&0), &1);
        assert_eq!(mappings.get("networks.backend").unwrap_or(&0), &2);
        assert_eq!(mappings.get("networks.backend.external").unwrap_or(&0), &3);

        assert_eq!(mappings.get("services").unwrap_or(&1), &4);
        assert_eq!(mappings.get("services.web").unwrap_or(&1), &5);
        assert_eq!(mappings.get("services.web.image").unwrap_or(&1), &6);
    }
}
