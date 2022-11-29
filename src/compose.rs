
use std::{path::Path, fmt::Display};
use anyhow::{Result, anyhow};
use log::{warn, debug};

pub mod spec;
pub mod rules;

pub use spec::*;
pub use rules::*;
use walkdir::WalkDir;


use crate::compose::ComposeSpec;


pub struct ComposeFile {
    pub path: String,
    pub compose: ComposeSpec,
}


pub fn find(path: &Path) -> Result<Vec<ComposeFile>> {
    let mut compose_files: Vec<ComposeFile> = Vec::new();
    
    if path.is_file() {
        debug!("Path is a file, parsing compose file");

        if let Ok(c) = ComposeFile::parse(path) {
            compose_files.push(c)
        }
        else {
            return Err(anyhow!("Failed to load compose file: {}", path.display()));
        }
    }
    else if path.is_dir() {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            let subpath = &entry.into_path();
            // TODO: This check should be better
            if subpath.is_file() && subpath.ends_with("docker-compose.yml") { 
                debug!("File file: {:?}", subpath);
                if let Ok(c) = ComposeFile::parse(subpath) {
                    compose_files.push(c);
                }
                else {
                    debug!("Docker Compose file unable to parse: {:?}", subpath);
                }
            }
        }
    }

    if compose_files.is_empty() {
        warn!("No compose file were found: {}", path.display());
    }

    Ok(compose_files)
}

impl Display for ComposeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ComposeFile('{}')", self.path)
    }
}

impl ComposeFile {
    pub fn parse(path: &Path) -> Result<Self> {
        match ComposeSpec::parse(path) {
            Ok(cs) => {
                Ok(ComposeFile {
                    path: path.display().to_string(), 
                    compose: cs,
                })
            },
            Err(err) => {
                warn!("Failed to load Compose File: {:?}", path);
                Err(anyhow!("Error: {}", err.to_string()))
            }
        }
    }
}


