use std::fs::canonicalize;

use anyhow::Result;
use clap::Parser;
use log::{debug, error, info, warn};

mod cli;
mod compose;
mod security;

use crate::{cli::{ArgumentCommands, Arguments}, security::Alert};

fn main() -> Result<()> {
    let arguments = Arguments::parse();

    let log_level = match arguments.debug {
        false => log::LevelFilter::Info,
        true => log::LevelFilter::Debug
    };

    env_logger::builder()
        .parse_default_env()
        .filter_level(log_level)
        .init();

    debug!("Finished initialising, starting main workflow...");

    // Subcommands 
    match &arguments.commands {
        ArgumentCommands::Compose { path, filter } => {
            let full_path = canonicalize(path)?;
            let compose_files = compose::find(&full_path)?;


            for cf in compose_files.iter() {
                let mut results: Vec<Alert> = Vec::new();

                info!("Compose File :: {}", cf.path);

                results.extend(compose::checks(cf));

                for result in results {
                    if result.severity.filter(filter.to_string()) {
                        debug!("Skipping: {}", result);
                        continue;
                    }

                    match result.severity {
                        security::Severity::Critical |
                        security::Severity::High => {
                            error!("- {}", result);
                        },
                        security::Severity::Medium |
                        security::Severity::Low => {
                            warn!("- {}", result);
                        },
                        _ => {
                            info!("- {}", result);
                        }
                    }
                }
            }
        }
        _ => {
            error!("Unsupported sub command...");
            todo!("Lets write some code...");
        }
    }
    
    Ok(())
}
