use std::fs::canonicalize;

use anyhow::Result;
use clap::Parser;
use console::style;
use log::{debug, error};

mod cli;
mod compose;
mod containers;
mod security;

use crate::{
    cli::{ArgumentCommands, Arguments, AUTHOR, BANNER, VERSION_NUMBER},
    security::Alert,
};

fn main() -> Result<()> {
    let arguments = Arguments::parse();

    let log_level = match arguments.debug {
        false => log::LevelFilter::Info,
        true => log::LevelFilter::Debug,
    };

    env_logger::builder()
        .parse_default_env()
        .filter_level(log_level)
        .init();

    if !arguments.disable_banner {
        println!(
            "{}    {} - v{}",
            style(BANNER).green(),
            style(AUTHOR).red(),
            style(VERSION_NUMBER).blue()
        );
    }

    debug!("Finished initialising, starting main workflow...");

    // Subcommands
    match &arguments.commands {
        ArgumentCommands::Compose { path, filter } => {
            let full_path = canonicalize(path)?;
            let compose_files = compose::find(&full_path)?;

            let mut results: Vec<Alert> = Vec::new();

            for cf in compose_files.iter() {
                debug!("Compose File :: {}", cf.path);
                results.extend(compose::checks(cf));
            }

            let mut current = String::new();
            for result in results {
                if !result.severity.filter(filter.to_string()) {
                    debug!("Skipping: {}", result);
                    continue;
                }

                if current != result.path.path {
                    println!("\n{:^32}\n", style(&result.path).bold().blue());
                    current = result.path.path.clone();
                }

                let severity = match result.severity {
                    security::Severity::Critical | security::Severity::High => {
                        style(&result.severity).red()
                    }
                    security::Severity::Medium | security::Severity::Low => {
                        style(&result.severity).yellow()
                    }
                    _ => style(&result.severity).green(),
                };
                println!("[{}] {}", severity, &result.details);
            }
        }
        ArgumentCommands::Registry { registry, image } => {
            println!(" >> {} :: {:?}", registry, image);
            todo!("Coming soon...");
        }
        _ => {
            error!("Unsupported sub command...");
            todo!("Lets write some code...");
        }
    }

    Ok(())
}
