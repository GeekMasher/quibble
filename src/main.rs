use std::{
    fs::canonicalize,
    path::{Path, PathBuf},
    process,
};

use anyhow::Result;
use clap::Parser;
use console::style;
use log::{debug, error};

mod cli;
mod compose;
mod config;
mod containers;
mod security;

use crate::{
    cli::{ArgumentCommands, Arguments, AUTHOR, BANNER, VERSION_NUMBER},
    config::Config,
    security::{Alert, Rules, Severity},
};

fn output_cli(_config: &Config, severity: Severity, results: Vec<Alert>) -> Result<bool> {
    // If a single alert
    let mut alert_present: bool = false;

    let mut current = PathBuf::new();
    for result in results {
        if severity < result.severity {
            debug!("Skipping: {}", result);
            continue;
        }

        if current != result.path.path && !result.path.path.is_empty() {
            println!("\n{:^32}\n", style(&result.path).bold().blue());
            current = result.path.path;
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

        alert_present = true;
    }
    Ok(alert_present)
}

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

    let config = Config::load(Path::new(&arguments.config))?;
    debug!("Config loaded: {:?}", config);

    debug!("Finished initialising, starting main workflow...");

    // Subcommands
    match &arguments.commands {
        ArgumentCommands::Compose {
            path,
            output: _,
            format,
            filter,
            disable_fail,
        } => {
            let full_path = canonicalize(path)?;
            let compose_files = compose::find(&full_path)?;

            let mut results: Vec<Alert> = Vec::new();

            // Severity from CLI filter or config
            let severity = match filter {
                Some(f) => Severity::from(f.to_string()),
                None => Severity::from(config.severity.to_string()),
            };
            debug!("Severity set :: {severity}");

            let mut rules = Rules::new(&config);
            debug!("Rule count: {}", rules.len());

            // Run the list of rules over the Compose File
            for cf in compose_files.iter() {
                debug!("Compose File :: {}", cf.path.display());
                results.extend(rules.run(cf));
            }

            let alert_present = match format.as_str() {
                "cli" => {
                    debug!("Running in CLI mode...");
                    output_cli(&config, severity, results)?
                }
                _ => {
                    error!("Unknown format output: `{format}`");
                    true
                }
            };

            if alert_present && !*disable_fail {
                process::exit(1);
            }
        }
        ArgumentCommands::Registry { registry, image } => {
            println!(" >> {registry} :: {image:?}");
            todo!("Coming soon...");
        }
        _ => {
            error!("Unsupported sub command...");
            todo!("Lets write some code...");
        }
    }

    Ok(())
}
