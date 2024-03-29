use std::{
    fs::canonicalize,
    path::{Path, PathBuf},
    process,
};

use anyhow::Result;
use clap::Parser;
use console::style;
use log::{debug, error, info};

mod cli;
mod compose;
mod config;
mod containers;
mod formatters;
mod rules;
mod security;

use crate::{
    cli::{ArgumentCommands, Arguments, AUTHOR, BANNER, VERSION_NUMBER},
    config::Config,
    formatters::sarif::SarifFile,
    rules::Rules,
    security::{Alert, Severity},
};

fn output_cli(_config: &Config, severity: Severity, results: Vec<Alert>) -> Result<bool> {
    // If a single alert
    let mut alert_present: bool = false;

    let mut previous = PathBuf::new();

    for result in results {
        if severity < result.severity {
            debug!("Skipping: {}", result);
            continue;
        }

        if previous != result.path.path.clone() {
            println!("\n{:^32}\n", style(&result.path).bold().blue());
            previous = result.path.path.clone();
        }

        let severity = match result.severity {
            security::Severity::Critical | security::Severity::High => {
                style(&result.severity).red()
            }
            security::Severity::Medium | security::Severity::Low => {
                style(&result.severity).yellow()
            }
            _ => style(&result.severity).green(),
        }
        .to_string();
        println!("[{:^22}] {}", severity, &result.details);

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
            output,
            format,
            filter,
            base,
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

            let mut rules = Rules::new(config.clone());
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
                "sarif" => {
                    info!("Running in SARIF mode...");
                    match output {
                        Some(o) => {
                            let sarif = SarifFile::new()
                                .set_tool(String::from("Quibble"), VERSION_NUMBER.to_string())
                                .base(base)
                                .add_results(results)
                                .build()?;

                            sarif.write(o)?;
                            info!("SARIF file written to: {}", o.display());
                            true
                        }
                        None => {
                            error!("No output file specified...");
                            false
                        }
                    }
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
