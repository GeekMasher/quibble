use anyhow::Result;
use log::debug;

use crate::{
    compose::{ComposeFile, ListOrHashMap, StringOrNumber},
    config::Config,
    security::{Alert, AlertLocation, RuleID, Severity},
};

/// Check environment variables for sensitive information
fn check_environment(
    compose_file: &ComposeFile,
    alerts: &mut Vec<crate::security::Alert>,
    service_name: &String,
    key: String,
    _value: String,
) {
    if key.contains("DEBUG") {
        let mapping = compose_file
            .mappings
            .get(format!("services.{}.environment.{}", service_name, key).as_str());

        alerts.push(Alert {
            id: RuleID::Cwe(String::from("1244")),
            details: String::from("Debugging enabled in the container"),
            severity: Severity::Medium,
            path: AlertLocation {
                path: compose_file.path.clone(),
                line: mapping.copied(),
            },
        })
    }
    // TODO: better way of detecting this
    if key.contains("PASSWORD") || key.contains("KEY") || key.contains("TOKEN") {
        let mapping = compose_file
            .mappings
            .get(format!("services.{}.environment.{}", service_name, key).as_str());

        alerts.push(Alert {
            id: RuleID::Cwe(String::from("215")),
            details: String::from("Possible Hardcoded password"),
            severity: Severity::Low,
            path: AlertLocation {
                path: compose_file.path.clone(),
                line: mapping.copied(),
            },
        })
    }
}

/// Environment Variable rules
pub fn environment_variables(
    _config: &Config,
    compose_file: &ComposeFile,
    alerts: &mut Vec<crate::security::Alert>,
) -> Result<()> {
    for (name, service) in &compose_file.compose.services {
        if let Some(envvars) = &service.environment {
            match envvars {
                ListOrHashMap::Vec(envvec) => {
                    for envvar in envvec {
                        match envvar {
                            StringOrNumber::Str(str) => {
                                if let Some((key, value)) = str.split_once('=') {
                                    check_environment(
                                        compose_file,
                                        alerts,
                                        name,
                                        key.to_string(),
                                        value.to_string(),
                                    )
                                }
                            }
                            _ => {
                                debug!("Unsupported type check int / none: {}", compose_file)
                            }
                        }
                    }
                }
                ListOrHashMap::Hash(envhash) => {
                    // warn!("Unsupported feature: envvars HashMap for {}", compose_file);
                    for (key, value) in envhash {
                        match value {
                            StringOrNumber::Str(value) => {
                                check_environment(
                                    compose_file,
                                    alerts,
                                    name,
                                    key.to_string(),
                                    value.to_string(),
                                );
                            }
                            _ => {
                                debug!("Unsupported type check int / none: {}", compose_file)
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
