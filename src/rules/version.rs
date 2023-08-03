use anyhow::Result;
use log::debug;

use crate::{
    compose::ComposeFile,
    config::Config,
    security::{Alert, AlertLocation, RuleID, Severity},
};

/// Check which compose spec version is being used
pub fn docker_version(
    _config: &Config,
    compose_file: &ComposeFile,
    alerts: &mut Vec<crate::security::Alert>,
) -> Result<()> {
    debug!("Compose Version rule enabled...");
    // https://docs.docker.com/compose/compose-file/compose-versioning/
    if let Some(version) = &compose_file.compose.version {
        match version.as_str() {
            "1" => alerts.push(Alert {
                id: RuleID::Quibble("COMPOSE_V1".to_string()),
                details: String::from("Compose v1"),
                severity: Severity::Medium,
                path: AlertLocation {
                    path: compose_file.path.clone(),
                    line: compose_file.mappings.get("version").copied(),
                },
            }),
            "2" | "2.0" | "2.1" | "2.2" | "2.3" | "2.4" => alerts.push(Alert {
                id: RuleID::Quibble("COMPOSE_V2".to_string()),
                details: String::from("Compose v2 used"),
                severity: Severity::Low,
                path: AlertLocation {
                    path: compose_file.path.clone(),
                    line: compose_file.mappings.get("version").copied(),
                },
            }),
            "3" | "3.0" | "3.1" | "3.2" | "3.3" | "3.4" | "3.5" => alerts.push(Alert {
                id: RuleID::Quibble("COMPOSE_V3".to_string()),
                details: String::from("Using old Compose v3 spec, consider upgrading"),
                severity: Severity::Low,
                path: AlertLocation {
                    path: compose_file.path.clone(),
                    line: compose_file.mappings.get("version").copied(),
                },
            }),
            _ => {
                debug!("Unknown or secure version of Docker Compose")
            }
        }
    }
    Ok(())
}
