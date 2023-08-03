// her

use anyhow::Result;
use log::debug;

use crate::{
    compose::ComposeFile,
    config::Config,
    security::{Alert, AlertLocation, RuleID, Severity},
};

/// Docker Socket Rule
pub fn docker_socket(
    _config: &Config,
    compose_file: &ComposeFile,
    alerts: &mut Vec<crate::security::Alert>,
) -> Result<()> {
    debug!("Docker Socker Rule enabled...");

    for (name, service) in &compose_file.compose.services {
        if let Some(volumes) = &service.volumes {
            let result = volumes
                .iter()
                .find(|&s| s.starts_with("/var/run/docker.sock"));

            if result.is_some() {
                let mapping_line = compose_file
                    .mappings
                    .get(format!("services.{}.volumes", name).as_str());

                alerts.push(Alert {
                    id: RuleID::Quibble("DOCKER_SOCKET".to_string()),
                    details: String::from("Docker Socket being passed into container"),
                    severity: Severity::High,
                    path: AlertLocation {
                        path: compose_file.path.clone(),
                        line: mapping_line.copied(),
                    },
                })
            }
        }
    }
    Ok(())
}
