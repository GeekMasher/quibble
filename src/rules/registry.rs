use anyhow::Result;

use crate::{
    compose::ComposeFile,
    config::Config,
    security::{Alert, AlertLocation, RuleID, Severity},
};

/// Docker registry Rule
///
/// Make sure that the container is being pulled from a trusted source
pub fn docker_registry(
    config: &Config,
    compose_file: &ComposeFile,
    alerts: &mut Vec<crate::security::Alert>,
) -> Result<()> {
    for service in compose_file.compose.services.values() {
        if let Ok(container) = service.parse_image() {
            if !config.registries.contains(&container.instance) {
                alerts.push(Alert {
                    id: RuleID::Quibble("DOCKER_REGISTRY".to_string()),
                    details: format!("Container from unknown registry: {}", &container.instance),
                    severity: Severity::High,
                    path: AlertLocation {
                        path: compose_file.path.clone(),
                        ..Default::default()
                    },
                });
            }
        }
    }
    Ok(())
}
