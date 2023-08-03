use anyhow::Result;

use crate::{
    compose::{ComposeFile, StringOrBuild},
    config::Config,
    security::{Alert, AlertLocation, RuleID, Severity},
};

/// Container Images
pub fn container_images(
    _config: &Config,
    compose_file: &ComposeFile,
    alerts: &mut Vec<crate::security::Alert>,
) -> Result<()> {
    for (name, service) in &compose_file.compose.services {
        // Manually building project
        if let Some(build_enum) = &service.build {
            let mapping_line = compose_file
                .mappings
                .get(format!("services.{}.build", name).as_str());

            match build_enum {
                StringOrBuild::Str(context) => alerts.push(Alert {
                    id: RuleID::Quibble("BUILD_CONTEXT".to_string()),
                    details: format!("Build context path: {context}"),
                    path: AlertLocation {
                        path: compose_file.path.clone(),
                        line: mapping_line.copied(),
                    },
                    ..Default::default()
                }),
                StringOrBuild::Build(build) => {
                    if let Some(context) = &build.context {
                        alerts.push(Alert {
                            id: RuleID::Quibble("BUILD_CONTEXT".to_string()),
                            details: format!("Build context path: {context}"),
                            path: AlertLocation {
                                path: compose_file.path.clone(),
                                line: mapping_line.copied(),
                            },
                            ..Default::default()
                        })
                    }
                }
            }
        }

        // Pulling remote image
        if let Some(image) = &service.image {
            let mapping_line = compose_file
                .mappings
                .get(format!("services.{}.image", name).as_str());

            // Format strings
            if image.contains("${") {
                alerts.push(Alert {
                    id: RuleID::Quibble("IMAGE_ENV_VAR".to_string()),
                    details: format!("Container Image using Environment Variable: {image}"),
                    path: AlertLocation {
                        path: compose_file.path.clone(),
                        line: mapping_line.copied(),
                    },
                    ..Default::default()
                })
            } else if let Ok(container) = service.parse_image() {
                alerts.push(Alert {
                    id: RuleID::Quibble("IMAGE_TAG".to_string()),
                    details: format!("Container Image: {container}"),
                    path: AlertLocation {
                        path: compose_file.path.clone(),
                        line: mapping_line.copied(),
                    },
                    ..Default::default()
                });

                // Rule: Pinned to latest rolling container image
                // - The main reason behind this is if you are using watchtower or other
                // service to update containers it might cause issues
                let latest = vec!["latest", "main", "master"];
                if latest.contains(&container.tag.as_str()) {
                    alerts.push(Alert {
                        id: RuleID::Quibble("IMAGE_TAG_LATEST".to_string()),
                        details: format!(
                            "Container using rolling release tag: `{}`",
                            container.tag
                        ),
                        severity: Severity::Medium,
                        path: AlertLocation {
                            path: compose_file.path.clone(),
                            line: mapping_line.copied(),
                        },
                        ..Default::default()
                    });
                }
            }
        }
    }
    Ok(())
}
