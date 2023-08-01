use anyhow::Result;
use log::debug;

use crate::{
    compose::{ComposeFile, ListOrHashMap, StringOrBuild, StringOrNumber},
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

pub fn privileged(
    _config: &Config,
    compose_file: &ComposeFile,
    alerts: &mut Vec<crate::security::Alert>,
) -> Result<()> {
    for service in compose_file.compose.services.values() {
        if let Some(privilege) = &service.privileged {
            if *privilege {
                alerts.push(Alert {
                    id: RuleID::Quibble("PRIVILEGED_CONTAINER".to_string()),
                    details: String::from("Container privilege enabled"),
                    severity: Severity::High,
                    path: AlertLocation {
                        path: compose_file.path.clone(),
                        ..Default::default()
                    },
                    ..Default::default()
                })
            }
        }
    }
    Ok(())
}

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
                    ..Default::default()
                });
            }
        }
    }
    Ok(())
}

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

/// Security Opts Rule
pub fn security_opts(
    _config: &Config,
    compose_file: &ComposeFile,
    alerts: &mut Vec<crate::security::Alert>,
) -> Result<()> {
    for (name, service) in &compose_file.compose.services {
        if let Some(secopts) = &service.security_opt {
            let mapping = compose_file
                .mappings
                .get(format!("services.{}.security_opt", name).as_str());

            for secopt in secopts {
                if secopt.starts_with("no-new-privileges") && secopt.ends_with("false") {
                    alerts.push(Alert {
                        id: RuleID::Quibble("SECURITY_OPTS".to_string()),
                        details: format!(
                            "Security Opts `no-new-privileges` set to `false` for '{service}'"
                        ),
                        severity: Severity::High,
                        path: AlertLocation {
                            path: compose_file.path.clone(),
                            line: mapping.copied(),
                        },
                    })
                }
            }
        } else {
            let mapping = compose_file
                .mappings
                .get(format!("services.{}", name).as_str());

            alerts.push(Alert {
                id: RuleID::Quibble("SECURITY_OPTS".to_string()),
                details: format!("Security Opts `no-new-privileges` not set for '{service}'"),
                severity: Severity::High,
                path: AlertLocation {
                    path: compose_file.path.clone(),
                    line: mapping.copied(),
                },
            })
        }
    }
    Ok(())
}

pub fn kernel_parameters(
    _config: &Config,
    compose_file: &ComposeFile,
    alerts: &mut Vec<crate::security::Alert>,
) -> Result<()> {
    for service in compose_file.compose.services.values() {
        if let Some(syscalls) = &service.sysctls {
            alerts.push(Alert {
                id: RuleID::Quibble("KERNEL_PARAMETERS".to_string()),
                details: String::from("Enabling extra syscalls"),
                ..Default::default()
            });

            fn syscall_check(
                syscall: &String,
                compose_file: &ComposeFile,
                alerts: &mut Vec<crate::security::Alert>,
            ) {
                if syscall.starts_with("net.ipv4.conf.all") {
                    alerts.push(Alert {
                        id: RuleID::Quibble("KERNEL_PARAMETERS".to_string()),
                        details: format!("IPv4 Kernal Parameters modified: {syscall}"),
                        severity: Severity::Information,
                        path: AlertLocation {
                            path: compose_file.path.clone(),
                            ..Default::default()
                        },
                    })
                }
            }

            match syscalls {
                ListOrHashMap::Vec(v) => {
                    for syscall in v {
                        match syscall {
                            StringOrNumber::Str(syscall) => {
                                syscall_check(syscall, compose_file, alerts);
                            }
                            _ => {
                                debug!("Unsupported syscall type: int / none")
                            }
                        }
                    }
                }
                ListOrHashMap::Hash(h) => {
                    for syscall in h.keys() {
                        syscall_check(syscall, compose_file, alerts);
                    }
                }
            }
        }

        if let Some(capabilities) = &service.cap_add {
            alerts.push(Alert {
                id: RuleID::Quibble("KERNEL_PARAMETERS".to_string()),
                details: String::from("Using extra Kernel Parameters"),
                ..Default::default()
            });

            for cap in capabilities {
                // https://man7.org/linux/man-pages/man7/capabilities.7.html
                // https://cloud.redhat.com/blog/increasing-security-of-istio-deployments-by-removing-the-need-for-privileged-containers
                if cap.contains("NET_ADMIN") {
                    alerts.push(Alert {
                        id: RuleID::Quibble("NET_ADMIN".to_string()),
                        details: String::from("Container with high networking privileages"),
                        severity: Severity::Medium,
                        path: AlertLocation {
                            path: compose_file.path.clone(),
                            ..Default::default()
                        },
                    })
                }

                if cap.contains("SYS_ADMIN") {
                    alerts.push(Alert {
                        id: RuleID::Quibble("SYS_ADMIN".to_string()),
                        details: String::from("Container with high system privileages"),
                        severity: Severity::Medium,
                        path: AlertLocation {
                            path: compose_file.path.clone(),
                            ..Default::default()
                        },
                    })
                }

                if cap.contains("ALL") {
                    alerts.push(Alert {
                        id: RuleID::Quibble("ALL".to_string()),
                        details: String::from("All capabilities are enabled"),
                        severity: Severity::High,
                        path: AlertLocation {
                            path: compose_file.path.clone(),
                            ..Default::default()
                        },
                        ..Default::default()
                    })
                }
            }
        }
    }
    Ok(())
}

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
