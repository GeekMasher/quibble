use anyhow::Result;
use log::debug;

use crate::{
    compose::{ComposeFile, ListOrHashMap, StringOrBuild},
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
    match compose_file.compose.version.as_str() {
        "1" => alerts.push(Alert {
            id: RuleID::None,
            details: String::from("Compose v1"),
            severity: Severity::Medium,
            path: AlertLocation {
                path: compose_file.path.clone(),
                ..Default::default()
            },
        }),
        "2" | "2.0" | "2.1" | "2.2" | "2.3" | "2.4" => alerts.push(Alert {
            id: RuleID::None,
            details: String::from("Compose v2 used"),
            severity: Severity::Low,
            path: AlertLocation {
                path: compose_file.path.clone(),
                ..Default::default()
            },
        }),
        "3" | "3.0" | "3.1" | "3.2" | "3.3" | "3.4" | "3.5" => alerts.push(Alert {
            id: crate::security::RuleID::None,
            details: String::from("Using old Compose v3 spec, consider upgrading"),
            severity: Severity::Low,
            path: AlertLocation {
                path: compose_file.path.clone(),
                ..Default::default()
            },
        }),
        _ => {
            debug!("Unknown or secure version of Docker Compose")
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
    for service in compose_file.compose.services.values() {
        // Manually building project
        if let Some(build_enum) = &service.build {
            match build_enum {
                StringOrBuild::Str(context) => alerts.push(Alert {
                    details: format!("Build context path: {context}"),
                    ..Default::default()
                }),
                StringOrBuild::Build(build) => {
                    if let Some(context) = &build.context {
                        alerts.push(Alert {
                            details: format!("Build context path: {context}"),
                            ..Default::default()
                        })
                    }
                }
            }
        }

        // Pulling remote image
        if let Some(image) = &service.image {
            // Format strings
            if image.contains("${") {
                alerts.push(Alert {
                    details: format!("Container Image using Environment Variable: {image}"),
                    path: AlertLocation {
                        path: compose_file.path.clone(),
                        ..Default::default()
                    },
                    ..Default::default()
                })
            } else if let Ok(container) = service.parse_image() {
                alerts.push(Alert {
                    details: format!("Container Image: {container}"),
                    path: AlertLocation {
                        path: compose_file.path.clone(),
                        ..Default::default()
                    },
                    ..Default::default()
                });

                // Rule: Pinned to latest rolling container image
                // - The main reason behind this is if you are using watchtower or other
                // service to update containers it might cause issues
                let latest = vec!["latest", "main", "master"];
                if latest.contains(&container.tag.as_str()) {
                    alerts.push(Alert {
                        details: format!("Container using rolling release tag: `{}`", container.tag),
                        severity: Severity::Low,
                        path: AlertLocation {
                            path: compose_file.path.clone(),
                            ..Default::default()
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

    for service in compose_file.compose.services.values() {
        if let Some(volumes) = &service.volumes {
            let result = volumes
                .iter()
                .find(|&s| s.starts_with("/var/run/docker.sock"));

            if result.is_some() {
                alerts.push(Alert {
                    id: RuleID::Owasp("D04".to_string()),
                    details: String::from("Docker Socket being passed into container"),
                    severity: Severity::High,
                    path: AlertLocation {
                        path: compose_file.path.clone(),
                        ..Default::default()
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
    for service in compose_file.compose.services.values() {
        if let Some(secopts) = &service.security_opt {
            for secopt in secopts {
                if secopt.starts_with("no-new-privileges") && secopt.ends_with("false") {
                    alerts.push(Alert {
                        id: RuleID::Owasp("D04".to_string()),
                        details: String::from("Security Opts `no-new-privileges` set to `false`"),
                        severity: Severity::High,
                        path: AlertLocation {
                            path: compose_file.path.clone(),
                            ..Default::default()
                        },
                    })
                }
            }
        } else {
            alerts.push(Alert {
                id: RuleID::Owasp("D04".to_string()),
                details: String::from("Security Opts `no-new-privileges` not set"),
                severity: Severity::High,
                path: AlertLocation {
                    path: compose_file.path.clone(),
                    ..Default::default()
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
                        id: RuleID::None,
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
                        syscall_check(syscall, compose_file, alerts);
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
                details: String::from("Using extra Kernal Parameters"),
                ..Default::default()
            });

            for cap in capabilities {
                // https://man7.org/linux/man-pages/man7/capabilities.7.html
                // https://cloud.redhat.com/blog/increasing-security-of-istio-deployments-by-removing-the-need-for-privileged-containers
                if cap.contains("NET_ADMIN") {
                    alerts.push(Alert {
                        id: RuleID::None,
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
                        id: RuleID::None,
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

pub fn environment_variables(
    _config: &Config,
    compose_file: &ComposeFile,
    alerts: &mut Vec<crate::security::Alert>,
) -> Result<()> {
    for service in compose_file.compose.services.values() {
        if let Some(envvars) = &service.environment {
            for envvar in envvars {
                if envvar.contains("DEBUG") {
                    alerts.push(Alert {
                        id: RuleID::Cwe(String::from("1244")),
                        details: String::from("Debugging enabled in the container"),
                        severity: Severity::Medium,
                        path: AlertLocation {
                            path: compose_file.path.clone(),
                            ..Default::default()
                        },
                    })
                }
                // TODO: better way of detecting this
                if envvar.contains("PASSWORD") || envvar.contains("KEY") {
                    alerts.push(Alert {
                        id: RuleID::Cwe(String::from("215")),
                        details: format!("Possible Hardcoded password: {envvar}"),
                        severity: Severity::High,
                        path: AlertLocation {
                            path: compose_file.path.clone(),
                            ..Default::default()
                        },
                    })
                }
            }
        }
    }
    Ok(())
}
