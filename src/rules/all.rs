use anyhow::Result;
use log::debug;

use crate::{
    compose::{ComposeFile, ListOrHashMap, StringOrNumber},
    config::Config,
    security::{Alert, AlertLocation, RuleID, Severity},
};

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
                        details: format!("IPv4 Kernel Parameters modified: {syscall}"),
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
