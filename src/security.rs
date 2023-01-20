#![allow(unused)]
use std::{cell::RefCell, fmt::Display, ops::Index, rc::Rc};

use anyhow::Result;
use log::{error, warn};

use crate::{
    compose::{rules, ComposeFile},
    config::Config,
    security,
};

const SEVERITIES: &[&str; 10] = &[
    "critical",
    "high",
    "errors",
    "medium",
    "low",
    "warnings",
    "information",
    "notes",
    "quality",
    "all",
];

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd)]
/// Severity for the alert
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Information,
    Quality,
    Hardening,
    All,
}

impl Severity {
    /// Filter allows a user to check if a security should be displayed to the user or not
    pub fn filter(&self, filter: String) -> bool {
        let filter_lower = filter.to_lowercase();
        let display = format!("{self}").to_lowercase();

        let mut fl = 0;
        let mut di = 0;

        for (index, &sev) in SEVERITIES.iter().enumerate() {
            if filter_lower == sev {
                fl = index;
            }
            if display == sev {
                di = index;
            }
        }

        di <= fl
    }
}

impl Default for Severity {
    fn default() -> Self {
        Self::Information
    }
}

impl From<String> for Severity {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "c" | "crit" | "critical" => Self::Critical,
            "h" | "high" => Self::High,
            "m" | "med" | "medium" => Self::Medium,
            "l" | "low" => Self::Low,
            "i" | "info" | "information" => Self::Information,
            "a" | "all" => Self::All,
            _ => {
                warn!("Unknown severity so setting to `All`");
                Self::All
            }
        }
    }
}

impl Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sev = match self {
            Self::Critical => "Crit",
            Self::High => "High",
            Self::Medium => "Med",
            Self::Low => "Low",
            Self::Information => "Info",
            Self::Quality => "Qual",
            Self::Hardening => "Hrdn",
            Self::All => "All",
        };
        write!(f, "{sev:^12}")
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
/// Rule ID using CWE or OWASP Docker Top 10
pub enum RuleID {
    Cwe(String),
    Owasp(String),
    None,
}

impl Default for RuleID {
    fn default() -> Self {
        RuleID::None
    }
}

impl Display for RuleID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = match self {
            RuleID::None => "N/A".to_string(),
            RuleID::Owasp(i) => {
                format!("OWASP-{i}")
            }
            RuleID::Cwe(c) => {
                format!("CWE-{c}")
            }
        };
        write!(f, "{id}")
    }
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
/// Security Alert and metadata
pub struct Alert {
    /// Details of the Alert
    pub details: String,
    /// Security of the Alert
    pub severity: Severity,
    /// Alert ID
    pub id: RuleID,
    /// Alert Location
    pub path: AlertLocation,
}

impl Alert {
    pub fn new() -> Self {
        Alert {
            ..Default::default()
        }
    }
}

impl Display for Alert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Alert({}, '{}', '{}', '{}')",
            self.severity, self.id, self.details, self.path
        )
    }
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
/// Alert Location with a path and line number
pub struct AlertLocation {
    pub path: String,
    pub line: Option<i32>,
}

impl Display for AlertLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.line {
            Some(l) => {
                write!(f, "{}#{}", self.path, l)
            }
            None => {
                write!(f, "{}", self.path)
            }
        }
    }
}

pub type Rule = dyn Fn(&Config, &ComposeFile, &mut Vec<Alert>) -> Result<()>;

pub struct Rules {
    config: Config,
    rules: Vec<Box<Rule>>,
}

impl Rules {
    pub fn new(config: Config) -> Self {
        let mut rules = Rules {
            config,
            rules: Vec::new(),
        };

        if !rules.config.disable_rules {
            rules
                .register(&rules::docker_version)
                .register(&rules::docker_socket)
                .register(&rules::docker_registry)
                .register(&rules::container_images)
                .register(&rules::kernel_parameters)
                .register(&rules::security_opts)
                .register(&rules::privileged)
                .register(&rules::environment_variables);
        }

        rules
    }

    pub fn run(&mut self, compose_file: &ComposeFile) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = Vec::new();
        for rule in self.rules.iter() {
            if let Err(err) = rule(&self.config, compose_file, &mut alerts) {
                error!("Error during rule execution: {err:?}");
            }
        }
        // Sort by severity
        alerts.sort_by(|a, b| a.severity.cmp(&b.severity));
        alerts
    }

    pub fn register<R>(&mut self, rule: R) -> &mut Self
    where
        R: Fn(&Config, &ComposeFile, &mut Vec<Alert>) -> Result<()> + 'static,
    {
        // let cell = Rc::new(RefCell::new(rule));
        // self.rules.push(cell);
        self.rules.push(Box::new(rule));
        self
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        compose::ComposeFile,
        security::{Alert, Rules, Severity},
    };

    #[test]
    fn compare_sevs() {
        assert!(Severity::High < Severity::Medium)
    }

    fn sort_sevs() {
        let sevs = vec![
            Severity::High,
            Severity::Low,
            Severity::Critical,
            Severity::Medium,
        ];
        assert_eq!(
            sevs,
            vec![
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low
            ]
        );
    }

    #[test]
    fn filter() {
        assert!(Severity::Medium.filter(String::from("medium")));
        assert!(Severity::High.filter(String::from("medium")));
    }
}
