#![allow(unused)]
use std::{cell::RefCell, fmt::Display, ops::Index, path::PathBuf, rc::Rc};

use anyhow::Result;
use log::{error, warn};

use crate::{compose::ComposeFile, config::Config, rules::*, security};

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

#[derive(Debug, Default, PartialEq, Eq, Ord, PartialOrd)]
/// Severity for the alert
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    #[default]
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
            Self::Critical => "Critical".to_string(),
            Self::High => "High".to_string(),
            Self::Medium => "Medium".to_string(),
            Self::Low => "Low".to_string(),
            Self::Information => "Information".to_string(),
            Self::Quality => "Quality".to_string(),
            Self::Hardening => "Hardening".to_string(),
            Self::All => "All".to_string(),
        };
        write!(f, "{}", sev)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
/// Rule ID using CWE or OWASP Docker Top 10
pub enum RuleID {
    Quibble(String),
    Cwe(String),
    Owasp(String),
}

impl Default for RuleID {
    fn default() -> Self {
        RuleID::Quibble("N/A".to_string())
    }
}

impl Display for RuleID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = match self {
            RuleID::Quibble(q) => q.to_string(),
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

    pub fn cvss(&self) -> String {
        match self.severity {
            Severity::Critical => "10.0".to_string(),
            Severity::High => "7.0".to_string(),
            Severity::Medium => "5.0".to_string(),
            Severity::Low => "3.0".to_string(),
            Severity::Hardening => "2.0".to_string(),
            Severity::Information | Severity::All | Severity::Quality => "".to_string(),
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

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// Alert Location with a path and line number
pub struct AlertLocation {
    pub path: PathBuf,
    pub line: Option<i32>,
}

impl Display for AlertLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.line {
            Some(l) => {
                write!(f, "{}#{}", self.path.display(), l + 1)
            }
            None => {
                write!(f, "{}", self.path.display())
            }
        }
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
