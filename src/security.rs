#![allow(unused)]
use std::fmt::Display;

use crate::compose::ComposeFile;

#[derive(Debug)]
pub enum Severity {
    Critical,
    High,
    Medium,
    // Low
    Low,
    // Informational
    Information,
    //
    Quality,
}

#[derive(Debug)]
pub enum RuleID {
    Cwe(String),
    Owasp(String),
    None
}

impl Default for RuleID {
    fn default() -> Self {
        RuleID::None
    }
}

impl Display for RuleID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = match self {
            RuleID::None => { "N/A".to_string() },
            RuleID::Owasp(i) => { format!("OWASP-{}", i) },
            RuleID::Cwe(c) => { format!("CWE-{}", c) }
        };
        write!(f, "{}", id)
    }
}

impl Default for Severity {
   fn default() -> Self {
        Self::Information
    } 
}

impl Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sev = match self {
            Self::Critical => { "Critical" },
            Self::High => { "High" },
            Self::Medium => { "Medium" },
            Self::Low => { "Low" },
            Self::Information => { "Information" },
            Self::Quality => { "Quality" }
        };
        write!(f, "{}", sev)
    }
}

#[derive(Debug, Default)]
pub struct Alert {
    pub details: String,
    pub severity: Severity,
    pub id: RuleID,
}

impl Alert {
    pub fn new() -> Self {
        Alert { .. Default::default() }
    }
}

impl Display for Alert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if ! matches!(self.id, RuleID::None) {
            write!(f, "Alert({}, {}, '{}')", self.severity, self.id, self.details)
        }
        else {
            write!(f, "Alert({}, '{}')", self.severity, self.details)
        }
    }
}

pub trait Rule {
    fn check(alerts: &mut Vec<Alert>, compose_file: &ComposeFile);
}

