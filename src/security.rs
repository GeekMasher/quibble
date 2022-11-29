#![allow(unused)]
use std::{fmt::Display, ops::Index};

use crate::{compose::ComposeFile, security};

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


impl Severity {
    /// Should I based on a filter (String) need to display this?
    pub fn filter(&self, filter: String) -> bool {
        // TODO: Create a better filter function...
        let sevs = vec!["critical", "high", "errors", "medium", "low", "warnings", "information", "notes", "quality"];

        let filter_lower = filter.to_lowercase();
        let display = format!("{}", self).to_lowercase();

        let (fl, _) = sevs.iter().enumerate().find(|(i, &s)| s == filter_lower).unwrap();
        let (di, _) = sevs.iter().enumerate().find(|(i, &s)| s == display).unwrap();

        di > fl
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
    pub path: AlertLocation,
}

impl Alert {
    pub fn new() -> Self {
        Alert { .. Default::default() }
    }
}

impl Display for Alert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Alert({}, '{}', '{}', '{}')", self.severity, self.id, self.details, self.path)
    }
}

#[derive(Debug, Default)]
pub struct AlertLocation {
    pub path: String,
    pub line: Option<i32>,
}

impl Display for AlertLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.line {
            Some(l) => { write!(f, "{}#{}", self.path, l) },
            None => { write!(f, "{}", self.path) }
        }
    }
}

pub trait Rule {
    fn check(alerts: &mut Vec<Alert>, compose_file: &ComposeFile);
}

