#![allow(unused)]
use std::{fmt::Display, ops::Index};

use crate::{compose::ComposeFile, security};


const SEVERITIES: &[&str; 9] = &[
    "critical",
    "high",
    "errors",
    "medium",
    "low",
    "warnings",
    "information",
    "notes",
    "quality"
];


#[derive(Debug)]
/// Severity for the alert
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Information,
    Quality,
}

impl Severity {
    /// Filter allows a user to check if a security should be displayed to the user or not
    pub fn filter(&self, filter: String) -> bool {
        // TODO: Create a better filter function...
        let filter_lower = filter.to_lowercase();
        let display = format!("{}", self).to_lowercase();

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


#[derive(Debug)]
/// Rule ID using CWE or OWASP Docker Top 10
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


#[derive(Debug, Default)]
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
        Alert { .. Default::default() }
    }
}

impl Display for Alert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Alert({}, '{}', '{}', '{}')", self.severity, self.id, self.details, self.path)
    }
}


#[derive(Debug, Default)]
/// Alert Location with a path and line number
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


/// Rule Trait which all rules need to follow
pub trait Rule {
    fn check(alerts: &mut Vec<Alert>, compose_file: &ComposeFile);
}



#[cfg(test)]
mod tests {
    use crate::security::Severity;

    #[test]
    fn filter() {
        assert!(Severity::Medium.filter(String::from("medium")));
        assert!(Severity::High.filter(String::from("medium")));
        assert!(!Severity::Low.filter(String::from("medium")));
    }
}


