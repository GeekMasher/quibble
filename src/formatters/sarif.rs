use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::security::Alert;

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifFile {
    /// https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json
    pub version: String,
    pub runs: Vec<Run>,
}

impl Default for SarifFile {
    fn default() -> Self {
        SarifFile {
            version: String::from("2.1.0"),
            runs: vec![],
        }
    }
}

impl SarifFile {
    /// Create a new SarifFile
    pub fn new() -> SarifBuilder {
        SarifBuilder::new()
    }

    pub fn write(&self, path: &PathBuf) -> Result<()> {
        let file = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(file, &self)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct SarifBuilder {
    tool: Tool,
    base: PathBuf,
    alerts: Vec<Alert>,
}

impl SarifBuilder {
    pub fn new() -> Self {
        SarifBuilder {
            ..Default::default()
        }
    }

    pub fn add_results(&mut self, results: Vec<Alert>) -> &mut Self {
        self.alerts.extend(results);
        self
    }

    pub fn base(&mut self, base: &PathBuf) -> &mut Self {
        self.base = std::fs::canonicalize(base).unwrap_or(base.clone());
        self
    }

    pub fn set_tool(&mut self, tool: String, version: String) -> &mut Self {
        self.tool = Tool {
            driver: Driver {
                name: tool,
                organization: String::from("geekmasher"),
                semantic_version: version,
                ..Default::default()
            },
        };
        self
    }

    pub fn build(&mut self) -> Result<SarifFile> {
        let mut sarif = SarifFile::default();
        let mut run = Run::default();
        run.tool = self.tool.clone();

        for alert in &self.alerts {
            let path = alert
                .path
                .path
                .strip_prefix(&self.base)
                .unwrap_or(&alert.path.path);

            run.tool.driver.rules.push(Rule {
                id: alert.id.to_string(),
                name: alert.details.to_string(),
                short_description: Message {
                    text: alert.details.to_string(),
                },
                full_description: Message {
                    text: alert.details.to_string(),
                },
                properties: Properties {
                    id: alert.id.to_string(),
                    severity: alert.severity.to_string().to_lowercase(),
                    security_severity: alert.cvss(),
                    precision: String::from("high"),
                    ..Default::default()
                },
                ..Default::default()
            });

            run.results.push(RunResult {
                rule_id: format!("{}", alert.id),
                message: Message {
                    text: alert.details.to_string(),
                },
                locations: vec![Location {
                    physical_location: PhysicalLocation {
                        artifact_location: ArtifactLocation {
                            uri: path.display().to_string(),
                            ..Default::default()
                        },
                        region: Region {
                            start_line: alert.path.line.unwrap_or(0) + 1,
                            ..Default::default()
                        },
                    },
                }],
            });
        }

        sarif.runs.push(run);
        Ok(sarif)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Run {
    pub tool: Tool,
    pub results: Vec<RunResult>,
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RunResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub message: Message,
    pub locations: Vec<Location>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Location {
    #[serde(rename = "physicalLocation")]
    pub physical_location: PhysicalLocation,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
    pub region: Region,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactLocation {
    pub uri: String,
    #[serde(rename = "uriBaseId")]
    pub uri_base_id: String,
    pub index: u32,
}

impl Default for ArtifactLocation {
    fn default() -> Self {
        ArtifactLocation {
            uri: String::new(),
            uri_base_id: String::from("%SRCROOT%"),
            index: 0,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Region {
    #[serde(rename = "startLine")]
    pub start_line: i32,
    #[serde(rename = "startColumn")]
    pub start_column: i32,
    #[serde(rename = "endLine")]
    pub end_line: i32,
    #[serde(rename = "endColumn")]
    pub end_column: i32,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub driver: Driver,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Driver {
    pub name: String,
    pub organization: String,
    #[serde(rename = "semanticVersion")]
    pub semantic_version: String,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: Message,
    #[serde(rename = "fullDescription")]
    pub full_description: Message,
    #[serde(rename = "helpUri")]
    pub help_uri: String,
    pub properties: Properties,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Message {
    pub text: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Properties {
    pub tags: Vec<String>,
    pub precision: String,
    pub severity: String,
    #[serde(rename = "security-severity")]
    pub security_severity: String,
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub location: ArtifactLocation,
}
