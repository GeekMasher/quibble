use crate::{compose::ComposeFile, config::Config, security::Alert};

pub mod all;
pub mod environment;
pub mod images;
pub mod registry;
pub mod socket;
pub mod version;

use all::*;
use anyhow::Result;
use environment::*;
use images::*;
use log::error;
use registry::*;
use socket::*;
use version::*;

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
                .register(docker_version)
                .register(docker_socket)
                .register(docker_registry)
                .register(container_images)
                .register(kernel_parameters)
                .register(security_opts)
                .register(privileged)
                .register(environment_variables);
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
        self.rules.push(Box::new(rule));
        self
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }
}
