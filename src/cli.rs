use std::path::PathBuf;

use clap::{Parser, Subcommand};

pub const VERSION_NUMBER: &str = env!("CARGO_PKG_VERSION");
pub const AUTHOR: &str = env!("CARGO_PKG_AUTHORS");

pub const BANNER: &str = r#" _____       _ _     _     _
|  _  |     (_) |   | |   | |
| | | |_   _ _| |__ | |__ | | ___
| | | | | | | | '_ \| '_ \| |/ _ \
\ \/' / |_| | | |_) | |_) | |  __/
 \_/\_\\__,_|_|_.__/|_.__/|_|\___|"#;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Arguments {
    /// Enable Debugging
    #[clap(long, default_value_t = false)]
    pub debug: bool,

    /// Disable Quibble Banner
    #[clap(long, default_value_t = false)]
    pub disable_banner: bool,

    /// Configuration file path
    #[clap(short, long, default_value = "./quibble.toml")]
    pub config: PathBuf,

    #[clap(subcommand)]
    pub commands: ArgumentCommands,
}

#[derive(Subcommand, Debug)]
pub enum ArgumentCommands {
    /// Check if setup and tools are all available
    Check,
    /// Scan compose file(s)
    Compose {
        /// Folder or compose file path
        #[clap(short, long, default_value = "./")]
        path: PathBuf,

        /// Output Location
        #[clap(short, long)]
        output: Option<PathBuf>,

        /// Output Format
        #[clap(long, default_value_t=String::from("cli"))]
        format: String,

        /// Base Source
        #[clap(short, long, default_value = "./")]
        base: PathBuf,

        /// Filter for which alerts are shown
        #[clap(short, long)]
        filter: Option<String>,

        /// Disable / Enabled CLI failure
        #[clap(long, default_value_t = false)]
        disable_fail: bool,
    },
    /// Scan registry containers
    Registry {
        /// Domain of the registry wanting to scan
        #[clap(short, long)]
        registry: String,

        /// Image name and tag from the registry
        #[clap(short, long)]
        image: Option<String>,
    },
}
