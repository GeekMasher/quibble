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
    #[clap(long, help = "Enable Debugging", default_value_t = false)]
    pub debug: bool,

    #[clap(long, help = "Disable Quibble Banner", default_value_t = false)]
    pub disable_banner: bool,

    #[clap(
        short,
        long,
        help = "Configuration file path",
        default_value_t=String::from("./quibble.toml")
    )]
    pub config: String,

    #[clap(subcommand)]
    pub commands: ArgumentCommands,
}

#[derive(Subcommand, Debug)]
pub enum ArgumentCommands {
    // Check if setup and tools are all avalible
    Check,
    // Scan compose file(s)
    Compose {
        #[clap(
            short,
            long,
            help = "Folder or compose file path",
            default_value_t=String::from("./")
        )]
        path: String,

        #[clap(
            short,
            long,
            help = "Filter for which alerts are shown",
            default_value_t=String::from("errors")
        )]
        filter: String,
    },
    // Scan registry containers
    Registry {
        #[clap(short, long, help = "Domain of the registry wanting to scan")]
        registry: String,

        #[clap(short, long, help = "Image name and tag from the registry")]
        image: Option<String>,
    },
}
