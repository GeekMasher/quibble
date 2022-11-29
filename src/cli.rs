use clap::{Parser, Subcommand};


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Arguments {
    #[clap(long, default_value_t=false)]
    pub debug: bool,

    #[clap(subcommand)]
    pub commands: ArgumentCommands,
}

#[derive(Subcommand, Debug)]
pub enum ArgumentCommands {
    // Check if setup and tools are all avalible
    Check,
    // Scan compose file(s)
    Compose {
        #[clap(short, long, default_value_t=String::from("./"))]
        path: String,

        #[clap(short, long, default_value_t=String::from("errors"))]
        filter: String,
    },
    // Scan registry containers
    Registry,
    // Scan Container / Docker files directory
    Build
}

