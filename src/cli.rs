use clap::{Parser, Subcommand};


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Arguments {
    #[clap(long, default_value_t=false)]
    pub debug: bool,
    
    #[clap(short, long, default_value_t=String::from("./quibble.toml"))]
    config: String,

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
    Registry {
        #[clap(short, long)]
        registry: String,

        #[clap(short, long)]
        image: Option<String>,
    },
    // Scan Container / Docker files directory
    Build
}

