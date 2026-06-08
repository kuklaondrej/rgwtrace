use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(version, about = "Trace Ceph RGW requests and export telemetry")]
pub struct Cli {
    #[arg(short = 'i', long = "import-json")]
    pub import_json: PathBuf,

    #[arg(long, default_value = "json")]
    pub output: OutputMode,

    #[arg(long, default_value = "http://localhost:4318/v1/traces")]
    pub otlp_endpoint: String,

    #[arg(long, default_value = "rgwtrace")]
    pub service_name: String,

    #[arg(short = 'p', long)]
    pub pid: Option<i32>,

    #[arg(short = 't', long)]
    pub timeout: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputMode {
    Json,
    Otlp,
}
