use std::{path::PathBuf, time::Duration};

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

    #[arg(long, value_parser = parse_http_header)]
    pub otlp_header: Vec<(String, String)>,

    #[arg(long, default_value = "5", value_parser = parse_duration_secs)]
    pub otlp_timeout: Duration,

    #[arg(long, default_value_t = 2)]
    pub otlp_retries: u32,

    #[arg(long, default_value = "none")]
    pub otlp_compression: OtlpCompression,

    #[arg(long, default_value = "30", value_parser = parse_duration_secs)]
    pub otlp_flush_interval: Duration,

    #[arg(long, default_value = "120", value_parser = parse_duration_secs)]
    pub correlation_ttl: Duration,

    #[arg(long, default_value = "rgwtrace")]
    pub service_name: String,

    #[arg(long, default_value = "warn")]
    pub log_level: String,

    #[arg(short = 'p', long)]
    pub pid: Option<i32>,

    #[arg(short = 't', long)]
    pub timeout: Option<u64>,

    #[arg(long)]
    pub dry_run: bool,

    #[arg(long)]
    pub preflight: bool,

    #[arg(long)]
    pub strict_build_id: bool,

    #[arg(long)]
    pub librados_path: Option<PathBuf>,

    #[arg(long)]
    pub librbd_path: Option<PathBuf>,

    #[arg(long)]
    pub libceph_common_path: Option<PathBuf>,

    #[arg(long)]
    pub radosgw_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputMode {
    Json,
    Otlp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OtlpCompression {
    None,
    Gzip,
}

fn parse_duration_secs(value: &str) -> Result<Duration, String> {
    let seconds = value
        .parse::<u64>()
        .map_err(|err| format!("invalid duration {value:?}: {err}"))?;
    if seconds == 0 {
        return Err("duration must be at least 1 second".to_string());
    }
    Ok(Duration::from_secs(seconds))
}

fn parse_http_header(value: &str) -> Result<(String, String), String> {
    let Some((name, header_value)) = value.split_once(':') else {
        return Err("header must use NAME:VALUE syntax".to_string());
    };
    let name = name.trim();
    let header_value = header_value.trim();
    if name.is_empty() || header_value.is_empty() {
        return Err("header name and value must be non-empty".to_string());
    }
    Ok((name.to_string(), header_value.to_string()))
}
