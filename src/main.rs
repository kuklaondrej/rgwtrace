mod events;

mod classify;
mod cli;
mod collector;
mod dwarf_json;
mod live;
mod otel;
mod preflight;
mod targets;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::{
    cli::{Cli, OutputMode},
    collector::Collector,
    dwarf_json::DwarfInfo,
};

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(&cli.log_level);

    info!(path = %cli.import_json.display(), "loading DWARF JSON");
    let dwarf = DwarfInfo::from_path(&cli.import_json)?;
    if cli.preflight {
        let report = preflight::run(&cli, &dwarf)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    preflight::validate_cli(&cli)?;
    let trace = if cli.dry_run {
        Collector::default().into_trace_document(cli.service_name.clone())
    } else {
        live::run(&cli, &dwarf)?
    };

    match cli.output {
        OutputMode::Json => {
            let output = serde_json::json!({
                "dwarf": dwarf.summary(),
                "trace": trace,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputMode::Otlp => {
            otel::export_otlp_http(
                &cli.otlp_endpoint,
                &cli.otlp_header,
                cli.otlp_timeout,
                cli.otlp_retries,
                &trace,
            )?;
        }
    }

    Ok(())
}

fn init_logging(default_filter: &str) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_filter))
        .unwrap_or_else(|_| EnvFilter::new("warn"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
