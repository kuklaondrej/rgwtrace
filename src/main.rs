mod events;

mod classify;
mod cli;
mod collector;
mod dwarf_input;
mod dwarf_json;
mod dwarf_native;
mod live;
mod otel;
mod preflight;
mod targets;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::{
    cli::{Cli, OutputMode},
    collector::Collector,
    dwarf_input::DwarfInput,
};

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(&cli.log_level);

    let dwarf_input = match cli.dwarf_source {
        cli::DwarfSource::Json => DwarfInput::json(
            cli.import_json
                .clone()
                .context("--import-json is required when --dwarf-source json is used")?,
        ),
        cli::DwarfSource::Native => {
            let targets = targets::discover(&cli)?;
            DwarfInput::native(vec![
                targets.librados,
                targets.librbd,
                targets.libceph_common,
                targets.radosgw,
            ])
        }
    };
    info!(source = %dwarf_input.description(), "loading DWARF probe data");
    let dwarf = dwarf_input.load()?;
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
            let export = if trace.spans.is_empty() {
                otel::ExportDiagnostics::default()
            } else {
                otel::export_otlp_http(
                    otel::ExportConfig {
                        endpoint: &cli.otlp_endpoint,
                        headers: &cli.otlp_header,
                        compression: cli.otlp_compression,
                        max_spans_per_batch: cli.otlp_max_spans_per_batch,
                        max_bytes_per_batch: cli.otlp_max_bytes_per_batch,
                        timeout: cli.otlp_timeout,
                        retries: cli.otlp_retries,
                    },
                    &trace,
                )?
            };
            info!(
                spans = trace.spans.len(),
                events_decoded = trace.diagnostics.events_decoded,
                decode_errors = trace.diagnostics.decode_errors,
                rados_ops = trace.diagnostics.rados_ops,
                correlated_rados_ops = trace.diagnostics.correlated_rados_ops,
                background_rados_ops = trace.diagnostics.background_rados_ops,
                export_attempts = export.attempts,
                export_failures = export.failures,
                "rgwtrace shutdown summary"
            );
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
