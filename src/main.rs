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
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::{
    cli::{Cli, OutputMode},
    collector::{Collector, TraceDocument},
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
            let mut paths = vec![targets.librados];
            if let Some(librbd) = targets.librbd {
                paths.push(librbd);
            }
            paths.push(targets.libceph_common);
            paths.push(targets.radosgw);
            DwarfInput::native(paths, cli.ceph_version.clone())
        }
    };
    info!(source = %dwarf_input.description(), "loading DWARF probe data");
    let dwarf = dwarf_input.load()?;
    if cli.export_dwarf_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&export_dwarf_json(&dwarf))?
        );
        return Ok(());
    }
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
            println!(
                "{}",
                serde_json::to_string_pretty(&trace_output_document(&dwarf, &trace)?)?
            );
        }
        OutputMode::Otlp => {
            let export = if trace.spans.is_empty() {
                Ok(otel::ExportDiagnostics::default())
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
                )
            };
            // Serialize once so a failed export can still preserve the trace.
            let document = trace_output_document(&dwarf, &trace)?;
            finish_otlp_export(export, &document, &trace, &mut std::io::stdout())?;
        }
    }

    Ok(())
}

/// Build the `{dwarf, trace}` JSON document emitted by the `OutputMode::Json`
/// arm. Shared so a failed OTLP export can dump the exact same shape to stdout.
fn trace_output_document(
    dwarf: &crate::dwarf_json::DwarfInfo,
    trace: &TraceDocument,
) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "dwarf": dwarf.summary(),
        "trace": trace,
    }))
}

/// Finish an `OutputMode::Otlp` session given the outcome of the final
/// synchronous export.
///
/// On success (including a partially-failed export that still returned
/// diagnostics), logs the shutdown summary and returns `Ok`. On a hard export
/// failure the collected trace would otherwise be lost, so it is dumped to `out`
/// as the same pretty JSON `{dwarf, trace}` document as `OutputMode::Json`, the
/// failure is logged and surfaced in the shutdown summary, and the session ends
/// with an error that points the operator at the dumped trace. The failure is
/// never masked, and the data is never silently discarded.
fn finish_otlp_export(
    export: Result<otel::ExportDiagnostics>,
    document: &serde_json::Value,
    trace: &TraceDocument,
    out: &mut impl std::io::Write,
) -> Result<()> {
    match export {
        Ok(export) => {
            info!(
                spans = trace.spans.len(),
                events_decoded = trace.diagnostics.events_decoded,
                decode_errors = trace.diagnostics.decode_errors,
                rados_ops = trace.diagnostics.rados_ops,
                correlated_rados_ops = trace.diagnostics.correlated_rados_ops,
                background_rados_ops = trace.diagnostics.background_rados_ops,
                export_attempts = export.attempts,
                export_failures = export.failures,
                export_failed = false,
                "rgwtrace shutdown summary"
            );
            Ok(())
        }
        Err(err) => {
            error!(
                error = %format_args!("{err:#}"),
                "final OTLP export failed; dumping the collected trace to stdout so it is not lost"
            );
            info!(
                spans = trace.spans.len(),
                events_decoded = trace.diagnostics.events_decoded,
                decode_errors = trace.diagnostics.decode_errors,
                rados_ops = trace.diagnostics.rados_ops,
                correlated_rados_ops = trace.diagnostics.correlated_rados_ops,
                background_rados_ops = trace.diagnostics.background_rados_ops,
                export_failed = true,
                "rgwtrace shutdown summary"
            );
            writeln!(out, "{}", serde_json::to_string_pretty(document)?)
                .context("failed to dump the un-exported trace to stdout")?;
            Err(err.context("OTLP export failed; the collected trace was dumped to stdout as JSON"))
        }
    }
}

fn export_dwarf_json(dwarf: &crate::dwarf_json::DwarfInfo) -> serde_json::Value {
    let mut root = serde_json::Map::new();
    if let Some(version) = &dwarf.version {
        root.insert(
            "version".to_string(),
            serde_json::Value::String(version.clone()),
        );
    }
    if let Some(arch) = &dwarf.arch {
        root.insert("arch".to_string(), serde_json::Value::String(arch.clone()));
    }
    for (name, module) in &dwarf.modules {
        root.insert(
            name.clone(),
            serde_json::to_value(module).expect("module serialization cannot fail"),
        );
    }
    serde_json::Value::Object(root)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_trace() -> TraceDocument {
        Collector::default().into_trace_document("rgwtrace")
    }

    #[test]
    fn finish_otlp_export_returns_ok_without_dumping_on_success() {
        let trace = sample_trace();
        let document = serde_json::json!({ "trace": &trace });
        let mut out = Vec::new();

        let result = finish_otlp_export(
            Ok(otel::ExportDiagnostics::default()),
            &document,
            &trace,
            &mut out,
        );

        assert!(result.is_ok(), "a successful export must not error");
        assert!(
            out.is_empty(),
            "a successful export must not dump the trace to stdout"
        );
    }

    #[test]
    fn finish_otlp_export_dumps_trace_and_errors_on_failure() {
        let trace = sample_trace();
        let document = serde_json::json!({ "dwarf": "summary", "trace": &trace });
        let mut out = Vec::new();

        let result = finish_otlp_export(
            Err(anyhow::anyhow!("connection refused")),
            &document,
            &trace,
            &mut out,
        );

        let err = result.expect_err("a failed export must surface an error");
        // The failure is not masked...
        assert!(format!("{err:#}").contains("connection refused"));
        // ...and the error tells the operator where the data went.
        assert!(format!("{err}").contains("dumped to stdout"));
        // ...and the trace document was actually written to the sink.
        let dumped = String::from_utf8(out).expect("stdout dump must be valid UTF-8");
        let parsed: serde_json::Value =
            serde_json::from_str(&dumped).expect("dumped trace must be valid JSON");
        assert_eq!(parsed, document);
    }
}
