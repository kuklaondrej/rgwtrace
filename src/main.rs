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
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::{
    cli::{Cli, OutputMode},
    collector::{Collector, TraceDocument},
    dwarf_input::DwarfInput,
    dwarf_json::DwarfInfo,
};

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(&cli.log_level);

    // Built first: a bad CA file or a malformed header must fail in
    // milliseconds, not after DWARF extraction and probe attach.
    let otlp_client = match cli.output {
        OutputMode::Otlp => Some(otel::ExportClient::from_cli(&cli)?),
        OutputMode::Json => None,
    };

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
        warn_if_export_unusable(&dwarf);
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
        warn_if_import_unusable(&dwarf);
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
            // Serialize once so a failed export can still preserve the trace.
            let document = trace_output_document(&dwarf, &trace)?;
            export_trace_otlp(
                otel::ExportConfig {
                    endpoint: &cli.otlp_endpoint,
                    client: otlp_client
                        .as_ref()
                        .expect("the OTLP client is built above for --output otlp"),
                    compression: cli.otlp_compression,
                    max_spans_per_batch: cli.otlp_max_spans_per_batch,
                    max_bytes_per_batch: cli.otlp_max_bytes_per_batch,
                    retries: cli.otlp_retries,
                    diagnostics: cli.otlp_diagnostics,
                },
                &trace,
                &document,
                &mut std::io::stdout(),
            )?;
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

/// The FINAL export of an `--output otlp` session: everything the live loop's
/// periodic drains left behind, plus -- when `--otlp-diagnostics` is set -- the
/// run summary.
///
/// With `--otlp-diagnostics` on it is deliberately UNCONDITIONAL. An empty final
/// trace is the NORMAL end to a live run, because the periodic drains have already
/// taken every span by then. But the final BPF counters are merged only after the
/// poll loop exits, so this document is the only one that carries the run's true
/// totals; skipping its export would leave the backend holding an earlier, stale
/// snapshot and the final numbers nowhere. `otel::export_final_otlp_http`
/// therefore always puts a diagnostics-bearing batch on the wire, spans or no
/// spans.
///
/// The consequence to accept, WITH the flag: an `--output otlp` run that captured
/// nothing still contacts the endpoint, so an unreachable endpoint is reported as
/// a failure instead of exiting silently. That is the correct trade -- "I asked
/// for OTLP diagnostics and nothing was delivered" must never be indistinguishable
/// from success.
///
/// With the flag off (the default) there is no run summary to force onto the wire,
/// so an empty final drain sends nothing -- the pre-diagnostics behavior -- and a
/// non-empty one exports its spans normally.
fn export_trace_otlp(
    config: otel::ExportConfig<'_>,
    trace: &TraceDocument,
    document: &serde_json::Value,
    out: &mut impl std::io::Write,
) -> Result<()> {
    let export = otel::export_final_otlp_http(config, trace);
    finish_otlp_export(export, document, trace, out)
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
    // Both arms render the COMPLETE diagnostics via `TraceDiagnostics::summary()`
    // rather than a hand-picked list of fields. An `--output otlp` run never prints
    // the JSON document, so this log line and the OTLP resource attributes are the
    // only two channels a live run can be evaluated through -- and a curated list
    // in either of them silently drops exactly the counters a new feature adds.
    match export {
        Ok(export) => {
            info!(
                spans = trace.spans.len(),
                diagnostics = %trace.diagnostics.summary(),
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
                diagnostics = %trace.diagnostics.summary(),
                export_failed = true,
                "rgwtrace shutdown summary"
            );
            writeln!(out, "{}", serde_json::to_string_pretty(document)?)
                .context("failed to dump the un-exported trace to stdout")?;
            Err(err.context("OTLP export failed; the collected trace was dumped to stdout as JSON"))
        }
    }
}

/// After `--export-dwarf-json` extraction, loudly warn (to stderr; stdout
/// carries the JSON) if any REQUIRED probe function resolved no var_fields in any
/// module. Such an artifact is silently unusable for live tracing: its `hprobes`
/// map stays empty and the uprobes return before emitting, so the tracer looks
/// healthy but captures nothing. Per-module empties are fine when another module
/// covers the function (the Ubuntu librados-vs-libceph-common split), so this
/// checks the cross-module total and only fires for a function empty everywhere,
/// naming the modules that produced a func2pc address but an empty func2vf.
fn warn_if_export_unusable(dwarf: &DwarfInfo) {
    for function in dwarf.required_functions_without_var_fields() {
        let modules = dwarf.modules_with_addr_but_empty_var_fields(function);
        warn!(
            function,
            ?modules,
            "exported DWARF artifact has NO variable fields for a required probe function; it is \
             UNUSABLE for live tracing (hprobes would be empty and the uprobe emits nothing) -- \
             re-run extraction against binaries with matching debuginfo"
        );
    }
}

/// At live start, warn (never hard-fail -- DWARF preflight stays advisory) if the
/// loaded/imported DWARF resolved no var_fields for a required probe function.
/// Fires before attach so the operator sees the dead-probe cause immediately;
/// complements the end-of-run `should_warn_no_request_markers` warning.
fn warn_if_import_unusable(dwarf: &DwarfInfo) {
    for function in dwarf.required_functions_without_var_fields() {
        warn!(
            function,
            "loaded DWARF has NO variable fields for a required probe function; its hprobe will \
             never populate and the uprobe will capture nothing -- the trace may be silently empty"
        );
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
    use std::sync::{Arc, Mutex};

    fn sample_trace() -> TraceDocument {
        Collector::default().into_trace_document("rgwtrace")
    }

    /// An end-of-run trace with NO spans (every span already left in a periodic
    /// drain) but real final counters -- the exact shape that used to lose its
    /// diagnostics.
    fn empty_trace_with_final_counters() -> TraceDocument {
        let mut trace = sample_trace();
        trace.spans.clear();
        trace.diagnostics.bpf_operate_seed_hits_reqstate = 41;
        trace.diagnostics.bpf_operate_seed_hits_rgwop = 7;
        trace
    }

    /// A `tracing` writer that captures the log into a buffer the test can read.
    #[derive(Clone)]
    struct CapturedLog(Arc<Mutex<Vec<u8>>>);

    impl CapturedLog {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Vec::new())))
        }

        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).expect("log must be UTF-8")
        }
    }

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Run `body` with the log captured, and return what was logged.
    fn capture_log(body: impl FnOnce()) -> String {
        let log = CapturedLog::new();
        let writer = log.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(tracing::Level::INFO)
            .finish();
        tracing::subscriber::with_default(subscriber, body);
        log.text()
    }

    /// THE SHUTDOWN LOG LINE, for the empty-final-trace case. The log is the other
    /// channel an `--output otlp` run can be evaluated through (it never prints the
    /// JSON document), so it must carry the FINAL counters even when the final
    /// trace holds no spans. Asserts on the emitted log text, not on
    /// `summary()`'s return value -- a summary that is built and never logged is
    /// the same bug as a batch that is built and never sent.
    #[test]
    fn shutdown_summary_log_carries_the_final_counters_with_no_spans() {
        let trace = empty_trace_with_final_counters();
        let document = serde_json::json!({ "trace": &trace });

        let logged = capture_log(|| {
            finish_otlp_export(
                Ok(otel::ExportDiagnostics::default()),
                &document,
                &trace,
                &mut Vec::new(),
            )
            .unwrap();
        });

        assert!(
            logged.contains("rgwtrace shutdown summary"),
            "the shutdown summary must be logged even when the final trace has no spans: {logged}"
        );
        assert!(
            logged.contains("bpf_operate_seed_hits_reqstate=41"),
            "the shutdown summary must carry the FINAL counters: {logged}"
        );
        assert!(
            logged.contains("bpf_operate_seed_hits_rgwop=7"),
            "the shutdown summary must carry the FINAL counters: {logged}"
        );
    }

    /// The same, on the export-failure path: the counters must survive a failed
    /// export, which is when an operator needs them most.
    #[test]
    fn shutdown_summary_log_carries_the_final_counters_when_the_export_fails() {
        let trace = empty_trace_with_final_counters();
        let document = serde_json::json!({ "trace": &trace });

        let logged = capture_log(|| {
            let result = finish_otlp_export(
                Err(anyhow::anyhow!("connection refused")),
                &document,
                &trace,
                &mut Vec::new(),
            );
            assert!(result.is_err());
        });

        assert!(logged.contains("rgwtrace shutdown summary"));
        assert!(
            logged.contains("bpf_operate_seed_hits_reqstate=41"),
            "a failed export must still log the final counters: {logged}"
        );
    }

    /// THE JSON PATH, for the same empty-final-trace case. It has no equivalent
    /// hole -- the document is printed unconditionally and serde carries every
    /// counter -- and this pins that: no `spans.is_empty()` short-circuit may ever
    /// be added to it.
    #[test]
    fn json_output_carries_the_final_counters_with_no_spans() {
        let trace = empty_trace_with_final_counters();
        let dwarf = DwarfInfo::default();

        let document = trace_output_document(&dwarf, &trace).unwrap();

        assert_eq!(document["trace"]["spans"].as_array().unwrap().len(), 0);
        assert_eq!(
            document["trace"]["diagnostics"]["bpf_operate_seed_hits_reqstate"],
            41
        );
        assert_eq!(
            document["trace"]["diagnostics"]["bpf_operate_seed_hits_rgwop"],
            7
        );
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
