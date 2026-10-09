use std::{path::PathBuf, time::Duration};

use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(version, about = "Trace Ceph RGW requests and export telemetry")]
pub struct Cli {
    #[arg(short = 'i', long = "import-json")]
    pub import_json: Option<PathBuf>,

    #[arg(long, default_value = "json")]
    pub dwarf_source: DwarfSource,

    #[arg(long)]
    pub ceph_version: Option<String>,

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

    #[arg(long, default_value_t = 512, value_parser = parse_positive_usize)]
    pub otlp_max_spans_per_batch: usize,

    #[arg(long, default_value_t = 0)]
    pub otlp_max_bytes_per_batch: usize,

    #[arg(long, default_value = "30", value_parser = parse_duration_secs)]
    pub otlp_flush_interval: Duration,

    /// Emit the run-summary diagnostic counters into the OTLP stream for live
    /// validation (default off).
    ///
    /// When set, every exported batch carries the cumulative run counters as
    /// `rgwtrace.diag.*` attributes on `ResourceSpans.resource`, and the final
    /// export adds a synthetic zero-duration `rgwtrace.run_summary` span carrying
    /// the same counters -- so a backend such as Tempo can surface numbers like
    /// `bpf_operate_seed_hits_reqstate` on an `--output otlp` run that never prints
    /// the JSON document.
    ///
    /// It is OFF by default because these are cumulative debug counters, not
    /// request telemetry: shipping them onto every span's resource and as a
    /// synthetic span pollutes the tracing backend. The same counters are ALWAYS
    /// available -- regardless of this flag -- in the end-of-run shutdown log line
    /// and in the `trace.diagnostics` block of the JSON output, so live validation
    /// never requires polluting OTLP.
    #[arg(long)]
    pub otlp_diagnostics: bool,

    #[arg(long, default_value = "120", value_parser = parse_duration_secs)]
    pub correlation_ttl: Duration,

    #[arg(long)]
    pub correlate_inferred: bool,

    /// Opt in to the fail-closed cross-thread RGW->RADOS correlation bridge
    /// (default off).
    ///
    /// RGW runs each S3 request as an asio coroutine that migrates to a different
    /// io_context pool thread at every yield, so request context written at one
    /// instant is abandoned at the next migration and the RADOS ops submitted
    /// afterwards look like background ops. This flag re-establishes the request's
    /// context on whatever thread is about to submit, at EVERY RADOS submit
    /// (`rgw_rados_operate`, both overloads), plus once on the execute thread
    /// (`rgw_process_authenticated`). Ops submitted from a migrated thread are then
    /// correlated and labelled `cross_thread`.
    ///
    /// Fail-closed and zero-mis-correlation by construction: the request is
    /// identified by the pointer VALUE of the `DoutPrefixProvider*` the submit
    /// carries (never dereferenced, never type-assumed), which is numerically the
    /// `req_state*` for a request's own dpp; any other dpp simply misses the bridge
    /// and correlates nothing. `_send_op` additionally re-validates every context
    /// against the request's liveness before stamping it. With the flag off no
    /// re-seed probe is attached and behavior is identical to not having the
    /// feature. Ops that never route through `rgw_rados_operate` (notably the
    /// striped `rgw::Aio` object-data path) remain `background`/`inferred`.
    #[arg(long)]
    pub correlate_cross_thread: bool,

    /// Drop the `RGWOp*` ALTERNATE bridge key, keying requests by their
    /// `req_state*` alone (default: the alternate key is ON).
    ///
    /// The alternate key is INSURANCE. It exists only in case RGW does not pass the
    /// `req_state` as the `DoutPrefixProvider*` at the `rgw_rados_operate` call
    /// sites -- inside an op's `execute()`, RGW often passes the `RGWOp` (`this`)
    /// instead. Without a matching key those submits miss the bridge and stay
    /// uncorrelated.
    ///
    /// It is also the ONE part of this design with a residual mis-correlation
    /// hazard that no amount of pointer-identity logic can remove:
    /// `RGWHandler_REST_S3Website::retarget` can free and replace an `RGWOp` while
    /// its request is still ALIVE, so a different `DoutPrefixProvider` heap object
    /// can be allocated at that address, be passed as a dpp, and be seeded as that
    /// request -- and the liveness gate PASSES, because the request genuinely is
    /// alive.
    ///
    /// Whether that risk buys anything is a MEASUREMENT, not an argument. Run with
    /// the key ON and read the run summary:
    ///
    ///   bpf_operate_seed_hits_reqstate healthy, bpf_operate_seed_hits_rgwop ~0
    ///       -> the key buys nothing. Pass this flag; the hazard disappears.
    ///   bpf_operate_seed_hits_rgwop is a large share of bpf_operate_seed_hits
    ///       -> the key is load-bearing. Keep it.
    ///
    /// Takes effect without a rebuild: it is published to the BPF side as a global
    /// before the probe that writes the key is attached.
    #[arg(long)]
    pub disable_rgw_op_bridge_key: bool,

    #[arg(long, default_value = "1", value_parser = parse_duration_secs)]
    pub inference_window: Duration,

    /// Cap on untagged RADOS ops waiting for a `--correlate-inferred` decision.
    /// Past it the oldest is decided immediately (usually as an ambiguous or
    /// no-candidate background op) and counted in
    /// `inference_pending_overflow_rados_ops`.
    #[arg(long, default_value_t = crate::collector::DEFAULT_INFERENCE_MAX_PENDING, value_parser = parse_positive_usize)]
    pub inference_max_pending: usize,

    /// How long a request whose END marker (`req_state::~req_state`) arrived is
    /// kept for late RADOS completions before it is exported, instead of the full
    /// `--correlation-ttl`. A straggler past it becomes a background op with
    /// reason `request_already_emitted`; it is never lost or duplicated. Capped
    /// at `--correlation-ttl`, and never shorter than `--inference-window` when
    /// `--correlate-inferred` is on.
    #[arg(long, default_value = "5", value_parser = parse_duration_secs)]
    pub closed_request_grace: Duration,

    #[arg(long, default_value = "rgwtrace")]
    pub service_name: String,

    // Default to `info` (not `warn`): native DWARF extraction can take ~30s+ on
    // real targets, and the "starting live tracing" / "finished live tracing"
    // readiness lines are `info!`. At `warn` an operator saw an empty stderr log
    // and started their workload before the trace window opened, mis-diagnosing
    // it as a probe that never fired. Logs go to stderr, so stdout stays clean.
    #[arg(long, default_value = "info")]
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
    pub export_dwarf_json: bool,

    #[arg(long)]
    pub strict_build_id: bool,

    #[arg(long, conflicts_with = "strict_build_id")]
    pub allow_build_id_mismatch: bool,

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
pub enum DwarfSource {
    Json,
    Native,
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

fn parse_positive_usize(value: &str) -> Result<usize, String> {
    let number = value
        .parse::<usize>()
        .map_err(|err| format!("invalid positive integer {value:?}: {err}"))?;
    if number == 0 {
        return Err("value must be at least 1".to_string());
    }
    Ok(number)
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
