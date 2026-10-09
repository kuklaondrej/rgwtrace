use std::{
    ffi::CString,
    mem::{align_of, size_of},
    path::Path,
    ptr::NonNull,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use libbpf_rs::{
    skel::OpenSkel, skel::SkelBuilder, AsRawLibbpf, Link, MapCore, MapFlags, OpenObject,
    RingBufferBuilder,
};
use tracing::{debug, info, warn};

use crate::{
    cli::{Cli, OutputMode},
    collector::{BpfDiagnostics, Collector, ExpiredBatch, TraceDocument},
    dwarf_json::{
        module_key_for_path, DwarfInfo, RadosOperateProbe, RequestEndProbe, RequestEndProbeGap,
        VarFieldKernel, REQ_STATE_DTOR, RGW_PROCESS_AUTHENTICATED, RGW_RADOS_OPERATE_READ,
        RGW_RADOS_OPERATE_WRITE,
    },
    events::{
        RawRadosEvent, RawRequestEvent, TraceEvent, RGWTRACE_EVENT_RADOS_OP,
        RGWTRACE_EVENT_REQUEST_END, RGWTRACE_EVENT_REQUEST_START,
    },
    otel, preflight, targets,
};

mod skel {
    include!(concat!(env!("OUT_DIR"), "/rgwtrace.skel.rs"));
}

use skel::*;

const EVENT_DATA_OFFSET: usize = 8;
const EINTR: i32 = 4;
// In DRAINS, not spans: each unit is one whole flush-interval drain. Splitting a
// drain into fixed-size units behind a fixed unit capacity would bound memory,
// but at production drain sizes (~10^5-10^6 spans) the poll thread's try_send
// loop outruns any HTTP exporter and would drop most of every drain -- far more
// than today, where a drop needs the exporter to be two whole intervals behind.
const OTLP_EXPORT_QUEUE_CAPACITY: usize = 2;
const BPF_DIAG_RINGBUF_REQUEST_DROPS: u32 = 0;
const BPF_DIAG_RINGBUF_RADOS_DROPS: u32 = 1;
const BPF_DIAG_RADOS_MAP_DROPS: u32 = 2;
const BPF_DIAG_RADOS_FINISH_MISSES: u32 = 3;
const BPF_DIAG_REQUEST_CONTEXT_DROPS: u32 = 4;
const BPF_DIAG_PROBE_READ_FAILURES: u32 = 5;
const BPF_DIAG_REQSTATE_MAP_DROPS: u32 = 6;
const BPF_DIAG_RESEED_HITS: u32 = 7;
const BPF_DIAG_RESEED_MISSES: u32 = 8;
const BPF_DIAG_RESEED_BASE_UNRESOLVED: u32 = 9;
const BPF_DIAG_REQUEST_END_HITS: u32 = 10;
const BPF_DIAG_REQUEST_END_MISSES: u32 = 11;
const BPF_DIAG_REQUEST_END_BASE_UNRESOLVED: u32 = 12;
const BPF_DIAG_SENDOP_STALE_CTX_DROPS: u32 = 13;
const BPF_DIAG_SENDOP_UNVERIFIABLE_CTX: u32 = 14;
const BPF_DIAG_OPERATE_SEED_HITS: u32 = 15;
const BPF_DIAG_OPERATE_SEED_MISSES: u32 = 16;
const BPF_DIAG_OPERATE_BASE_UNRESOLVED: u32 = 17;
const BPF_DIAG_SENDOP_UNBRIDGED_CTX_DROPS: u32 = 18;
const BPF_DIAG_OPERATE_MISS_CTX_CLEARED: u32 = 19;
const BPF_DIAG_RGWOP_KEY_INSERTS: u32 = 20;
const BPF_DIAG_RGWOP_KEY_REVOKES: u32 = 21;
const BPF_DIAG_RGWOP_KEY_REVOKE_SKIPPED: u32 = 22;
const BPF_DIAG_RGWOP_KEY_UNRESOLVED: u32 = 23;
const BPF_DIAG_OPERATE_SEED_HITS_REQSTATE: u32 = 24;
const BPF_DIAG_OPERATE_SEED_HITS_RGWOP: u32 = 25;
const BPF_DIAG_OPERATE_SEED_HITS_UNATTRIBUTED: u32 = 26;
const BPF_DIAG_OPERATE_UNRESOLVED_CTX_CLEARED: u32 = 27;
const BPF_DIAG_RGWOP_KEY_REVOKE_ABSENT: u32 = 28;
const BPF_DIAG_RGWOP_KEY_INDEX_DROPS: u32 = 29;
const BPF_DIAG_RGWOP_KEY_DISABLED: u32 = 30;
const BPF_DIAG_OPERATE_MISS_HOME_CTX_PRESERVED: u32 = 31;
const BPF_DIAG_OPERATE_UNRESOLVED_HOME_CTX_PRESERVED: u32 = 32;

struct OtlpExporter {
    // Detached request groups, not rendered spans: the exporter thread renders
    // them, so the ring-buffer thread never pays for span construction.
    sender: SyncSender<ExpiredBatch>,
    handle: JoinHandle<Result<otel::ExportDiagnostics>>,
}

struct OtlpExporterConfig {
    service_name: String,
    endpoint: String,
    headers: Vec<(String, String)>,
    compression: crate::cli::OtlpCompression,
    max_spans_per_batch: usize,
    max_bytes_per_batch: usize,
    timeout: Duration,
    retries: u32,
    diagnostics: bool,
}

pub fn run(cli: &Cli, dwarf: &DwarfInfo) -> Result<TraceDocument> {
    let targets = preflight::validated_targets(cli, dwarf)?;
    let pid = cli.pid.unwrap_or(-1);
    info!(pid, "starting live tracing");

    let mut open_object = std::mem::MaybeUninit::<OpenObject>::uninit();
    let open = RgwtraceSkelBuilder::default().open(&mut open_object)?;
    configure_rodata(open.maps.rodata_data, dwarf.version.as_deref())?;
    let mut skel = open.load()?;

    populate_hprobes(&mut skel.maps.hprobes, dwarf)?;
    // The BPF globals (`REQUEST_END_PROBE_ATTACHED`, `RGW_OP_BRIDGE_KEY_ENABLED`)
    // are published INSIDE attach_probes, between the destructor attach and the
    // first probe that can create or consume a bridge entry. Publishing them here,
    // after every probe is already live, is exactly the ordering bug that let a
    // request complete before its revoker existed -- see `ATTACH_ORDER`.
    let attached = attach_probes(
        &mut skel,
        dwarf,
        &targets,
        pid,
        cli.correlate_cross_thread,
        !cli.disable_rgw_op_bridge_key,
    )?;
    let _links = attached.links;
    let timestamp_offset_ns = unix_boottime_offset_ns()?;

    let mut collector_state = if cli.correlate_inferred {
        Collector::with_inferred_correlation(duration_ns(cli.inference_window))
    } else {
        Collector::default()
    };
    // Same fact, userspace half: with the END probe attached, a request that has
    // not produced an END is still OPEN and must not be TTL-expired out from
    // under its pending END (which would export it twice). Without it, no END is
    // ever coming and the plain idle TTL is correct.
    collector_state.set_end_probe_attached(attached.request_end_probe);
    collector_state.set_closed_request_grace(duration_ns(cli.closed_request_grace));
    collector_state.set_inference_max_pending(cli.inference_max_pending);
    let collector = Arc::new(Mutex::new(collector_state));
    let otlp_exporter = matches!(cli.output, OutputMode::Otlp).then(|| OtlpExporter::spawn(cli));
    let collector_cb = Arc::clone(&collector);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);
    ctrlc::set_handler(move || stop_handler.store(true, Ordering::SeqCst))
        .context("failed to install Ctrl-C handler")?;

    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(&skel.maps.events, move |data| {
        match decode_event(data) {
            Ok(mut event) => {
                event.add_timestamp_offset(timestamp_offset_ns);
                collector_cb
                    .lock()
                    .expect("collector lock poisoned")
                    .push(event);
            }
            Err(err) => {
                collector_cb
                    .lock()
                    .expect("collector lock poisoned")
                    .record_decode_error();
                warn!(error = %format_args!("{err:#}"), "failed to decode rgwtrace event");
            }
        }
        0
    })?;
    let ringbuf = ringbuf_builder.build()?;

    let started = Instant::now();
    let mut last_flush = Instant::now();
    // Latches once the OTLP exporter thread dies so a single fatal/misconfig
    // OTLP response cannot tear down the session or spam the log.
    let mut otlp_export_disabled = false;
    // Batches drained from the collector for OTLP export but stranded when the
    // exporter channel was found `Disconnected`. Those spans have already left
    // the collector, so retain them here and fold them back into the end-of-run
    // trace rather than losing them.
    let mut retained_otlp: Vec<ExpiredBatch> = Vec::new();
    loop {
        let ret = ringbuf.poll_raw(Duration::from_millis(250));
        if ret < 0 {
            let errno = -ret;
            if errno == EINTR {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                continue;
            }
            return Err(libbpf_rs::Error::from_raw_os_error(errno).into());
        }
        if stop.load(Ordering::SeqCst) {
            break;
        }
        if let Some(timeout) = cli.timeout {
            if started.elapsed() >= Duration::from_secs(timeout) {
                debug!(timeout_seconds = timeout, "trace timeout reached");
                break;
            }
        }
        if matches!(cli.output, OutputMode::Otlp) && last_flush.elapsed() >= cli.otlp_flush_interval
        {
            merge_bpf_diagnostics(&skel.maps.diagnostics, &collector)?;
            if let Some(exporter) = &otlp_exporter {
                if let Some(retained) = queue_expired_otlp(
                    cli,
                    &collector,
                    &exporter.sender,
                    &mut otlp_export_disabled,
                )? {
                    retained_otlp.push(retained);
                }
            }
            last_flush = Instant::now();
        }
    }

    drop(ringbuf);
    merge_bpf_diagnostics(&skel.maps.diagnostics, &collector)?;
    if let Some(exporter) = otlp_exporter {
        // The exporter thread returns `Err` after a fatal/exhausted OTLP export.
        // Surface it for logging, but never let it abort the session: the
        // collected spans below must still be emitted on the non-OTLP path.
        match exporter.finish() {
            Ok(export) => info!(
                export_batches = export.batches,
                export_attempts = export.attempts,
                export_failures = export.failures,
                "finished live OTLP exporter"
            ),
            Err(err) => warn!(
                error = %format_args!("{err:#}"),
                "live OTLP exporter thread ended with an error; continuing without OTLP export"
            ),
        }
    }
    let collector = Arc::try_unwrap(collector)
        .map_err(|_| anyhow::anyhow!("collector still has outstanding references"))?
        .into_inner()
        .expect("collector lock poisoned");
    let mut trace = collector.into_trace_document(cli.service_name.clone());
    if !retained_otlp.is_empty() {
        // Merge only the spans: `drain_expired` already folded these batches'
        // diagnostics into the collector's cumulative counters (which
        // `into_trace_document` above emitted), so the retained snapshots are
        // stale and must be discarded to avoid double counting.
        let retained_spans: usize = retained_otlp.iter().map(ExpiredBatch::span_count).sum();
        for batch in retained_otlp {
            trace
                .spans
                .extend(batch.into_trace_document(cli.service_name.clone()).spans);
        }
        trace.diagnostics.spans_produced = trace.spans.len() as u64;
        debug!(
            retained_spans,
            "merged OTLP spans stranded by a disconnected exporter into the end-of-run trace"
        );
    }
    // The run summary belongs in the log, not only in the JSON body: with
    // `--output otlp` the JSON document is never printed, so without it a live run
    // cannot be evaluated without guessing.
    //
    // EVERY counter, rendered from `TraceDiagnostics::counters()` -- not a curated
    // list of `info!` fields. The curated list was how the Phase B counters came to
    // be missing from the OTLP export: a hand-maintained subset silently falls
    // behind the struct, and the counters that go missing are always the newest
    // ones, i.e. exactly the ones a validation run needs.
    info!(
        spans = trace.spans.len(),
        diagnostics = %trace.diagnostics.summary(),
        "finished live tracing"
    );
    // Operator UX: OTLP export backpressure silently dropped batches during the
    // run. Surface it as a warning so a partial export is not mistaken for a
    // complete one; the counters above give the exact magnitude.
    if should_warn_otlp_queue_drops(trace.diagnostics.otlp_queue_dropped_spans) {
        warn!(
            otlp_queue_dropped_traces = trace.diagnostics.otlp_queue_dropped_traces,
            otlp_queue_dropped_spans = trace.diagnostics.otlp_queue_dropped_spans,
            "dropped OTLP spans under export backpressure -- the exported trace is incomplete"
        );
    }
    // Operator UX: RADOS ops were seen but not a single RGW request marker. The
    // most common cause is a workload started before the trace window opened
    // (native DWARF extraction is slow), so nothing correlates. Surface it as a
    // warning rather than leaving the operator to infer a dead probe.
    if should_warn_no_request_markers(
        trace.diagnostics.request_markers,
        trace.diagnostics.rados_ops,
    ) {
        warn!(
            rados_ops = trace.diagnostics.rados_ops,
            "no RGW request markers captured -- did the workload run after 'starting live tracing'?"
        );
    }
    Ok(trace)
}

/// Whether to emit the "no RGW request markers" end-of-run warning: RADOS ops
/// were captured but no request marker fired, so nothing could correlate. The
/// typical cause is a workload started before the (slow-to-open) trace window.
fn should_warn_no_request_markers(request_markers: u64, rados_ops: u64) -> bool {
    request_markers == 0 && rados_ops > 0
}

/// Whether to emit the "OTLP spans dropped" end-of-run warning: the export
/// queue was full at least once, so backpressure dropped whole batches and the
/// exported trace is missing those spans.
fn should_warn_otlp_queue_drops(otlp_queue_dropped_spans: u64) -> bool {
    otlp_queue_dropped_spans > 0
}

fn merge_bpf_diagnostics(map: &impl MapCore, collector: &Arc<Mutex<Collector>>) -> Result<()> {
    let diagnostics = read_bpf_diagnostics(map)?;
    collector
        .lock()
        .expect("collector lock poisoned")
        .merge_bpf_diagnostics(diagnostics);
    Ok(())
}

fn read_bpf_diagnostics(map: &impl MapCore) -> Result<BpfDiagnostics> {
    Ok(BpfDiagnostics {
        ringbuf_request_drops: read_bpf_counter(map, BPF_DIAG_RINGBUF_REQUEST_DROPS)?,
        ringbuf_rados_drops: read_bpf_counter(map, BPF_DIAG_RINGBUF_RADOS_DROPS)?,
        rados_map_drops: read_bpf_counter(map, BPF_DIAG_RADOS_MAP_DROPS)?,
        rados_finish_misses: read_bpf_counter(map, BPF_DIAG_RADOS_FINISH_MISSES)?,
        request_context_drops: read_bpf_counter(map, BPF_DIAG_REQUEST_CONTEXT_DROPS)?,
        probe_read_failures: read_bpf_counter(map, BPF_DIAG_PROBE_READ_FAILURES)?,
        reqstate_map_drops: read_bpf_counter(map, BPF_DIAG_REQSTATE_MAP_DROPS)?,
        reseed_hits: read_bpf_counter(map, BPF_DIAG_RESEED_HITS)?,
        reseed_misses: read_bpf_counter(map, BPF_DIAG_RESEED_MISSES)?,
        reseed_base_unresolved: read_bpf_counter(map, BPF_DIAG_RESEED_BASE_UNRESOLVED)?,
        request_end_hits: read_bpf_counter(map, BPF_DIAG_REQUEST_END_HITS)?,
        request_end_misses: read_bpf_counter(map, BPF_DIAG_REQUEST_END_MISSES)?,
        request_end_base_unresolved: read_bpf_counter(map, BPF_DIAG_REQUEST_END_BASE_UNRESOLVED)?,
        sendop_stale_ctx_drops: read_bpf_counter(map, BPF_DIAG_SENDOP_STALE_CTX_DROPS)?,
        sendop_unverifiable_ctx: read_bpf_counter(map, BPF_DIAG_SENDOP_UNVERIFIABLE_CTX)?,
        operate_seed_hits: read_bpf_counter(map, BPF_DIAG_OPERATE_SEED_HITS)?,
        operate_seed_misses: read_bpf_counter(map, BPF_DIAG_OPERATE_SEED_MISSES)?,
        operate_base_unresolved: read_bpf_counter(map, BPF_DIAG_OPERATE_BASE_UNRESOLVED)?,
        sendop_unbridged_ctx_drops: read_bpf_counter(map, BPF_DIAG_SENDOP_UNBRIDGED_CTX_DROPS)?,
        operate_miss_ctx_cleared: read_bpf_counter(map, BPF_DIAG_OPERATE_MISS_CTX_CLEARED)?,
        rgw_op_key_inserts: read_bpf_counter(map, BPF_DIAG_RGWOP_KEY_INSERTS)?,
        rgw_op_key_revokes: read_bpf_counter(map, BPF_DIAG_RGWOP_KEY_REVOKES)?,
        rgw_op_key_revoke_skipped: read_bpf_counter(map, BPF_DIAG_RGWOP_KEY_REVOKE_SKIPPED)?,
        rgw_op_key_unresolved: read_bpf_counter(map, BPF_DIAG_RGWOP_KEY_UNRESOLVED)?,
        operate_seed_hits_reqstate: read_bpf_counter(map, BPF_DIAG_OPERATE_SEED_HITS_REQSTATE)?,
        operate_seed_hits_rgwop: read_bpf_counter(map, BPF_DIAG_OPERATE_SEED_HITS_RGWOP)?,
        operate_seed_hits_unattributed: read_bpf_counter(
            map,
            BPF_DIAG_OPERATE_SEED_HITS_UNATTRIBUTED,
        )?,
        operate_unresolved_ctx_cleared: read_bpf_counter(
            map,
            BPF_DIAG_OPERATE_UNRESOLVED_CTX_CLEARED,
        )?,
        rgw_op_key_revoke_absent: read_bpf_counter(map, BPF_DIAG_RGWOP_KEY_REVOKE_ABSENT)?,
        rgw_op_key_index_drops: read_bpf_counter(map, BPF_DIAG_RGWOP_KEY_INDEX_DROPS)?,
        rgw_op_key_disabled: read_bpf_counter(map, BPF_DIAG_RGWOP_KEY_DISABLED)?,
        operate_miss_home_ctx_preserved: read_bpf_counter(
            map,
            BPF_DIAG_OPERATE_MISS_HOME_CTX_PRESERVED,
        )?,
        operate_unresolved_home_ctx_preserved: read_bpf_counter(
            map,
            BPF_DIAG_OPERATE_UNRESOLVED_HOME_CTX_PRESERVED,
        )?,
    })
}

fn read_bpf_counter(map: &impl MapCore, counter: u32) -> Result<u64> {
    let key = counter.to_ne_bytes();
    let Some(values) = map.lookup_percpu(&key, MapFlags::ANY)? else {
        return Ok(0);
    };
    values.into_iter().try_fold(0_u64, |total, value| {
        if value.len() < size_of::<u64>() {
            bail!(
                "BPF diagnostics counter value is too short: {}",
                value.len()
            );
        }
        let mut bytes = [0_u8; size_of::<u64>()];
        bytes.copy_from_slice(&value[..size_of::<u64>()]);
        Ok(total.saturating_add(u64::from_ne_bytes(bytes)))
    })
}

impl OtlpExporter {
    fn spawn(cli: &Cli) -> Self {
        let (sender, receiver) = mpsc::sync_channel(OTLP_EXPORT_QUEUE_CAPACITY);
        let config = OtlpExporterConfig {
            service_name: cli.service_name.clone(),
            endpoint: cli.otlp_endpoint.clone(),
            headers: cli.otlp_header.clone(),
            compression: cli.otlp_compression,
            max_spans_per_batch: cli.otlp_max_spans_per_batch,
            max_bytes_per_batch: cli.otlp_max_bytes_per_batch,
            timeout: cli.otlp_timeout,
            retries: cli.otlp_retries,
            diagnostics: cli.otlp_diagnostics,
        };
        let handle = thread::spawn(move || run_otlp_exporter(receiver, config));
        Self { sender, handle }
    }

    fn finish(self) -> Result<otel::ExportDiagnostics> {
        drop(self.sender);
        self.handle
            .join()
            .map_err(|_| anyhow::anyhow!("OTLP exporter thread panicked"))?
    }
}

fn run_otlp_exporter(
    receiver: Receiver<ExpiredBatch>,
    config: OtlpExporterConfig,
) -> Result<otel::ExportDiagnostics> {
    let mut total = otel::ExportDiagnostics::default();
    for batch in receiver {
        // Rendered here, off the ring-buffer thread and outside the collector
        // lock: span construction is the expensive half of a drain.
        let trace = batch.into_trace_document(config.service_name.clone());
        let spans = trace.spans.len();
        let export = otel::export_otlp_http(
            otel::ExportConfig {
                endpoint: &config.endpoint,
                headers: &config.headers,
                compression: config.compression,
                max_spans_per_batch: config.max_spans_per_batch,
                max_bytes_per_batch: config.max_bytes_per_batch,
                timeout: config.timeout,
                retries: config.retries,
                diagnostics: config.diagnostics,
            },
            &trace,
        )?;
        total.batches += export.batches;
        total.attempts += export.attempts;
        total.failures += export.failures;
        info!(
            spans,
            export_attempts = export.attempts,
            export_failures = export.failures,
            "exported expired OTLP spans"
        );
    }
    Ok(total)
}

fn queue_expired_otlp(
    cli: &Cli,
    collector: &Arc<Mutex<Collector>>,
    sender: &SyncSender<ExpiredBatch>,
    disabled: &mut bool,
) -> Result<Option<ExpiredBatch>> {
    // Once the exporter thread has gone away we permanently stop draining spans
    // into the (dead) channel so the session keeps running and the end-of-run
    // `into_trace_document` still produces output for the non-OTLP path.
    if *disabled {
        return Ok(None);
    }

    let ttl_ns = duration_ns(cli.correlation_ttl);
    let now_ns = clock_time_ns(libc::CLOCK_REALTIME)?;
    // Only the cheap detach runs under the lock (and on this, the ring-buffer
    // thread); spans are rendered by the exporter thread.
    let trace = collector
        .lock()
        .expect("collector lock poisoned")
        .drain_expired_batch(now_ns, ttl_ns);
    let Some(trace) = trace else {
        return Ok(None);
    };

    // A `Some` return carries a batch the caller must retain: it left the
    // collector but could not reach a disconnected exporter.
    Ok(dispatch_expired_otlp(collector, sender, trace, disabled))
}

/// Hand a drained batch of expired spans to the OTLP exporter thread, degrading
/// gracefully instead of aborting the session.
///
/// A dead exporter thread (channel `Disconnected`) is treated as a permanent,
/// non-fatal condition: OTLP export is disabled for the rest of the run via
/// `disabled` and a single warning is logged. The batch has already left the
/// collector, so it is NOT counted as a drop; instead it is returned as
/// `Some(trace)` for the caller to retain and re-emit at end of run. Subsequent
/// calls observe `disabled` and stay silent, so a transient/misconfig OTLP
/// error can neither tear down live tracing nor spam the log.
///
/// Returns `Some(trace)` when the batch must be retained by the caller; `None`
/// when it was queued for export or dropped as genuine backpressure (`Full`).
fn dispatch_expired_otlp<T: SpanCount>(
    collector: &Arc<Mutex<Collector>>,
    sender: &SyncSender<T>,
    trace: T,
    disabled: &mut bool,
) -> Option<T> {
    // Export already disabled: the channel is known dead, so retain the batch
    // for end-of-run emission rather than dropping it. In the live loop
    // `queue_expired_otlp` short-circuits before draining once disabled, so this
    // path is defensive.
    if *disabled {
        return Some(trace);
    }

    let spans = trace.span_count();
    match sender.try_send(trace) {
        Ok(()) => {
            info!(spans, "queued expired OTLP spans");
            None
        }
        Err(TrySendError::Full(trace)) => {
            // Asymmetry with `Disconnected` below is deliberate. `Full` is
            // transient backpressure: retaining every full-dropped batch would
            // grow `retained_otlp` without bound under sustained backpressure,
            // so we drop the batch (counted via `record_otlp_queue_drop`) to
            // keep memory bounded. `Disconnected` is a permanent condition that
            // affects exactly one batch, so retaining that single batch is safe.
            collector
                .lock()
                .expect("collector lock poisoned")
                .record_otlp_queue_drop(trace.span_count());
            warn!(
                spans = trace.span_count(),
                "dropped expired OTLP spans; export queue is full"
            );
            None
        }
        Err(TrySendError::Disconnected(trace)) => {
            *disabled = true;
            warn!(
                spans = trace.span_count(),
                "OTLP exporter worker stopped; retaining these spans for end-of-run emission and disabling OTLP export for the rest of this run"
            );
            Some(trace)
        }
    }
}

/// What crosses the exporter queue, as far as the drop/retain accounting is
/// concerned. The live queue carries [`ExpiredBatch`]es; a rendered
/// [`TraceDocument`] counts the same way.
trait SpanCount {
    fn span_count(&self) -> usize;
}

impl SpanCount for ExpiredBatch {
    fn span_count(&self) -> usize {
        ExpiredBatch::span_count(self)
    }
}

impl SpanCount for TraceDocument {
    fn span_count(&self) -> usize {
        self.spans.len()
    }
}

fn configure_rodata(rodata: &mut types::rodata, version: Option<&str>) -> Result<()> {
    let version = version.context(
        "Ceph version is required to select ceph_osd_op ABI offsets; pass --ceph-version or use DWARF JSON with a version",
    )?;
    let squid_or_newer = is_squid_or_newer(version).with_context(|| {
        format!("failed to parse Ceph version {version:?} for ceph_osd_op ABI offsets")
    })?;

    if squid_or_newer {
        rodata.CEPH_OSD_OP_SIZE = 112;
        rodata.CEPH_OSD_OP_BUFFER_CARRIAGE_OFFSET = 56;
    } else {
        rodata.CEPH_OSD_OP_SIZE = 152;
        rodata.CEPH_OSD_OP_BUFFER_CARRIAGE_OFFSET = 96;
    }

    rodata.CEPH_OSD_OP_EXTENT_OFFSET_OFFSET = 6;
    rodata.CEPH_OSD_OP_EXTENT_LENGTH_OFFSET = 14;
    rodata.CEPH_OSD_OP_CLS_CLASS_OFFSET = 6;
    rodata.CEPH_OSD_OP_CLS_METHOD_OFFSET = 7;
    rodata.CEPH_OSD_OP_BUFFER_RAW_OFFSET = 8;
    rodata.CEPH_OSD_OP_BUFFER_DATA_OFFSET = 32;
    Ok(())
}

fn populate_hprobes(map: &mut impl MapCore, dwarf: &DwarfInfo) -> Result<()> {
    for entry in dwarf.hprobe_entries() {
        let key = entry.key.to_ne_bytes();
        let value = bytes_of(&entry.field);
        map.update(&key, value, MapFlags::ANY).with_context(|| {
            format!("failed to populate hprobe {}:{}", entry.function, entry.key)
        })?;
    }
    Ok(())
}

/// What `attach_probes` attached, beyond the links themselves.
struct AttachedProbes {
    links: Vec<Link>,
    /// Whether the request-END probe (`req_state::~req_state`) is live. Drives
    /// both the BPF `REQUEST_END_PROBE_ATTACHED` gate (whether a request context
    /// found on a submitting thread can be liveness-checked against the bridge)
    /// and the collector's open-request expiry model (whether an END is still
    /// expected for a request that has not produced one).
    request_end_probe: bool,
}

/// One step of the attach sequence. The ORDER of these steps is a correctness
/// property, not a style choice -- see [`ATTACH_ORDER`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttachStep {
    /// `req_state::~req_state` -- the ONLY thing that deletes a bridge entry.
    RequestEndProbe,
    /// Publish the BPF globals (`REQUEST_END_PROBE_ATTACHED`,
    /// `RGW_OP_BRIDGE_KEY_ENABLED`) that every probe below reads.
    PublishBpfConfig,
    /// `RGWREST::get_handler` -- creates a request's CANONICAL bridge entry.
    GetHandler,
    /// `rgw_process_authenticated` -- creates the ALTERNATE bridge entry, and
    /// consumes the bridge (Stage-3 re-seed).
    ProcessAuthenticated,
    /// Both `rgw_rados_operate` overloads -- consume the bridge (Phase B).
    RadosOperate,
    /// `Objecter::_send_op` / `_finish_op` -- consume the seeded thread context
    /// (this is what actually stamps a trans_id onto an op).
    ObjecterOps,
}

impl AttachStep {
    /// Does this step attach a probe that can CREATE a bridge entry?
    fn is_bridge_producer(self) -> bool {
        matches!(self, Self::GetHandler | Self::ProcessAuthenticated)
    }

    /// Does this step attach a probe that can READ a bridge entry (or the thread
    /// context seeded from one) and act on it?
    fn is_bridge_consumer(self) -> bool {
        matches!(
            self,
            Self::ProcessAuthenticated | Self::RadosOperate | Self::ObjecterOps
        )
    }
}

/// THE ATTACH ORDER, and why it is this one.
///
/// A bridge entry is created by `get_handler` and revoked by ONE probe only: the
/// `req_state` destructor. If `get_handler` attached first, a request could pass it
/// -- creating its canonical bridge entry -- and then RUN TO COMPLETION before the
/// destructor probe went live. Nothing would ever delete that entry. It would sit
/// in `rgw_ctx_by_reqstate` for the rest of the run, and the moment
/// `REQUEST_END_PROBE_ATTACHED` flipped to 1 it would start PASSING the `_send_op`
/// liveness gate's identity check (`start_ns`/`tid` match the copy, because both
/// came from the same dead request) -- so a later `_send_op` on that thread, or any
/// per-submit seed that hit that entry, would stamp a DEAD request's trans_id onto
/// a live op. That is a mis-correlation, which is strictly worse than no
/// correlation, and it would be permanent: nothing can revoke an entry whose
/// destructor was never probed.
///
/// So: the REVOKER attaches first, then the config it depends on is published,
/// and only then can anything PRODUCE or CONSUME a bridge entry. Every entry that
/// can ever exist is therefore created with its revoker already live.
///
/// `validate_attach_order` enforces exactly that, and `attach_probes` DRIVES this
/// array rather than restating the order in code, so the order that is tested is
/// the order that runs.
const ATTACH_ORDER: [AttachStep; 6] = [
    AttachStep::RequestEndProbe,
    AttachStep::PublishBpfConfig,
    AttachStep::GetHandler,
    AttachStep::ProcessAuthenticated,
    AttachStep::RadosOperate,
    AttachStep::ObjecterOps,
];

/// Fail closed if the attach sequence would let a bridge entry exist before its
/// revoker (or before the gate that depends on the revoker) is live. This is a
/// tripwire for a future edit that reorders `ATTACH_ORDER`, and it runs before a
/// single probe is attached.
fn validate_attach_order(steps: &[AttachStep]) -> Result<()> {
    let revoker = steps
        .iter()
        .position(|step| *step == AttachStep::RequestEndProbe)
        .context(
            "the attach order must include the request-END probe (the bridge's only revoker)",
        )?;
    let config = steps
        .iter()
        .position(|step| *step == AttachStep::PublishBpfConfig)
        .context("the attach order must publish the BPF config")?;
    if config < revoker {
        bail!(
            "attach order is unsafe: the BPF config is published before the request-END probe \
             attaches, so REQUEST_END_PROBE_ATTACHED could claim a revoker that is not live yet"
        );
    }

    for (idx, step) in steps.iter().enumerate() {
        if step.is_bridge_producer() && idx < revoker {
            bail!(
                "attach order is unsafe: {step:?} can create a bridge entry before the request-END \
                 probe is attached, so that entry could never be revoked and would eventually pass \
                 the liveness gate for a DEAD request"
            );
        }
        if (step.is_bridge_producer() || step.is_bridge_consumer()) && idx < config {
            bail!(
                "attach order is unsafe: {step:?} touches the bridge before the BPF config that \
                 gates it has been published"
            );
        }
    }
    Ok(())
}

/// Outcome of an optional uprobe attach. `Skipped` is not an error -- the
/// artifact simply has no address for the function -- but it is never silent:
/// callers decide whether to debug-log it (a probe that is legitimately absent
/// on this module) or warn about it (the END probe, whose absence silently
/// downgrades every request duration the operator sees).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttachOutcome {
    Attached,
    Skipped,
}

fn attach_probes(
    skel: &mut RgwtraceSkel<'_>,
    dwarf: &DwarfInfo,
    targets: &targets::ProbeTargets,
    pid: i32,
    correlate_cross_thread: bool,
    rgw_op_bridge_key: bool,
) -> Result<AttachedProbes> {
    // Fail closed BEFORE attaching anything: a reordered ATTACH_ORDER that could
    // strand an unrevocable bridge entry must not be discovered in production.
    validate_attach_order(&ATTACH_ORDER)?;

    let mut links = Vec::new();
    let mut request_end_probe = false;

    for step in ATTACH_ORDER {
        match step {
            // FIRST, ALWAYS. The bridge's only revoker. Every entry that can ever
            // be created must be created with this probe already live.
            //
            // ON by default -- it is what makes `rgw.request` durations real -- but
            // strictly OPTIONAL and FAIL SOFT: an RGW build whose destructor symbol
            // or `this` descriptor cannot be resolved (stripped binary, unexpected
            // destructor mangling, older build) simply keeps today's behavior, with
            // request ends derived from the RADOS child bounds and
            // `rgw.duration_quality = "marker"`. Preflight reports the same
            // condition as an advisory `warn`, never a hard error.
            //
            // This is an ENTRY uprobe (`retprobe = false`), never a uretprobe: see
            // the handler comment in bpf/rgwtrace.bpf.c.
            AttachStep::RequestEndProbe => {
                request_end_probe =
                    attach_request_end_probe(&mut links, skel, dwarf, &targets.radosgw, pid)
                        == AttachOutcome::Attached;
            }
            // Published from the ACTUAL attach outcome above, and BEFORE any probe
            // that reads it. `REQUEST_END_PROBE_ATTACHED` tells the BPF side that
            // the presence of a bridge entry is a meaningful LIVENESS signal for
            // `_send_op`'s stamp gate -- true only because the revoker is now live.
            // `RGW_OP_BRIDGE_KEY_ENABLED` is the operator's kill switch for the
            // `RGWOp*` alternate key, read by the probe attached in the next step.
            AttachStep::PublishBpfConfig => {
                skel.maps.bss_data.REQUEST_END_PROBE_ATTACHED = u32::from(request_end_probe);
                skel.maps.bss_data.RGW_OP_BRIDGE_KEY_ENABLED = u32::from(rgw_op_bridge_key);
            }
            AttachStep::GetHandler => {
                attach_if_present(
                    &mut links,
                    &skel.progs.uprobe_rgw_get_handler,
                    false,
                    pid,
                    &targets.radosgw,
                    dwarf,
                    "RGWREST::get_handler",
                )?;
                // The cross-thread bridge's precondition: get_handler must resolve
                // the request's `req_state*` from a REGISTER, or nothing is ever
                // bridged. With the END probe attached, `_send_op` then refuses to
                // stamp any op at all (fail-closed: an unbridged context can never
                // be revoked, so it could be a long-dead request's). That is a total
                // correlation blackout and must be said out loud, not discovered
                // from an empty trace.
                warn_if_req_state_is_not_bridgeable(dwarf, &targets.radosgw, request_end_probe);
            }
            // Cross-thread correlation, opt-in via --correlate-cross-thread. It is
            // ONE feature attached at TWO kinds of site, both gated by the one flag:
            //
            //   * the Stage-3 re-seed at `rgw_process_authenticated` (here): one
            //     seed at one instant, on the request execute thread -- and the site
            //     that registers a request's ALTERNATE bridge key (the `RGWOp*`);
            //   * PHASE B, the per-submit re-seed at both `rgw_rados_operate`
            //     overloads: the context re-established immediately before EVERY
            //     RADOS submit, on whatever pool thread the coroutine has migrated
            //     onto by then.
            //
            // Phase B is what actually makes the feature work (N fixed seed sites
            // can never cover a coroutine that yields M times), and Stage 3 is now
            // mostly redundant with it as a SEED -- but it is kept because it costs
            // one probe on a cold path, it still covers a submit that reaches
            // librados without passing through `rgw_rados_operate`, and it is the
            // only site where the executing RGWOp* can be captured. With the flag
            // off neither is attached, so the dormant BPF programs cannot change any
            // behavior: baseline stays byte-for-byte identical.
            AttachStep::ProcessAuthenticated => {
                if correlate_cross_thread && reseed_var_field_present(dwarf, &targets.radosgw) {
                    attach_if_present(
                        &mut links,
                        &skel.progs.uprobe_rgw_process_authenticated,
                        false,
                        pid,
                        &targets.radosgw,
                        dwarf,
                        RGW_PROCESS_AUTHENTICATED,
                    )?;
                    if rgw_op_bridge_key {
                        warn_if_rgw_op_key_unavailable(dwarf, &targets.radosgw);
                    } else {
                        info!(
                            "--disable-rgw-op-bridge-key: requests are keyed by their req_state* \
                             ONLY. RADOS ops whose dpp is the executing RGWOp will MISS the bridge \
                             and stay uncorrelated -- read bpf_operate_seed_hits_rgwop from a run \
                             WITH the key before deciding this is free"
                        );
                    }
                }
            }
            // PHASE B REQUIRES THE END PROBE. The per-submit re-seed looks up EVERY
            // rados operate's `dpp` in the bridge, including the many foreign dpps
            // of background work. That is only safe while bridge entries are REVOKED
            // at request end -- which only the END probe does. Without it, entries
            // live forever, and a recycled req_state stack address or RGWOp heap
            // address (or a numerically-matching foreign dpp) would HIT a long-dead
            // request's entry and seed its trans_id onto a live submit.
            // `request_ctx_is_live` cannot save us there either: with no revoker it
            // is switched off and fails OPEN. So Phase B degrades to Phase A rather
            // than risk mis-correlation.
            AttachStep::RadosOperate => {
                if correlate_cross_thread {
                    if request_end_probe {
                        attach_rados_operate_probes(&mut links, skel, dwarf, &targets.radosgw, pid);
                    } else {
                        warn!(
                            "--correlate-cross-thread: the per-submit re-seed (rgw_rados_operate) \
                             is DISABLED because the request-END probe did not attach. Nothing \
                             would revoke a request's bridge entries, so a recycled \
                             req_state/RGWOp address could seed a DEAD request's trans_id onto a \
                             live RADOS op -- a mis-correlation, which is worse than no \
                             correlation. Cross-thread correlation degrades to seeding at \
                             get_handler/rgw_process_authenticated only; most ops submitted after \
                             a coroutine migration will be reported as background/inferred"
                        );
                    }
                }
            }
            AttachStep::ObjecterOps => {
                for path in targets.rados_libraries() {
                    attach_if_present(
                        &mut links,
                        &skel.progs.uprobe_send_op,
                        false,
                        pid,
                        path,
                        dwarf,
                        "Objecter::_send_op",
                    )?;
                    attach_if_present(
                        &mut links,
                        &skel.progs.uprobe_finish_op,
                        false,
                        pid,
                        path,
                        dwarf,
                        "Objecter::_finish_op",
                    )?;
                }
            }
        }
    }

    if links.is_empty() {
        bail!("no uprobes were attached; check DWARF JSON and target paths")
    }

    Ok(AttachedProbes {
        links,
        request_end_probe,
    })
}

/// Warn when a request's `req_state*` is not register-resolvable at get_handler:
/// the bridge is then never populated, and (with the END probe attached) the
/// `_send_op` liveness gate fails closed on every context, so NOTHING is
/// correlated. A silent empty trace would look like an idle gateway.
fn warn_if_req_state_is_not_bridgeable(dwarf: &DwarfInfo, radosgw: &Path, end_probe: bool) {
    let bridgeable = module_key_for_path(radosgw)
        .is_some_and(|module| dwarf.get_handler_req_state_is_register_resolvable(&module));
    if bridgeable {
        return;
    }
    if end_probe {
        warn!(
            path = %radosgw.display(),
            "this build's RGWREST::get_handler does not hold the req_state* in a register at \
             entry, so no request can be bridged -- and with the request-END probe attached, ops \
             are then left UNCORRELATED rather than stamped from a context that can never be \
             verified or revoked (fail-closed). Expect zero RADOS correlation and a nonzero \
             bpf_sendop_unbridged_ctx_drops; re-export the DWARF artifact, or run without the end \
             probe to fall back to unverified same-thread stamping"
        );
    } else {
        warn!(
            path = %radosgw.display(),
            "this build's RGWREST::get_handler does not hold the req_state* in a register at \
             entry, so no request can be bridged: cross-thread correlation is unavailable and \
             ops are stamped WITHOUT a liveness check (bpf_sendop_unverifiable_ctx)"
        );
    }
}

/// Warn when a request cannot be keyed by the `RGWOp*` executing it. RGW passes
/// that pointer as the `dpp` at most call sites inside `op->execute()`, so without
/// this key the per-submit re-seed misses on the whole op data path and Phase B
/// recovers little or nothing -- while every counter still looks healthy.
fn warn_if_rgw_op_key_unavailable(dwarf: &DwarfInfo, radosgw: &Path) {
    let available = module_key_for_path(radosgw)
        .is_some_and(|module| dwarf.function_has_rgw_op_descriptor(&module));
    if available {
        return;
    }
    warn!(
        path = %radosgw.display(),
        "--correlate-cross-thread: the artifact carries no proven `RGWOp*&` descriptor for \
         {RGW_PROCESS_AUTHENTICATED}, so requests are keyed by their req_state* ONLY. RGW passes \
         the executing RGWOp -- not the req_state -- as the `dpp` at most call sites in an op's \
         data path, so those RADOS ops will MISS the bridge and stay uncorrelated. Re-export the \
         DWARF artifact with a current rgwtrace (native extraction proves the identity from DWARF \
         and refuses to guess it)"
    );
}

/// PHASE B. Attach the per-submit re-seed to BOTH `rgw_rados_operate` overloads.
///
/// The two overloads are DISTINCT functions at DISTINCT addresses that share one
/// demangled name, so each is resolved through the provenance-checked accessor
/// (`DwarfInfo::rados_operate_probe`) which refuses any address whose MANGLED
/// linkage name does not prove it is that very overload. Neither probe can end up
/// on the other's address, and neither can be bound by "whichever symbol came
/// first".
///
/// Attaching to only ONE of them is a legitimate partial state (e.g. an artifact
/// that resolved the read overload but not the write one), and is strictly better
/// than nothing: each probe carries its own hprobe descriptor extracted from its
/// own definition, so a probe that attaches always reads the right register. It is
/// warned about, because losing an overload silently loses an entire half of the
/// data path -- every RADOS write, or every RADOS read -- from the traces.
///
/// FAIL SOFT, NEVER SILENT: an older/stripped RGW whose `rgw_rados_operate`
/// symbols cannot be resolved keeps Phase A behavior (correlation only for ops
/// submitted on a seed thread), with a warning that says exactly that.
fn attach_rados_operate_probes(
    links: &mut Vec<Link>,
    skel: &mut RgwtraceSkel<'_>,
    dwarf: &DwarfInfo,
    radosgw: &Path,
    pid: i32,
) -> usize {
    let read = attach_rados_operate_probe(
        links,
        &skel.progs.uprobe_rgw_rados_operate_read,
        false,
        dwarf,
        radosgw,
        pid,
        RGW_RADOS_OPERATE_READ,
    );
    let write = attach_rados_operate_probe(
        links,
        &skel.progs.uprobe_rgw_rados_operate_write,
        false,
        dwarf,
        radosgw,
        pid,
        RGW_RADOS_OPERATE_WRITE,
    );

    let attached = [read, write]
        .iter()
        .filter(|outcome| **outcome == AttachOutcome::Attached)
        .count();
    if attached == 0 {
        warn!(
            path = %radosgw.display(),
            "--correlate-cross-thread: NEITHER rgw_rados_operate overload could be probed, so \
             RADOS ops submitted after a coroutine migration cannot be correlated. Cross-thread \
             correlation degrades to seeding at get_handler/rgw_process_authenticated only -- most \
             request ops will still be reported as background/inferred"
        );
    }
    attached
}

fn attach_rados_operate_probe(
    links: &mut Vec<Link>,
    prog: &libbpf_rs::ProgramMut<'_>,
    retprobe: bool,
    dwarf: &DwarfInfo,
    radosgw: &Path,
    pid: i32,
    function: &'static str,
) -> AttachOutcome {
    let probe = module_key_for_path(radosgw)
        .map(|module| dwarf.rados_operate_probe(&module, function))
        .unwrap_or(RadosOperateProbe::Unavailable(
            crate::dwarf_json::RadosOperateProbeGap {
                function,
                gap: crate::dwarf_json::ProvenanceGap::NoModule,
            },
        ));

    let addr = match probe {
        RadosOperateProbe::Available { addr, linkage } => {
            debug!(
                function,
                linkage,
                addr,
                path = %radosgw.display(),
                "resolved an rgw_rados_operate overload; attaching the per-submit re-seed uprobe"
            );
            addr
        }
        RadosOperateProbe::Unavailable(gap) => {
            warn!(
                function,
                path = %radosgw.display(),
                reason = %gap.reason(),
                "per-submit cross-thread re-seed unavailable for this rgw_rados_operate overload; \
                 RADOS ops it would have submitted stay uncorrelated (background/inferred)"
            );
            return AttachOutcome::Skipped;
        }
    };

    match attach_uprobe(prog, retprobe, pid, radosgw, addr as usize) {
        Ok(link) => {
            links.push(link);
            AttachOutcome::Attached
        }
        Err(err) => {
            warn!(
                function,
                error = %format_args!("{err:#}"),
                "failed to attach the per-submit cross-thread re-seed uprobe; continuing without it"
            );
            AttachOutcome::Skipped
        }
    }
}

/// Attach the request-END probe, degrading gracefully instead of failing the run,
/// and NEVER silently.
///
/// Ways it can be unavailable, all non-fatal and all warned about, because each
/// one silently changes what every `rgw.request` duration in the output means:
/// 1. the artifact has no `req_state::~req_state` address (older/stripped RGW, or
///    native extraction refused every destructor variant it saw);
/// 2. the artifact cannot PROVE the address is the complete/base destructor
///    (D1/D2) -- an imported artifact with no `func2linkage` provenance, or one
///    naming the deleting destructor (D0). Refused: attaching an END uprobe to
///    the wrong destructor variant is not a degradation, it is a wrong probe;
/// 3. the varid-50 `this` descriptor is absent or is not the register-only
///    raw-pointer shape the BPF handler reads (`fetch_param_ptr`);
/// 4. the uprobe itself fails to attach in the kernel.
///
/// In every case the collector falls back to deriving request ends from the
/// correlated RADOS child bounds, exactly as it did before this probe existed
/// (`rgw.duration_quality = "marker"`). Requiring the end probe would break
/// tracing on builds that worked, so it stays optional -- but the operator is
/// told, at attach time, that their durations are derived rather than measured.
fn attach_request_end_probe(
    links: &mut Vec<Link>,
    skel: &mut RgwtraceSkel<'_>,
    dwarf: &DwarfInfo,
    radosgw: &Path,
    pid: i32,
) -> AttachOutcome {
    let probe = module_key_for_path(radosgw)
        .map(|module| dwarf.request_end_probe(&module))
        .unwrap_or(RequestEndProbe::Unavailable(RequestEndProbeGap::NoModule));

    let addr = match probe {
        RequestEndProbe::Available { addr, linkage } => {
            debug!(
                function = REQ_STATE_DTOR,
                linkage,
                addr,
                path = %radosgw.display(),
                "resolved the request-END destructor; attaching uprobe"
            );
            addr
        }
        RequestEndProbe::Unavailable(gap) => {
            warn!(
                function = REQ_STATE_DTOR,
                path = %radosgw.display(),
                reason = %gap.reason(),
                "request-END probe unavailable; request span durations will be DERIVED from RADOS \
                 child bounds (rgw.duration_quality=\"marker\") instead of measured"
            );
            return AttachOutcome::Skipped;
        }
    };

    match attach_uprobe(
        &skel.progs.uprobe_rgw_req_state_dtor,
        false,
        pid,
        radosgw,
        addr as usize,
    ) {
        Ok(link) => {
            links.push(link);
            AttachOutcome::Attached
        }
        Err(err) => {
            warn!(
                function = REQ_STATE_DTOR,
                error = %format_args!("{err:#}"),
                "failed to attach the request-END probe; continuing with DERIVED request durations"
            );
            AttachOutcome::Skipped
        }
    }
}

/// Whether the radosgw DWARF carries a valid varid-40 raw-pointer descriptor for
/// `rgw_process_authenticated`. The BPF re-seed handler reads only `location.reg`
/// (`fetch_param_ptr`), so we require the exact raw-pointer shape, not mere
/// presence: a stale/hand-edited JSON with a wrong register or a member-deref
/// chain here could make the bridge re-seed request context from a wrong entry.
/// When the descriptor is missing or malformed the re-seed probe is left
/// unattached and the tracer falls back to main's same-thread behavior.
fn reseed_var_field_present(dwarf: &DwarfInfo, radosgw: &Path) -> bool {
    module_key_for_path(radosgw).is_some_and(|module| {
        dwarf.function_has_raw_pointer_descriptor(&module, "rgw_process_authenticated")
    })
}

/// Attach `function`'s uprobe if the artifact resolves an address for it in
/// `path`'s module. Returns whether it was actually attached: an absent address
/// is a legitimate skip (the function lives in another module), not an error, but
/// the caller -- not this helper -- decides how loud that skip should be.
fn attach_if_present(
    links: &mut Vec<Link>,
    prog: &libbpf_rs::ProgramMut<'_>,
    retprobe: bool,
    pid: i32,
    path: &Path,
    dwarf: &DwarfInfo,
    function: &str,
) -> Result<AttachOutcome> {
    // Derive the artifact module key from the CANONICALIZED path so a soname
    // symlink (`librados.so.2`) resolves to the versioned module the artifact
    // keys by (`librados.so.2.0.0`). The uprobe still attaches to `path`, whose
    // canonical form is the same inode, so the attach target is unchanged.
    let Some(module) = module_key_for_path(path) else {
        return Ok(AttachOutcome::Skipped);
    };
    let Some(addr) = dwarf.function_addr(&module, function) else {
        debug!(
            module = %module,
            function,
            path = %path.display(),
            "no artifact module resolved a func2pc address; uprobe skipped"
        );
        return Ok(AttachOutcome::Skipped);
    };
    debug!(
        module = %module,
        function,
        addr,
        path = %path.display(),
        "resolved func2pc; attaching uprobe"
    );

    let link = attach_uprobe(prog, retprobe, pid, path, addr as usize)
        .with_context(|| format!("failed to attach {function} to {}", path.display()))?;
    links.push(link);
    Ok(AttachOutcome::Attached)
}

fn attach_uprobe(
    prog: &libbpf_rs::ProgramMut<'_>,
    retprobe: bool,
    pid: i32,
    binary_path: &Path,
    func_offset: usize,
) -> Result<Link> {
    let path = binary_path
        .to_str()
        .with_context(|| format!("{} is not valid unicode", binary_path.display()))?;
    let path = CString::new(path).context("uprobe path contains an interior NUL byte")?;
    let ptr = unsafe {
        libbpf_rs::libbpf_sys::bpf_program__attach_uprobe(
            prog.as_libbpf_object().as_ptr(),
            retprobe,
            pid,
            path.as_ptr(),
            func_offset as libbpf_rs::libbpf_sys::size_t,
        )
    };
    match unsafe { libbpf_rs::libbpf_sys::libbpf_get_error(ptr.cast()) } {
        0 => {
            let ptr = NonNull::new(ptr).context("libbpf returned a null uprobe link")?;
            Ok(unsafe { Link::from_ptr(ptr) })
        }
        err => {
            Err(libbpf_rs::Error::from_raw_os_error(-err as i32)).context("failed to attach uprobe")
        }
    }
}

fn decode_event(data: &[u8]) -> Result<TraceEvent> {
    if data.len() < EVENT_DATA_OFFSET {
        bail!("event too short: {}", data.len());
    }

    let event_type = u32::from_ne_bytes(data[..4].try_into()?);
    let payload = &data[EVENT_DATA_OFFSET..];
    match event_type {
        // get_handler START marker: request identity + start_ns (end_ns == 0).
        RGWTRACE_EVENT_REQUEST_START => Ok(TraceEvent::RequestStart(
            read_payload::<RawRequestEvent>(payload)?.into(),
        )),
        // req_state::~req_state END marker: the request's measured end. Optional
        // -- absent when the end probe could not attach.
        RGWTRACE_EVENT_REQUEST_END => Ok(TraceEvent::RequestEnd(
            read_payload::<RawRequestEvent>(payload)?.into(),
        )),
        RGWTRACE_EVENT_RADOS_OP => Ok(TraceEvent::RadosOp(
            read_payload::<RawRadosEvent>(payload)?.into(),
        )),
        other => bail!("unknown event type {other}"),
    }
}

fn read_payload<T: Copy>(payload: &[u8]) -> Result<T> {
    if payload.len() < size_of::<T>() {
        bail!(
            "payload too short for {}: {} < {}",
            std::any::type_name::<T>(),
            payload.len(),
            size_of::<T>()
        );
    }

    let ptr = payload.as_ptr() as *const T;
    Ok(unsafe { ptr.read_unaligned() })
}

fn unix_boottime_offset_ns() -> Result<u64> {
    let realtime_ns = clock_time_ns(libc::CLOCK_REALTIME)?;
    let boottime_ns = clock_time_ns(libc::CLOCK_BOOTTIME)?;
    realtime_ns
        .checked_sub(boottime_ns)
        .context("CLOCK_REALTIME is earlier than CLOCK_BOOTTIME")
}

fn clock_time_ns(clock_id: libc::clockid_t) -> Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ret = unsafe { libc::clock_gettime(clock_id, &mut ts) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).context("clock_gettime failed");
    }

    let seconds = u64::try_from(ts.tv_sec).context("clock_gettime returned negative seconds")?;
    let nanos = u64::try_from(ts.tv_nsec).context("clock_gettime returned negative nanoseconds")?;
    Ok(seconds.saturating_mul(1_000_000_000).saturating_add(nanos))
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn bytes_of(value: &VarFieldKernel) -> &[u8] {
    let ptr = value as *const VarFieldKernel as *const u8;
    unsafe { std::slice::from_raw_parts(ptr, size_of::<VarFieldKernel>()) }
}

fn is_squid_or_newer(version: &str) -> Option<bool> {
    let major = version
        .split(['.', '-'])
        .next()
        .and_then(|major| major.parse::<u64>().ok())?;
    Some(major >= 19)
}

const _: () = {
    assert!(EVENT_DATA_OFFSET.is_multiple_of(align_of::<RawRequestEvent>()));
    assert!(EVENT_DATA_OFFSET.is_multiple_of(align_of::<RawRadosEvent>()));
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::{SpanDocument, TraceDiagnostics};
    use crate::events::{RawClsOp, MAX_ACTING, MAX_RADOS_OPS};

    fn trace_document_with_spans(span_count: usize) -> TraceDocument {
        TraceDocument {
            service_name: "rgwtrace".to_string(),
            spans: (0..span_count)
                .map(|idx| SpanDocument {
                    trace_id: format!("{idx:032x}"),
                    span_id: format!("{idx:016x}"),
                    parent_span_id: None,
                    name: "rgw.request".to_string(),
                    start_ns: 10,
                    end_ns: 20,
                    attributes: Vec::new(),
                    events: Vec::new(),
                })
                .collect(),
            diagnostics: TraceDiagnostics::default(),
        }
    }

    #[test]
    fn warns_only_when_rados_ops_seen_without_request_markers() {
        // The empty-window operator hazard: RADOS ops but no request markers.
        assert!(should_warn_no_request_markers(0, 5));
        // Markers present -> correlation is possible, no warning.
        assert!(!should_warn_no_request_markers(3, 5));
        // Nothing captured at all (e.g. idle target) -> not this diagnosis.
        assert!(!should_warn_no_request_markers(0, 0));
        // Markers but no RADOS ops -> a different situation, no warning.
        assert!(!should_warn_no_request_markers(2, 0));
    }

    #[test]
    fn the_production_attach_order_never_lets_a_bridge_entry_outlive_its_revoker() {
        // THE ORDERING INVARIANT. `get_handler` used to attach BEFORE the destructor
        // probe, and the liveness gate's flag was only published after EVERY probe
        // was up. A request could therefore pass get_handler -- creating its
        // canonical bridge entry -- and COMPLETE before its destructor probe existed.
        // Nothing would ever revoke that entry. It would then sit in the bridge for
        // the whole run, and once the flag flipped to 1 it would PASS the liveness
        // gate's identity check (its start_ns/tid match, because the copy and the
        // entry came from the same dead request), letting a later _send_op inherit a
        // DEAD request's trans_id. Permanent, and a mis-correlation.
        validate_attach_order(&ATTACH_ORDER)
            .expect("the shipped attach order must be safe by construction");

        // Stated positionally as well, so a reorder cannot pass by accident.
        let position = |step: AttachStep| {
            ATTACH_ORDER
                .iter()
                .position(|candidate| *candidate == step)
                .expect("step is in the attach order")
        };
        assert_eq!(position(AttachStep::RequestEndProbe), 0);
        assert_eq!(position(AttachStep::PublishBpfConfig), 1);
        for step in ATTACH_ORDER {
            if step.is_bridge_producer() || step.is_bridge_consumer() {
                assert!(
                    position(step) > position(AttachStep::PublishBpfConfig),
                    "{step:?} touches the bridge and must attach after the revoker and its config"
                );
            }
        }
    }

    #[test]
    fn an_attach_order_that_strands_a_bridge_entry_is_rejected() {
        // The tripwire itself must actually trip -- otherwise the test above only
        // proves that a constant equals itself.

        // get_handler before the revoker: an entry created in that window can NEVER
        // be revoked. This is the exact bug.
        let err = validate_attach_order(&[
            AttachStep::GetHandler,
            AttachStep::RequestEndProbe,
            AttachStep::PublishBpfConfig,
            AttachStep::ProcessAuthenticated,
            AttachStep::RadosOperate,
            AttachStep::ObjecterOps,
        ])
        .expect_err("a producer before the revoker must be rejected");
        assert!(format!("{err}").contains("GetHandler"));

        // The config published before the revoker attached would claim a liveness
        // signal that does not exist yet.
        let err = validate_attach_order(&[
            AttachStep::PublishBpfConfig,
            AttachStep::RequestEndProbe,
            AttachStep::GetHandler,
            AttachStep::ProcessAuthenticated,
            AttachStep::RadosOperate,
            AttachStep::ObjecterOps,
        ])
        .expect_err("publishing the config before the revoker attaches must be rejected");
        assert!(format!("{err}").contains("REQUEST_END_PROBE_ATTACHED"));

        // A consumer (_send_op) before the config: it would read a gate value that
        // has not been published.
        let err = validate_attach_order(&[
            AttachStep::RequestEndProbe,
            AttachStep::ObjecterOps,
            AttachStep::PublishBpfConfig,
            AttachStep::GetHandler,
            AttachStep::ProcessAuthenticated,
            AttachStep::RadosOperate,
        ])
        .expect_err("a bridge consumer before the config must be rejected");
        assert!(format!("{err}").contains("ObjecterOps"));

        // A sequence with no revoker at all cannot be validated.
        assert!(
            validate_attach_order(&[AttachStep::PublishBpfConfig, AttachStep::GetHandler]).is_err()
        );
    }

    #[test]
    fn warns_only_when_otlp_spans_were_dropped() {
        // No backpressure drops -> the export is complete, stay silent.
        assert!(!should_warn_otlp_queue_drops(0));
        // Any dropped spans -> the exported trace is incomplete, warn.
        assert!(should_warn_otlp_queue_drops(1));
        assert!(should_warn_otlp_queue_drops(42));
    }

    #[test]
    fn dispatch_disconnected_otlp_does_not_abort_and_retains_batch() {
        // Receiver dropped up front: every `try_send` sees `Disconnected`, the
        // exact condition that previously `bail!`-ed and tore down the session.
        let (sender, receiver) = mpsc::sync_channel::<TraceDocument>(OTLP_EXPORT_QUEUE_CAPACITY);
        drop(receiver);

        let collector = Arc::new(Mutex::new(Collector::default()));
        let mut disabled = false;

        // First disconnected dispatch: must not panic/return Err, must latch
        // OTLP export off, and must RETAIN (return) the batch rather than drop
        // it — the spans already left the collector.
        let retained = dispatch_expired_otlp(
            &collector,
            &sender,
            trace_document_with_spans(3),
            &mut disabled,
        );
        assert!(disabled, "a disconnected exporter must disable OTLP export");
        assert_eq!(
            retained.map(|doc| doc.spans.len()),
            Some(3),
            "the disconnect-discovering batch must be retained, not dropped"
        );

        // Idempotent: repeated calls stay disabled and keep retaining. The
        // log-once guarantee is structural: only the first, transitioning call
        // reaches the warning branch; later calls take the disabled path.
        let retained = dispatch_expired_otlp(
            &collector,
            &sender,
            trace_document_with_spans(2),
            &mut disabled,
        );
        assert!(
            disabled,
            "export must remain disabled after repeated disconnects"
        );
        assert_eq!(
            retained.map(|doc| doc.spans.len()),
            Some(2),
            "batches must keep being retained while disabled"
        );

        // The disconnect case must NOT bump the drop counter: retained spans are
        // preserved, not lost.
        let diagnostics = Arc::try_unwrap(collector)
            .expect("collector still referenced")
            .into_inner()
            .expect("collector lock poisoned")
            .into_trace_document("rgwtrace")
            .diagnostics;
        assert_eq!(diagnostics.otlp_queue_dropped_traces, 0);
        assert_eq!(diagnostics.otlp_queue_dropped_spans, 0);
    }

    #[test]
    fn dispatch_successful_otlp_send_keeps_export_enabled() {
        // A live receiver: the batch is accepted, no drop is recorded, and OTLP
        // export stays enabled.
        let (sender, receiver) = mpsc::sync_channel::<TraceDocument>(OTLP_EXPORT_QUEUE_CAPACITY);
        let collector = Arc::new(Mutex::new(Collector::default()));
        let mut disabled = false;

        let retained = dispatch_expired_otlp(
            &collector,
            &sender,
            trace_document_with_spans(4),
            &mut disabled,
        );

        assert!(!disabled, "a successful send must not disable export");
        assert!(
            retained.is_none(),
            "a queued batch must not be retained by the caller"
        );
        let received = receiver.try_recv().expect("batch should be queued");
        assert_eq!(received.spans.len(), 4);

        let diagnostics = Arc::try_unwrap(collector)
            .expect("collector still referenced")
            .into_inner()
            .expect("collector lock poisoned")
            .into_trace_document("rgwtrace")
            .diagnostics;
        assert_eq!(diagnostics.otlp_queue_dropped_traces, 0);
    }

    #[test]
    fn dispatch_full_queue_counts_every_span_of_an_unrendered_batch() {
        // The live queue carries detached request groups; a Full drop must still
        // count the spans they WOULD have rendered to (request + children +
        // background), or the drop counters under-report.
        let mut source = Collector::default();
        source.push(TraceEvent::RequestStart(crate::events::RequestEvent {
            start_ns: 10,
            end_ns: 0,
            pid: 1,
            tid: 2,
            trans_id: "tx-full".into(),
            truncation: Default::default(),
        }));
        for (trans_id, sent_ns) in [("tx-full", 11), ("tx-full", 12), ("", 13)] {
            source.push(TraceEvent::RadosOp(crate::events::RadosEvent {
                pid: 1,
                send_tid: 2,
                cid: 1,
                tid: sent_ns,
                sent_ns,
                finish_ns: sent_ns + 1,
                duration_ns: 1,
                pool: 1,
                target_osd: 0,
                pg_seed: 0,
                acting: Vec::new(),
                rw: crate::events::RadosDirection::Read,
                object_name: "obj".to_string(),
                trans_id: trans_id.into(),
                truncation: Default::default(),
                ops: Vec::new(),
                offset: 0,
                length: 0,
            }));
        }
        let batch = source
            .drain_expired_batch(1_000, 100)
            .expect("everything is expired");
        assert_eq!(batch.span_count(), 4);

        let (sender, _receiver) = mpsc::sync_channel::<ExpiredBatch>(1);
        let mut filler_source = Collector::default();
        filler_source.push(TraceEvent::RequestStart(crate::events::RequestEvent {
            start_ns: 10,
            end_ns: 0,
            pid: 1,
            tid: 2,
            trans_id: "tx-filler".into(),
            truncation: Default::default(),
        }));
        sender
            .try_send(filler_source.drain_expired_batch(1_000, 100).unwrap())
            .expect("first unit fits");

        let collector = Arc::new(Mutex::new(Collector::default()));
        let mut disabled = false;
        let retained = dispatch_expired_otlp(&collector, &sender, batch, &mut disabled);
        assert!(retained.is_none(), "a Full drop is not retained");
        assert!(!disabled);
        let diagnostics = Arc::try_unwrap(collector)
            .expect("collector still referenced")
            .into_inner()
            .expect("collector lock poisoned")
            .into_trace_document("rgwtrace")
            .diagnostics;
        assert_eq!(diagnostics.otlp_queue_dropped_traces, 1);
        assert_eq!(diagnostics.otlp_queue_dropped_spans, 4);
    }

    #[test]
    fn decodes_request_end_event() {
        let raw = RawRequestEvent {
            start_ns: 10,
            end_ns: 30,
            pid: 42,
            tid: 7,
            flags: 0,
            trans_id: bytes("tx0001"),
        };

        let event = decode_event(&event_data(RGWTRACE_EVENT_REQUEST_END, &raw)).unwrap();

        let TraceEvent::RequestEnd(request) = event else {
            panic!("expected request end event");
        };
        assert_eq!(request.start_ns, 10);
        assert_eq!(request.end_ns, 30);
        assert_eq!(request.pid, 42);
        assert_eq!(&*request.trans_id, "tx0001");
    }

    #[test]
    fn decodes_request_start_event() {
        // The get_handler START marker: identity + start_ns, and an end_ns of 0
        // because get_handler cannot know when the request ends. It is a real
        // event now (it used to be ABI-reserved and never emitted), and it opens
        // the request the END marker later closes.
        let raw = RawRequestEvent {
            start_ns: 10,
            end_ns: 0,
            pid: 42,
            tid: 7,
            flags: 0,
            trans_id: bytes("tx0001"),
        };

        let event = decode_event(&event_data(RGWTRACE_EVENT_REQUEST_START, &raw)).unwrap();

        let TraceEvent::RequestStart(request) = event else {
            panic!("expected request start event");
        };
        assert_eq!(request.start_ns, 10);
        assert_eq!(request.end_ns, 0);
        assert_eq!(request.tid, 7);
        assert_eq!(&*request.trans_id, "tx0001");
    }

    #[test]
    fn decodes_rados_event() {
        let mut acting = [-1; MAX_ACTING];
        acting[0] = 1;
        acting[1] = 2;
        let raw = RawRadosEvent {
            cid: 9,
            tid: 10,
            sent_ns: 100,
            finish_ns: 150,
            pool: 16,
            offset: 64,
            length: 4096,
            pid: 42,
            send_tid: 77,
            target_osd: 7,
            pg_seed: 0x2a,
            rw: 0,
            ops_size: 1,
            flags: 0,
            acting,
            ops: [0x1201, 0, 0],
            cls_ops: [RawClsOp {
                cls_name: [0; 8],
                method_name: [0; 32],
            }; MAX_RADOS_OPS],
            trans_id: bytes("tx0002"),
            object_name: bytes("bucket-object"),
        };

        let event = decode_event(&event_data(RGWTRACE_EVENT_RADOS_OP, &raw)).unwrap();

        let TraceEvent::RadosOp(rados) = event else {
            panic!("expected rados event");
        };
        assert_eq!(rados.sent_ns, 100);
        assert_eq!(rados.send_tid, 77);
        assert_eq!(rados.duration_ns, 50);
        assert_eq!(rados.acting, vec![1, 2]);
        assert_eq!(rados.ops[0].name, "read");
        assert_eq!(rados.object_name, "bucket-object");
        assert_eq!(&*rados.trans_id, "tx0002");
    }

    #[test]
    fn rejects_short_event_header() {
        let err = decode_event(&[0, 1, 2, 3]).unwrap_err();

        assert!(err.to_string().contains("event too short"));
    }

    #[test]
    fn rejects_unknown_event_type() {
        let mut data = 99_u32.to_ne_bytes().to_vec();
        data.extend_from_slice(&0_u32.to_ne_bytes());

        let err = decode_event(&data).unwrap_err();

        assert!(err.to_string().contains("unknown event type 99"));
    }

    #[test]
    fn rejects_short_payload() {
        let mut data = RGWTRACE_EVENT_REQUEST_END.to_ne_bytes().to_vec();
        data.extend_from_slice(&0_u32.to_ne_bytes());
        data.extend_from_slice(&[1, 2, 3]);

        let err = decode_event(&data).unwrap_err();

        assert!(err.to_string().contains("payload too short"));
    }

    #[test]
    fn rejects_missing_ceph_version_for_abi_layout() {
        let mut rodata = rodata();

        let err = configure_rodata(&mut rodata, None).unwrap_err();

        assert!(err.to_string().contains("Ceph version is required"));
    }

    #[test]
    fn configures_pre_squid_abi_layout() {
        let mut rodata = rodata();

        configure_rodata(&mut rodata, Some("18.2.8-1jammy")).unwrap();

        assert_eq!(rodata.CEPH_OSD_OP_SIZE, 152);
        assert_eq!(rodata.CEPH_OSD_OP_BUFFER_CARRIAGE_OFFSET, 96);
    }

    #[test]
    fn configures_squid_abi_layout() {
        let mut rodata = rodata();

        configure_rodata(&mut rodata, Some("19.2.0")).unwrap();

        assert_eq!(rodata.CEPH_OSD_OP_SIZE, 112);
        assert_eq!(rodata.CEPH_OSD_OP_BUFFER_CARRIAGE_OFFSET, 56);
    }

    fn event_data<T: Copy>(event_type: u32, payload: &T) -> Vec<u8> {
        let mut data = event_type.to_ne_bytes().to_vec();
        data.extend_from_slice(&0_u32.to_ne_bytes());
        let payload =
            unsafe { std::slice::from_raw_parts(payload as *const T as *const u8, size_of::<T>()) };
        data.extend_from_slice(payload);
        data
    }

    fn bytes<const N: usize>(value: &str) -> [u8; N] {
        let mut bytes = [0; N];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        bytes
    }

    fn rodata() -> types::rodata {
        types::rodata {
            CEPH_OSD_OP_SIZE: 0,
            CEPH_OSD_OP_EXTENT_OFFSET_OFFSET: 0,
            CEPH_OSD_OP_EXTENT_LENGTH_OFFSET: 0,
            CEPH_OSD_OP_CLS_CLASS_OFFSET: 0,
            CEPH_OSD_OP_CLS_METHOD_OFFSET: 0,
            CEPH_OSD_OP_BUFFER_CARRIAGE_OFFSET: 0,
            CEPH_OSD_OP_BUFFER_RAW_OFFSET: 0,
            CEPH_OSD_OP_BUFFER_DATA_OFFSET: 0,
        }
    }
}
