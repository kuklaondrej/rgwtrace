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
    collector::{BpfDiagnostics, Collector, TraceDocument},
    dwarf_json::{basename, DwarfInfo, VarFieldKernel},
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
const OTLP_EXPORT_QUEUE_CAPACITY: usize = 2;
const BPF_DIAG_RINGBUF_REQUEST_DROPS: u32 = 0;
const BPF_DIAG_RINGBUF_RADOS_DROPS: u32 = 1;
const BPF_DIAG_RADOS_MAP_DROPS: u32 = 2;
const BPF_DIAG_RADOS_FINISH_MISSES: u32 = 3;
const BPF_DIAG_REQUEST_CONTEXT_DROPS: u32 = 4;
const BPF_DIAG_PROBE_READ_FAILURES: u32 = 5;

struct OtlpExporter {
    sender: SyncSender<TraceDocument>,
    handle: JoinHandle<Result<otel::ExportDiagnostics>>,
}

struct OtlpExporterConfig {
    endpoint: String,
    headers: Vec<(String, String)>,
    compression: crate::cli::OtlpCompression,
    max_spans_per_batch: usize,
    max_bytes_per_batch: usize,
    timeout: Duration,
    retries: u32,
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
    let _links = attach_probes(&mut skel, dwarf, &targets, pid)?;
    let timestamp_offset_ns = unix_boottime_offset_ns()?;

    let collector = Arc::new(Mutex::new(if cli.correlate_inferred {
        Collector::with_inferred_correlation(duration_ns(cli.correlation_ttl))
    } else {
        Collector::default()
    }));
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
                queue_expired_otlp(cli, &collector, &exporter.sender)?;
            }
            last_flush = Instant::now();
        }
    }

    drop(ringbuf);
    merge_bpf_diagnostics(&skel.maps.diagnostics, &collector)?;
    if let Some(exporter) = otlp_exporter {
        let export = exporter.finish()?;
        info!(
            export_batches = export.batches,
            export_attempts = export.attempts,
            export_failures = export.failures,
            "finished live OTLP exporter"
        );
    }
    let collector = Arc::try_unwrap(collector)
        .map_err(|_| anyhow::anyhow!("collector still has outstanding references"))?
        .into_inner()
        .expect("collector lock poisoned");
    let trace = collector.into_trace_document(cli.service_name.clone());
    info!(spans = trace.spans.len(), "finished live tracing");
    Ok(trace)
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
            endpoint: cli.otlp_endpoint.clone(),
            headers: cli.otlp_header.clone(),
            compression: cli.otlp_compression,
            max_spans_per_batch: cli.otlp_max_spans_per_batch,
            max_bytes_per_batch: cli.otlp_max_bytes_per_batch,
            timeout: cli.otlp_timeout,
            retries: cli.otlp_retries,
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
    receiver: Receiver<TraceDocument>,
    config: OtlpExporterConfig,
) -> Result<otel::ExportDiagnostics> {
    let mut total = otel::ExportDiagnostics::default();
    for trace in receiver {
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
    sender: &SyncSender<TraceDocument>,
) -> Result<()> {
    let ttl_ns = duration_ns(cli.correlation_ttl);
    let now_ns = clock_time_ns(libc::CLOCK_REALTIME)?;
    let trace = collector
        .lock()
        .expect("collector lock poisoned")
        .drain_expired(cli.service_name.clone(), now_ns, ttl_ns);
    let Some(trace) = trace else {
        return Ok(());
    };

    let spans = trace.spans.len();
    match sender.try_send(trace) {
        Ok(()) => info!(spans, "queued expired OTLP spans"),
        Err(TrySendError::Full(trace)) => {
            collector
                .lock()
                .expect("collector lock poisoned")
                .record_otlp_queue_drop(trace.spans.len());
            warn!(
                spans = trace.spans.len(),
                "dropped expired OTLP spans; export queue is full"
            );
        }
        Err(TrySendError::Disconnected(trace)) => {
            collector
                .lock()
                .expect("collector lock poisoned")
                .record_otlp_queue_drop(trace.spans.len());
            bail!("OTLP exporter worker stopped before accepting expired spans");
        }
    }
    Ok(())
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

fn attach_probes(
    skel: &mut RgwtraceSkel<'_>,
    dwarf: &DwarfInfo,
    targets: &targets::ProbeTargets,
    pid: i32,
) -> Result<Vec<Link>> {
    let mut links = Vec::new();

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

    attach_if_present(
        &mut links,
        &skel.progs.uprobe_rgw_get_handler,
        false,
        pid,
        &targets.radosgw,
        dwarf,
        "RGWREST::get_handler",
    )?;

    if links.is_empty() {
        bail!("no uprobes were attached; check DWARF JSON and target paths")
    }

    Ok(links)
}

fn attach_if_present(
    links: &mut Vec<Link>,
    prog: &libbpf_rs::ProgramMut<'_>,
    retprobe: bool,
    pid: i32,
    path: &Path,
    dwarf: &DwarfInfo,
    function: &str,
) -> Result<()> {
    let Some(module) = basename(path) else {
        return Ok(());
    };
    let Some(addr) = dwarf.function_addr(module, function) else {
        return Ok(());
    };

    let link = attach_uprobe(prog, retprobe, pid, path, addr as usize)
        .with_context(|| format!("failed to attach {function} to {}", path.display()))?;
    links.push(link);
    Ok(())
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
        RGWTRACE_EVENT_REQUEST_START => Ok(TraceEvent::RequestStart(
            read_payload::<RawRequestEvent>(payload)?.into(),
        )),
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
    use crate::events::{RawClsOp, MAX_ACTING, MAX_RADOS_OPS};

    #[test]
    fn decodes_request_start_event() {
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
        assert_eq!(request.pid, 42);
        assert_eq!(request.trans_id, "tx0001");
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
        assert_eq!(rados.duration_ns, 50);
        assert_eq!(rados.acting, vec![1, 2]);
        assert_eq!(rados.ops[0].name, "read");
        assert_eq!(rados.object_name, "bucket-object");
        assert_eq!(rados.trans_id, "tx0002");
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
