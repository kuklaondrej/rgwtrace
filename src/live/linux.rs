use std::{
    ffi::CString,
    mem::{align_of, size_of},
    path::Path,
    ptr::NonNull,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use libbpf_rs::{
    skel::OpenSkel, skel::SkelBuilder, AsRawLibbpf, Link, MapCore, MapFlags, OpenObject,
    RingBufferBuilder,
};
use tracing::{debug, info, warn};

use crate::{
    cli::Cli,
    collector::{Collector, TraceDocument},
    dwarf_json::{basename, DwarfInfo, VarFieldKernel},
    events::{
        RawRadosEvent, RawRequestEvent, TraceEvent, RGWTRACE_EVENT_RADOS_OP,
        RGWTRACE_EVENT_REQUEST_END, RGWTRACE_EVENT_REQUEST_START,
    },
    targets,
};

mod skel {
    include!(concat!(env!("OUT_DIR"), "/rgwtrace.skel.rs"));
}

use skel::*;

const EVENT_DATA_OFFSET: usize = 8;
const EINTR: i32 = 4;

pub fn run(cli: &Cli, dwarf: &DwarfInfo) -> Result<TraceDocument> {
    let targets = targets::discover(cli)?;
    let pid = cli.pid.unwrap_or(-1);
    info!(pid, "starting live tracing");

    let mut open_object = std::mem::MaybeUninit::<OpenObject>::uninit();
    let open = RgwtraceSkelBuilder::default().open(&mut open_object)?;
    configure_rodata(open.maps.rodata_data, dwarf.version.as_deref());
    let mut skel = open.load()?;

    populate_hprobes(&mut skel.maps.hprobes, dwarf)?;
    let _links = attach_probes(&mut skel, dwarf, &targets, pid)?;
    let timestamp_offset_ns = unix_boottime_offset_ns()?;

    let collector = Arc::new(Mutex::new(Collector::default()));
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
            Err(err) => warn!(error = %format_args!("{err:#}"), "failed to decode rgwtrace event"),
        }
        0
    })?;
    let ringbuf = ringbuf_builder.build()?;

    let started = Instant::now();
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
    }

    drop(ringbuf);
    let collector = Arc::try_unwrap(collector)
        .map_err(|_| anyhow::anyhow!("collector still has outstanding references"))?
        .into_inner()
        .expect("collector lock poisoned");
    let trace = collector.into_trace_document(cli.service_name.clone());
    info!(spans = trace.spans.len(), "finished live tracing");
    Ok(trace)
}

fn configure_rodata(rodata: &mut types::rodata, version: Option<&str>) {
    let squid_or_newer = version.map(is_squid_or_newer).unwrap_or(false);

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

fn bytes_of(value: &VarFieldKernel) -> &[u8] {
    let ptr = value as *const VarFieldKernel as *const u8;
    unsafe { std::slice::from_raw_parts(ptr, size_of::<VarFieldKernel>()) }
}

fn is_squid_or_newer(version: &str) -> bool {
    let Some(major) = version
        .split(['.', '-'])
        .next()
        .and_then(|major| major.parse::<u64>().ok())
    else {
        return false;
    };
    major >= 19
}

const _: () = {
    assert!(EVENT_DATA_OFFSET % align_of::<RawRequestEvent>() == 0);
    assert!(EVENT_DATA_OFFSET % align_of::<RawRadosEvent>() == 0);
};
