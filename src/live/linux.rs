use std::{
    mem::{align_of, size_of},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use libbpf_rs::{Link, MapCore, MapFlags, RingBufferBuilder};

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

pub fn run(cli: &Cli, dwarf: &DwarfInfo) -> Result<TraceDocument> {
    let targets = targets::discover(cli)?;
    let pid = cli.pid.unwrap_or(-1);

    let mut open = RgwtraceSkelBuilder::default().open()?;
    configure_rodata(open.rodata_mut(), dwarf.version.as_deref());
    let mut skel = open.load()?;

    populate_hprobes(skel.maps_mut().hprobes(), dwarf)?;
    let _links = attach_probes(&mut skel, dwarf, &targets, pid)?;

    let collector = Arc::new(Mutex::new(Collector::default()));
    let collector_cb = Arc::clone(&collector);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);
    ctrlc::set_handler(move || stop_handler.store(true, Ordering::SeqCst))
        .context("failed to install Ctrl-C handler")?;

    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(skel.maps().events(), move |data| {
        match decode_event(data) {
            Ok(event) => collector_cb
                .lock()
                .expect("collector lock poisoned")
                .push(event),
            Err(err) => eprintln!("failed to decode rgwtrace event: {err:#}"),
        }
        0
    })?;
    let ringbuf = ringbuf_builder.build()?;

    let started = Instant::now();
    loop {
        ringbuf.poll(Duration::from_millis(250))?;
        if stop.load(Ordering::SeqCst) {
            break;
        }
        if let Some(timeout) = cli.timeout {
            if started.elapsed() >= Duration::from_secs(timeout) {
                break;
            }
        }
    }

    let collector = Arc::try_unwrap(collector)
        .map_err(|_| anyhow::anyhow!("collector still has outstanding references"))?
        .into_inner()
        .expect("collector lock poisoned");
    Ok(collector.into_trace_document(cli.service_name.clone()))
}

fn configure_rodata(rodata: &mut rgwtrace_bss_types::rodata, version: Option<&str>) {
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
            skel.progs_mut().uprobe_send_op(),
            false,
            pid,
            path,
            dwarf,
            "Objecter::_send_op",
        )?;
        attach_if_present(
            &mut links,
            skel.progs_mut().uprobe_finish_op(),
            false,
            pid,
            path,
            dwarf,
            "Objecter::_finish_op",
        )?;
    }

    attach_if_present(
        &mut links,
        skel.progs_mut().uprobe_rgw_process_request(),
        false,
        pid,
        &targets.radosgw,
        dwarf,
        "process_request",
    )?;
    attach_if_present(
        &mut links,
        skel.progs_mut().uretprobe_rgw_process_request(),
        true,
        pid,
        &targets.radosgw,
        dwarf,
        "process_request",
    )?;
    attach_if_present(
        &mut links,
        skel.progs_mut().uprobe_rgw_get_handler(),
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
    prog: &mut libbpf_rs::Program,
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

    let link = prog
        .attach_uprobe(retprobe, pid, path, addr as usize)
        .with_context(|| format!("failed to attach {function} to {}", path.display()))?;
    links.push(link);
    Ok(())
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
