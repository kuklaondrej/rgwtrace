//! Collector hot-path microbenchmarks (userspace only; no BPF, no root).
//!
//! These are `#[ignore]`d tests so `cargo test` stays fast. Run them in release:
//!
//! ```sh
//! cargo test --release collector_bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! They time the three paths the ring-buffer poll thread runs while holding the
//! collector mutex -- event decode+ingest, a request marker under
//! `--correlate-inferred`, and the periodic expiry drain -- and count heap
//! allocations with a thread-local counting allocator.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    hint::black_box,
    time::Instant,
};

use crate::{
    collector::{Collector, IntervalSet},
    events::{
        CaptureTruncation, RadosEvent, RawClsOp, RawRadosEvent, RequestEvent, TraceEvent,
        MAX_ACTING, MAX_OBJECT_NAME, MAX_TRANS_ID,
    },
};

struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

// SAFETY: delegates every call to `System`; the only addition is a thread-local
// counter bump, which is const-initialized and never allocates.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn allocations() -> u64 {
    ALLOCATIONS.with(Cell::get)
}

const PID: u32 = 4242;
const MS: u64 = 1_000_000;
const SEC: u64 = 1_000 * MS;

fn fixed<const N: usize>(value: &str) -> [u8; N] {
    let mut bytes = [0; N];
    bytes[..value.len()].copy_from_slice(value.as_bytes());
    bytes
}

fn raw_rados(trans_id: &str, object: &str, sent_ns: u64) -> RawRadosEvent {
    let mut acting = [-1; MAX_ACTING];
    acting[..3].copy_from_slice(&[11, 22, 33]);
    let empty = RawClsOp {
        cls_name: [0; 8],
        method_name: [0; 32],
    };
    RawRadosEvent {
        cid: 1,
        tid: sent_ns,
        sent_ns,
        finish_ns: sent_ns + MS,
        pool: 7,
        offset: 0,
        length: 4096,
        pid: PID,
        send_tid: 100,
        target_osd: 11,
        pg_seed: 0x2a,
        rw: 0x0020,
        ops_size: 2,
        flags: 0,
        acting,
        ops: [0x2202, 0x1401, 0],
        cls_ops: [
            empty,
            RawClsOp {
                cls_name: fixed("rgw"),
                method_name: fixed("bucket_complete_op"),
            },
            empty,
        ],
        trans_id: fixed::<MAX_TRANS_ID>(trans_id),
        object_name: fixed::<MAX_OBJECT_NAME>(object),
    }
}

fn request(trans_id: &str, tid: u32, start_ns: u64, end_ns: u64) -> RequestEvent {
    RequestEvent {
        start_ns,
        end_ns,
        pid: PID,
        tid,
        trans_id: trans_id.into(),
        truncation: CaptureTruncation::default(),
    }
}

fn trans_id(i: u64) -> String {
    format!("tx{i:021x}-0065f1a2b3-1234567-default")
}

fn report(name: &str, iterations: u64, elapsed_ns: u128, allocs: u64) {
    println!(
        "BENCH {name}: {iterations} iters, {:.1} ns/iter, {:.2} allocs/iter",
        elapsed_ns as f64 / iterations as f64,
        allocs as f64 / iterations as f64
    );
}

/// Decode one RADOS event off the wire and ingest it (trans_id-tagged, so it
/// joins a request group) -- the per-event work of the ring-buffer callback.
#[test]
#[ignore = "benchmark; run with --release --ignored --nocapture"]
fn collector_bench_decode_and_ingest() {
    const N: u64 = 200_000;
    const OPS_PER_REQUEST: u64 = 8;
    let raws: Vec<RawRadosEvent> = (0..N)
        .map(|i| raw_rados(&trans_id(i / OPS_PER_REQUEST), "bucket-object", i * 1_000))
        .collect();

    let before = allocations();
    let started = Instant::now();
    for raw in &raws {
        black_box(RadosEvent::from(*raw));
    }
    report(
        "decode_rados_event",
        N,
        started.elapsed().as_nanos(),
        allocations() - before,
    );

    let mut collector = Collector::default();
    let before = allocations();
    let started = Instant::now();
    for raw in &raws {
        collector.push(TraceEvent::RadosOp(RadosEvent::from(*raw)));
    }
    report(
        "decode_and_ingest_rados_event",
        N,
        started.elapsed().as_nanos(),
        allocations() - before,
    );
    black_box(collector);
}

/// One START+END marker pair under `--correlate-inferred` with `groups` closed
/// request groups resident and `pending` untagged ops waiting on an ambiguous
/// inference -- the production steady state the audit flagged.
fn inference_marker_bench(groups: u64, pending: u64, markers: u64) {
    let mut collector = Collector::with_inferred_correlation(SEC);
    collector.set_end_probe_attached(true);
    // `groups` requests, 1 ms apart, 50 ms long, across 64 worker threads.
    for i in 0..groups {
        let start = SEC + i * MS;
        let id = trans_id(i);
        collector.push(TraceEvent::RequestStart(request(
            &id,
            (i % 64) as u32,
            start,
            0,
        )));
        collector.push(TraceEvent::RequestEnd(request(
            &id,
            (i % 64) as u32,
            start,
            start + 50 * MS,
        )));
    }
    // Untagged ops in the middle of that traffic: always ambiguous.
    let last = SEC + groups * MS;
    for i in 0..pending {
        let sent = last - (i % 500) * MS;
        let mut raw = raw_rados("", "bucket-object", sent);
        raw.send_tid = 9_999;
        collector.push(TraceEvent::RadosOp(RadosEvent::from(raw)));
    }

    let started = Instant::now();
    for i in 0..markers {
        let start = last + (i + 1) * MS;
        let id = trans_id(groups + i);
        collector.push(TraceEvent::RequestStart(request(&id, 1, start, 0)));
        collector.push(TraceEvent::RequestEnd(request(&id, 1, start, start + MS)));
    }
    report(
        &format!("inference_marker_pair groups={groups} pending={pending}"),
        markers,
        started.elapsed().as_nanos(),
        0,
    );
    black_box(collector);
}

#[test]
#[ignore = "benchmark; run with --release --ignored --nocapture"]
fn collector_bench_inference_marker() {
    inference_marker_bench(2_000, 1_000, 100);
    inference_marker_bench(20_000, 5_000, 20);
}

fn populated_collector(groups: u64, ops_per_request: u64) -> Collector {
    let mut collector = Collector::default();
    collector.set_end_probe_attached(true);
    for i in 0..groups {
        let start = SEC + i * MS;
        let id = trans_id(i);
        collector.push(TraceEvent::RequestStart(request(&id, 1, start, 0)));
        for op in 0..ops_per_request {
            let raw = raw_rados(&id, "bucket-object", start + op * 10_000);
            collector.push(TraceEvent::RadosOp(RadosEvent::from(raw)));
        }
        collector.push(TraceEvent::RequestEnd(request(
            &id,
            1,
            start,
            start + 5 * MS,
        )));
    }
    collector
}

/// A periodic drain where only `expired` of `groups` resident groups have aged
/// out: the cost should follow `expired`, not `groups`.
fn drain_bench(groups: u64, expired: u64) {
    const OPS_PER_REQUEST: u64 = 4;
    const TTL: u64 = 120 * SEC;
    let mut collector = populated_collector(groups, OPS_PER_REQUEST);
    // Group i's last activity is ~SEC + i*MS + 5ms; expire exactly the first
    // `expired` of them.
    let now = SEC + expired * MS + TTL;
    // The part that runs under the collector lock on the ring-buffer thread.
    let before = allocations();
    let started = Instant::now();
    let batch = collector.drain_expired_batch(now, TTL);
    let locked = started.elapsed().as_nanos();
    let locked_allocs = allocations() - before;
    // The part the OTLP exporter thread now does, outside the lock.
    let before = allocations();
    let started = Instant::now();
    let spans = batch
        .map(|batch| batch.into_trace_document("rgwtrace").spans.len())
        .unwrap_or(0);
    let render = started.elapsed().as_nanos();
    println!(
        "BENCH drain groups={groups} expired={expired}: locked {:.3} ms ({locked_allocs} allocs), \
         render {:.3} ms ({} allocs), {spans} spans",
        locked as f64 / 1e6,
        render as f64 / 1e6,
        allocations() - before
    );
    black_box(collector);
}

#[test]
#[ignore = "benchmark; run with --release --ignored --nocapture"]
fn collector_bench_drain() {
    drain_bench(200_000, 1_000);
    drain_bench(200_000, 20_000);
}

/// An untagged op with NO candidate, older than every resident request: the
/// case an `upper`-ordered candidate scan cannot cut short (every newer request
/// has `upper >= op.start`, none overlaps).
#[test]
#[ignore = "benchmark; run with --release --ignored --nocapture"]
fn collector_bench_inference_no_candidate() {
    const GROUPS: u64 = 20_000;
    const OPS: u64 = 1_000;
    let mut collector = Collector::with_inferred_correlation(SEC);
    collector.set_end_probe_attached(true);
    for i in 0..GROUPS {
        let start = 10 * SEC + i * MS;
        let id = trans_id(i);
        collector.push(TraceEvent::RequestStart(request(
            &id,
            (i % 64) as u32,
            start,
            0,
        )));
        collector.push(TraceEvent::RequestEnd(request(
            &id,
            (i % 64) as u32,
            start,
            start + 50 * MS,
        )));
    }
    let started = Instant::now();
    for i in 0..OPS {
        let mut raw = raw_rados("", "bucket-object", i * 1_000);
        raw.send_tid = 9_999;
        collector.push(TraceEvent::RadosOp(RadosEvent::from(raw)));
    }
    report(
        &format!("inference_no_candidate_op groups={GROUPS}"),
        OPS,
        started.elapsed().as_nanos(),
        0,
    );
    black_box(collector);
}

/// The drain's pending-inference guard with 10,000 long-lived ops that ended
/// before the request being considered. The end index should skip every op.
#[test]
#[ignore = "benchmark; run with --release --ignored --nocapture"]
fn collector_bench_drain_pending_no_overlap() {
    const OPS: u64 = 10_000;
    const CHECKS: u64 = 100_000;
    let mut pending = IntervalSet::default();
    for id in 0..OPS {
        pending.insert(100 * SEC, 170 * SEC, id);
    }
    let started = Instant::now();
    for _ in 0..CHECKS {
        black_box(pending.any_overlapping(180 * SEC, 181 * SEC, &0));
    }
    report(
        "drain_pending_no_overlap ops=10000",
        CHECKS,
        started.elapsed().as_nanos(),
        0,
    );
    assert_eq!(pending.scanned.get(), 0);
}
