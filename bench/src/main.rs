// SPDX-License-Identifier: GPL-2.0-only
//! rgwtrace per-probe overhead microbenchmark.
//!
//! Measures the REAL per-probe cost of rgwtrace's actual BPF programs by
//! attaching them to a synthetic, self-hosted target (this very binary) -- no
//! Ceph required. See bench/README.md for the methodology, the JSON schema, and
//! how full-path execution is guaranteed.
//!
//! Must run as root (BPF load + uprobe attach). Build/test work without root;
//! only the run needs privilege, so the pure aggregation logic in `stats` is
//! unit-tested via `cargo test` while the harness below is exercised by the
//! orchestrator.

mod descriptors;
mod stats;
mod target;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("rgwtrace-bench requires Linux (eBPF uprobes)");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::hint::black_box;
    use std::io::Write;
    use std::mem::MaybeUninit;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use anyhow::{bail, Context, Result};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder, UprobeOpts};
    use serde::Serialize;

    use crate::stats::{aggregate, derive, Aggregate, Derived};
    use crate::target::{
        self, descriptor_set, SynState, SYN_ACTING, SYN_CID, SYN_EXTENT_LENGTH, SYN_EXTENT_OFFSET,
        SYN_OBJECT_NAME, SYN_OPS_SIZE, SYN_OSD_OP_READ, SYN_POOL, SYN_TARGET_OSD, SYN_TID,
        SYN_TRANS_ID,
    };

    mod skel {
        pub mod rgwtrace {
            include!(concat!(env!("OUT_DIR"), "/rgwtrace.skel.rs"));
        }
        pub mod trap {
            include!(concat!(env!("OUT_DIR"), "/bench_trap.skel.rs"));
        }
    }
    use skel::rgwtrace::RgwtraceSkelBuilder;
    use skel::trap::BenchTrapSkelBuilder;

    const SCHEMA_VERSION: u32 = 2;

    // R1: the events ring buffer is resized to 16 MiB for the TIMED phases only.
    // bpf_ringbuf_reserve/submit cost is capacity-INDEPENDENT (a ringbuf is a
    // fixed-stride producer/consumer queue; reserve just bumps the producer
    // position modulo capacity), so the measured probe path is byte-for-byte
    // unchanged. What the extra capacity buys is a ~240 ms horizon of consumer
    // absence at ~125k events/s, which absorbs a multi-ms vCPU deschedule
    // (hypervisor steal / guest preemption) that a 256 KiB, ~474-record, ~3.7 ms
    // ring cannot -- and which no amount of busy-spinning on the consumer can
    // prevent. Ringbuf sizes must be a power-of-two multiple of the page size;
    // 16 MiB qualifies.
    const TIMED_EVENTS_RING_BYTES: u32 = 16 * 1024 * 1024;
    // R2: the ringbuf_saturation phase pins the ring at 256 KiB -- the size
    // rgwtrace shipped with before --ringbuf-size (default now 16 MiB) -- because
    // it measures the record-capacity math (~455 RADOS records of 576 ring bytes)
    // against a known size. It runs against a SECOND skeleton instance.
    const PRODUCTION_EVENTS_RING_BYTES: u32 = 256 * 1024;
    // Bounded wait for the drainer to fully consume a warmup/timed window before
    // the diagnostics counters are snapshotted. Generous; a real stall errors out
    // rather than silently under-counting.
    const DRAIN_BARRIER_TIMEOUT: Duration = Duration::from_secs(60);

    // rgwtrace diagnostics counter indices (bpf/rgwtrace_events.h).
    const DIAG_RINGBUF_REQUEST_DROPS: u32 = 0;
    const DIAG_RINGBUF_RADOS_DROPS: u32 = 1;
    const DIAG_PROBE_READ_FAILURES: u32 = 5;
    const DIAG_OPERATE_SEED_HITS: u32 = 15;

    // rgwtrace_event wire layout (record-relative; event `data` starts at +8).
    const EVENT_DATA_OFFSET: usize = 8;
    const EVENT_TYPE_START: u32 = 1;
    const EVENT_TYPE_END: u32 = 2;
    const EVENT_TYPE_RADOS: u32 = 3;
    // rados event field offsets within the event record (struct
    // rgwtrace_rados_event, see src/events.rs RawRadosEvent).
    const OFF_RADOS_CID: usize = EVENT_DATA_OFFSET; // struct +0
    const OFF_RADOS_TID: usize = EVENT_DATA_OFFSET + 8; // struct +8
    const OFF_RADOS_POOL: usize = EVENT_DATA_OFFSET + 32; // struct +32
    const OFF_RADOS_OFFSET: usize = EVENT_DATA_OFFSET + 40; // struct +40 (extent offset)
    const OFF_RADOS_LENGTH: usize = EVENT_DATA_OFFSET + 48; // struct +48 (extent length)
    const OFF_RADOS_TARGET_OSD: usize = EVENT_DATA_OFFSET + 64; // struct +64
    const OFF_RADOS_OPS_SIZE: usize = EVENT_DATA_OFFSET + 76; // struct +76
    const OFF_RADOS_ACTING: usize = EVENT_DATA_OFFSET + 84; // struct +84 (int[16])
    const OFF_RADOS_OPS: usize = EVENT_DATA_OFFSET + 148; // struct +148 (u16[3])
    const OFF_RADOS_TRANS_ID: usize = EVENT_DATA_OFFSET + 298; // struct +298 (char[128])
    const OFF_RADOS_OBJECT_NAME: usize = EVENT_DATA_OFFSET + 426; // struct +426 (char[128])

    struct Config {
        baseline_iters: u64,
        iters: u64,
        reps: usize,
        warmup: u64,
        k: u64,
        flood: u64,
        cpu: usize,
        out_dir: PathBuf,
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                // Baseline calls are ~1-3 ns; 2M keeps the two clock reads far
                // below 1% of the timed window.
                baseline_iters: 2_000_000,
                // Probed calls are ~0.3-2 us; 200k is ~40-400 ms per rep, still
                // clock-overhead-negligible, and small enough that a concurrent
                // drainer keeps the 256 KiB ring buffer from overflowing.
                iters: 200_000,
                reps: 5,
                warmup: 20_000,
                k: 4,
                flood: 20_000,
                cpu: 0,
                out_dir: PathBuf::from("bench-results"),
            }
        }
    }

    fn take_value<'a>(argv: &'a [String], i: &mut usize, flag: &str) -> Result<&'a str> {
        *i += 1;
        argv.get(*i)
            .map(String::as_str)
            .with_context(|| format!("missing value for {flag}"))
    }

    fn take_u64(argv: &[String], i: &mut usize, flag: &str) -> Result<u64> {
        take_value(argv, i, flag)?
            .parse::<u64>()
            .with_context(|| format!("{flag} expects an unsigned integer"))
    }

    fn parse_config() -> Result<Config> {
        let mut cfg = Config::default();
        let argv: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i < argv.len() {
            let arg = argv[i].as_str();
            match arg {
                "--baseline-iterations" => cfg.baseline_iters = take_u64(&argv, &mut i, arg)?,
                "--iterations" | "-n" => cfg.iters = take_u64(&argv, &mut i, arg)?,
                "--reps" => cfg.reps = take_u64(&argv, &mut i, arg)? as usize,
                "--warmup" => cfg.warmup = take_u64(&argv, &mut i, arg)?,
                "--k" => cfg.k = take_u64(&argv, &mut i, arg)?,
                "--flood" => cfg.flood = take_u64(&argv, &mut i, arg)?,
                "--cpu" => cfg.cpu = take_u64(&argv, &mut i, arg)? as usize,
                "--out-dir" => cfg.out_dir = PathBuf::from(take_value(&argv, &mut i, arg)?),
                "--help" | "-h" => {
                    println!(
                        "usage: rgwtrace-bench [--iterations N] [--baseline-iterations N] \
                         [--reps N] [--warmup N] [--k N] [--flood N] [--cpu N] [--out-dir DIR]"
                    );
                    std::process::exit(0);
                }
                other => bail!("unknown argument: {other}"),
            }
            i += 1;
        }
        if cfg.reps == 0 {
            bail!("--reps must be >= 1");
        }
        Ok(cfg)
    }

    // ---- CPU affinity + monotonic clock ----------------------------------

    fn pin_to_cpu(cpu: usize) -> Result<()> {
        // SAFETY: zero-inits a cpu_set_t and sets one bit; libc calls are FFI.
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_ZERO(&mut set);
            libc::CPU_SET(cpu, &mut set);
            let ret = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
            if ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("sched_setaffinity(cpu={cpu})"));
            }
        }
        Ok(())
    }

    fn now_ns() -> u64 {
        // SAFETY: standard clock_gettime FFI into a stack timespec.
        unsafe {
            let mut ts: libc::timespec = std::mem::zeroed();
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
            (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
        }
    }

    /// Warmup, then `reps` timed repetitions of `iters` calls to `body`. Returns
    /// per-rep ns/call. `body` must call the synthetic target function(s) with
    /// `black_box` so nothing is optimized away.
    fn time_reps(warmup: u64, iters: u64, reps: usize, mut body: impl FnMut()) -> Vec<f64> {
        for _ in 0..warmup {
            body();
        }
        let mut samples = Vec::with_capacity(reps);
        for _ in 0..reps {
            let t0 = now_ns();
            for _ in 0..iters {
                body();
            }
            let t1 = now_ns();
            samples.push((t1 - t0) as f64 / iters as f64);
        }
        samples
    }

    // ---- ring-buffer drainer ---------------------------------------------

    struct Counters {
        start: AtomicU64,
        end: AtomicU64,
        rados: AtomicU64,
        /// rados events whose late-written fields did NOT match the synthetic
        /// expectations -- i.e. send_op bailed before writing them, or a
        /// `bpf_probe_read_user` silently failed. Must be 0.
        rados_bad: AtomicU64,
        decode_err: AtomicU64,
        /// Whether to additionally require the correlated trans_id ("bench-trans-id")
        /// on every rados event (combined phase only; the background-op phases
        /// leave trans_id empty by design).
        check_trans_id: bool,
    }

    impl Counters {
        fn new(check_trans_id: bool) -> Self {
            Self {
                start: AtomicU64::new(0),
                end: AtomicU64::new(0),
                rados: AtomicU64::new(0),
                rados_bad: AtomicU64::new(0),
                decode_err: AtomicU64::new(0),
                check_trans_id,
            }
        }

        fn record(&self, data: &[u8]) {
            if data.len() < EVENT_DATA_OFFSET {
                self.decode_err.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let ty = u32::from_ne_bytes(data[0..4].try_into().unwrap());
            match ty {
                EVENT_TYPE_START => {
                    self.start.fetch_add(1, Ordering::Relaxed);
                }
                EVENT_TYPE_END => {
                    self.end.fetch_add(1, Ordering::Relaxed);
                }
                EVENT_TYPE_RADOS => {
                    self.rados.fetch_add(1, Ordering::Relaxed);
                    if !self.rados_fields_match(data) {
                        self.rados_bad.fetch_add(1, Ordering::Relaxed);
                    }
                }
                _ => {
                    self.decode_err.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        /// Verify the RADOS_OP event carries the synthetic values written at
        /// EVERY point of send_op's body -- scalar members, the object name, all
        /// three acting entries, the op code, and the extent offset/length that
        /// come from the deepest (per-op, extent-branch) `bpf_probe_read_user`s.
        /// EVERY expected value is nonzero and distinct, so a match proves not
        /// only that send_op reached slot 11 (`ops_size`) but that each deep read
        /// actually SUCCEEDED (a failed read leaves the field at 0 / -1).
        fn rados_fields_match(&self, data: &[u8]) -> bool {
            let read_u64 = |off: usize| -> Option<u64> {
                data.get(off..off + 8)
                    .map(|b| u64::from_ne_bytes(b.try_into().unwrap()))
            };
            let read_u32 = |off: usize| -> Option<u32> {
                data.get(off..off + 4)
                    .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
            };
            let read_i32 = |off: usize| -> Option<i32> {
                data.get(off..off + 4)
                    .map(|b| i32::from_ne_bytes(b.try_into().unwrap()))
            };
            let read_u16 = |off: usize| -> Option<u16> {
                data.get(off..off + 2)
                    .map(|b| u16::from_ne_bytes(b.try_into().unwrap()))
            };

            let scalars = read_u64(OFF_RADOS_CID) == Some(SYN_CID)
                && read_u64(OFF_RADOS_TID) == Some(SYN_TID)
                && read_u64(OFF_RADOS_POOL) == Some(SYN_POOL)
                && read_u32(OFF_RADOS_TARGET_OSD) == Some(SYN_TARGET_OSD)
                && read_u32(OFF_RADOS_OPS_SIZE) == Some(SYN_OPS_SIZE);

            // Object name (slot 4 -> name string read).
            let object_name = data
                .get(OFF_RADOS_OBJECT_NAME..OFF_RADOS_OBJECT_NAME + SYN_OBJECT_NAME.len())
                == Some(SYN_OBJECT_NAME);

            // acting[0..3] (slots 8/9 -> per-element reads).
            let acting = read_i32(OFF_RADOS_ACTING) == Some(SYN_ACTING[0])
                && read_i32(OFF_RADOS_ACTING + 4) == Some(SYN_ACTING[1])
                && read_i32(OFF_RADOS_ACTING + 8) == Some(SYN_ACTING[2]);

            // op code + the extent-branch offset/length (the deepest reads).
            let ops = read_u16(OFF_RADOS_OPS) == Some(SYN_OSD_OP_READ)
                && read_u64(OFF_RADOS_OFFSET) == Some(SYN_EXTENT_OFFSET)
                && read_u64(OFF_RADOS_LENGTH) == Some(SYN_EXTENT_LENGTH);

            // Correlated trans_id (combined phase only).
            let trans_id = !self.check_trans_id
                || data.get(OFF_RADOS_TRANS_ID..OFF_RADOS_TRANS_ID + SYN_TRANS_ID.len())
                    == Some(SYN_TRANS_ID);

            scalars && object_name && acting && ops && trans_id
        }

        fn snapshot(&self) -> (u64, u64, u64, u64, u64) {
            (
                self.start.load(Ordering::Relaxed),
                self.end.load(Ordering::Relaxed),
                self.rados.load(Ordering::Relaxed),
                self.rados_bad.load(Ordering::Relaxed),
                self.decode_err.load(Ordering::Relaxed),
            )
        }

        /// (start, end, rados, bad) -- the four counters the timed-window
        /// witnesses subtract across a phase's drain barriers.
        fn snapshot4(&self) -> (u64, u64, u64, u64) {
            (
                self.start.load(Ordering::Relaxed),
                self.end.load(Ordering::Relaxed),
                self.rados.load(Ordering::Relaxed),
                self.rados_bad.load(Ordering::Relaxed),
            )
        }

        /// Total events the drainer has decoded so far, across all types. Used as
        /// the drain-barrier metric: once it reaches the events PRODUCED so far,
        /// the ring is empty and the diagnostics counters can be snapshotted.
        fn total_received(&self) -> u64 {
            self.start.load(Ordering::Relaxed)
                + self.end.load(Ordering::Relaxed)
                + self.rados.load(Ordering::Relaxed)
        }
    }

    /// Snapshot of the diagnostics counters relevant to the timed phases.
    #[derive(Clone, Copy, Default)]
    struct DiagSnap {
        req_drops: u64,
        rados_drops: u64,
        read_fails: u64,
        operate_hits: u64,
    }

    impl DiagSnap {
        fn read<M: MapCore>(map: &M) -> Result<Self> {
            Ok(Self {
                req_drops: read_diag(map, DIAG_RINGBUF_REQUEST_DROPS)?,
                rados_drops: read_diag(map, DIAG_RINGBUF_RADOS_DROPS)?,
                read_fails: read_diag(map, DIAG_PROBE_READ_FAILURES)?,
                operate_hits: read_diag(map, DIAG_OPERATE_SEED_HITS)?,
            })
        }

        fn delta(self, base: Self) -> Self {
            Self {
                req_drops: self.req_drops - base.req_drops,
                rados_drops: self.rados_drops - base.rados_drops,
                read_fails: self.read_fails - base.read_fails,
                operate_hits: self.operate_hits - base.operate_hits,
            }
        }
    }

    /// Per-timed-rep diagnostics deltas, for attribution in the JSON.
    #[derive(Clone, Copy, Serialize)]
    struct RepDiag {
        rep: usize,
        request_drops: u64,
        rados_drops: u64,
        probe_read_failures: u64,
    }

    /// Everything a timed event/diag phase produced, all scoped to the TIMED
    /// window (between the post-warmup drain barrier and the final drain barrier).
    struct PhaseRun {
        samples: Vec<f64>,
        recv_start: u64,
        recv_end: u64,
        recv_rados: u64,
        recv_bad: u64,
        diag: DiagSnap,
        per_rep: Vec<RepDiag>,
        /// True if ANY timed rep saw a ring drop or a probe-read failure.
        any_rep_bad: bool,
    }

    /// Busy-wait until the drainer has decoded `target` total events, or error on
    /// timeout. This is the drain barrier: it guarantees the ring is empty so the
    /// synchronous diagnostics counters describe exactly the window just run.
    fn wait_received(counters: &Counters, target: u64, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        loop {
            if counters.total_received() >= target {
                return Ok(());
            }
            if start.elapsed() > timeout {
                bail!(
                    "drain barrier timed out after {:?}: drainer decoded {} of {} events (the \
                     consumer could not keep up -- lower --iterations or investigate host steal)",
                    timeout,
                    counters.total_received(),
                    target
                );
            }
            std::hint::spin_loop();
        }
    }

    /// Run a timed phase with the ready handshake (R3), a post-warmup drain
    /// barrier + timed-window-only accounting (R4), and per-rep diagnostics
    /// snapshots. `setup` runs once before warmup (e.g. to seed the bridge) and
    /// may itself produce `setup_events`; each timed iteration of `call` produces
    /// `events_per_iter` ring events.
    #[allow(clippy::too_many_arguments)]
    fn run_event_phase<M, D>(
        events_map: &M,
        diag_map: &D,
        counters: &Counters,
        drainer_cpu: usize,
        setup_events: u64,
        events_per_iter: u64,
        warmup: u64,
        iters: u64,
        reps: usize,
        mut setup: impl FnMut(),
        mut call: impl FnMut(),
    ) -> Result<PhaseRun>
    where
        M: MapCore,
        D: MapCore,
    {
        with_drainer(
            events_map,
            counters,
            drainer_cpu,
            |ready| -> Result<PhaseRun> {
                // R3: do not touch the target until the drainer is pinned and running,
                // or warmup could produce into a ring nobody is consuming yet.
                while !ready.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }

                setup();
                for _ in 0..warmup {
                    call();
                }

                // R4: post-warmup drain barrier, then baseline the counters. A warmup
                // drop can no longer invalidate the phase, because the timed window is
                // measured strictly between this barrier and the final one.
                let warm_target = setup_events + warmup * events_per_iter;
                wait_received(counters, warm_target, DRAIN_BARRIER_TIMEOUT)?;
                let diag_base = DiagSnap::read(diag_map)?;
                let (base_start, base_end, base_rados, base_bad) = counters.snapshot4();

                let mut samples = Vec::with_capacity(reps);
                let mut per_rep = Vec::with_capacity(reps);
                let mut any_rep_bad = false;
                for rep in 0..reps {
                    let before = DiagSnap::read(diag_map)?;
                    let t0 = now_ns();
                    for _ in 0..iters {
                        call();
                    }
                    let t1 = now_ns();
                    samples.push((t1 - t0) as f64 / iters as f64);
                    let after = DiagSnap::read(diag_map)?;
                    let d = after.delta(before);
                    if d.req_drops > 0 || d.rados_drops > 0 || d.read_fails > 0 {
                        any_rep_bad = true;
                    }
                    per_rep.push(RepDiag {
                        rep,
                        request_drops: d.req_drops,
                        rados_drops: d.rados_drops,
                        probe_read_failures: d.read_fails,
                    });
                }

                // Final drain barrier: wait for every timed event to be decoded so the
                // received/diag deltas below are exact for the timed window.
                let final_target = setup_events + (warmup + iters * reps as u64) * events_per_iter;
                wait_received(counters, final_target, DRAIN_BARRIER_TIMEOUT)?;
                let diag_final = DiagSnap::read(diag_map)?;
                let (fin_start, fin_end, fin_rados, fin_bad) = counters.snapshot4();

                Ok(PhaseRun {
                    samples,
                    recv_start: fin_start - base_start,
                    recv_end: fin_end - base_end,
                    recv_rados: fin_rados - base_rados,
                    recv_bad: fin_bad - base_bad,
                    diag: diag_final.delta(diag_base),
                    per_rep,
                    any_rep_bad,
                })
            },
        )?
    }

    /// Run `body` with a background thread continuously draining the events ring
    /// buffer into `counters`. The drainer keeps polling until `body` returns and
    /// then drains whatever is left before the counters are read.
    ///
    /// The `RingBuffer` (which is `Send`) is built on this thread and MOVED into
    /// the drainer thread; only `&AtomicBool` crosses back to coordinate stop.
    ///
    /// The drainer PINS ITSELF to `drainer_cpu` (distinct from the timed thread's
    /// CPU) as its FIRST action. A newly spawned Linux thread inherits its
    /// creator's CPU affinity mask (`man 2 sched_setaffinity`: "A child created
    /// via fork(2) inherits its parent's CPU affinity mask. The affinity mask is
    /// preserved across an execve(2)."; the same inheritance holds for threads
    /// created via clone/pthread_create). The timed thread is pinned to
    /// `cfg.cpu` BEFORE any drainer is spawned, so without this the drainer would
    /// run on the timed CPU and its userspace decode work would contend with the
    /// measurement -- a cost the no-probe baselines do not pay.
    fn with_drainer<R, M>(
        events_map: &M,
        counters: &Counters,
        drainer_cpu: usize,
        body: impl FnOnce(&AtomicBool) -> R,
    ) -> Result<R>
    where
        M: MapCore,
    {
        let mut builder = RingBufferBuilder::new();
        builder.add(events_map, |data| {
            counters.record(data);
            0
        })?;
        let rb = builder.build()?;

        let stop = AtomicBool::new(false);
        // R3: set true by the drainer AFTER it has pinned itself and is about to
        // busy-drain, so the timed body can wait before producing anything.
        let ready = AtomicBool::new(false);
        std::thread::scope(|scope| -> Result<R> {
            let stop_ref = &stop;
            let ready_ref = &ready;
            let handle = scope.spawn(move || -> Result<()> {
                // Move the drainer OFF the timed CPU before touching the buffer.
                pin_to_cpu(drainer_cpu)?;
                // Announce readiness only once pinned and about to drain.
                ready_ref.store(true, Ordering::Release);
                // BUSY-DRAIN, do NOT poll(). Decode is ~1 us/event versus ~8
                // us/event production, so a tight consume_raw() spin on this
                // dedicated CPU keeps the (now 16 MiB) ring near-empty. The large
                // ring plus this spin absorbs multi-ms consumer descheduling that
                // no poll() interval could. spin_loop() is a politeness hint on the
                // empty path (no syscall, no sleep).
                while !stop_ref.load(Ordering::Relaxed) {
                    if rb.consume_raw() <= 0 {
                        std::hint::spin_loop();
                    }
                }
                // Final catch-up drain: consume until the buffer reports empty.
                while rb.consume_raw() > 0 {}
                Ok(())
            });
            // The body owns the ready handshake and the drain barriers; by the time
            // it returns, the ring is already empty, so no settle sleep is needed.
            let r = body(&ready);
            stop.store(true, Ordering::Relaxed);
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("ring-buffer drainer panicked"))??;
            Ok(r)
        })
    }

    fn read_diag<M: MapCore>(map: &M, counter: u32) -> Result<u64> {
        let key = counter.to_ne_bytes();
        let Some(values) = map.lookup_percpu(&key, MapFlags::ANY)? else {
            return Ok(0);
        };
        let mut total = 0_u64;
        for value in values {
            if value.len() >= 8 {
                total = total.saturating_add(u64::from_ne_bytes(value[..8].try_into().unwrap()));
            }
        }
        Ok(total)
    }

    fn read_trap_count<M: MapCore>(map: &M) -> Result<u64> {
        read_diag(map, 0)
    }

    // ---- JSON report structs ---------------------------------------------

    #[derive(Serialize)]
    struct Witness {
        kind: &'static str,
        label: String,
        expected: u64,
        observed: u64,
        dropped: u64,
        full_path_ok: bool,
    }

    #[derive(Serialize)]
    struct PhaseReport {
        name: &'static str,
        description: &'static str,
        iterations: u64,
        reps: usize,
        #[serde(flatten)]
        aggregate: Aggregate,
        witnesses: Vec<Witness>,
        /// Per-timed-rep diagnostics deltas (drops / probe-read failures) for
        /// attribution. Empty for baselines, the trap phase, and saturation.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        per_rep: Vec<RepDiag>,
    }

    #[derive(Serialize)]
    struct DerivedCost {
        program: &'static str,
        /// Number of uprobe hits per timed iteration in this phase (each costs
        /// one `t_trap`). get_handler=1, send+finish=2, operate=1, dtor pair=2,
        /// combined=2+3k.
        probe_hits: f64,
        /// Total per-call overhead: probed phase median - that phase's own
        /// no-probe baseline median.
        overhead_ns: Derived,
        /// Program-body cost with the trap machinery removed:
        /// overhead - probe_hits * t_trap.
        t_prog_ns: Derived,
    }

    #[derive(Serialize)]
    struct HostInfo {
        kernel: String,
        arch: &'static str,
        nproc: usize,
        pinned_cpu: usize,
    }

    #[derive(Serialize)]
    struct ConfigReport {
        baseline_iterations: u64,
        iterations: u64,
        reps: usize,
        warmup: u64,
        k: u64,
        flood: u64,
        /// R1: the events ring size (bytes) used for the TIMED phases. Enlarged
        /// from the production default purely to absorb consumer descheduling;
        /// bpf_ringbuf_reserve/submit cost is capacity-independent.
        timed_events_ring_bytes: u32,
        /// R2: the events ring size (bytes) used by the ringbuf_saturation phase --
        /// 256 KiB, whose ~455-record limit that phase measures.
        saturation_events_ring_bytes: u32,
    }

    #[derive(Serialize)]
    struct BenchOutput {
        schema_version: u32,
        generated_unix_ns: u64,
        host: HostInfo,
        config: ConfigReport,
        t_trap_ns: Derived,
        phases: Vec<PhaseReport>,
        derived: Vec<DerivedCost>,
        full_path_ok: bool,
    }

    // ---- the harness ------------------------------------------------------

    pub fn run() -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            bail!("rgwtrace-bench must run as root (BPF load + uprobe attach)");
        }
        let cfg = parse_config()?;
        let ncpus = num_cpus_online();
        if ncpus < 2 {
            bail!(
                "the benchmark needs >= 2 online CPUs: the timed loop is pinned to cpu {} and the \
                 ring-buffer drainer must run on a DIFFERENT CPU so its userspace decode work does \
                 not contend with the measurement (only baselines would then be contention-free)",
                cfg.cpu
            );
        }
        if cfg.cpu >= ncpus {
            bail!(
                "--cpu {} is out of range (only {ncpus} CPUs online)",
                cfg.cpu
            );
        }
        // The drainer runs here; distinct from the timed CPU. See with_drainer.
        let drainer_cpu = (cfg.cpu + 1) % ncpus;
        pin_to_cpu(cfg.cpu)?;

        let exe = std::env::current_exe().context("resolve current executable path")?;
        let pid = std::process::id() as i32;

        // --- open + configure + load the REAL rgwtrace skeleton -----------
        // R1: the timed phases run against a skeleton whose events ring is resized
        // to 16 MiB. The saturation phase (R2) later loads a SECOND skeleton at
        // the production default size.
        let mut open_object = MaybeUninit::uninit();
        let skel = load_rgwtrace_skel(&mut open_object, Some(TIMED_EVENTS_RING_BYTES))?;

        // --- open + load the bench-only trap skeleton ---------------------
        let mut trap_object = MaybeUninit::uninit();
        let trap_skel = BenchTrapSkelBuilder::default()
            .open(&mut trap_object)?
            .load()
            .context("load bench_trap skeleton")?;

        let state = SynState::new();
        let rs = state.req_state_ptr();
        let op = state.syn_op_ptr();
        let k = cfg.k;
        // The OS thread id the timed loop runs on (main thread, pinned). Used to
        // clear this thread's request context between phases so a leftover from an
        // earlier phase cannot silently change which send_op path we measure.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;

        let mut phases: Vec<PhaseReport> = Vec::new();

        // === Phase: baseline (trap target, no probe) ======================
        let baseline_trap = time_reps(cfg.warmup, cfg.baseline_iters, cfg.reps, || {
            black_box(target::syn_trap_target(black_box(1)));
        });
        phases.push(simple_phase(
            "baseline_trap",
            "no probe: bare synthetic call cost (trap target)",
            cfg.baseline_iters,
            cfg.reps,
            &baseline_trap,
        )?);

        // === Phase: trivial trap ==========================================
        let trap_samples = {
            let before = read_trap_count(&trap_skel.maps.trap_count)?;
            let _link = trap_skel.progs.bench_trap.attach_uprobe_with_opts(
                pid,
                &exe,
                0,
                UprobeOpts {
                    func_name: "syn_trap_target".to_string(),
                    ..Default::default()
                },
            )?;
            let samples = time_reps(cfg.warmup, cfg.iters, cfg.reps, || {
                black_box(target::syn_trap_target(black_box(1)));
            });
            let after = read_trap_count(&trap_skel.maps.trap_count)?;
            let calls = cfg.warmup + cfg.iters * cfg.reps as u64;
            let observed = after - before;
            // Exactly one per-CPU array increment per call, and nothing else. This
            // increment is why t_trap is not the raw trap-frame cost (documented in
            // bench/README.md); keeping it is what makes this counter a WITNESS.
            let ok = observed == calls;
            let mut report = simple_phase(
                "trap",
                "bench-only always-return-0 uprobe: isolates pure trap cost",
                cfg.iters,
                cfg.reps,
                &samples,
            )?;
            report.witnesses.push(Witness {
                kind: "diag_counter",
                label: "bench_trap fired".to_string(),
                expected: calls,
                observed,
                dropped: 0,
                full_path_ok: ok,
            });
            phases.push(report);
            samples
        };

        // === Phase: baseline (rgw get_handler target, no probe) ===========
        let baseline_gh = time_reps(cfg.warmup, cfg.baseline_iters, cfg.reps, || {
            black_box(target::syn_get_handler(black_box(rs)));
        });
        phases.push(simple_phase(
            "baseline_get_handler",
            "no probe: bare syn_get_handler call cost",
            cfg.baseline_iters,
            cfg.reps,
            &baseline_gh,
        )?);

        // === Phase: get_handler (real program) ============================
        let gh_samples = {
            let counters = Counters::new(false);
            let _link = skel.progs.uprobe_rgw_get_handler.attach_uprobe_with_opts(
                pid,
                &exe,
                0,
                UprobeOpts {
                    func_name: "syn_get_handler".to_string(),
                    ..Default::default()
                },
            )?;
            // events_per_iter = 1 (one START per call); no setup.
            let run = run_event_phase(
                &skel.maps.events,
                &skel.maps.diagnostics,
                &counters,
                drainer_cpu,
                0,
                1,
                cfg.warmup,
                cfg.iters,
                cfg.reps,
                || {},
                || {
                    black_box(target::syn_get_handler(black_box(rs)));
                },
            )?;
            let timed_calls = cfg.iters * cfg.reps as u64;
            // TIMED-window witness: exact receipt, zero drops in EVERY rep, zero
            // probe-read failures, zero field mismatches.
            let ok = timed_ok(
                run.recv_start,
                timed_calls,
                run.diag.req_drops,
                run.diag.read_fails,
                run.recv_bad,
            ) && !run.any_rep_bad;
            let mut report = timed_phase(
                "get_handler",
                "uprobe_rgw_get_handler full body (emits START)",
                cfg.iters,
                cfg.reps,
                &run,
            )?;
            report.witnesses.push(Witness {
                kind: "ringbuf_events",
                label: "REQUEST_START == timed calls, 0 drops (every rep), 0 probe-read failures"
                    .to_string(),
                expected: timed_calls,
                observed: run.recv_start,
                dropped: run.diag.req_drops,
                full_path_ok: ok,
            });
            phases.push(report);
            run.samples
        };

        // === Phase: baseline (send+finish pair, no probe) =================
        let baseline_rados = time_reps(cfg.warmup, cfg.baseline_iters, cfg.reps, || {
            black_box(target::syn_send_op(black_box(op)));
            black_box(target::syn_finish_op(black_box(op)));
        });
        phases.push(simple_phase(
            "baseline_rados",
            "no probe: bare syn_send_op + syn_finish_op call cost",
            cfg.baseline_iters,
            cfg.reps,
            &baseline_rados,
        )?);

        // === Phase: send_op + finish_op (real programs) ===================
        // Clear any request context an earlier phase (get_handler) left on this
        // thread, so this phase deterministically measures the BACKGROUND-op path
        // (no live context -> send_op skips the liveness gate and trans_id stamp).
        // The correlated path (with the liveness gate) is measured by the
        // combined_request phase instead.
        let _ = skel.maps.rgw_requests.delete(&tid.to_ne_bytes());
        let rados_samples = {
            let counters = Counters::new(false);
            let _l1 = skel.progs.uprobe_send_op.attach_uprobe_with_opts(
                pid,
                &exe,
                0,
                UprobeOpts {
                    func_name: "syn_send_op".to_string(),
                    ..Default::default()
                },
            )?;
            let _l2 = skel.progs.uprobe_finish_op.attach_uprobe_with_opts(
                pid,
                &exe,
                0,
                UprobeOpts {
                    func_name: "syn_finish_op".to_string(),
                    ..Default::default()
                },
            )?;
            // events_per_iter = 1 (one RADOS_OP per send+finish pair).
            let run = run_event_phase(
                &skel.maps.events,
                &skel.maps.diagnostics,
                &counters,
                drainer_cpu,
                0,
                1,
                cfg.warmup,
                cfg.iters,
                cfg.reps,
                || {},
                || {
                    black_box(target::syn_send_op(black_box(op)));
                    black_box(target::syn_finish_op(black_box(op)));
                },
            )?;
            let timed_calls = cfg.iters * cfg.reps as u64;
            // TIMED: exact receipt, zero drops in every rep, zero probe-read
            // failures, every field of every event verified (run.recv_bad == 0).
            let ok = timed_ok(
                run.recv_rados,
                timed_calls,
                run.diag.rados_drops,
                run.diag.read_fails,
                run.recv_bad,
            ) && !run.any_rep_bad;
            let mut report = timed_phase(
                "send_finish_op",
                "uprobe_send_op + uprobe_finish_op full bodies (finish emits RADOS_OP)",
                cfg.iters,
                cfg.reps,
                &run,
            )?;
            report.witnesses.push(Witness {
                kind: "ringbuf_events",
                label:
                    "RADOS_OP == timed calls, 0 drops (every rep), 0 read failures, all fields verified"
                        .to_string(),
                expected: timed_calls,
                observed: run.recv_rados,
                dropped: run.diag.rados_drops,
                full_path_ok: ok,
            });
            phases.push(report);
            run.samples
        };

        // === Phase: baseline (operate target, no probe) ===================
        let baseline_operate = time_reps(cfg.warmup, cfg.baseline_iters, cfg.reps, || {
            black_box(target::syn_rados_operate(black_box(
                rs as *const std::ffi::c_void,
            )));
        });
        phases.push(simple_phase(
            "baseline_operate",
            "no probe: bare syn_rados_operate call cost",
            cfg.baseline_iters,
            cfg.reps,
            &baseline_operate,
        )?);

        // === Phase: rgw_rados_operate (real program, per-submit re-seed) ==
        let operate_samples = {
            let counters = Counters::new(false);
            // get_handler must be attached to CREATE the bridge entry the
            // operate re-seed looks up; it is attached but only called ONCE in
            // setup, so it is not on the timed path.
            let _lgh = skel.progs.uprobe_rgw_get_handler.attach_uprobe_with_opts(
                pid,
                &exe,
                0,
                UprobeOpts {
                    func_name: "syn_get_handler".to_string(),
                    ..Default::default()
                },
            )?;
            let _lop = skel
                .progs
                .uprobe_rgw_rados_operate_read
                .attach_uprobe_with_opts(
                    pid,
                    &exe,
                    0,
                    UprobeOpts {
                        func_name: "syn_rados_operate".to_string(),
                        ..Default::default()
                    },
                )?;
            // Diag-witnessed phase: the timed operate calls emit NO ring events
            // (events_per_iter = 0); the single setup get_handler emits ONE START
            // (setup_events = 1), which the barrier accounts for. OPERATE_SEED_HITS
            // over the timed window must equal the timed operate call count.
            let run = run_event_phase(
                &skel.maps.events,
                &skel.maps.diagnostics,
                &counters,
                drainer_cpu,
                1,
                0,
                cfg.warmup,
                cfg.iters,
                cfg.reps,
                || {
                    // Seed the bridge once (creates rgw_ctx_by_reqstate[(rs, pid)]).
                    black_box(target::syn_get_handler(black_box(rs)));
                },
                || {
                    black_box(target::syn_rados_operate(black_box(
                        rs as *const std::ffi::c_void,
                    )));
                },
            )?;
            let timed_calls = cfg.iters * cfg.reps as u64;
            // Every timed operate must HIT the bridge (a miss = the cheaper
            // fail-closed path). The operate body does no probe_read_user, so the
            // only reads are the setup get_handler's (during warmup, outside the
            // timed window), hence timed read_fails must be 0.
            let ok = run.diag.operate_hits == timed_calls
                && run.diag.read_fails == 0
                && !run.any_rep_bad;
            let mut report = timed_phase(
                "rados_operate",
                "uprobe_rgw_rados_operate_read full body (per-submit bridge re-seed, HIT)",
                cfg.iters,
                cfg.reps,
                &run,
            )?;
            report.witnesses.push(Witness {
                kind: "diag_counter",
                label: "OPERATE_SEED_HITS == timed calls, 0 probe-read failures".to_string(),
                expected: timed_calls,
                observed: run.diag.operate_hits,
                dropped: 0,
                full_path_ok: ok,
            });
            phases.push(report);
            run.samples
        };

        // === Phase: baseline (get_handler + dtor pair, no probe) ==========
        let baseline_req = time_reps(cfg.warmup, cfg.baseline_iters, cfg.reps, || {
            black_box(target::syn_get_handler(black_box(rs)));
            black_box(target::syn_req_state_dtor(black_box(rs)));
        });
        phases.push(simple_phase(
            "baseline_request_end",
            "no probe: bare syn_get_handler + syn_req_state_dtor call cost",
            cfg.baseline_iters,
            cfg.reps,
            &baseline_req,
        )?);

        // === Phase: get_handler + req_state dtor (real programs) ==========
        // dtor DELETES the bridge entry, so each iteration re-creates it via
        // get_handler first: START then END per iteration.
        let request_end_samples = {
            let counters = Counters::new(false);
            let _lgh = skel.progs.uprobe_rgw_get_handler.attach_uprobe_with_opts(
                pid,
                &exe,
                0,
                UprobeOpts {
                    func_name: "syn_get_handler".to_string(),
                    ..Default::default()
                },
            )?;
            let _ldt = skel
                .progs
                .uprobe_rgw_req_state_dtor
                .attach_uprobe_with_opts(
                    pid,
                    &exe,
                    0,
                    UprobeOpts {
                        func_name: "syn_req_state_dtor".to_string(),
                        ..Default::default()
                    },
                )?;
            // events_per_iter = 2 (one START + one END per iteration).
            let run = run_event_phase(
                &skel.maps.events,
                &skel.maps.diagnostics,
                &counters,
                drainer_cpu,
                0,
                2,
                cfg.warmup,
                cfg.iters,
                cfg.reps,
                || {},
                || {
                    black_box(target::syn_get_handler(black_box(rs)));
                    black_box(target::syn_req_state_dtor(black_box(rs)));
                },
            )?;
            let timed_calls = cfg.iters * cfg.reps as u64;
            // TIMED: each iteration emits exactly one START and one END; with zero
            // drops in every rep both must equal `timed_calls`.
            let ok = timed_ok(
                run.recv_start + run.recv_end,
                2 * timed_calls,
                run.diag.req_drops,
                run.diag.read_fails,
                0,
            ) && run.recv_start == timed_calls
                && run.recv_end == timed_calls
                && !run.any_rep_bad;
            let mut report = timed_phase(
                "request_end",
                "get_handler + req_state dtor per iter (dtor emits END, needs the bridge get_handler creates)",
                cfg.iters,
                cfg.reps,
                &run,
            )?;
            report.witnesses.push(Witness {
                kind: "ringbuf_events",
                label: "START==timed AND END==timed, 0 drops (every rep), 0 read failures"
                    .to_string(),
                expected: 2 * timed_calls,
                observed: run.recv_start + run.recv_end,
                dropped: run.diag.req_drops,
                full_path_ok: ok,
            });
            phases.push(report);
            run.samples
        };

        // === Phase: baseline (combined request sequence, no probe) ========
        let baseline_combined = time_reps(cfg.warmup, cfg.baseline_iters, cfg.reps, || {
            black_box(target::syn_get_handler(black_box(rs)));
            for _ in 0..k {
                black_box(target::syn_rados_operate(black_box(
                    rs as *const std::ffi::c_void,
                )));
                black_box(target::syn_send_op(black_box(op)));
                black_box(target::syn_finish_op(black_box(op)));
            }
            black_box(target::syn_req_state_dtor(black_box(rs)));
        });
        phases.push(simple_phase(
            "baseline_combined",
            "no probe: bare combined request sequence (1 get_handler + k*(operate+send+finish) + 1 dtor)",
            cfg.baseline_iters,
            cfg.reps,
            &baseline_combined,
        )?);

        // === Phase: combined request (ALL FIVE programs) ==================
        // One request per iteration = 1 get_handler + k*(operate + send + finish)
        // + 1 dtor. The operate re-seed runs on every submit, and because
        // get_handler seeded a LIVE request context this iteration, send_op takes
        // its liveness-gate + trans_id-stamp path -- verified by requiring the
        // correlated trans_id on every RADOS_OP event (Counters::new(true)).
        let combined_samples = {
            let counters = Counters::new(true);
            let _l = attach_all(&skel, pid, &exe)?;
            // events_per_iter = 2 + k (1 START + 1 END + k RADOS_OP). operate emits
            // no ring event; its work is witnessed via OPERATE_SEED_HITS.
            let run = run_event_phase(
                &skel.maps.events,
                &skel.maps.diagnostics,
                &counters,
                drainer_cpu,
                0,
                2 + k,
                cfg.warmup,
                cfg.iters,
                cfg.reps,
                || {},
                || {
                    black_box(target::syn_get_handler(black_box(rs)));
                    for _ in 0..k {
                        black_box(target::syn_rados_operate(black_box(
                            rs as *const std::ffi::c_void,
                        )));
                        black_box(target::syn_send_op(black_box(op)));
                        black_box(target::syn_finish_op(black_box(op)));
                    }
                    black_box(target::syn_req_state_dtor(black_box(rs)));
                },
            )?;
            let timed_calls = cfg.iters * cfg.reps as u64;
            // TIMED: zero drops in every rep and zero probe-read failures throughout.
            let req_ok = timed_ok(
                run.recv_start + run.recv_end,
                2 * timed_calls,
                run.diag.req_drops,
                run.diag.read_fails,
                0,
            ) && run.recv_start == timed_calls
                && run.recv_end == timed_calls
                && !run.any_rep_bad;
            let rad_ok = timed_ok(
                run.recv_rados,
                timed_calls * k,
                run.diag.rados_drops,
                run.diag.read_fails,
                run.recv_bad,
            ) && !run.any_rep_bad;
            let operate_ok = run.diag.operate_hits == timed_calls * k;
            let mut report = timed_phase(
                "combined_request",
                "one request = 1 get_handler + k*(operate+send+finish) + 1 dtor per iter",
                cfg.iters,
                cfg.reps,
                &run,
            )?;
            report.witnesses.push(Witness {
                kind: "ringbuf_events",
                label: "START==timed AND END==timed, 0 drops (every rep), 0 read failures"
                    .to_string(),
                expected: 2 * timed_calls,
                observed: run.recv_start + run.recv_end,
                dropped: run.diag.req_drops,
                full_path_ok: req_ok,
            });
            report.witnesses.push(Witness {
                kind: "ringbuf_events",
                label: "RADOS_OP == k*timed, 0 drops, all fields + correlated trans_id verified"
                    .to_string(),
                expected: timed_calls * k,
                observed: run.recv_rados,
                dropped: run.diag.rados_drops,
                full_path_ok: rad_ok,
            });
            report.witnesses.push(Witness {
                kind: "diag_counter",
                label: "OPERATE_SEED_HITS == k*timed".to_string(),
                expected: timed_calls * k,
                observed: run.diag.operate_hits,
                dropped: 0,
                full_path_ok: operate_ok,
            });
            phases.push(report);
            run.samples
        };

        // === Phase: ring-buffer saturation ================================
        // R2: this phase MUST use a 256 KiB events ring (the pre---ringbuf-size
        // production size, not the 16 MiB one), because it measures the ~455-record
        // capacity math. So it runs against a SECOND skeleton instance sized to it. All of skel1's uprobe links are dropped by now, so attaching
        // the saturation skeleton's send/finish to the same symbols is conflict-free.
        {
            let mut sat_object = MaybeUninit::uninit();
            let sat_skel = load_rgwtrace_skel(&mut sat_object, Some(PRODUCTION_EVENTS_RING_BYTES))?;
            let _ = sat_skel.maps.rgw_requests.delete(&tid.to_ne_bytes());
            let _l1 = sat_skel.progs.uprobe_send_op.attach_uprobe_with_opts(
                pid,
                &exe,
                0,
                UprobeOpts {
                    func_name: "syn_send_op".to_string(),
                    ..Default::default()
                },
            )?;
            let _l2 = sat_skel.progs.uprobe_finish_op.attach_uprobe_with_opts(
                pid,
                &exe,
                0,
                UprobeOpts {
                    func_name: "syn_finish_op".to_string(),
                    ..Default::default()
                },
            )?;

            // Variant A: flood WITHOUT draining. The 256 KiB ring fills after
            // ~455 records of 576 ring bytes, then every further reserve fails.
            let a_before = read_diag(&sat_skel.maps.diagnostics, DIAG_RINGBUF_RADOS_DROPS)?;
            for _ in 0..cfg.flood {
                black_box(target::syn_send_op(black_box(op)));
                black_box(target::syn_finish_op(black_box(op)));
            }
            let a_drops =
                read_diag(&sat_skel.maps.diagnostics, DIAG_RINGBUF_RADOS_DROPS)? - a_before;
            // Records that fit before the first reservation failure == capacity.
            let fitted = cfg.flood.saturating_sub(a_drops);
            // Drain whatever is left so the buffer is clean for variant B.
            drain_all(&sat_skel.maps.events)?;

            // Variant B: flood WITH the busy-drainer running. Received + dropped
            // must still equal flood; with the busy-drain, drops now approach 0.
            let counters = Counters::new(false);
            let b_before = read_diag(&sat_skel.maps.diagnostics, DIAG_RINGBUF_RADOS_DROPS)?;
            with_drainer(&sat_skel.maps.events, &counters, drainer_cpu, |ready| {
                while !ready.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                for _ in 0..cfg.flood {
                    black_box(target::syn_send_op(black_box(op)));
                    black_box(target::syn_finish_op(black_box(op)));
                }
            })?;
            let b_drops =
                read_diag(&sat_skel.maps.diagnostics, DIAG_RINGBUF_RADOS_DROPS)? - b_before;
            let (_s, _e, b_rados, _bad, _err) = counters.snapshot();

            // The 256 KiB ring holds ~455 RADOS records; assert the measured capacity
            // is in that neighbourhood (tolerant of record-size/overhead rounding).
            const SAT_CAP_MIN: u64 = 400;
            const SAT_CAP_MAX: u64 = 600;
            let cap_ok = a_drops > 0 && (SAT_CAP_MIN..=SAT_CAP_MAX).contains(&fitted);

            // Saturation is a producer-only phase; report it with a zeroed
            // aggregate (no per-call timing) and two witnesses.
            let mut report = PhaseReport {
                name: "ringbuf_saturation",
                description:
                    "flood RADOS_OP events on a PRODUCTION 256 KiB ring; undrained capacity vs drained",
                iterations: cfg.flood,
                reps: 0,
                aggregate: zero_aggregate(),
                witnesses: Vec::new(),
                per_rep: Vec::new(),
            };
            report.witnesses.push(Witness {
                kind: "ringbuf_saturation",
                label: format!(
                    "undrained capacity {fitted} records in range {SAT_CAP_MIN}..={SAT_CAP_MAX} (256 KiB)"
                ),
                expected: cfg.flood,
                observed: fitted,
                dropped: a_drops,
                full_path_ok: cap_ok,
            });
            report.witnesses.push(Witness {
                kind: "ringbuf_saturation",
                label: "drained: received + dropped == flood, drops ~ 0".to_string(),
                expected: cfg.flood,
                observed: b_rados,
                dropped: b_drops,
                full_path_ok: b_rados + b_drops == cfg.flood,
            });
            phases.push(report);
        }

        // --- derived costs ------------------------------------------------
        //
        // program_overhead = probed_median - that phase's OWN unprobed baseline.
        // t_trap           = trap_median  - baseline_trap_median (ONE trap hit).
        // t_prog           = program_overhead - (probe_hits_in_phase * t_trap).
        //
        // Subtracting probe_hits * t_trap (not a single trap phase's absolute
        // time) is what makes a two-hit phase like send+finish report the body
        // cost of BOTH programs with BOTH traps removed, instead of retaining a
        // full trap. See bench/README.md and F1.
        let med = |s: &[f64]| aggregate(s).map(|a| a.median_ns).unwrap_or(0.0);
        let t_trap = derive(med(&trap_samples), med(&baseline_trap));
        let t_trap_ns = t_trap.value_ns;

        let cost = |program: &'static str, probed: &[f64], baseline: &[f64], hits: f64| {
            let overhead = derive(med(probed), med(baseline));
            let t_prog_raw = overhead.raw_ns - hits * t_trap_ns;
            DerivedCost {
                program,
                probe_hits: hits,
                overhead_ns: overhead,
                t_prog_ns: Derived {
                    value_ns: t_prog_raw.max(0.0),
                    raw_ns: t_prog_raw,
                    noisy: t_prog_raw < 0.0,
                },
            }
        };

        let k_f = k as f64;
        let derived = vec![
            cost("uprobe_rgw_get_handler", &gh_samples, &baseline_gh, 1.0),
            cost(
                "uprobe_send_op + uprobe_finish_op",
                &rados_samples,
                &baseline_rados,
                2.0,
            ),
            cost(
                "uprobe_rgw_rados_operate_read",
                &operate_samples,
                &baseline_operate,
                1.0,
            ),
            cost(
                "get_handler + req_state dtor (pair)",
                &request_end_samples,
                &baseline_req,
                2.0,
            ),
            cost(
                "combined_request (all five, per request)",
                &combined_samples,
                &baseline_combined,
                2.0 + 3.0 * k_f,
            ),
        ];

        let full_path_ok = phases
            .iter()
            .flat_map(|p| p.witnesses.iter())
            .all(|w| w.full_path_ok);

        let output = BenchOutput {
            schema_version: SCHEMA_VERSION,
            generated_unix_ns: unix_now_ns(),
            host: HostInfo {
                kernel: kernel_release(),
                arch: std::env::consts::ARCH,
                nproc: num_cpus_online(),
                pinned_cpu: cfg.cpu,
            },
            config: ConfigReport {
                baseline_iterations: cfg.baseline_iters,
                iterations: cfg.iters,
                reps: cfg.reps,
                warmup: cfg.warmup,
                k: cfg.k,
                flood: cfg.flood,
                timed_events_ring_bytes: TIMED_EVENTS_RING_BYTES,
                saturation_events_ring_bytes: PRODUCTION_EVENTS_RING_BYTES,
            },
            t_trap_ns: t_trap,
            phases,
            derived,
            full_path_ok,
        };

        print_human_table(&output);
        let path = write_json(&cfg.out_dir, &output)?;
        println!("\nmachine-readable results: {}", path.display());
        if !output.full_path_ok {
            bail!(
                "at least one full-path witness FAILED: the measurement may reflect a bail-early \
                 path and must not be trusted. See the witness table above."
            );
        }
        Ok(())
    }

    /// Attach all five real programs to their synthetic functions; the returned
    /// links keep them attached until dropped.
    /// Open, configure, (optionally resize the events ring), load, populate
    /// `hprobes`, and publish the BPF globals for a fresh rgwtrace skeleton. The
    /// returned skel borrows `obj`, which must outlive it.
    ///
    /// `events_ring_bytes = Some(n)` resizes the events ringbuf to `n` bytes
    /// before load (R1, R2). `None` keeps the default declared in
    /// bpf/rgwtrace.bpf.c (16 MiB, the --ringbuf-size default).
    fn load_rgwtrace_skel(
        obj: &mut MaybeUninit<libbpf_rs::OpenObject>,
        events_ring_bytes: Option<u32>,
    ) -> Result<skel::rgwtrace::RgwtraceSkel<'_>> {
        let mut open = RgwtraceSkelBuilder::default().open(obj)?;
        // rodata is const volatile -> set BEFORE load. Squid ceph_osd_op ABI:
        // the ops loop needs the op size (advance) and the extent offset/length.
        open.maps.rodata_data.CEPH_OSD_OP_SIZE = 112;
        open.maps.rodata_data.CEPH_OSD_OP_EXTENT_OFFSET_OFFSET = 6;
        open.maps.rodata_data.CEPH_OSD_OP_EXTENT_LENGTH_OFFSET = 14;
        open.maps.rodata_data.CEPH_OSD_OP_BUFFER_CARRIAGE_OFFSET = 56;
        open.maps.rodata_data.CEPH_OSD_OP_BUFFER_RAW_OFFSET = 8;
        open.maps.rodata_data.CEPH_OSD_OP_BUFFER_DATA_OFFSET = 32;
        if let Some(bytes) = events_ring_bytes {
            open.maps
                .events
                .set_max_entries(bytes)
                .context("resize events ringbuf")?;
        }
        let skel = open.load().context("load rgwtrace skeleton")?;

        for (key, vf) in descriptor_set() {
            skel.maps
                .hprobes
                .update(&key.to_ne_bytes(), vf.as_bytes(), MapFlags::ANY)
                .with_context(|| format!("populate hprobe slot {key}"))?;
        }
        // Publish the BPF globals: enable send_op's liveness gate (the fuller path)
        // in the combined phase; the RGWOp bridge key flag is irrelevant here
        // (process_authenticated is not attached) but set for realism.
        skel.maps.bss_data.REQUEST_END_PROBE_ATTACHED = 1;
        skel.maps.bss_data.RGW_OP_BRIDGE_KEY_ENABLED = 1;
        Ok(skel)
    }

    fn attach_all<'a>(
        skel: &'a skel::rgwtrace::RgwtraceSkel<'a>,
        pid: i32,
        exe: &std::path::Path,
    ) -> Result<Vec<libbpf_rs::Link>> {
        let specs: [(&libbpf_rs::ProgramMut<'_>, &str); 5] = [
            (&skel.progs.uprobe_rgw_get_handler, "syn_get_handler"),
            (&skel.progs.uprobe_send_op, "syn_send_op"),
            (&skel.progs.uprobe_finish_op, "syn_finish_op"),
            (&skel.progs.uprobe_rgw_req_state_dtor, "syn_req_state_dtor"),
            (
                &skel.progs.uprobe_rgw_rados_operate_read,
                "syn_rados_operate",
            ),
        ];
        let mut links = Vec::new();
        for (prog, func) in specs {
            links.push(prog.attach_uprobe_with_opts(
                pid,
                exe,
                0,
                UprobeOpts {
                    func_name: func.to_string(),
                    ..Default::default()
                },
            )?);
        }
        Ok(links)
    }

    fn drain_all<M: MapCore>(events_map: &M) -> Result<()> {
        let mut builder = RingBufferBuilder::new();
        builder.add(events_map, |_data| 0)?;
        let rb = builder.build()?;
        loop {
            let n = rb.consume_raw();
            if n <= 0 {
                break;
            }
        }
        Ok(())
    }

    /// Full-path check for a TIMED probed phase. Unlike the saturation phase, a
    /// drop here is NOT acceptable: a failed `bpf_ringbuf_reserve` skips the
    /// copy/submit tail of the program, so it is not a full execution. Require
    /// exact receipt, zero drops, zero `bpf_probe_read_user` failures, and zero
    /// field mismatches.
    fn timed_ok(
        received: u64,
        expected: u64,
        dropped: u64,
        read_fail_delta: u64,
        bad: u64,
    ) -> bool {
        received == expected && dropped == 0 && read_fail_delta == 0 && bad == 0
    }

    fn simple_phase(
        name: &'static str,
        description: &'static str,
        iterations: u64,
        reps: usize,
        samples: &[f64],
    ) -> Result<PhaseReport> {
        let aggregate = aggregate(samples).context("phase produced no samples")?;
        Ok(PhaseReport {
            name,
            description,
            iterations,
            reps,
            aggregate,
            witnesses: Vec::new(),
            per_rep: Vec::new(),
        })
    }

    /// Build a PhaseReport from a timed [`PhaseRun`], attaching its per-rep
    /// diagnostics for attribution.
    fn timed_phase(
        name: &'static str,
        description: &'static str,
        iterations: u64,
        reps: usize,
        run: &PhaseRun,
    ) -> Result<PhaseReport> {
        let aggregate = aggregate(&run.samples).context("phase produced no samples")?;
        Ok(PhaseReport {
            name,
            description,
            iterations,
            reps,
            aggregate,
            witnesses: Vec::new(),
            per_rep: run.per_rep.clone(),
        })
    }

    fn zero_aggregate() -> Aggregate {
        Aggregate {
            reps: 0,
            median_ns: 0.0,
            min_ns: 0.0,
            max_ns: 0.0,
            mean_ns: 0.0,
            spread_frac: 0.0,
        }
    }

    fn print_human_table(out: &BenchOutput) {
        println!("rgwtrace per-probe overhead benchmark");
        println!(
            "host: {} {} ({} cpus, pinned to cpu {})",
            out.host.kernel, out.host.arch, out.host.nproc, out.host.pinned_cpu
        );
        println!(
            "config: baseline_iters={} iters={} reps={} warmup={} k={} flood={}",
            out.config.baseline_iterations,
            out.config.iterations,
            out.config.reps,
            out.config.warmup,
            out.config.k,
            out.config.flood
        );
        println!();
        println!(
            "{:<22} {:>12} {:>10} {:>10} {:>8}  full_path",
            "phase", "median_ns", "min_ns", "max_ns", "spread"
        );
        for p in &out.phases {
            let wok = if p.witnesses.is_empty() {
                "-".to_string()
            } else if p.witnesses.iter().all(|w| w.full_path_ok) {
                "OK".to_string()
            } else {
                "FAIL".to_string()
            };
            println!(
                "{:<22} {:>12.2} {:>10.2} {:>10.2} {:>7.1}%  {}",
                p.name,
                p.aggregate.median_ns,
                p.aggregate.min_ns,
                p.aggregate.max_ns,
                p.aggregate.spread_frac * 100.0,
                wok
            );
        }
        println!();
        println!("derived per-probe cost (ns/call):");
        println!(
            "  t_trap (trap - baseline)          = {:>8.2}{}",
            out.t_trap_ns.value_ns,
            if out.t_trap_ns.noisy { " (noisy)" } else { "" }
        );
        for d in &out.derived {
            println!(
                "  {:<40} hits={:>5.1}  overhead={:>9.2}  t_prog(=overhead-hits*t_trap)={:>9.2}{}",
                d.program,
                d.probe_hits,
                d.overhead_ns.value_ns,
                d.t_prog_ns.value_ns,
                if d.t_prog_ns.noisy { " (noisy)" } else { "" }
            );
        }
        println!();
        for p in &out.phases {
            for w in &p.witnesses {
                if !w.full_path_ok {
                    println!(
                        "  WITNESS FAIL [{}] {}: expected {} observed {} dropped {}",
                        p.name, w.label, w.expected, w.observed, w.dropped
                    );
                }
            }
        }
    }

    fn write_json(out_dir: &std::path::Path, output: &BenchOutput) -> Result<PathBuf> {
        std::fs::create_dir_all(out_dir)
            .with_context(|| format!("create results dir {}", out_dir.display()))?;
        let path = out_dir.join(format!(
            "rgwtrace-overhead-{}.json",
            output.generated_unix_ns
        ));
        let json = serde_json::to_string_pretty(output)?;
        let mut f =
            std::fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
        f.write_all(json.as_bytes())?;
        f.write_all(b"\n")?;
        Ok(path)
    }

    fn unix_now_ns() -> u64 {
        // SAFETY: CLOCK_REALTIME into a stack timespec.
        unsafe {
            let mut ts: libc::timespec = std::mem::zeroed();
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
            (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
        }
    }

    fn kernel_release() -> String {
        // SAFETY: uname into a zeroed utsname; read the NUL-terminated release.
        unsafe {
            let mut uts: libc::utsname = std::mem::zeroed();
            if libc::uname(&mut uts) != 0 {
                return "unknown".to_string();
            }
            let bytes: &[u8] =
                std::slice::from_raw_parts(uts.release.as_ptr() as *const u8, uts.release.len());
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[..end]).into_owned()
        }
    }

    fn num_cpus_online() -> usize {
        let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if n < 1 {
            1
        } else {
            n as usize
        }
    }
}
