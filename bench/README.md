<!-- SPDX-License-Identifier: GPL-2.0-only -->
# rgwtrace-bench — per-probe overhead microbenchmark

Measures the **real** per-probe cost of rgwtrace's actual BPF programs by
attaching them to a **synthetic, self-hosted target** — the bench binary itself
— with **no Ceph required**. A companion analysis doc predicts the values; this
benchmark produces the measured counterparts.

## Running

```sh
scripts/bench-overhead.sh                 # defaults
scripts/bench-overhead.sh --iterations 500000 --reps 7 --k 8
```

The script builds `--release`, checks the synthetic symbols survived in the ELF,
and runs the harness as root (via `sudo` if needed). Results print as a table
and are written to `bench-results/rgwtrace-overhead-<unix_ns>.json`.

Requires: root (BPF load + uprobe attach), a kernel with BPF ring buffer + uprobe
support (Linux 5.8+), and the same clang/BPF toolchain the main crate's build
already uses. Building and unit-testing (`cargo test -p rgwtrace-bench`) need
neither root nor a Ceph install.

### Arguments

| flag | default | meaning |
|------|---------|---------|
| `--iterations N` / `-n` | 200000 | calls per timed rep in probed phases |
| `--baseline-iterations N` | 2000000 | calls per timed rep in no-probe baselines |
| `--reps N` | 5 | timed repetitions per phase (median + spread) |
| `--warmup N` | 20000 | untimed warmup calls before each phase |
| `--k N` | 4 | RADOS ops per request in the combined phase |
| `--flood N` | 20000 | events fired in the ring-buffer saturation phase |
| `--cpu N` | 0 | CPU the timed loop is pinned to |
| `--out-dir DIR` | `bench-results` | JSON output directory |

## Methodology

* **Real programs, unmodified.** The bench builds the exact `bpf/rgwtrace.bpf.c`
  the tool ships (via its own `build.rs`) and attaches those programs. Only the
  trivial always-return-0 trap lives in a separate bench-only
  `bench/bpf/bench_trap.bpf.c`; `bpf/rgwtrace.bpf.c` is not touched.
* **Self-attaching uprobes.** The harness attaches uprobes to its own ELF
  (`/proc/self/exe`) at the `syn_*` symbols, filtered to its own pid, and then
  calls those functions — no child process, no IPC.
* **Warmup + repetitions.** Each phase runs `--warmup` untimed calls, then
  `--reps` timed reps of `N` calls, reporting **median** (robust to a single
  slow rep) plus **min/max** and peak-to-peak **spread**.
* **Clock overhead is negligible.** Timing uses two `clock_gettime(MONOTONIC)`
  reads around a loop of `N` calls (not per call). With `N` ≥ 200k (probed) and
  ≥ 2M (baseline), the two reads are far below 1 % of the timed window.
* **Pinned + black-boxed.** The timed thread is pinned with `sched_setaffinity`;
  a background thread **busy-drains** the ring buffer on its own separate CPU.
  Every synthetic call is wrapped in `std::hint::black_box` so nothing is
  optimized away, and the functions read through their pointer argument and return
  a distinct value so identical-code-folding cannot merge two probe targets onto
  one address.
* **Enlarged ring for timed phases (16 MiB).** The events ring used to be
  256 KiB (~474 records, ~3.7 ms of horizon at ~125k events/s); rgwtrace now
  defaults to 16 MiB (`--ringbuf-size`), and the bench pins sizes explicitly. That cannot
  survive a multi-ms consumer deschedule (hypervisor steal / guest preemption),
  and no consumer busy-spin can prevent one. For the **timed** phases only, the
  bench resizes the events map to **16 MiB** (`bpf_map__set_max_entries` before
  load), which absorbs ~240 ms of consumer absence. `bpf_ringbuf_reserve`/`submit`
  cost is **capacity-independent** (a ringbuf is a fixed-stride producer/consumer
  queue; reserve just advances the producer position modulo capacity), so the
  measured probe path is byte-for-byte unchanged. The size used is recorded in the
  JSON `config.timed_events_ring_bytes`. (The `ringbuf_saturation` phase pins a
  256 KiB ring — see below.)
* **Busy-drain, ready handshake, drain barriers.** The drainer spins on
  `consume_raw()` (with a `spin_loop()` hint on the empty path) on its dedicated
  CPU. It sets a ready flag only after pinning itself; the timed body waits for it
  before producing anything. After warmup — and again after the timed reps — the
  body waits at a **drain barrier** (busy-wait until the drainer has decoded every
  event produced so far, with a bounded timeout that errors rather than
  under-counts). All witnesses are then computed over **exactly the timed window**
  (between the two barriers), so a warmup drop can never invalidate a phase, and
  the synchronous BPF drop / probe-read-failure counters are snapshotted per rep
  for attribution (JSON `per_rep`).

### Derived costs

* `t_trap = trap_median − baseline_trap_median` — the cost of ONE uprobe hit
  with an (almost) empty program. The trap program does a single per-CPU array
  increment (kept because it is the trap's fire **witness**), so `t_trap`
  includes that increment (tens of ns, well under 1 % of a full probe body). It
  is therefore a slight *over*-estimate of the bare trap-frame cost.
* `overhead(prog) = probed_median − that phase's OWN unprobed baseline_median` —
  the total per-call cost the operator pays.
* `t_prog(prog) = overhead − (probe_hits × t_trap)` — the program body's cost with
  the trap machinery removed. `probe_hits` is the number of uprobe hits per timed
  iteration: get_handler=1, send+finish=**2**, operate=1, dtor pair=2,
  combined=**2+3k**. Subtracting `probe_hits × t_trap` (rather than one trap
  phase's absolute time) is essential: a phase with two hits, like send+finish,
  otherwise retains a full extra trap. (Assumes trap cost is function-independent;
  it is dominated by the int3/dispatch path, not the target's own body.)

## Full-path execution is *verified*, not assumed

The real programs **bail early and cheaply** if their `hprobes` descriptor
lookup fails. A benchmark that silently hit the bail path would understate
overhead and be worthless. So every probed phase asserts a witness that can only
be satisfied if the program ran its **full body**, and the harness exits
non-zero (`full_path_ok=false`) if any witness fails.

For every **timed** phase the witness requires, over the **timed window only**,
**exact receipt AND zero drops in every rep AND zero `bpf_probe_read_user`
failures** (`RGWTRACE_DIAG_PROBE_READ_FAILURES` delta == 0). A dropped ring-buffer
record is *not* treated as a full execution: a failed `bpf_ringbuf_reserve` skips
the program's copy/submit tail. The per-rep drop and read-failure deltas are
recorded in the JSON (`per_rep`), and the phase fails if **any** timed rep saw a
drop or read failure. (The drop-tolerant `received + dropped == expected`
invariant is used **only** in the `ringbuf_saturation` phase, where drops are the
whole point.)

How each real probe's descriptor is satisfied and its full path witnessed:

| probe (id) | synthetic fn / arg | descriptor(s) | full-path witness |
|------------|--------------------|---------------|-------------------|
| `uprobe_rgw_get_handler` (30,31) | `syn_get_handler(*ReqState)` | 30 → reg+`offsetof(trans_id_len)` (int>0); 31 → reg+`offsetof(trans_id_ptr)` (ptr>0 → trans_id string). Register value is the `req_state*` bridge key. | `REQUEST_START` received == calls, 0 drops, 0 read failures |
| `uprobe_send_op` (0–11) | `syn_send_op(*SynOp)` | 12 register+member descriptors, one per slot (tid, cid, target_osd, name_len, name_ptr, rw, pool, pg_seed, acting_start, acting_finish, ops_start, ops_size). acting spans 3 ints; ops has one extent op. | via finish (below): **every** late-written field of **every** `RADOS_OP` event is checked against a **distinct nonzero** sentinel — `ops_size`, `pool`, `target_osd`, `cid`, `tid`, the object name (`"bench"`), all three `acting` entries (111/222/333), the op code, and the extent **offset/length** (the deepest per-op reads). A zero would mean a silently-failed read; every value is nonzero, so a match proves each read *succeeded* |
| `uprobe_finish_op` (20,21) | `syn_finish_op(*SynOp)` | 20 → reg+`offsetof(tid)`, 21 → reg+`offsetof(cid)` (same key send_op inserted, so the lookup hits) | `RADOS_OP` received == calls, 0 drops, 0 read failures |
| `uprobe_rgw_req_state_dtor` (50) | `syn_req_state_dtor(*ReqState)` | 50 → raw register pointer (`this`) | needs get_handler's bridge entry; `REQUEST_START==calls AND REQUEST_END==calls`, 0 drops, 0 read failures |
| `uprobe_rgw_rados_operate_read` (60) | `syn_rados_operate(dpp)` | 60 → raw register pointer (`dpp` = the same `req_state*`) | `OPERATE_SEED_HITS` diag == calls (every call HIT the bridge, i.e. the full re-seed ran, not the fail-closed miss path) + 0 read failures |

State dependencies are sequenced so the full path exists: `finish_op` runs after
`send_op` (same `client_op_key`); `dtor` re-creates the bridge via `get_handler`
each iteration (the dtor deletes it); `rados_operate` seeds the bridge once via
`get_handler` before the timed loop. The **combined_request** phase exercises all
**five** at once — `1 get_handler + k·(operate + send + finish) + 1 dtor` per
iteration — with `REQUEST_END_PROBE_ATTACHED=1`, so `send_op` additionally runs
its liveness-gate + trans_id-stamp path; the combined RADOS witness therefore also
requires the correlated `trans_id` (`"bench-trans-id"`) on every event, and adds
an `OPERATE_SEED_HITS == k·iterations` witness.

## Ring-buffer saturation

The `ringbuf_saturation` phase measures a 256 KiB ring's real capacity (the size
rgwtrace shipped with before `--ringbuf-size`), so — unlike the timed phases — it
runs against a **second skeleton instance resized to 256 KiB** (the first skeleton's uprobe links are
all dropped by then, so attaching the saturation skeleton to the same symbols is
conflict-free). It fires `--flood` `RADOS_OP` events as fast as possible, first
with the consumer **not** draining and then **draining**:

* undrained: the 256 KiB buffer fills after ~455 records of 576 ring bytes
  (568 B record + 8 B header; it was ~474 of 552 before `cls_name` widened) and the
  remainder fail to reserve. The witness asserts `RGWTRACE_DIAG_RINGBUF_RADOS_DROPS
  > 0` **and** that the measured capacity (`flood − drops`) lands in `400..=600`.
* drained: with the busy-drainer running, `received + dropped == flood` and drops
  are ~0.

This tests the 256 KiB capacity analysis directly against the reservation-failure
diagnostic. The size used is recorded in `config.saturation_events_ring_bytes`.

## JSON schema (`schema_version: 2`)

```jsonc
{
  "schema_version": 2,
  "generated_unix_ns": 0,                 // CLOCK_REALTIME at write time
  "host": { "kernel": "6.1.0", "arch": "x86_64", "nproc": 8, "pinned_cpu": 0 },
  "config": { "baseline_iterations": 2000000, "iterations": 200000,
              "reps": 5, "warmup": 20000, "k": 4, "flood": 20000,
              "timed_events_ring_bytes": 16777216,      // R1: 16 MiB for timed phases
              "saturation_events_ring_bytes": 262144 }, // R2: 256 KiB production ring
  "t_trap_ns": { "value_ns": 0.0, "raw_ns": 0.0, "noisy": false },
  "phases": [
    {
      "name": "get_handler",
      "description": "…",
      "iterations": 200000,
      "reps": 5,
      // flattened Aggregate:
      "median_ns": 0.0, "min_ns": 0.0, "max_ns": 0.0,
      "mean_ns": 0.0, "spread_frac": 0.0,
      "witnesses": [
        { "kind": "ringbuf_events",   // | "diag_counter" | "ringbuf_saturation"
          "label": "…",
          "expected": 0, "observed": 0, "dropped": 0,
          "full_path_ok": true }
      ],
      // Per-timed-rep diagnostics deltas (omitted for baselines / trap /
      // saturation). Every entry must be all-zero for a timed phase to pass.
      "per_rep": [
        { "rep": 0, "request_drops": 0, "rados_drops": 0, "probe_read_failures": 0 }
      ]
    }
    // … one entry per phase (see phase list below)
  ],
  "derived": [
    { "program": "uprobe_rgw_get_handler",
      "probe_hits": 1.0,                   // uprobe hits per timed iteration
      "overhead_ns": { "value_ns": 0.0, "raw_ns": 0.0, "noisy": false },
      "t_prog_ns":   { "value_ns": 0.0, "raw_ns": 0.0, "noisy": false } }
    // … send+finish (hits 2), operate (1), dtor pair (2), combined (2+3k)
  ],
  "full_path_ok": true                    // AND of every witness
}
```

`Derived.value_ns` is `max(0, raw_ns)`; `noisy` is true when `raw_ns` was
negative (the subtraction fell below the measurement floor — treat the cost as
indistinguishable from zero). `t_prog_ns.raw_ns = overhead.raw_ns − probe_hits ×
t_trap.value_ns`.

Phases, in order: `baseline_trap`, `trap`, `baseline_get_handler`,
`get_handler`, `baseline_rados`, `send_finish_op`, `baseline_operate`,
`rados_operate`, `baseline_request_end`, `request_end`, `baseline_combined`,
`combined_request`, `ringbuf_saturation` (the saturation phase carries a zeroed
aggregate — it is producer-only, not per-call timed).

## Files

* `bench/bpf/bench_trap.bpf.c` — the bench-only trivial trap program.
* `bench/build.rs` — builds the real rgwtrace skeleton **and** the trap skeleton.
* `bench/src/target.rs` — synthetic functions, structs, backing memory, and the
  `hprobes` descriptor set.
* `bench/src/descriptors.rs` — `VarField` encoding (mirror of `bpf/ceph_abi.h`).
* `bench/src/stats.rs` — pure aggregation (median/spread/derive) + unit tests.
* `bench/src/main.rs` — the harness.
* `scripts/bench-overhead.sh` — the entry point.

## Collector (userspace) microbenchmarks

The BPF harness above measures the probes. The userspace consumer -- event
decode, collector ingest, `--correlate-inferred` markers, and the expiry drain --
is measured by ignored tests in `src/collector_bench.rs`, which need neither root
nor Linux:

```sh
cargo test --release collector_bench -- --ignored --nocapture --test-threads=1
```

Each prints `BENCH ...` lines with time per operation and heap allocations
(counted by a thread-local counting allocator that exists only in test builds).
See `docs/perf-collector-hot-path.md` for reference numbers.
