# RGW A/B Overhead Benchmark

`scripts/bench-rgw-ab.sh` measures the real end-to-end cost of attaching
`rgwtrace` to a live `radosgw`. It drives a fixed S3 workload under several
tracing "arms", interleaves them so drift and cache warm-up are shared fairly,
and reports client-side latency/throughput deltas alongside `radosgw` and
`rgwtrace` process CPU/RSS.

It is a **macro** benchmark: it measures what an operator actually pays
(request latency, RGW CPU) rather than micro-costs of individual probes.

---

## Prerequisites

- Run on the MicroCeph/RGW host itself, as `root` (uprobes need
  `CAP_BPF`/`CAP_PERFMON`).
- A running `radosgw` with `librados.so.2` loaded (auto-discovered, or pass
  `--pid`).
- A built tracer at `target/release/rgwtrace` (`cargo build --release`), or pass
  `--rgwtrace-bin`.
- `python3` with `boto3` (same dependency the e2e workload uses).
- An S3 user/keys on the target RGW. The defaults match the MicroCeph e2e test
  (`RGWTRACEACCESSKEY001` / the e2e secret, endpoint `http://127.0.0.1:8080`);
  override with `--access-key` / `--secret-key` / `--endpoint`.

Native DWARF extraction is the default. If native debug info is unavailable,
pass `--dwarf-json /path/to/rgwtrace_dwarf.json` (and optionally
`--ceph-version`), mirroring the e2e conventions.

---

## Arms

| Arm | Label | rgwtrace flags |
|-----|-------|----------------|
| A | `baseline` | none (tracing off) |
| B | `traced_default` | default attach |
| C | `traced_cross_thread` | `--correlate-cross-thread` |
| D | `traced_inferred` | `--correlate-cross-thread --correlate-inferred` (only with `--with-inferred`) |

Each traced arm is bracketed by a baseline **before and after** it, and the
block is repeated `--repeats` times (default 3). The scheduling is
**counterbalanced**: the traced-arm order rotates per repeat (repeat 1 `B,C,D`;
repeat 2 `C,D,B`; repeat 3 `D,B,C`; ...) so no traced arm is permanently biased
by always following B or always running against a warmer cache. A repeat with
arms `B,C` therefore looks like `A,B,A,C,A`; the next like `A,C,A,B,A`.

Two views are reported at the end:

- **Pooled** — all valid latency samples for an arm are pooled across repeats and
  percentiles recomputed (a true pooled p99). Baseline accumulates the most
  samples and is the stable reference.
- **Paired** — because each traced phase is bracketed, its metrics are also
  compared against the mean of its two bracketing baselines, and the
  **median of those per-phase paired deltas** is reported per arm. This preserves
  local pairing (each arm vs the baseline right next to it) that pooling
  discards, so it is more robust to slow drift across a long run.

---

## Invocation

Validate the plan off-cluster (no root, no cluster contact):

```sh
scripts/bench-rgw-ab.sh --dry-run
scripts/bench-rgw-ab.sh --dry-run --with-inferred --repeats 5 --requests 500
```

`--dry-run` prints every command it *would* run, including the `rgwtrace` and
`s3-workload.py` argv and the `/proc` sampling points, and writes nothing.

Real run on the RGW host:

```sh
sudo scripts/bench-rgw-ab.sh --requests 500 --concurrency 8 --repeats 5
sudo scripts/bench-rgw-ab.sh --with-inferred --object-size 65536
sudo scripts/bench-rgw-ab.sh --dwarf-json /path/to/rgwtrace_dwarf.json --pid "$(pidof radosgw | awk '{print $1}')"
```

Common flags (`--help` lists all):

- `--requests N` measured PUT/GET requests per phase (default 200)
- `--concurrency C` concurrent client workers (default 4)
- `--object-size BYTES` payload size (default 4096)
- `--put-fraction F` fraction of requests that are PUTs, rest are GETs (default 0.5)
- `--repeats R` interleaved blocks (default 3)
- `--warmup-requests N` unmeasured warm-up run before the phases (default 50)
- `--with-inferred` adds arm D
- `--endpoint / --access-key / --secret-key` S3 target and credentials
- `--pid` radosgw PID to trace; `--rgwtrace-bin`, `--dwarf-json`, `--ceph-version`

---

## Output

- A per-arm table to stdout: pooled `p50/p95/p99` client latency (microseconds),
  mean throughput, mean `radosgw` CPU-seconds/phase, pooled deltas vs baseline
  (%), the **paired median delta** per arm, collector CPU (measured-window delta,
  with lifetime shown alongside) and peak RSS, any non-zero diagnostics drops,
  and a list of any invalid phases.
- Raw artifacts under `bench-results/<UTC-timestamp>/` (gitignored):
  - `NNN-<arm>.meta.json` — per-phase metrics + a `valid`/`invalid_reason` flag.
  - `NNN-<arm>.workload.json` — the `s3-workload.py --summary` for that phase
    (per-op latency percentiles + raw `latencies_us`, throughput).
  - `NNN-<arm>.workload.jsonl` — per-operation records.
  - `NNN-<arm>.state.json` — bucket/seed-key state shared by the phase's
    prepare/run/cleanup invocations.
  - `NNN-<arm>.trace.json` / `.rgwtrace.log` — the tracer output for traced arms.
  - `summary.json` — the per-arm report (pooled + paired) backing the table.

If any phase is invalid (tracer failed to attach, exited abnormally, died
mid-run, or produced a missing/unparseable trace JSON), that phase is excluded
from aggregation, listed in the output, and the script exits non-zero.

---

## What each metric means

- **Client latency p50/p95/p99** — wall time per S3 request measured in the
  client (`s3-workload.py`), pooled across all repeats of an arm before
  percentiles are recomputed (so p99 is a true pooled percentile, not an average
  of per-repeat p99s). This is what a caller of RGW observes.
- **Throughput (rps)** — measured requests divided by the wall time of the
  **measured window only**. Each phase runs as three `s3-workload.py`
  invocations: an unmeasured `prepare` (bucket create + object seeding), the
  measured `run`, and an unmeasured `cleanup`. In the measured `run`, all boto3
  clients and worker threads are constructed and the per-op JSONL is buffered in
  memory *before* the timer starts, so setup and file I/O do not pollute the
  throughput window.
- **radosgw CPU-seconds** — `utime+stime` delta from `/proc/<pid>/stat` sampled
  immediately before and after the measured `run` (not around prepare/seed/
  cleanup), converted with `getconf CLK_TCK`. This is the server-side CPU the
  measured traffic cost the RGW process; the delta between a traced arm and
  baseline is the CPU the **uprobes themselves** added inside `radosgw`.
- **radosgw RSS** — `VmRSS` before/after the phase and the process-wide peak
  `VmHWM`. `VmHWM` is cumulative since `radosgw` started (it runs across all
  phases), so treat it as informational, not per-phase.
- **rgwtrace collector CPU** — `utime+stime` **delta** sampled across the same
  measured `run` window (reported as `collector CPU .../phase`). This is the
  userspace decoding / correlation / export cost that lives **outside**
  `radosgw`, attributable to the measured traffic. The tracer's **lifetime** CPU
  (which also includes DWARF extraction, BPF load/attach, and the settle sleep)
  is reported separately as informational only. Peak RSS is the collector's
  `VmHWM` (a fresh process per phase, so meaningful per-phase).
- **Diagnostics drops** — selected `trace.diagnostics` counters
  (`bpf_ringbuf_*_drops`, `bpf_rados_map_drops`, `bpf_request_context_drops`,
  `bpf_reqstate_map_drops`, `decode_errors`, `dropped_otlp_queue_spans`). Any
  non-zero drop means the workload outran the collector's capture path at that
  intensity — the latency/CPU numbers for that arm are then a lower bound on
  what a drop-free run would show.

## How to interpret

Attribute the two kinds of overhead separately:

- **In-process (uprobe) cost** shows up as the `radosgw` CPU delta and, more
  visibly, in client-side latency (p95/p99). uprobes execute synchronously on
  the RGW threads, so this is the overhead that can slow requests. Compare
  `traced_default` vs `baseline` for the base probe set, and
  `traced_cross_thread` vs `traced_default` for the extra per-submit re-seed the
  bridge adds.
- **Out-of-process (collector) cost** is the `rgwtrace` CPU/RSS line. It runs on
  its own threads and competes for host CPU but does not directly serialize RGW
  request handling; on a CPU-saturated host it can still show up indirectly as
  latency.

Expect `traced_cross_thread` and `traced_inferred` to cost more than
`traced_default`: the cross-thread bridge re-seeds context at every RADOS submit
and adds the request-END probe, and inference adds userspace matching work.

Prefer the **paired median delta** over the pooled % delta when the run is long
or the rig drifts: the paired number compares each traced phase only against the
baselines immediately bracketing it, so a slow warm-up or a background load ramp
that lifts later phases affects the traced phase and its brackets together and
cancels out. If pooled and paired deltas disagree substantially, drift is
present and the paired number is the more trustworthy one.

## Caveats

- **Client latency includes network and RGW-queue noise.** On a shared or busy
  rig, p99 in particular moves run-to-run. Use enough requests for stable tails —
  a few hundred per phase minimum, and prefer `--requests 500`+ with
  `--repeats 5` when reporting p99. The interleaving controls for drift but not
  for one-off stalls.
- **Peak RSS for `radosgw` is cumulative**, so cross-arm RSS comparison is not
  meaningful; the collector's peak RSS (a fresh process per phase) is.
- **The collector is stopped with SIGINT to flush its JSON**, so its CPU is
  sampled just before shutdown; flush-time CPU is not counted. This slightly
  understates collector CPU but not the in-`radosgw` uprobe cost.
- **Non-zero diagnostics drops invalidate a strict overhead read** for that arm;
  lower `--concurrency`/`--requests` or investigate the ring buffer before
  trusting those deltas.
- Results are specific to the traced Ceph/RGW build and the rig's core count and
  storage; do not extrapolate absolute numbers across hardware.
