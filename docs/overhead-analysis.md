# Tracing overhead & problems: a theoretical analysis

> Scope: a first-principles cost and correctness analysis of the rgwtrace uprobe
> layer, with numeric predictions that a later microbenchmark will confirm or
> refute. Every claim about the code cites `file:line`. Every claim about
> *magnitude* is marked **fact** (derived from the code / struct layout) or
> **assumption** (a literature value or a modelled constant to be measured). The
> predictions table (§6) is the interface the benchmark subtask consumes.

> **Update (BPF live-path hardening, see
> [bugfix-bpf-live-path-hardening.md](bugfix-bpf-live-path-hardening.md)).** The
> numbers below were derived and measured against the earlier layout and are kept
> as recorded. Since then: `hprobes` is an 80-slot `ARRAY` (lookups are inlined
> to a bounds check plus an add, cheaper than the hash lookups costed below, so
> `send_op`'s "12 map lookups" are now mostly free); the ring buffer defaults to
> 16 MiB (`--ringbuf-size`); a RADOS record is 568 B (576 B on the ring) and a
> request marker reserves 168 B (176 B on the ring) instead of the full union;
> and `rados_ops` defaults to 32 768 entries (`--bpf-rados-ops-entries`).

The one number the whole model turns on is the **per-hit uprobe cost** `t_trap`.
A uprobe fires by patching the target instruction with `int3`; each hit traps
into the kernel, runs the attached BPF program, and single-steps/returns the
displaced instruction. Published measurements on modern x86_64 put this at
**~1.5–4 µs per hit** (kernel uprobe trap + minimal BPF body). That is the
a-priori range used throughout; it is **literature-derived and must be measured
on the target rig** — it dominates everything else here, so a factor-of-2 error
in it is a factor-of-2 error in every latency and CPU figure below.

---

## 1. Probe-site inventory

All probes are **ENTRY uprobes**; there are **no uretprobes anywhere** (a
`process_request` return probe crashed RGW live — asio switches fiber stacks
under the patched return address; `bpf/rgwtrace.bpf.c:592-593`,
`ARCHITECTURE.md:36`).

Ring-buffer record size is **fixed at `sizeof(struct rgwtrace_event) = 544 B`**
for *every* event, request or RADOS, because both reserve `sizeof(*e)`
(`bpf/rgwtrace.bpf.c:309`, `:1410`) over the union type (`request` arm 160 B,
`rados` arm 536 B; union+tag = 544 B — measured from `rgwtrace_events.h:245-282`
with the ABI constants in `bpf/ceph_abi.h:7-10`). Only `send_op`'s data is *not*
emitted at `send_op`: it is stashed in the `rados_ops` map value and emitted once
at `finish_op` (`:1169-1171`, `:1410-1421`).

| BPF program | Fires | Gated by | Map ops | `probe_read_user` (bytes) | Ringbuf reserve |
| --- | --- | --- | --- | --- | --- |
| `uprobe_rgw_get_handler` (`:484`) | per request (START) | always | `rgw_requests` delete+lookup+update+lookup (`:489-500`); `hprobes` ×2 (`:507,:525`); `rgw_ctx_by_reqstate` update (`:575`) | len 4 (`:522`), base 8 (`:532`), `trans_id` str ≤128 (`:537`) = **3 reads, ≤140 B** | 544 B (START, `:549`) |
| `uprobe_rgw_req_state_dtor` (`:619`) | per request (END) | END probe attached | `hprobes` ×1 (`:622`); `rgw_ctx_by_reqstate` lookup+delete (`:636,:665`); `rgw_op_keys` lookup+delete (`:686,:691`); `rgw_ctx_by_reqstate` lookup+delete (alt key, `:694,:701`); `rgw_requests` lookup+delete (`:714,:716`) | **0** (register-only `this`) | 544 B on hit (END, `:662`) |
| `uprobe_rgw_process_authenticated` (`:766`) | per request | `--correlate-cross-thread` | `hprobes` ×2 (`:769,:817`); `rgw_ctx_by_reqstate` lookup+update×2 (`:788,:857,:867`); `rgw_op_keys` update (`:846`); `rgw_requests` update (`:887`) | `RGWOp*&` ref read 8 (`:818` → `bpf_utils.h:138`) = **1 read, 8 B** | none |
| `uprobe_rgw_rados_operate_read/write` (`:1119,:1134`) | **per RADOS submit** on the operate path | `--correlate-cross-thread` | `hprobes` ×1 (`:1062`); `rgw_ctx_by_reqstate` lookup (`:381`); on hit `rgw_requests` update (`:393`); on miss `rgw_requests` lookup+maybe-delete (`:1014,:1026`) | **0** (register-only `dpp`, never dereferenced; `:923`) | none |
| `uprobe_send_op` (`:1139`) | **per RADOS op** (hot) | always | `hprobes` ×12 (varids 0–11); `rados_ops` update+lookup (`:1159,:1163`); `rgw_requests` lookup (`:1177`); `rgw_ctx_by_reqstate` lookup in liveness gate when END attached (`:474`) | ~15 typical, up to ~40 worst case (see below) | none (stashed in map) |
| `uprobe_finish_op` (`:1381`) | **per RADOS op** (hot) | always | `hprobes` ×2 (`:1385,:1394`); `rados_ops` lookup+delete (`:1401,:1421`) | tid 8, cid 8 = **2 reads, 16 B** | 544 B (RADOS_OP, `:1410`) |

**`send_op` read count** (`:1148-1372`): fixed reads tid/cid/osd/name_len/
name_base/rw/pool/pg_seed/acting_start/acting_finish/ops_start/ops_size = 12,
plus `object_name` ≤127 B (`:1231`), plus the `acting` loop up to `MAX_ACTING=16`
(`:1289-1297`), plus the `ops` loop up to `MAX_RADOS_OPS=3` with 3 reads (extent
op: op code + offset + length) to 8 reads (CALL op) each (`:1324-1373`). Typical
(3-replica extent op, 1 op): 12 fixed + 1 `object_name` + 3 `acting` + 3 `ops`
(extent) = **~19 reads** (the `:430-431` code comment's "~15" is a rough
underestimate). Worst case (16 acting, 3 CALL ops): ~12 + 1 + 16 + 3×8 ≈ **~53
reads**. It is the heaviest
program by a wide margin and is on the hot path.

Every failure path bumps a `diagnostics` `PERCPU_ARRAY` counter (`count_diag`,
`:23-27`); that is a per-CPU add, negligible.

---

## 2. Parametric cost model

Let `k` = RADOS ops per request. Per-hit cost of program *X* is
`h_X = t_trap + t_prog,X`, where `t_trap` is the program-independent trap cost
(§intro) and `t_prog,X` is the BPF body. Nominal modelled constants (**to be
measured**, §6 P2/P3):

- `c_light = t_trap + ~0.3 µs ≈ 2.5 µs` — `get_handler`, `dtor`, `finish_op`,
  `operate`, `process_authenticated` (few map ops, ≤3 user reads).
- `c_send  = t_trap + ~1.0 µs ≈ 3.5 µs` — `send_op` (~15 reads, 12 map lookups).

Using the nominal `t_trap = 2.5 µs` midpoint. **All BPF/trap work runs inline on
the probed RGW/Objecter thread**, so it is added *directly* to that thread's wall
clock — this is added request latency, not just host CPU.

### 2.1 Added latency per request

Baseline (END probe attached, no cross-thread): the fired probes are
`get_handler` ×1, `dtor` ×1, `send_op` ×k, `finish_op` ×k. Hits per request
= `2 + 2k`. `finish_op` is in the `c_light` class (§2 above), so its per-hit cost
is `c_light`.

```
L(k) = c_light + c_light + k·(c_send + c_light)   [get_handler + dtor + k·(send + finish)]
     = 2·2.5 + k·(3.5 + 2.5)
     = 5.0 + 6.0·k        [µs]
```

With `--correlate-cross-thread` add `process_authenticated` ×1 and `operate` ×k_op
(one operate hit per op submitted through `rgw_rados_operate`; `k_op ≤ k`, take
`k_op = k` as the worst case):

```
L_ct(k) = L(k) + c_light + k·c_light = 5.0 + 6.0·k + 2.5 + 2.5·k
        = 7.5 + 8.5·k        [µs]
```

| k | `L(k)` baseline | nominal range (`t_trap` 1.5–4 µs) | `L_ct(k)` cross-thread |
| --- | --- | --- | --- |
| 3 | **23 µs** | 13–41 µs | **33 µs** |
| 10 | **65 µs** | 37–115 µs | **92 µs** |

### 2.2 Predicted CPU on an 8-core host

Tracing CPU-time per second (traced-process side) = `R · L(k)` where `R` = req/s.
As a fraction of an 8-core host: `R·L(k) / (8·10⁶) · 100 %`.

Baseline:

| R (req/s) | k | CPU-time/s | cores | % of 8-core host |
| --- | --- | --- | --- | --- |
| 1 000 | 3 | 23 ms/s | 0.023 | **0.3 %** |
| 1 000 | 10 | 65 ms/s | 0.065 | **0.8 %** |
| 5 000 | 3 | 115 ms/s | 0.115 | **1.4 %** |
| 5 000 | 10 | 325 ms/s | 0.325 | **4.1 %** |
| 20 000 | 3 | 460 ms/s | 0.46 | **5.8 %** |
| 20 000 | 10 | 1.30 s/s | 1.30 | **16.3 %** |

Cross-thread (`L_ct`): the 20k/k=10 corner rises to `20000·92 µs = 1.84 s/s`
≈ **23 %** of the host.

**Concentration caveat (matters more than the average).** `send_op`/`finish_op`
run on the Objecter's few messenger/dispatch threads, not spread across 8 cores.
At 20k req/s, k=10 that is `20000·2·10 = 400 000` op-probe hits/s ×~3 µs
≈ **1.2 core-seconds/s concentrated on a handful of threads**. If the Objecter
runs ~2–4 threads, each absorbs 0.3–0.6 of a core purely in trap overhead — the
per-core figure saturates long before the 8-core average looks alarming. The
8-core % above understates the risk on the hot threads.

### 2.3 Userspace decode cost

Records/s = `R·(2 + k)` (2 request markers + k RADOS ops; `send_op` emits
nothing). The single ring-buffer callback decodes each event and pushes it into
the collector under one `Mutex` (`src/live/linux.rs:142-160`,
`src/collector.rs:604`). At 20k req/s, k=10 that is `20000·12 = 240 000`
records/s. At an assumed ~1 µs decode+push each → **~0.24 core** on the tracer
process (separate from the traced process). Measured (release build, Apple M-series,
`src/collector_bench.rs`): decode ~0.18 µs and decode+ingest of a tagged RADOS op
~0.27 µs with 6.3 heap allocations, so the assumption is ~4x conservative. The
periodic drain and `--correlate-inferred` markers no longer scale with resident
state; see `docs/perf-collector-hot-path.md`. This is a **single-threaded**
consumer behind a mutex; §3 shows why its throughput ceiling is the ring-buffer
drop threshold.

---

## 3. Ring buffer analysis

Capacity: `256 * 1024 = 262 144 B` (`bpf/rgwtrace.bpf.c:244`). Each record is
544 B payload + an 8-byte kernel ringbuf header, 8-aligned → **552 B consumed per
record**. Max simultaneously-resident records:

```
262144 / 552 ≈ 474 records
```

(With the current 16 MiB default and 576 B RADOS records:
`16777216 / 576 ≈ 29 127` records, ~121 ms at 240k records/s or ~1.4 s at
20k RADOS ops/s. Request markers now take 176 B each.)

Steady-state record rate = `R·(2 + k)`. Byte rate at 20k/k=10:
`240 000 · 552 B ≈ 132 MB/s`.

**Buffering horizon.** 474 records at 240k records/s = **~2.0 ms** of slack. If
the consumer stalls longer than that — blocked on the collector `Mutex`, or on
the periodic OTLP flush that runs on the same loop (`src/live/linux.rs:194-207`)
— reservations start failing. `poll_raw` is called with a 250 ms timeout
(`:174`) but returns as soon as data is ready, so the effective drain is
callback-paced, not 250 ms-paced; the risk is a *stall inside the callback*, not
the poll interval.

**Drop onset.** Let the consumer sustain `D` records/s and a burst deliver `P`
records/s. Reservation failures begin when the backlog exceeds ~474 records, i.e.
after `262144 / ((P − D)·552)` seconds of `P > D`. Sustained `P > D` drops
unconditionally. With a ~1 µs decode, `D ≈ 10⁶ records/s` in the best case, but
mutex contention with the OTLP flush and collector growth lower it; the benchmark
must measure `D`, not assume it (§6 P6).

**What is LOST on a drop is correlation quality, not just rows.** The BPF map
lifecycle is unaffected by a ringbuf drop (the map delete still runs — e.g.
`finish_op` deletes `rados_ops` even on a reserve failure, `:1413`), so no map
leak; but:

- **Dropped `finish_op` RADOS_OP** (`RGWTRACE_DIAG_RINGBUF_RADOS_DROPS`, `:1412`):
  the op vanishes. Its parent request span under-counts children, and on a
  `marker`/`rados_bounds`-quality request whose end is *derived from child bounds*
  (`ARCHITECTURE.md:99-100`) the derived end shifts.
- **Dropped START** (`RGWTRACE_DIAG_RINGBUF_REQUEST_DROPS`, `:311`): if the END
  still arrives it carries the seeded `start_ns` and the request survives; if both
  drop, the request is reconstructed purely from RADOS timestamps →
  `duration_quality = rados_bounds`, the worst tier.
- **Dropped END**: no measured end → `duration_quality` downgrades from `measured`
  to `marker` (`ARCHITECTURE.md:97-99`), and the group is held open until the
  10×-TTL lifetime backstop (`expired_open_requests`, `ARCHITECTURE.md:104`).

So a busy-gateway burst does not merely thin the data — it **silently degrades
the provenance labels** the tool exists to guarantee.

---

## 4. Perturbation & correctness problems

These are not costs; they are ways the tracing can be *wrong* or can *distort the
thing it measures*.

### 4.1 LRU_HASH live-entry eviction on many-core hosts (silent correlation loss)

`rgw_ctx_by_reqstate` is the one `LRU_HASH` (`:177-182`, `max_entries=131072`).
LRU per-CPU freelists reserve ~128 nodes per CPU that touches the map, so usable
capacity shrinks with core count and the allocator can evict **live, in-flight**
entries — the exact regression that forced `rados_ops`/`rgw_requests` to plain
`HASH` (`:86-97`, `:105-114`). The sizing comment works the arithmetic:
122 880 usable → 61 440 requests at 64 CPUs, down to 98 304 → 49 152 at 256 CPUs
(`:151-153`). Symptom is **silent**: an evicted live entry makes the `_send_op`
liveness gate fail closed (`request_ctx_is_live`, `:476-480`) and the op comes out
uncorrelated — visible only as a rising `RGWTRACE_DIAG_SENDOP_STALE_CTX_DROPS`
and `RGWTRACE_DIAG_RGWOP_KEY_REVOKE_ABSENT` (`:698`). A small rig cannot
reproduce this; it needs ≥64 CPUs. The design mitigates (large map, lookups keep
live entries hot `:440-441`) but does not eliminate it.

### 4.2 TID-keyed context copies lingering on pooled threads

`rgw_requests` holds a *copy* of the request context keyed by tid, and a copy is
scattered onto every thread the bridge re-seeds (`:398-409`). The END probe can
only revoke the copy on the destructor's own thread (`:709-716`), so every other
copy outlives its request on a shared Beast pool thread. The liveness gate
(`:453-482`) is what prevents these stale copies from mis-stamping — but **only
when the END probe is attached**. On a build where it is not, the gate is
switched off (`:454-466`) and every stamp is unverifiable
(`RGWTRACE_DIAG_SENDOP_UNVERIFIABLE_CTX`): the pre-gate stamp-whatever-is-here
behavior, which can attribute an op to a long-dead request.

### 4.3 Observer effect: probes inside the measured span inflate it

The request span is `end_ns(dtor) − start_ns(get_handler)`, both entry uprobes.
Every `send_op`/`finish_op` (and `operate`) hit lands **inside** that window and
adds its trap latency to the wall clock between the two markers. Inflation ≈
in-window hits × `t_trap` = `2k·t_trap` (baseline), or `(3k+…)·t_trap` with
cross-thread:

- k=10, baseline, `t_trap=2.5 µs`: ~20 hits → **~50 µs added** to each request's
  reported duration.
- A slow request (10 ms) sees +0.5 % — negligible. A **cache-hit request
  (~100 µs)** sees +50 % — a gross distortion. The absolute inflation is roughly
  constant, so the *relative* error is worst exactly where latency matters most.

*Measured on this host (§7): `2k·t_trap = 20 × 5.46 µs ≈ 109 µs` added @ k=10 —
more than double the 50 µs nominal, because `t_trap` measured 5.46 µs, not 2.5.*

Independently, each **RADOS op duration** (`send_ns`→`finish_ns`) is inflated by
the `finish_op` trap latency itself, so per-op durations read high by ~`t_trap`.

### 4.4 Uprobe trap serialization on hot Objecter threads

`_send_op`/`_finish_op` execute on the Objecter's few dispatch threads. Every op
serializes through the `int3` trap → kernel → BPF → single-step path on those
threads. This is a genuine serialization point: at high op rates the trap handler
becomes a per-thread bottleneck (see §2.2 concentration), independent of the
8-core average. It cannot be parallelized away because the ops genuinely run on
those threads.

*Measured on this host (§7): the `send_op`+`finish_op` pair costs **14.29 µs per
op** (2 × 5.46 µs trap + 3.36 µs body), all of it inline on the Objecter thread.*

### 4.5 Memory footprint

BPF maps are `HASH`/`LRU_HASH` (preallocated at load). Static sizing:

| Map | key + value (B) | entries | ≈ bytes |
| --- | --- | --- | --- |
| `rgw_ctx_by_reqstate` (`:177`) | 16 + 168 | 131 072 | **~24.1 MB** |
| `rados_ops` (`:98`) | 16 + 536 | 8 192 | ~4.5 MB |
| `rgw_requests` (`:109`) | 4 + 168 | 8 192 | ~1.4 MB |
| `hprobes` (`:235`) | 4 + 96 | 8 192 | ~0.8 MB |
| `rgw_op_keys` (`:228`) | 16 + 24 | 16 384 | ~0.7 MB |
| `events` ringbuf (`:242`) | — | — | 0.25 MB |

BPF total ≈ **~32 MB**, dominated by the one LRU. (Current defaults: `rados_ops`
16 + 560 B × 32 768 ≈ ~20 MB, `hprobes` an 80 × 100 B array ≈ 8 KB, `events`
16 MiB; total ≈ ~62 MB.) Userspace adds the **8 MiB
Bloom filter** (`EMITTED_BLOOM_BITS = 1<<26`, allocated lazily on first insert,
`src/collector.rs:32,:115-117`) plus the live `requests` `BTreeMap` (one
`RequestBuilder` per request until it expires -- END-closed requests after
`--closed-request-grace`, 5 s by default, rather than the 120 s TTL) and the
inference pending queue (capped by `--inference-max-pending`). Floor is **~40 MB RSS** before any
in-flight state; the Bloom filter is fixed-size for the life of the run by design
(no per-request growth, `ARCHITECTURE.md:108-112`).

### 4.6 Attach/detach cost and the uretprobe constraint

Attach patches each probed instruction with `int3` (one-time, per-address). The
ordering is a **correctness** property, not just startup latency: `ATTACH_ORDER`
requires the END probe (the sole bridge revoker) live before `get_handler`, or a
request could create a bridge entry that nothing revokes (`:247-270`,
`ARCHITECTURE.md:148-150`). The hard constraint: **no uretprobe may ever be
added** — a `process_request` return probe crashed RGW live because uretprobes
patch the on-stack return address while asio switches fiber stacks under it
(`:591-593`, `ARCHITECTURE.md:36`). This is why the request END is an entry uprobe
on the destructor rather than a return probe.

---

## 5. Assumptions vs facts (summary)

- **Fact** (from code / layout): every ringbuf record is 544 B (`:309,:1410`);
  474-record ring capacity; records/request = `2 + k`; `send_op` does ~15 reads
  typical / ~53 worst; map static memory ~32 MB; probe fire frequencies and gates
  per §1; no uretprobes.
- **Assumption** (to be measured): `t_trap` ∈ [1.5, 4] µs (literature); the BPF
  body constants `t_prog` (`c_light ≈ 0.3 µs`, `c_send ≈ 1.0 µs` increments);
  userspace per-event decode ~1 µs; drain rate `D`. All latency and CPU numbers
  inherit the uncertainty in these.

---

## 6. Predictions to test

| # | Prediction (nominal) | How to confirm / refute | Verdict (§7, this host) |
| --- | --- | --- | --- |
| **P1** | Added request latency `L(k) = 5.0 + 6.0k µs`: **23 µs @ k=3**, **65 µs @ k=10** (range 13–115 µs over `t_trap` 1.5–4 µs). | Fixed synthetic load at known k; compare p50/p99 request latency traced vs. untraced. | **Form confirmed, constants host-dependent.** Measured `L(4) ≈ 96.5 µs` on the cross-thread-shaped combined path (vs. 41.5 µs nominal); the 14-hit combined agrees with per-probe sums to ~2 %. Re-parameterized in §7. |
| **P2** | Per-hit uprobe cost `t_trap` ∈ **1.5–4 µs** on x86_64. | Attach one light probe (e.g. `finish_op`), divide added CPU-time by measured hit count; or `bpftool prog profile`. | **Measured 5.46 µs — above the literature band.** Explained: HYPERVISOR + PTI (CR3 switch per transition) + MDS/TAA buffer-clears, 2 transitions per hit. Bare-metal no-PTI should fall back near/below the nominal band. |
| **P3** | `send_op` is the heaviest body: `c_send ≈ c_light + ~1 µs` (~15 reads, 12 map lookups typical; up to ~53 reads worst). | Per-program run-time via `bpftool prog show`/`run` stats; compare `send_op` vs `finish_op`. | **Direction confirmed.** `send_op`+`finish_op` is the heaviest pair (3.36 µs body). But `rados_operate` measured **≈ 0.014 µs** (essentially free) — `c_light` overestimated it, so cross-thread's marginal cost is **trap-dominated**, not body-dominated. |
| **P4** | Traced-process CPU at **20k req/s, k=10 ≈ 16 %** of an 8-core host baseline (**~23 %** with `--correlate-cross-thread`); **≤1.5 %** at 5k/k=3. | `pidstat`/`perf` on the RGW process, tracer on and off, at each (R,k) grid point. | **Untested (needs real RGW A/B, `scripts/bench-rgw-ab.sh`).** Recomputed from measured constants in §7.2: 20k/k=10 baseline ≈ **40 %**, cross-thread ≈ **55 %** on this host class — model projection, not a live A/B. |
| **P5** | Ring buffer resident capacity ≈ **474 records**; ~**2.0 ms** buffering slack at 240k records/s. | Fill the ring with the consumer paused; count records before `RINGBUF_*_DROPS` increments. | **Confirmed exactly: 474 records.** Undrained 256 KiB flood dropped all but 474; drained flood took ~0 drops. |
| **P6** | Single-threaded drain ceiling `D` (records/s) sets the drop threshold; sustained `R·(2+k) > D` drops, and any consumer stall > `474/D` s drops. | Ramp R until `bpf_*_ringbuf_*_drops` becomes nonzero; record the rate; inject a callback stall and confirm the 474-record horizon. | **Qualitatively confirmed.** A busy-spin drainer on its own CPU took 0 drops at ~125k ev/s; a 2 ms-poll consumer took **0.05–0.26 % drops** at the same rate — multi-ms scheduler/hypervisor stalls against the ~3.7 ms 256 KiB horizon. The stall, not the mean rate, is the production risk. |
| **P7** | On a **≥64-CPU** host, `rgw_ctx_by_reqstate` live-entry eviction begins well below `max_entries` and shows as rising `bpf_sendop_stale_ctx_drops` / `bpf_rgw_op_key_revoke_absent`; **not reproducible on <64-CPU rigs**. | Run identical load on a 64+ CPU host vs. a small rig; watch those counters and the correlated-op fraction. | **Untested** — this 8-vCPU host cannot reproduce it by construction. Needs a ≥64-CPU host. |
| **P8** | Observer effect inflates reported request duration by ≈ `2k·t_trap` (**~50 µs @ k=10**); relative error is large (~tens of %) for sub-ms requests, negligible for multi-ms ones. | Compare rgwtrace span duration against an external client-side timer for fast vs. slow request classes. | **Formula recalibrated, not yet A/B-tested.** With measured `t_trap`, `2k·t_trap ≈ 109 µs @ k=10` on this host class (vs. 50 µs nominal). The relative-error argument stands; needs a live fast/slow A/B to close. |
| **P9** | Steady-state memory floor ≈ **32 MB BPF + 8 MiB Bloom ≈ 40 MB RSS**, dominated by the 131 072-entry LRU (~24 MB); Bloom stays fixed regardless of request volume. | `bpftool map` byte accounting + tracer RSS over a long run at high request volume. | **Untested** — the microbench times probe paths, not tracer RSS. Needs long-run live tracing with map/RSS accounting. |
| **P10** | **Zero** RGW crashes attributable to fiber-stack corruption, because no uretprobe is ever attached (entry-probe-only invariant). | Long-soak live run under asio migration; assert no return-probe attach and no crash. | **Untested** — no live RGW in the microbench. Needs a long-soak live run. |

The benchmark subtask should treat P1–P4 as the headline overhead claims, P5–P6
as the saturation/loss boundary, and P7–P10 as correctness/perturbation guards.
§7 records what the microbenchmark
(`bench-results/rgwtrace-overhead-1784196847643059819.json`) settled: **P1, P3,
P5, P6 confirmed** (form and, for P5, exact value); **P2 measured above the
literature band with a mechanism**; **P4, P7, P8, P9, P10 remain open**, awaiting
a live A/B, a many-core host, or a long soak.

---

## 7. Measured results (this host)

Source: `bench-results/rgwtrace-overhead-1784196847643059819.json`, produced by
`bench/` (`scripts/bench-overhead.sh`). Methodology per `bench/README.md`.

**Host.** 8-vCPU cloud VM, Xeon E5-2683 v4 (Broadwell), kernel
`6.1.0-40-cloud-amd64`, with **HYPERVISOR + PTI (Meltdown) + MDS/TAA
buffer-clear** mitigations active. Each uprobe hit is two user↔kernel transitions
(int3 trap in, `iret` out), and PTI forces a CR3/TLB switch on each — this is why
the measured trap cost lands above the bare-metal literature band.

**Methodology (one paragraph).** The bench builds and attaches the **real,
unmodified** `bpf/rgwtrace.bpf.c` programs (only a trivial always-return-0 trap
lives in bench-only code) to a **synthetic self-hosted target** — `syn_*`
functions in the bench binary, uprobed on `/proc/self/exe`, pid-filtered — so no
Ceph is needed. Every probed phase carries a **full-path witness** that only
passes if the program ran its whole body: exact event receipt, **zero drops in
every rep**, **zero `bpf_probe_read_user` failures**, and — for RADOS ops — every
late-written field (including `trans_id`, object name, acting set, extent
offset/length) matched against a distinct nonzero sentinel. Medians over 5 reps,
20k-call warmup, timed thread pinned, ring **busy-drained on a separate CPU**. The
**timed** phases use a 16 MiB events ring (`timed_events_ring_bytes`) so a
multi-ms consumer deschedule cannot inject a drop into a latency number; ringbuf
reserve/submit cost is capacity-independent (fixed-stride producer/consumer
queue), so the probe path measured is byte-for-byte the production one. The
**`ringbuf_saturation`** phase alone uses the production **256 KiB** ring
(`saturation_events_ring_bytes`) to measure real capacity. This run reported
`full_path_ok: true` with all witnesses green and spreads ≤2.7 % on probed phases.

### 7.1 Measured per-probe table

| Quantity | Measured | Notes |
| --- | --- | --- |
| `t_trap` | **5.46 µs** | trivial BPF program; includes one per-CPU array increment (<1 % bias, slight over-estimate of the bare trap frame). |
| `get_handler` body | **2.29 µs** | overhead 7.75 µs − 1 × `t_trap`. |
| `send_op` + `finish_op` body (pair) | **3.36 µs** | overhead 14.29 µs − 2 × `t_trap`. Heaviest body, as predicted (P3). |
| `rados_operate` body | **0.014 µs** | overhead 5.48 µs − 1 × `t_trap` ⇒ **essentially free** (hprobes lookup + LRU update, no user read). |
| `req_state_dtor` body | **≈1.92 µs** | from the get_handler+dtor pair (4.20 µs bodies) minus get_handler (2.29 µs). |
| combined request, k=4, all 5 programs | **96.5 µs** | 14 hits × 5.46 µs (**76.5 µs, 79 %**) + **20.0 µs** bodies. Cross-thread path exercised; `trans_id` stamp and `OPERATE_SEED_HITS == 4k` witnessed. |

**Model validated as linear.** The 14-hit combined figure (96.5 µs) agrees with
the per-probe hit+body sums to ~2 %. The one residual: combined bodies (20.0 µs)
exceed the sum of the isolated bodies (~17.7 µs at k=4) by **~2.3 µs**. That is
**explained, not anomalous** — the correlated path does work the isolated phases
skip: `send_op` runs its liveness-gate re-validation + `trans_id` stamp
(`bpf/rgwtrace.bpf.c:1185-1189`), and `rados_operate` runs the re-seed **HIT**
tail (`:393`) rather than the cheap miss. That is ~0.57 µs/op of extra body, i.e.
`2.3 µs / 4 ops`. No inconsistency remained unexplained.

**`t_trap` is the dominant term (79 % of the combined cost).** Per-platform
calibration of `t_trap` with this benchmark is therefore the way to project
overhead onto any target host — a bare-metal modern x86 without PTI should sit
near or below the original nominal band (§intro), roughly halving these figures.

### 7.2 Re-parameterized model (this host class)

The §2 form `L(k) = (hits) · t_trap + (bodies)` holds; substituting the measured
constants (`t_trap = 5.46 µs`; bodies get_handler 2.29, dtor 1.92, send+finish
3.36/op):

**Baseline** (END attached, no cross-thread; hits `= 2 + 2k`):

```
L(k) = (2 + 2k)·5.46 + [2.29 + 1.92 + 3.36·k]
     = 15.13 + 14.28·k        [µs, this host class]
```

**Cross-thread-shaped** (the combined path: operate + correlated send_op per op;
hits `= 2 + 3k`, +0.57 µs/op correlated body):

```
L_ct(k) = (2 + 3k)·5.46 + [4.21 + (0.014 + 3.36 + 0.57)·k]
        = 15.13 + 20.32·k     [µs, this host class]   (L_ct(4)=96.5, matches)
```

| k | `L(k)` baseline (measured constants) | nominal §2.1 was | `L_ct(k)` cross-thread |
| --- | --- | --- | --- |
| 3 | **58 µs** | 23 µs | **76 µs** |
| 10 | **158 µs** | 65 µs | **218 µs** |

**CPU on this 8-vCPU host** (`R·L(k) / (8·10⁶) · 100 %`), baseline:

| R (req/s) | k | CPU-time/s | % of 8-core host |
| --- | --- | --- | --- |
| 1 000 | 3 | 58 ms/s | **0.7 %** |
| 1 000 | 10 | 158 ms/s | **2.0 %** |
| 5 000 | 3 | 290 ms/s | **3.6 %** |
| 5 000 | 10 | 790 ms/s | **9.9 %** |
| 20 000 | 3 | 1.16 s/s | **14.5 %** |
| 20 000 | 10 | 3.16 s/s | **39.5 %** |

Cross-thread (`L_ct`) at 20k/k=10: `20000·218 µs = 4.37 s/s` ≈ **55 %** of the
host; 20k/k=3 ≈ **19 %**. These are **model projections** from the measured
per-probe constants, not a live A/B (P4 stays open). Roughly **2.4×** the §2.2
nominal, driven by `t_trap = 5.46` vs 2.5 µs and by cross-thread adding a full
extra trap per op (the operate **body** is free, but its **trap** is not).

**Concentration still dominates the risk.** The measured `send_op`+`finish_op`
pair is 14.29 µs/op, all inline on the Objecter threads. At 20k/k=10 that is
`200 000 ops/s · 14.29 µs = 2.86 core-seconds/s` on a handful of threads — the
per-core hot-thread load, not the 8-core average, is the ceiling.

### 7.3 Ring buffer (measured)

The production 256 KiB ring held **exactly 474 records** before reservation
failures — the §3 prediction to the record (`ringbuf_saturation`: 20 000 flooded,
19 526 dropped undrained; 0 drops drained). This ties P5 shut.

For P6/§3: a **busy-spinning dedicated** consumer took **0 drops at ~125k
events/s**, but a **2 ms-poll** consumer (closer to production cadence) took
**0.05–0.26 % drops** at the same rate — multi-ms scheduler/hypervisor stalls
overrunning the ~3.7 ms buffer horizon of the 256 KiB ring at 125k ev/s. The
production insight: at high event rates it is the **consumer stall**, not the mean
drain rate, that drops records, and on a hypervisor guest such stalls are
unavoidable — which argues for a larger events ring in production, exactly the
trade the bench's timed phases make (`bench/README.md`, "Enlarged ring").
