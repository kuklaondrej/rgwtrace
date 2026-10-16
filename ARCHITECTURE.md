# Architecture

Live tracing pipeline for RGW and RADOS.

[Documentation index](docs/README.md) · [Example traces](docs/trace-examples.md)

---

## Follow

`rgwtrace` starts by loading probe metadata from native DWARF or `cephtrace` JSON.

The Linux runner opens the BPF skeleton, configures Ceph ABI offsets and map sizes, populates the `hprobes` map, attaches uprobes, and polls the ring buffer.

### BPF maps that are sized or maintained from userspace

| Map | Type | Size | Why |
|---|---|---|---|
| `hprobes` | `ARRAY` | `RGWTRACE_HPROBE_SLOTS` = 80 | Probe descriptors keyed by `function base id + var_field index` (bases 0, 20, 30, 40, 50, 60, 70). An array lookup is a bounds check plus an add, which matters because `_send_op` does about a dozen of them per op while RGW holds the Objecter lock. Array lookups never miss for an in-range key, so every `struct VarField` carries a `present` word and `hprobe_lookup()` treats `present == 0` as "no descriptor". |
| `events` | `RINGBUF` | `--ringbuf-size`, default 16 MiB | Set on the open object before load. A RADOS record takes 576 ring bytes (568 + 8-byte header), a request record 176 (168 + 8), so 16 MiB holds ~29k RADOS records: ~1.4 s of reader stall at 20k RADOS ops/s. The old fixed 256 KiB held ~470 (~25 ms). |
| `rados_ops` | `HASH` (preallocated) | `--bpf-rados-ops-entries`, default 32768 | In-flight ops between `_send_op` and `_finish_op`. The default is above Ceph's `objecter_inflight_ops` (24576). ~600 bytes per entry, so ~20 MiB of kernel memory. |

**Stale `rados_ops` sweep.** An op whose client exits before `_finish_op` is never deleted by BPF. When enabled, the poll loop walks the map in batches of at most 256 keys per poll turn and deletes entries whose `sent_ns` (`CLOCK_BOOTTIME`) is older than `--rados-ops-stale-after` (default 300 s). The iterator stays across poll turns; a scan cycle is capped at twice the map's `max_entries` to bound restarts caused by concurrent `_finish_op` deletions. Stale candidates are collected before deletion because deleting a key a hash iteration sits on restarts the iteration. The count is added to `stale_rados_ops_swept` per delete batch. Ceph can resend a candidate op between the scan and the delete (same `cid`/`tid` key, fresh `sent_ns`), so each candidate is removed with an atomic lookup-and-delete and judged on the value actually removed; a refreshed entry is re-inserted with `NO_EXIST`. Only an `EEXIST` restore failure proves a newer submit already won. Other restore errors (such as a full map) fail the current batch with context instead of silently losing the removed entry. Kernels before 5.14 lack lookup-and-delete on hash maps and fall back to re-read-then-delete, which narrows the window without closing it. An entry with `sent_ns == 0` was just inserted and is never swept. The threshold floor is 60 s (twice Ceph's 30 s slow-op complaint time): the sweep must never evict a live op. An op still blocked past the threshold (an inactive PG, for example) is evicted anyway; its later `_finish_op` counts as `bpf_rados_finish_misses` and emits no event. `0` disables the sweep.

**Ending the run.** The loop stops on `--timeout`, on SIGINT/SIGTERM/SIGHUP (ctrlc with its `termination` feature), or, with `--pid`, when the target exits: a pidfd (`pidfd_open`) polls readable once the process has exited, with a `/proc/<pid>/stat` state check (`Z`/`X`, or the file gone) as the fallback when `pidfd_open` is unavailable. All three paths finalize output the same way. On target exit the ring buffer is drained once more first: the target can no longer write, so its last completions and request ENDs are all still in the ring.

Before live attach, preflight validation checks CLI input, discovered target files, required DWARF functions, minimum variable-field counts for the probes used by the BPF program, and ELF build IDs.

A probe-metadata artifact maps, per module, `func2pc` (function -> address), `func2vf` (function -> variable-field descriptors), and `func2linkage` (function -> the **mangled** linkage name the address was resolved from). `func2linkage` is written only for functions whose demangled name cannot identify a single definition: `req_state::~req_state` (whose D0/D1/D2 variants all demangle identically) and the two `rgw_rados_operate` overloads (distinct functions at distinct addresses that collapse onto one demangled name once the argument list is stripped). It is the address's *provenance*, and an imported artifact that cannot prove its destructor address is the complete/base variant (D1/D2), or that an operate address is the overload it is filed under, does not get that probe at all. Artifacts exported before this field existed keep working; they simply fall back to derived request durations and seed-thread-only correlation, with a warning that names the fix (re-export).

Pipeline:

```text
native DWARF or cephtrace JSON -> hprobes -> eBPF uprobes -> ring buffer -> Rust events -> spans -> JSON or OTLP protobuf
```

---

## Capture

The BPF program attaches RADOS probes to `Objecter::_send_op` and `Objecter::_finish_op`.

It also attaches `RGWREST::get_handler` to read the RGW `trans_id` and seed request context.

This is a **two-marker model**, and both markers are ENTRY uprobes:

- **START** -- `RGWREST::get_handler` (base id 30), the earliest entry probe at which the request identity (`trans_id`) is known. It emits a `REQUEST_START` carrying the start timestamp (its `end_ns` is 0: get_handler cannot know when the request ends).
- **END** -- `req_state::~req_state` (base id 50, BPF program `uprobe_rgw_req_state_dtor`), the true, unconditional end of a request. `req_state` is stack-allocated in `process_request`, so its destructor runs at scope exit -- after logging and after `client_io->complete_request()` -- and `process_request` calls it out-of-line. The probe reads `this` (`req_state*`) through a register-only raw-pointer descriptor, looks the request up in the `(req_state*, tgid)` bridge that `get_handler` populated, and emits a `REQUEST_END` carrying the seeded start plus a **real** end timestamp. It is also the **only deleter** on that bridge map -- it revokes *every* key the request was inserted under (see the multi-key bridge under Correlate), which is what bounds the map and what makes "entry present" a meaningful liveness signal.

There is still **no return probe anywhere** in the BPF program: a `process_request` return probe crashed RGW in live testing, because a uretprobe patches the return address on the stack while asio switches fiber stacks underneath it. The END probe avoids this entirely by being an entry probe on the destructor.

**Destructor variant.** The Itanium C++ ABI emits up to three destructors -- `D0` (deleting), `D1` (complete object), `D2` (base object) -- and all three demangle to the same name, `req_state::~req_state`. The extractor therefore ranks candidates by their *mangled* linkage name: it binds only to `D1`/`D2` (preferring `D1`, the one `process_request` calls) and **rejects `D0` outright**, in both the symbol-table and DWARF-DIE resolution paths. This matters because g++ lists `D0` first in both. See `docs/design-request-end-probe.md`.

**The END probe is optional and fails soft.** When the destructor address or its `this` descriptor cannot be resolved (stripped binary, unexpected mangling, older RGW), the probe is not attached, no `REQUEST_END` arrives, and the collector falls back to deriving each request's end from its correlated RADOS child bounds -- the pre-end-probe behavior. Preflight reports this as an advisory `request_end_probe` `warn`, never a hard error.

Captured request data:

- Start timestamp (START marker, from `get_handler`).
- Real end timestamp (END marker, from the `req_state` destructor) -- absent when the END probe is unattached.
- Process ID and thread ID.
- RGW `trans_id`.

Captured RADOS data:

- Process ID, client ID, and operation TID.
- Send and finish timestamps.
- Pool, PG seed, target OSD, and acting set.
- Object name, operation codes, class method calls, direction, offset, and length.

---

## Decode

BPF timestamps use `bpf_ktime_get_boot_ns()`.

Rust converts them to Unix epoch nanoseconds by adding `CLOCK_REALTIME - CLOCK_BOOTTIME` before aggregation.

Fixed capture limits:

- `MAX_TRANS_ID = 128`.
- `MAX_OBJECT_NAME = 128`.
- `MAX_ACTING = 16`.
- `MAX_RADOS_OPS = 3`.
- Class names are 16 bytes (`MAX_CLS_NAME`; every in-tree Ceph class fits).
- Method names are 32 bytes (`MAX_METHOD_NAME`).

For an OSD `call` op the indata is `class || method || payload`, so the method is read at the class name's full wire length. Only the copy lengths are clamped; a truncated class name does not move the method read.

Wire layout (asserted at compile time on both sides: `_Static_assert` in `bpf/rgwtrace_events.h` and `bpf/ceph_abi.h`, `const` `size_of`/`offset_of!` assertions in `src/events.rs` and `src/dwarf_json.rs`):

| Struct | Bytes |
|---|---|
| `struct rgwtrace_request_event` | 160 |
| `struct rgwtrace_rados_event` | 560 |
| `struct rgwtrace_event` (payload at offset 8) | 568 |
| `struct rgwtrace_request_record` (what a request marker reserves) | 168 |
| `struct VarField` (`hprobes` value) | 100 |

RADOS records reserve the full `struct rgwtrace_event`; request markers reserve only `struct rgwtrace_request_record`. The decoder accepts any record at least as long as header + payload for its `type`. A test checks that every `RGWTRACE_*` constant in the headers, including the diagnostics indices, appears in Rust with the same value.

BPF events carry truncation flags for these limits. Rust exposes counters in trace diagnostics and adds `rgwtrace.truncated` to affected RADOS spans. A BPF diagnostics map also counts ring-buffer reservation failures, RADOS state-map failures, missing finish state, request-context map failures, and probe-read failures.

---

## Correlate

The BPF layer stores RGW request context by Linux thread ID when it reads a `trans_id`.

`Objecter::_send_op` copies that `trans_id` into the RADOS event when the thread carries a request context **that still belongs to a live request**. That liveness check matters because `rgw_requests[tid]` holds a *copy*: a request's context is copied onto its `get_handler` thread and onto every thread the cross-thread bridge re-seeds it onto, while the END probe can only revoke the copy on the one thread its destructor runs on (clearing another thread's context could un-correlate a *different* live request). Every other copy outlives its request, so before stamping, `_send_op` re-validates the copy against the `(req_state*, tgid)` bridge, whose entry is deleted exactly at request end:

- **entry present and identity matches** (same `start_ns` and `tid`) -> the request is alive; stamp the `trans_id`. The identity compare is required because `req_state` is stack-allocated, so its address is recycled by the next request on the same worker thread -- a presence-only check would validate a stale copy against a *new* request's entry.
- **no `req_state*` on the context at all** (`get_handler` could not resolve it from a register on this build) -> stamp nothing, counted in `bpf_sendop_unbridged_ctx_drops`. Such a context was never bridged, so it can never be *found* -- which means the destructor's lookup misses and returns **before** clearing it off the thread, and it lingers on a pooled thread for the rest of the run. Trusting it would let a long-dead request stamp later ops. A build in this state correlates nothing, and attach warns about it explicitly rather than letting it look like an idle gateway.
- **otherwise** -> stamp nothing. The op is left uncorrelated (it becomes background/inferred) and the drop is counted in `bpf_sendop_stale_ctx_drops`. Fail-closed: an uncorrelated op is a known unknown, a mis-correlated one is a lie.

The gate proves the cached request still **exists**. It cannot prove that request is the coroutine *currently executing on this thread* -- that is a separate problem, solved on the write side by the per-submit re-seed's fail-closed clear (below).

When the END probe is not attached, nothing revokes bridge entries, so their presence carries no liveness information; the gate is then switched off (via a userspace-written `REQUEST_END_PROBE_ATTACHED` global set from the actual attach outcome), `_send_op` keeps its pre-gate behavior, and those unproven stamps are counted in `bpf_sendop_unverifiable_ctx`. The per-submit re-seed is **not attached at all** in that state (see below). See `docs/design-request-end-probe.md`.

The Rust collector groups request and RADOS events by `trans_id`. The START marker opens a request group and the END marker supplies its measured end; either can arrive first (ring-buffer delivery is not ordered across probes), and an END alone still yields a complete request because it carries the seeded start.

`rgw.duration_quality` records how the span's bounds were obtained, so a consumer can always tell a real duration from a reconstructed one:

| value | meaning |
| --- | --- |
| `measured` | the END probe fired and **both** span bounds are the request's real ones (`start_ns` = the `get_handler` marker, `end_ns` = the destructor) |
| `measured_extended` | the END probe fired, but a bound had to be stretched off its measured value to envelope a correlated child -- the end pushed out past a late child, or the **start pulled back** to a child that began before the marker (also covers a measured end clamped up to the start). `rgw.request.measured_start_ns` / `rgw.request.measured_end_ns` preserve the true interval |
| `marker` | no END marker (probe unattached, or the request outlived the trace window): the end is **derived** from the correlated RADOS child bounds. The start is still measured |
| `rados_bounds` | no request marker at all; the whole span is reconstructed from RADOS timestamps, so neither bound is measured |

There is still no `"request_lifecycle"` value. Child RADOS spans are never clamped *into* their parent -- their bounds are measured facts and shrinking them would corrupt the reported op duration -- so when a child falls outside the request's real interval the **parent is stretched** and the span is labelled `measured_extended` rather than silently claiming a measured duration.

**Request-group expiry is lifecycle-aware.** A group whose END is still expected (the END probe is attached and no END marker has arrived) is **open** and is never idle-expired: exporting it on idleness and then rebuilding it when its END arrived would emit a *second* span with the same trace/span id. Open groups are bounded by lifetime instead (10x `--correlation-ttl` since the request began), which caps a lost END (ring-buffer drop, destructor bridge miss) and is counted in `expired_open_requests`. Closed groups -- END received, or no END probe attached at all -- keep the plain idle `--correlation-ttl`.

Every exported request key is then **remembered for the whole session**, so a straggler can never re-open the group: a late marker is dropped (`late_request_markers_dropped`) and a late RADOS op becomes a background span with `rgw.correlation_reason = "request_already_emitted"`. **No request is ever emitted twice under one span id.**

That memory is a never-reset **Bloom filter** (2^26 bits = 8 MiB, 20 hashes, `emitted_request_keys` counts the keys in it), not an exact set and not a bounded FIFO:

- it has **no false negatives**, so the no-duplicate guarantee holds for the entire run regardless of request volume -- which a bounded FIFO did *not* deliver: at production rates its memory turned over in seconds, so a force-expired long request's tombstone was evicted before its late END arrived, and that END then re-emitted the same deterministic span id;
- its memory is **fixed**, unlike an exact set, which would grow ~100 bytes per request forever alongside a production RGW;
- its one failure mode is a false **positive** (~1e-7 up to ~2M requests), and a false positive can only ever cause a **drop** -- a discarded straggler, or (rarely) a fresh request whose key collides being dropped and its ops demoted to background. It can never duplicate. Past the design capacity the rate climbs, and the collector warns once.

RADOS events without `trans_id` become background spans instead of being attached to a request.

Correlated RADOS spans are marked with `rgw.correlation = "same_thread"` when the op was submitted on the request's own `get_handler` thread, or `rgw.correlation = "cross_thread"` (with `rgw.correlation_reason = "reseed_bridge"`) when it was submitted from a thread the request's asio coroutine had migrated onto and was recovered by the opt-in cross-thread re-seed bridge. This split is not committed at ingest -- a `trans_id`-tagged op is recorded thread-unresolved (RADOS events can arrive before their request marker) and the label is derived late in `request_spans` by comparing the op's send thread to the request marker's thread; a group reconstructed purely from RADOS bounds (no marker) has no thread evidence and stays `same_thread`. The counters satisfy `correlated_rados_ops == same_thread_correlations + cross_thread_correlations + inferred_correlations`. Cross-thread correlation is opt-in and build-dependent: it covers every RADOS op submitted through `rgw_rados_operate` (the metadata/index/head-object path), while object-payload I/O dispatched through `rgw::Aio`/`aio_operate` does not route through that frame and remains `background`/`inferred` (`docs/design-cross-thread-correlation.md`). Background RADOS spans are marked with `rgw.correlation = "none"` and a reason such as `missing_trans_id`, `classified_background_role`, `no_inference_candidate`, or `ambiguous_inference_candidates`.

When `--correlate-inferred` is enabled, untagged RADOS events can be attached to a request only if there is exactly one conservative candidate in the configured inference window and the RADOS role is not classified as RGW background work. The collector first prefers a unique request whose Linux thread ID matches the RADOS send thread, then falls back to same-PID/time-window matching. Untagged RADOS ops can stay pending until request markers arrive or until expiration/final trace output makes them final background spans. Inferred spans use `rgw.correlation = "inferred"` and `rgw.correlation_reason = "pid_time_window"`. Untagged RADOS ops that are not attached remain background spans, with diagnostics distinguishing missing candidates from ambiguous candidates.

`--correlate-cross-thread` (opt-in, default off) adds a fail-closed bridge so that RADOS ops inherit their request's `trans_id` even though the submitting thread is not the thread `get_handler` ran on.

RGW runs each S3 request as an asio coroutine that **migrates to a different `io_context` pool thread at every `optional_yield`**. Correlation is thread-keyed (`_send_op` looks up `rgw_requests[current_tid]`), so context written at any fixed instant is abandoned at the very next yield: *N* seed sites can only ever cover *N* instants, and a coroutine that yields *M* times needs its context re-established at every submit.

**The bridge is MULTI-KEYED.** `rgw_ctx_by_reqstate` is a PID-scoped LRU map from *(opaque pointer, tgid)* to request context, and one request is inserted under **every `dpp` identity RGW might plausibly pass for it**:

| key | inserted at | why |
| --- | --- | --- |
| `req_state*` | `get_handler` | **canonical**: the only handle the destructor has (`this`), so it is the key the liveness gate re-derives and the key revocation is driven from |
| `RGWOp*` | `rgw_process_authenticated` | RGW threads a `const DoutPrefixProvider* dpp` down its data path, and at most call sites inside `op->execute()` that pointer is the **RGWOp** (`this`), *not* the `req_state`. Without this key the per-submit re-seed misses on the entire op data path -- every lookup a foreign-dpp miss, every counter healthy, and nothing recovered |

Both keys map to a byte-identical value, so a seed through either one produces a context whose canonical `req_state_ptr` the liveness gate can check. The `RGWOp*` is read from the `RGWOp*& op` parameter -- a *reference to a pointer*, so the register holds an `RGWOp**` and the handler does exactly **one** read of the pointee (`fetch_param_ptr_ref`). Native extraction emits that descriptor only after proving from DWARF that the parameter really is `reference -> pointer -> RGWOp` **and** that `RGWOp` inherits `DoutPrefixProvider` at offset 0 (same check for `req_state`); a build where either proof fails loses the key -- or, for `req_state`, the whole per-submit re-seed -- rather than keying the bridge on a guess.

**Both keys are revoked together at the destructor.** The alternate key is carried *inside* the context value (`rgw_op_ptr`) purely so the destructor -- which only knows the `req_state*` -- can find and delete it. A key that outlives its request is a mis-correlation source: `RGWOp` is heap-allocated and its address is recycled, so a stale key could be hit by a later dpp and seed a dead request's `trans_id`. The alternate key is deleted only while it still *describes this request* (`start_ns`/`tid`/`pid` match), because a newer request may already have re-keyed that recycled address to itself; that skip is counted in `bpf_rgw_op_key_revoke_skipped`. `bpf_rgw_op_key_inserts` minus `bpf_rgw_op_key_revokes` should track in-flight requests -- a persistent, growing gap means keys are leaking.

Two kinds of probe read the bridge back, both gated by the flag:

- **Per-submit re-seed (the load-bearing one).** An entry uprobe on **both overloads** of `rgw_rados_operate` -- the last common frame before a RADOS submit, from which librados' `aio_operate` -> `op_submit` -> `_send_op` runs *synchronously on the calling thread* before the coroutine suspends. BPF programs `uprobe_rgw_rados_operate_read` (base id 60) and `uprobe_rgw_rados_operate_write` (base id 70), each with one register-only raw-pointer descriptor for the `dpp` parameter. The two overloads are distinct functions at distinct addresses that share one demangled name, so each is bound by its **mangled linkage name** (`func2linkage`, re-verified at attach) and can never be attached to the other's address.
  - The `dpp` (`DoutPrefixProvider*`, arg0) is used as an **opaque identity token and is never dereferenced**. A request's `dpp` is numerically its `req_state*` or its `RGWOp*` (both inherit `DoutPrefixProvider` at offset 0 -- *verified in DWARF per build*, not assumed), both of which are bridge keys. RGW passes many other `DoutPrefixProvider` implementations here (stack `DoutPrefix`/`DoutPrefixPipe` wrappers, GC/LC/quota threads); those simply miss the bridge and correlate nothing. Fail-closed by construction, and it sidesteps the type-unsafe "walk the `dpp` to reach `trans_id`" approach the design rejected.
  - **A miss CLEARS the thread's SEEDED context** (`bpf_operate_miss_ctx_cleared`). Request A can leave its context on *every* pool thread it ever ran an operate on; request B can then resume on one of them and submit through a dpp we cannot key. A is genuinely still alive, so the liveness gate would happily pass its context and B's op would be stamped as A. The gate proves existence, never "is running here now", and nothing available at this probe can prove the latter. So on a miss nothing is assumed *about a copy the re-seed made*. The cost is real -- a request's own operate through a wrapper dpp, on a migrated thread, goes uncorrelated -- and it is counted; the multi-key bridge is what keeps it small.
  - **...but it NEVER clears a HOME context** (`bpf_operate_miss_home_ctx_preserved`). A HOME context is one `get_handler` placed on **this very thread** for the request that started here (`ctx->tid == this tid`); a SEEDED one is a copy migrated onto a thread that does not own the request (`ctx->tid != this tid`). Only the latter is the re-seed's to destroy. An unscoped clear cost a live ListObjects request **all 16** of its `call(rgw.bucket_list)` shard ops: RGW submits a sharded listing through the cls_rgw AIO path (`CLSRGWIssueBucketList` -> `IoCtx::aio_operate`), which never reaches `rgw_rados_operate`, so those ops correlate *only* off the HOME context -- and one foreign-dpp operate on that thread wiped it. Clearing a HOME context buys no soundness either, because a submit that never reaches this probe inherits the thread's context regardless. See the accepted residual hazard in `docs/design-cross-thread-correlation.md` §11.3.
  - **It is attached only when the request-END probe attached.** The END probe is the only thing that revokes bridge entries; without it a recycled `req_state`/`RGWOp` address (or a numerically-matching foreign dpp) would hit a long-dead request's entry, and the liveness gate -- switched off for want of a revoker -- would fail *open* and stamp it. Phase B therefore degrades (loudly) to the execute-thread seed rather than risk mis-correlation.
- **Execute-thread re-seed.** The `rgw_process_authenticated` uprobe (base id 40): a cold-path seed that also covers a submit reaching librados without passing through `rgw_rados_operate`, and -- since the bridge became multi-keyed -- the **only site where the executing `RGWOp*` can be captured** (it is created by `handler->get_op()`, whose result is a *return value*, and return probes are forbidden here). On a miss it fails closed by deleting a *foreign* lingering context (mismatched `req_state*` or `tgid`) so `_send_op` stamps nothing, while keeping this request's own.

A re-seeded context is a **copy of the bridge entry**, so its `start_ns`/`tid`/`pid` are the entry's own and it satisfies `_send_op`'s liveness gate by construction; its `tid` stays the `get_handler` thread, which is what makes a migrated submit come out as `cross_thread` rather than `same_thread`. Probes attach only when the flag is set and the address + descriptor + linkage provenance all resolve, so the flag-off path is byte-for-byte identical, and an RGW build without these symbols degrades (loudly) to seed-thread-only correlation. Object-payload I/O dispatched through `rgw::Aio`/`aio_operate` does not route through `rgw_rados_operate` and remains `background`/`inferred`; see `docs/design-cross-thread-correlation.md`. Coverage is surfaced via the informational `bpf_operate_seed_hits` (split by which key matched: `bpf_operate_seed_hits_reqstate` / `bpf_operate_seed_hits_rgwop`), `bpf_operate_seed_misses`, `bpf_operate_base_unresolved`, `bpf_rgw_op_key_*`, and `bpf_reseed_*` diagnostics.

**An unresolved `dpp` fails closed exactly like a foreign one** (`bpf_operate_unresolved_ctx_cleared`, and `bpf_operate_unresolved_home_ctx_preserved` for the HOME case). A missing/stack-located descriptor or a NULL `dpp` argument leaves us unable to say who is submitting -- which is precisely when a re-seeded copy lingering on a shared pool thread must not be trusted. Returning early without clearing would have let a live request's copy stamp another coroutine's op; clearing a HOME context would have stranded the AIO submits of the request that owns the thread.

### Attach ordering is a correctness property

The bridge has exactly one revoker: the `req_state` destructor probe. So `attach_probes` drives an explicit `ATTACH_ORDER` -- **END probe → publish BPF globals → `get_handler` → `rgw_process_authenticated` → `rgw_rados_operate` → `Objecter::_send_op`/`_finish_op`** -- and `validate_attach_order` refuses to attach anything if that order could let a bridge entry exist before its revoker. If `get_handler` attached first, a request could create its canonical bridge entry and *complete* before the destructor probe was live; nothing would ever delete that entry, and once `REQUEST_END_PROBE_ATTACHED` flipped to 1 it would start **passing** the liveness gate's identity check (its `start_ns`/`tid` match, because both the entry and any context copy came from the same dead request), letting a later submit inherit a dead request's `trans_id` -- permanently.

### Revocation is total

A request's alternate (`RGWOp*`) key is revoked at its destructor **even if the LRU evicted the request's canonical entry first**. The key is recorded in `rgw_op_keys` -- a plain HASH keyed by the canonical key, which never evicts -- written *before* the alternate key is inserted, and read by the destructor unconditionally (a canonical-entry miss no longer short-circuits it). A key is never created without its revocation record, and a failed key insert deletes the record again. That makes the health metric exact: `bpf_rgw_op_key_inserts == revokes + revoke_skipped + revoke_absent + in-flight requests`.

### The `RGWOp*` key is switchable, because its value is a measurement

`--disable-rgw-op-bridge-key` drops the alternate key at runtime (a BPF global published before the probe that writes it attaches). The key is insurance against RGW not passing the `req_state` as the `dpp`, and it carries the one hazard pointer identity cannot close -- the S3-website `retarget` replacing a live request's `RGWOp` (design doc §10.1). Whether it earns that risk is answered by `bpf_operate_seed_hits_rgwop` on a real rig, not by argument; see the interpretation table in `RUNBOOK.md`.

For OTLP live mode, old request groups and background RADOS ops are queued to a background exporter when their correlation TTL expires. This bounds memory growth while keeping a conservative window for late RADOS events to join a request without blocking ring-buffer polling on collector latency.

---

## Shape

Correlated traces use one root request span with RADOS child spans:

```text
rgw.request
  rados.op
  rados.op
```

The request span has `rgw.trans_id`, `rgw.request_class`, `rgw.duration_quality`, and `rgw.request.tid` (the request marker's thread) attributes, plus `rgw.request.measured_start_ns` whenever a request marker exists and `rgw.request.measured_end_ns` when the END probe supplied a real end. Those two carry the untouched measured interval, so the true duration is recoverable even when a span bound was stretched to envelope a child.

Each `rados.op` child span uses the request trace ID and request span ID as its parent, and carries `ceph.rados.send_tid` (the thread that submitted the op). `send_tid` versus the parent's `rgw.request.tid` is the direct, exported evidence of an asio coroutine migration: RGW resumes a request on a different io_context pool thread after every `optional_yield`, so an op submitted after a migration has `send_tid != rgw.request.tid`.

Uncorrelated operations become root spans:

```text
rgw.background.rados_op
```

---

## Record

RADOS span attributes:

- `ceph.rados.duration_ns`.
- `ceph.rados.pool`.
- `ceph.rados.pg` as `<pool>.<seed_hex>`.
- `ceph.rados.pg_seed`.
- `ceph.rados.target_osd`.
- `ceph.rados.acting` as `[osd,osd,...]`.
- `ceph.rados.object`.
- `ceph.rados.ops`.
- `ceph.rados.rw`.
- `ceph.rados.offset`.
- `ceph.rados.length`.
- `rgw.rados_role`.
- `rgw.correlation`.
- `rgw.correlation_reason` when correlation is absent.
- `rgwtrace.truncated` when fixed capture limits truncated one or more fields.

`rgw.rados_role` is classified from object names and request context, including RGW data/bucket metadata, GC/notify work, realm/zone/period config objects, and RGW metadata/data sync logs.

Roles include data, bucket index, bucket metadata, user metadata, auth metadata, GC, notify, sync, config, and unknown.

---

## Export

JSON output prints a debug document with DWARF summary, trace spans, and trace diagnostics counters.

OTLP output sends OTLP/HTTP protobuf to `--otlp-endpoint` and sets `service.name` from `--service-name`.

The exporter uses a bounded blocking HTTP client with configurable timeout, retry count, extra headers, periodic flush interval, and correlation TTL.

Trace diagnostics count decoded events, decode errors, request START markers (`request_markers`) and END markers (`request_end_markers`), request-duration provenance (`measured_duration_requests` / `derived_duration_requests`), RADOS ops, correlated/background RADOS ops, same-thread, cross-thread, and inferred correlations, inference misses/ambiguity, missing-`trans_id` background ops, background breakdowns by role/reason, capture truncation counters, produced spans, expired request groups, open requests force-expired at the lifetime backstop (`expired_open_requests`), markers dropped for an already-exported request (`late_request_markers_dropped`), expired background RADOS ops, dropped OTLP queue spans, the no-duplicate tombstone's occupancy (`emitted_request_keys`), and BPF-side drop/failure counters plus the informational re-seed (`bpf_reseed_*`), per-submit re-seed (`bpf_operate_seed_hits`, `bpf_operate_seed_misses`, `bpf_operate_miss_ctx_cleared`, `bpf_operate_miss_home_ctx_preserved`, `bpf_operate_unresolved_home_ctx_preserved`, `bpf_operate_base_unresolved`), multi-key bridge (`bpf_rgw_op_key_inserts`, `bpf_rgw_op_key_revokes`, `bpf_rgw_op_key_revoke_skipped`, `bpf_rgw_op_key_unresolved`), request-end (`bpf_request_end_*`), and `_send_op` liveness-gate (`bpf_sendop_stale_ctx_drops`, `bpf_sendop_unverifiable_ctx`, `bpf_sendop_unbridged_ctx_drops`) coverage counters.

The run-summary counters are **always** surfaced two ways, regardless of any flag: the end-of-run `finished live tracing` / `rgwtrace shutdown summary` log lines carry them in a `diagnostics=` field of `key=value` pairs, and the JSON `trace.diagnostics` block carries them in full.

**Emitting the run summary into OTLP is opt-in via `--otlp-diagnostics` (default off).** These are cumulative debug counters, not request telemetry, so shipping them onto every span's Resource and as a synthetic span pollutes the tracing backend -- the wrong default for normal tracing. Because the same counters are always readable off the shutdown log and the JSON output, the default keeps OTLP clean while validation stays possible. With the flag OFF the OTLP resource carries just `service.name` and no `rgwtrace.run_summary` span is emitted; an empty final drain sends nothing (the pre-diagnostics behavior). The gating is a single `diagnostics` bool on `otel::ExportConfig`, plumbed from `cli.otlp_diagnostics` through both the periodic (`live::linux`) and final (`main`) export paths.

**With `--otlp-diagnostics` the final export is guaranteed, and it carries a run-summary span.** The final BPF counters are merged out of the BPF maps only after the poll loop exits, so the end-of-run document is the only one holding the run's true totals -- but the periodic drains have usually already taken every span, so it typically holds ZERO spans. An empty span set produces no span batches, so without this the export would deliver nothing and the backend would hold an earlier snapshot with the final totals nowhere. With the flag on, `otel::export_final_otlp_http` therefore always puts at least one batch on the wire, and appends to it a synthetic zero-duration span named `rgwtrace.run_summary` carrying every counter as `rgwtrace.diag.*` span attributes, plus the same counters on the batch's Resource. Both fields are populated because they fail differently: a span-less batch's Resource reaches the collector but is stored by no trace backend, whereas a span is always stored and indexed. The consequence, with the flag on: the run always contacts its endpoint, so an unreachable endpoint fails loudly instead of exiting silently when nothing was captured.

**Every sink is generated from one function** (`TraceDiagnostics::counters()`, derived from the struct's serde representation) rather than from maintained lists. The lists had already rotted: the OTLP one omitted `bpf_operate_seed_*`, `bpf_operate_miss_ctx_cleared`, `bpf_rgw_op_key_*`, `bpf_sendop_unbridged_ctx_drops` and `emitted_request_keys` -- i.e. exactly the counters that say whether cross-thread correlation is working -- which made an `--output otlp --otlp-diagnostics` validation run unable to distinguish a working Phase B from an inert one. `every_diagnostics_field_reaches_every_output_path` is the tripwire: it fails if any field of `TraceDiagnostics` does not reach the JSON and the log (always) and the OTLP resource + run-summary span (with the flag on), and asserts the resource is clean with the flag off. It checks CONSTRUCTION; `final_export_delivers_the_run_summary_when_the_last_drain_left_no_spans` checks DELIVERY (flag on), decoding the protobuf a mock collector actually received, and `flag_off_final_export_of_an_empty_drain_sends_nothing` pins the flag-off empty-final behavior -- the empty-final-trace hole was invisible to a construction-only test.

It supports HTTP and HTTPS.

It supports optional gzip compression, span-count batching, and encoded-size batching.

---

## Limit

Native DWARF parsing supports the current RGW/RADOS probe set: `Objecter::_send_op`, `Objecter::_finish_op`, and `RGWREST::get_handler`.

It discovers debug data from embedded DWARF, `.gnu_debuglink`, and build-id paths, then extracts module build IDs, probe PCs, variable locations, and member field paths into the existing probe field model.

Native extraction treats every input file as untrusted (see [DWARF parser limits](docs/bugfix-dwarf-parser-limits.md)):

- Reference-following loops are bounded: 64 typedef/cv or pointer links per type walk, 4096 base classes per member lookup (with a visited set). The whole-unit type and scope searches are iterative `next_dfs` walks. The two function walkers stay recursive, because their `EntriesTree` skips subprogram bodies via `DW_AT_sibling`, and are capped at 256 scope levels. A limit that is hit is an error naming the DIE's `.debug_info` offset.
- `--max-debug-file-bytes` (default 4 GiB) caps every whole-file read (target, debuglink/build-id debug file, DWZ supplementary file) and the total declared size of one file's compressed sections. The cap is checked before anything is read or inflated.
- The Ceph version comes from `--ceph-version`, then an embedded `ceph version` string, then MicroCeph metadata, then the host package database. The host database is skipped, with an error that asks for `--ceph-version`, when a target is under a `/proc/<pid>/root` that is not the host root. Host tools run by absolute path with a cleared environment.

Performance notes:

- Each target is read once. The embedded version and the module build ID come from the buffer `parse_module` already holds. Preflight reads the build-ID note through `object::ReadCache`.
- Uncompressed DWARF sections are borrowed from the file buffer, not copied.
- Mangled names are demangled only if they contain a probe's leaf identifier, which is derived from the probe table.
- Still open: type and scope lookups re-walk every unit per lookup, and zstd sections are bounded only after inflation (`object` 0.39). See the bugfix note.

`cephtrace` JSON import remains supported as a stable fallback and oracle for native extraction.

Build IDs are validated against discovered binaries. Mismatches fail by default and require `--allow-build-id-mismatch` to continue.

Field offsets can be wrong if native debug data or imported JSON does not match the runtime binaries.

Request correlation is intentionally conservative.

Cross-thread, late async, startup, and background RADOS operations may remain standalone spans. Optional inferred correlation never joins ambiguous candidates.

See [Production Runbook](RUNBOOK.md) for operating guidance and troubleshooting.
