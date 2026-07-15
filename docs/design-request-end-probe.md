# Request-END probe: `req_state::~req_state`

## The defect this fixes

rgwtrace had **no request-completion probe at all**. `emit_request_event(RGWTRACE_EVENT_REQUEST_END, ...)` was called from the `RGWREST::get_handler` **entry** uprobe, so the marker's `start_ns` and `end_ns` were the same instant. The `rgw.request` span's visible duration was then fabricated in userspace as `max(marker.end_ns, max(child rados end))` -- the span simply ended at its last correlated child.

Consequences:

- `rgw.request` durations were **fiction**. A request whose ops all completed early, or whose ops were lost to the coroutine-migration problem, reported a duration that had nothing to do with how long RGW took.
- `rgw.duration_quality = "marker"` only meant "a marker existed". It could not distinguish a real duration from a reconstructed one, because there were no real durations.

## Why the destructor

`process_request` stack-allocates `req_state`. Its destructor therefore runs at scope exit -- after logging, after `client_io->complete_request()` -- on **every** path out of the request, and `process_request` calls it **out-of-line** (verified on Ceph 18.2.4 reef and 19.2.4 squid: `call <_ZN9req_stateD1Ev>`). That makes it the true, unconditional end of an RGW request.

It is an **entry** uprobe. It must never be a uretprobe: a uretprobe patches the return address on the stack, and asio switches fiber stacks underneath the probe. That is precisely why the old `process_request` **return** probe crashed RGW live, and why there is no return probe anywhere in this BPF program.

Alternatives considered and rejected:

- **`rgw_log_op(RGWREST*, req_state*, RGWOp const*, OpsLogSink*)`** -- rejected. In `process_request` it is guarded by `if (should_log)` (config-dependent via `mgr->get_logging()`), so it does not fire for every request, and it has a third call site inside `rgw::lua::request::RequestLog` (a Lua scripting binding) that would fire the probe spuriously.
- **A `process_request` return probe** -- rejected: it crashes RGW (above).

## The destructor-variant hazard (D0 / D1 / D2)

The Itanium C++ ABI emits up to three destructors for one class, and **all three demangle to the same name**:

| mangled | variant | demangled |
| --- | --- | --- |
| `_ZN9req_stateD0Ev` | deleting destructor | `req_state::~req_state` |
| `_ZN9req_stateD1Ev` | complete object destructor | `req_state::~req_state` |
| `_ZN9req_stateD2Ev` | base object destructor | `req_state::~req_state` |

A probe that matched on the demangled name alone would bind to whichever variant the symbol table or DWARF happened to list first. On real g++ output that is **`D0`** -- it precedes `D1`/`D2` both in `.symtab` order and in DIE order. `D0` runs only for heap-`delete`d objects (it calls the base dtor, then `operator delete`), so probing it would fire on the wrong path, or never, for a stack-allocated `req_state`.

Resolution is therefore ranked by the **mangled linkage name** (`dtor_variant_rank` in `src/dwarf_native.rs`), in *both* resolution paths -- the ELF symbol table and the DWARF DIE walk:

- `D1` (complete object) -- accepted, rank 0. This is the one `process_request` calls, so it is preferred whenever it exists.
- `D2` (base object) -- accepted, rank 1. On both verified Ceph builds it is **aliased to `D1` at the same address**; the two can only diverge for a class with virtual bases, and `req_state`'s only base (`DoutPrefixProvider`) is non-virtual at offset 0. When both exist, `D1` wins on rank.
- `D0` (deleting), `D4`/`D5` (GCC's DWARF-only "unified" placeholders, which appear on the class-scope *declaration* and have no PC anyway), and anything else -- **rejected outright**. A rejected variant contributes no address, so it can never be probed by accident.
- A destructor definition with no reachable linkage name is also rejected: the variant cannot be proven, and shipping a coin flip is worse than shipping no end probe.

Every other probe function ranks 0 and keeps the previous first-definition-wins behavior.

Both paths are covered by tests that compile a real C++ fixture (a polymorphic `req_state` destroyed both on the stack and through `delete`, which is what forces g++ to emit all three variants) and assert the extractor binds to the complete/base address and never to the deleting one -- once with the symbol table present, and once with the destructor symbols stripped so resolution must come from the DIE walk.

## The D0-variant hazard on the JSON-import path

The ranking above is an *extraction*-time defence. An artifact imported with
`--import-dwarf-json` is just `demangled name -> address`, and the demangled name
is the same for all three variants. A third-party or cephtrace-style producer
that resolved "the first destructor with this name" would hand us **D0**, and
neither the address nor the `this` descriptor could reveal it: both validate
perfectly.

So the artifact must carry the **provenance** of the address, and the importer
must check it:

- Native extraction now exports **`func2linkage`** per module -- the *mangled*
  linkage name of the definition each address came from -- for every function
  whose demangled name is ambiguous (`VARIANT_PROVENANCE_FUNCTIONS`, i.e. exactly
  the `req_state` destructor today).
- `DwarfInfo::request_end_probe` (`src/dwarf_json.rs`) is the single gate used by
  both preflight and attach. It returns `Available { addr, linkage }` only when
  the address, the register-only `this` descriptor, **and** a `func2linkage` entry
  whose mangled name passes `dtor_variant_rank` (D1/D2) are all present. Every
  other case is `Unavailable(gap)` with an operator-facing reason.
- **Older artifacts** (exported before `func2linkage` existed) simply lack the
  field. They keep loading and keep working for everything else; they just do not
  get the end probe, and preflight/attach say so
  (`MissingVariantProvenance` -> "re-export the DWARF artifact"). Fail-closed: an
  END uprobe on a deleting destructor is not a degradation, it is a wrong probe.

## Mechanism

```
get_handler(entry)            req_state::~req_state(entry)
  |                             |
  | REQUEST_START (start_ns)    | look up rgw_ctx_by_reqstate[(this, tgid)]
  | rgw_ctx_by_reqstate[        |   hit  -> REQUEST_END (start_ns, REAL end_ns)
  |   (req_state*, tgid)] = ctx |          delete the bridge entry   <-- revocation
  |                             |          delete rgw_requests[tid] IF it is this request's
  |                             |   miss -> count a diagnostic, emit nothing

_send_op(entry)
  |
  | ctx = rgw_requests[tid]              (a COPY of some request's context)
  | request_ctx_is_live(ctx)?            (is that request still alive?)
  |   yes -> stamp ctx->trans_id onto the op
  |   no  -> stamp nothing; count RGWTRACE_DIAG_SENDOP_STALE_CTX_DROPS
```

### Why `_send_op` must re-validate the context it finds

`rgw_requests` is keyed by tid and holds a **copy** of a request's context. A
request's context is copied onto its `get_handler` thread and onto every thread
the cross-thread bridge re-seeds it onto. The destructor can only revoke the copy
on the **one** thread it runs on -- it must not clear another live request's
context off a shared Beast pool thread. Every other copy therefore **outlives its
request**, and an op submitted later from such a thread (a subsequent request, or
a background op) would inherit a dead request's `trans_id` and be attributed to
the wrong request. That is strictly worse than an uncorrelated op: it is
confidently wrong telemetry, and Phase B (seeding the bridge at every
`rgw_rados_operate`) would scatter such copies across far more threads.

The revocation signal already exists: `rgw_ctx_by_reqstate[(req_state*, tgid)]`
is created at `get_handler` and **deleted exactly at request end**. So its
presence *is* liveness, and `request_ctx_is_live` (bpf/rgwtrace.bpf.c) consults
it before `_send_op` stamps anything.

**Presence alone is not enough, because req_state addresses are recycled.**
`req_state` is stack-allocated inside `process_request`, so consecutive requests
on the same Beast worker thread routinely reuse the *same* address -- the
`(req_state*, tgid)` key is genuinely re-keyed by a *new* request, and a pure
presence check would validate a stale copy against the new request's entry and
stamp the old `trans_id`. The gate therefore also compares **identity**: the
bridged entry's `start_ns` (the `get_handler` boot-clock read) and `tid` must
equal the copy's. Two `get_handler` entries cannot observe the same nanosecond on
the same thread, and a different thread implies a different stack address, so
`(req_state*, tgid, start_ns, tid)` distinguishes "same request still alive" from
"new request at a recycled address".

**Cost.** One hash lookup plus two scalar compares, only on the path that was
about to stamp a `trans_id` anyway. `_send_op` already performs ~12 `hprobes`
lookups and ~15 `bpf_probe_read_user` calls per op, so the gate is a small
single-digit percentage of the probe's existing work. There is no cheaper sound
design: any generation/epoch scheme still has to fetch the request's current
generation from somewhere -- the same lookup, plus a new map. (The lookup has a
useful side effect, too: it keeps a live request's bridge entry hot in the LRU.)

**Fail-closed, and gated on the END probe.** If a bridge entry is LRU-evicted
while its request is still alive, the gate says "not live" and the op is left
**uncorrelated** (counted in `bpf_sendop_stale_ctx_drops`). Uncorrelated is a
known unknown; mis-correlated is a lie -- so this is the right way to be wrong,
and the counter makes it measurable on a live run. And when the END probe is
**not attached**, nothing ever deletes a bridge entry, so presence carries no
liveness information at all: the gate is then switched off entirely (via the
`REQUEST_END_PROBE_ATTACHED` global, which userspace sets from the *actual*
attach outcome), `_send_op` keeps its pre-gate behavior, and the ops it stamps
without proof are counted in `bpf_sendop_unverifiable_ctx`.

## Open requests must not be TTL-expired (the duplicate-span hazard)

A request group used to expire purely on idleness (`--correlation-ttl`, default
120s since its last event). With a real END marker that is a bug: a long-running
request that is merely *quiet* between RADOS ops would be exported with a derived
duration and removed -- and its destructor END, arriving later, would rebuild the
group and emit a **second span with the same trace/span id**, splitting the
request's children across two spans.

The collector therefore models request groups as **open** or **closed**:

- **Open** = the END probe is attached and no END marker has arrived yet, so one
  is still expected. Open groups are **never** idle-expired.
- **Closed** = the END arrived, or the END probe is not attached at all (no END is
  ever coming, so the pre-end-probe idle TTL is exactly right).

An END can still be genuinely lost (a ring-buffer drop, or a destructor bridge
miss), so an open group is bounded by **lifetime**, not idleness:
`OPEN_REQUEST_TTL_MULTIPLIER * --correlation-ttl` (10x, i.e. 20 minutes at the
default) since the request began. Past that it is exported with a derived end and
counted in `expired_open_requests`.

Whatever the reason a request span is exported, its key is **remembered** (a
bounded FIFO). A straggler event for an already-exported request can then never
re-open the group: a late marker is dropped and counted
(`late_request_markers_dropped`), and a late RADOS op becomes a background span
with `rgw.correlation_reason = "request_already_emitted"` rather than a duplicate
parent span. **No request is ever emitted twice under one span id.**

The END probe reads `this` (`req_state*`) through the varid-50 **register-only raw-pointer descriptor** -- the same shape as the varid-40 `rgw_process_authenticated` descriptor, and the same fail-closed import validation. The register is derived from DWARF (reg 5 / `rdi` on x86-64); nothing about the ABI is hardcoded.

Two details worth calling out:

- **It is the first and only delete on `rgw_ctx_by_reqstate`.** That map was insert-only and relied purely on LRU eviction to bound growth. The end of a request is exactly when its bridge entry stops being needed, so the map is now bounded by lifecycle. It stays `LRU_HASH` (it is not request/op state, and eviction of a stale entry there is harmless).
- **It clears `rgw_requests[tid]` only when that context is provably this request's own** (`cur->req_state_ptr == rsp && cur->pid == tgid`). RGW/Beast pool threads are shared: after a coroutine migration the context sitting on this tid may belong to *another* in-flight request, and clearing it would silently un-correlate that request's RADOS ops.

## Fail-soft contract

The END probe is **optional**. It is not attached when the destructor address, its variant provenance, or the `this` descriptor does not resolve, and an attach failure is warned about rather than propagated. Every one of those skips is **warned at attach time**, never silent: a missing end probe silently changes what every `rgw.request` duration in the output means, so an operator who never ran preflight separately must still be told. The collector then derives each request's end from its correlated RADOS child bounds exactly as before, and labels the span `rgw.duration_quality = "marker"`. Preflight surfaces the same condition as an advisory `request_end_probe` `warn`, never a hard error. An RGW build that worked before this change keeps working.

## Out-of-bounds children: BOTH boundaries have provenance

With a real parent end, a correlated child can now, in principle, fall outside its parent at *either* end:

- it can **end after** the parent (a late `_finish_op`, an `--correlate-inferred` child, or cross-CPU boot-clock skew between `_send_op` and `_finish_op`), and
- it can **start before** the parent's marker (an inferred or late-delivered child that was already in flight when `get_handler` fired).

Children are **never clamped into the parent** -- a RADOS op's bounds are measured facts, and shrinking them would corrupt the op's reported duration and break the `ceph.rados.duration_ns == end_ns - start_ns` invariant the JSON validator enforces. Instead the **parent is stretched** to cover the child (its end forward, or its start backward), which preserves the child-within-parent invariant, and the stretch is **disclosed**:

- `rgw.duration_quality` becomes `measured_extended` (not `measured`) if **either** boundary was moved off its measured value. Checking only the end would let a span whose start was pulled back to an early child keep claiming `measured` while part of its duration is fictional.
- `rgw.request.measured_start_ns` and `rgw.request.measured_end_ns` carry the untouched real interval, so a consumer can always recover the true request duration regardless of which boundary was stretched.

`measured_start_ns` is emitted whenever a request marker exists (the `get_handler` clock read is a measured instant even when the end is derived); a `rados_bounds` span has neither attribute, because neither boundary was measured. The same disclosure applies to the degenerate case where a measured end precedes its start and is clamped up: the span is `measured_extended`, never `measured`.
