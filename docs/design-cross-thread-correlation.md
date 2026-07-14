# Cross-thread RGW→RADOS correlation: design after live Stage 0

> **SUPERSEDED IN PART BY PHASE B (§9) AND THE REVIEW FINDINGS (§10). Read §9,
> then §10 — §10 corrects §9.**
>
> §9 fixed *where* to re-seed. §10 fixes *what identity to key on* (the dpp at an
> op's data-path call sites is the **RGWOp**, not the `req_state` — so the bridge
> is multi-keyed), *what a miss means* (fail closed: a live-but-not-running
> request's context must never stamp another request's op), and *when the feature
> may attach at all* (only with a revoking END probe).
>
> §§1–8 below record the Stage 0 measurements and the conclusion drawn from
> them: that cross-thread correlation was *not achievable* without the
> type-unsafe `dpp`-walking that sank PR#2, and that the honest ceiling was the
> **~20–25%** of ops submitted synchronously on the execute thread. **That
> conclusion was wrong, and §9 explains exactly which premise was wrong.** The
> measurements in §2 remain valid and are, in fact, what Phase B exploits; the
> *recommendation* in §3 and §8 does not. The rejected alternative in §7
> ("bridged via DWARF inheritance offset") is still rejected, for the reasons
> given — Phase B is **not** that design, and §9.3 spells out the difference.
>
> Do not implement from §§3/6/8 without reading §9.

**Original status (retained for the record): REVISED per Stage 0 (live-measured
on quay.io/ceph/ceph:v18, 18.2.8, beast). Recommendation: ship a bounded,
fail-closed, opt-in bridge; STOP short of full cross-thread correlation — it is
not achievable on this async build without reintroducing PR#2's failure class.**
Supersedes PR#2 (`rgw-rados-context-correlation`), which is not merged.
Load-bearing claims are tagged **[MEASURED]** (on the live local rig) or
**[CONFIRM]** (to re-verify on the reference MicroCeph rig).

## 1. Problem statement & success criteria

Main correlates a RADOS op only when `_send_op` runs on the same TID as
`get_handler`. The landed Stage 1–2 work added an inert `(tgid,
req_state_ptr)` reqstate map (populated at `get_handler`) and an e2e
zero-mis-correlation gate; the planned re-seed at `rgw_process_authenticated`
assumed **[A1]** that librados data I/O is synchronous on the execute thread.
**Stage 0 falsified [A1]** (see §2). Success criteria are therefore revised to
what is measurably attainable *without fragile object-graph walking*:

- **Primary (attainable):** the fail-closed reqstate bridge correlates every
  RADOS op **submitted synchronously on the execute thread**, with **zero
  mis-correlations**, baseline unregressed. Measured ceiling on this rig:
  **~20–25%** of all `_send_op` (§2). **[CONFIRM]** the data-path (GET-read /
  PUT-write) subset of that ceiling on MicroCeph via role cross-check.
- **Explicitly de-scoped:** the ≥90% data-path target. Stage 0 shows the RADOS
  submit for data ops is dispatched to a decoupled worker pool; closing that
  gap requires walking `dpp`→`trans_id` (PR#2's fragility). **Recommended
  against** (§3, §7).
- Missing DWARF/probe/reqstate ⇒ degrade to main; **fail closed**, never
  mis-correlate.

## 2. Thread & pointer flow — MEASURED (this rig) vs assumed

Live Objecter symbols resolve only from `/usr/lib64/librados.so.2.0.0`
(.symtab, unstripped); the exported `libceph-common` Objecter symbols are dead
code. All numbers below are from `bpftrace` uprobes on the live radosgw (PID
via `pgrep -f 'radosgw --name'`), workload `tests/e2e/s3-workload.py` (single
+ `--concurrent-requests 4`). Artifacts:
`/tmp/stage0/{h1-opsubmit,h3-sync,h4-aio}.{bt,out}`,
`summary-{single,concurrent}.txt`, `tidbreakdown.out`.

- **[A2] PASS 100%** — `rgw_process_authenticated(RGWHandler_REST*, RGWOp*&,
  RGWRequest*, req_state* s@arg3, optional_yield, Driver*, bool)` exists; its
  `req_state*` is pointer-identical to `get_handler`'s within 1 s (130/130,
  78/78). The `(tgid, req_state_ptr)` key is sound.
- **[A3] PASS 100%** — plausible heap pointer in the arg register at entry,
  both sites.
- **[A1] FALSE** — `_send_op` on a seeded (execute) TID: **229/1145 = 20%**
  single, **136/740 = 18%** concurrent. `op_submit` on a seeded TID: **96/412
  = 23%**. `aio_operate` (async data-path submit) on a seeded TID: **94/378 =
  25%**. → The RADOS **submit runs off the execute thread ~75%**.
- **`op_submit → _send_op` is 100% same-thread synchronous** — 202/202 sends
  ran on the exact TID that called `op_submit`; 0 differed. Submission
  scatters across **~120 distinct worker TIDs** (comm: `radosgw` bulk,
  `ceph_timer` 45–54 resends, `io_context_pool` 5–10). So the hop is **not**
  between op_submit and send; it is **inside `execute()`**, before
  `aio_operate`.
- **Op*-keyed op_submit→_send_op handoff (PR#2's "one robust piece") adds
  nothing** — Op* is a valid join (**412/476 = 87%** of sends were seen at
  op_submit), but handoff coverage `send_from_seeded_op = 96/476 = 20%`,
  **identical** to thread-keyed `send_tid_seeded = 96`. Because op_submit is
  itself off-thread, moving the read one frame up recovers zero ops. The v1
  rejection of the handoff as "thread-equivalent to `_send_op`" is now
  **confirmed by measurement** (they are co-threaded 100%).
- **Residual 19%** — of seeded sends, 19% ran on a TID last seeded >50 ms
  earlier (`old>1s` bucket non-empty). Finding #3's lingering-context hazard
  is real and *requires* fail-closed scoping.

**[CONFIRM]** on MicroCeph: (a) the seeded % may differ by frontend/thread-pool
config; (b) whether the ~20–25% seeded submits are the GET/PUT data ops or
incidental synchronous metadata ops (role cross-check via rgwtrace output).

**Live bridge validation (this rig, Stages 3+4 built, `--correlate-cross-thread`
ON) [MEASURED]:** `reseed_hits` 43/43 requests (0 misses, 0 base_unresolved);
82 correlated ops, counter equation holds; e2e manifest cross-check EXIT=0 with
zero mis-correlations; per-role coverage decomposes as **GET-read 2/2 (100%)
vs PUT-write 0/4 (0%)** — reads submit synchronously on the execute thread
(bridgeable), writes dispatch to the async worker pool (the de-scoped gap).
The ~20–25% aggregate ceiling is therefore read-dominated on this build.

**Mechanistic conclusion (measured):** `execute()` dispatches object I/O
asynchronously (`aio_operate` + `AioCompletion` overloads are present and are
the data path; `aio_operate` is itself off-execute-thread 75%). The chain
`aio_operate → op_submit → _send_op` is co-threaded on a worker pool decoupled
from the execute thread. On that worker thread the only request identity
available above Objecter is the librados `dpp` (`DoutPrefixProvider*`, an
abstract base subobject); `trans_id` is reachable from it only through
concrete-type + multiple-inheritance offsets — **the exact
hardcoded/object-graph-walking fragility that sank PR#2.**

## 3. Chosen approach

**Ship the reqstate bridge, fail-closed, behind an opt-in flag, scoped
honestly to on-execute-thread submits. Do not pursue dpp-walking.**

The landed Stage 1 reqstate map already moves ctx from `T_h` (get_handler) to
the execute thread correctly. The bridge re-seeds `rgw_requests[T_e]` at
`rgw_process_authenticated`; any op that *does* submit synchronously on `T_e`
inherits `trans_id`. This is a real gain over main (main seeds only `T_h`,
which is never `T_e`), bounded at the measured ~20–25%.

**Mechanism (unchanged from the reviewed design, kept intact):**

- ctx struct gains `__u64 req_state_ptr` (no wire ABI change). *(Landed,
  Stage 1.)*
- Maps: `rados_ops` `(cid,op_tid)` LRU (unchanged); `rgw_requests` TID→ctx
  (unchanged shape, carries `req_state_ptr`); `rgw_ctx_by_reqstate` LRU keyed
  `{ __u64 req_state_ptr; __u32 tgid; __u32 _pad; }` (PID-scoped — `--pid` is
  optional, `src/cli.rs:60`). *(Landed, Stage 1.)*
- Raw-pointer param descriptor: `fetch_param_ptr(ctx,vf) = vf->varloc.stack ?
  0 : fetch_register(ctx, vf->varloc.reg)`; native/JSON emit the entry-PC
  **register** location + one sentinel field (`dwarf_native.rs:523` rejects
  empty paths); stack-located-at-entry ⇒ skip + diagnostic (finding #4).
  *(Helper landed, Stage 1; extraction lands Stage 3.)*
- `get_handler` (landed): if `!vf30->varloc.stack && v>0`, set
  `request->req_state_ptr=v` and `rgw_ctx_by_reqstate[{v,tgid}] = *request`
  (overwrite-on-reuse = aliasing cure).
- **New re-seed uprobe `rgw_process_authenticated`** (base id 40, one
  raw-pointer var_field), **gated behind `--correlate-cross-thread` (default
  OFF)**:

  ```
  rsp = fetch_param_ptr(ctx, vf40);      if (!rsp) { count(reseed_base_unresolved); return; }
  ctx = lookup(rgw_ctx_by_reqstate, {rsp, tgid});
  if (ctx)  rgw_requests[tid] = *ctx;                                   // hit: authoritative
  else {                                                                 // FAIL CLOSED
     cur = lookup(rgw_requests, tid);
     if (cur && (cur->req_state_ptr != rsp || cur->pid != tgid))
                bpf_map_delete_elem(&rgw_requests, &tid);                // clear foreign lingering ctx
     count(reseed_misses);                                              // keep only if it is THIS request
  }
  ```

  This identity-checked clear is the fix for both review finding #1 (foreign
  lingering `trans_id` is cleared → no mis-correlation) and the same-thread
  non-regression (this request's own fresh ctx on the rare hit-miss is
  preserved).

  **Superseded in part by the request-END probe.** The clear above only fires on
  threads that actually reach `rgw_process_authenticated`, so it cannot revoke a
  context copy left on some *other* thread once the request ends. `_send_op` is
  therefore no longer unchanged: it now re-validates any context it finds against
  the `(req_state*, tgid)` bridge — whose entry the destructor probe deletes at
  request end — and stamps nothing when that context belongs to a request that
  has already ended (`request_ctx_is_live`, counted in
  `bpf_sendop_stale_ctx_drops`). See `docs/design-request-end-probe.md`. This is a
  precondition for Phase B (seeding the bridge at every `rgw_rados_operate`),
  which scatters context copies across many more threads.
- Collector labels late (finding #6): non-empty `trans_id` records
  `RadosCorrelation::TransId` (thread-unresolved) at ingest; `request_spans`
  resolves `same_thread` (`send_tid==marker.tid`) vs `cross_thread` (differs),
  no-marker groups keep `same_thread`.
- **No Op*-keyed `objecter_ops` map, no `op_submit` probe** — measured to add
  zero coverage (§2).

## 4. Why PR#2's failure modes cannot recur (in what we ship)

1. **Hardcoded offsets** — none. Only DWARF-derived: `get_handler`'s reused
   base register + one register-at-entry `req_state*`. **No `dpp` walking** —
   the whole point of the pivot is to *refuse* it.
2. **Heap-pointer key aliasing** — `rados_ops` keyed `(cid,op_tid)`;
   `rgw_ctx_by_reqstate` PID-scoped, overwritten by each request's
   `get_handler` before its re-seed, and consumers fail closed on identity
   mismatch.
3. **100 ms TTL stack** — gone; overwrite + identity-checked clear, no time
   window.
4. **Remapped slots / `fetch_var_value`** — 30/31 kept; new fn appended at 40;
   `fetch_register`+`fetch_var_member_addr` verbatim; `fetch_param_ptr` is
   register-only, never composes varloc.

## 5. Failure-mode analysis

| Mode | Detection | Behavior |
|---|---|---|
| Re-seed miss, foreign lingering ctx (finding #1; residual 19% **[MEASURED]**) | `reseed_misses` | foreign ctx **cleared** ⇒ `_send_op` stamps nothing ⇒ background/inferred. **Fail closed.** |
| Re-seed miss, ctx is this request (same-thread, entry evicted) | `reseed_misses` | ctx **kept** ⇒ still correlated. No baseline regression. |
| **Async submit off execute thread (A1-false, ~75% [MEASURED])** | coverage counters; e2e role cross-check | op never reaches a seeded thread ⇒ background/inferred. **Not mis-correlation.** This is the de-scoped gap; **not** closed by this design. |
| `req_state*` stack-at-entry / abstract_origin-only (LTO) | `reseed_base_unresolved` | var_field skipped ⇒ baseline. Mitigate via cephtrace JSON or extractor fix. |
| `rgw_process_authenticated` renamed/inlined (version skew) | preflight advisory; hits==0 | probe unattached ⇒ baseline. |
| reqstate LRU eviction | `reseed_misses`++ / `sendop_stale_ctx_drops`++ | clear-if-foreign ⇒ background; and the `_send_op` liveness gate reads an evicted entry as "not live" ⇒ the op is left uncorrelated, never mis-correlated. **Fail closed.** |
| Context copy outliving its request on a pooled thread | `sendop_stale_ctx_drops` | bridge entry deleted at request end ⇒ `_send_op` stamps nothing. **Fail closed.** |
| Cross-process `req_state*` collision | — | prevented by `(tgid, req_state_ptr)` key. |
| Verifier rejection | `scripts/verify-bpf-load.sh` | 2 lookups + 1 update/delete, no loops ⇒ passes. |

## 6. Staged plan (Stages 1–2 already landed; renumbered)

- **Stage 1 — DONE** (`2bbc0b1`). Inert `(tgid,req_state_ptr)` reqstate map +
  `get_handler` population + `req_state_ptr` in ctx + `fetch_param_ptr`.
- **Stage 2 — DONE** (`16ab810`). e2e object↔request zero-mis-correlation
  cross-check + concurrent workload on baseline. This gate now guards the
  opt-in bridge.
- **Stage 3 — Fail-closed re-seed behind `--correlate-cross-thread` (default
  OFF).** Add base 40 + register-at-entry extraction + the
  identity-checked-clear handler + diagnostics
  (`reseed_hits/misses/base_unresolved`). **Ship default-off**; the Stage-2
  gate must pass with the flag ON on the reference rig before any default-on
  discussion. Baseline (flag off) untouched.
- **Stage 4 — Late `cross_thread` label.** `RadosCorrelation::TransId` at
  ingest; resolve in `request_spans`; add `cross_thread_correlations`; enforce
  `correlated_rados_ops == same_thread + cross_thread + inferred`; add
  `"cross_thread"` to `verify-rgwtrace-json.py` VALID sets; refresh goldens.
- **Stage 5 (conditional) — abstract_origin extractor fix** if Stage 3 shows
  unresolved LTO params.
- **No Stage for dpp-walking.** See §7.

**Deliberate test updates (finding #5, not regressions):**
`src/dwarf_json.rs:474` (`slot_capacities_match_base_id_gaps`) — get_handler
capacity `8192-30 → 40-30 = 10`, add the new fn's `8192-40`;
`tests/cli_dry_run.rs:29` (`hprobe_entries == 3`) — the fixture gains the new
fn's one var_field.

## 7. Rejected alternatives (with measured reasons)

- **Op*-keyed op_submit→_send_op handoff (PR#2 salvage)** — **[MEASURED]**
  identical 20% coverage to thread-keying; op_submit is off-execute-thread
  77%. Zero gain.
- **Seed at `op_submit` / `_op_submit_with_budget`** — same TID as `_send_op`
  (100% co-threaded); adds nothing.
- **Seed at a submission-thread RGW SAL frame carrying `dpp`, bridged via
  DWARF inheritance offset (`dpp = req_state + base_offset`)** — mechanically
  viable (the SAL frame *is* on the submission thread, co-threaded with
  `op_submit`/`_send_op`), but **recommended against**: (i) requires
  base-class-offset extraction the native extractor lacks; (ii) the `dpp`
  passed to the data path is not guaranteed to be the request's `req_state`
  subobject (RGW frequently passes op/bucket/wrapper dpps), so `req_state +
  offset` need not match → silent mis-correlation; (iii) the target
  SAL/`aio_operate` callers are multiple, virtual/templated, version-specific,
  and could not be reliably identified here (frame-pointer-less builds defeat
  `ustack`). This is PR#2's failure class re-created with a DWARF-derived
  offset. **High risk, low confidence — do not ship.**
- **Async-context (asio executor / `optional_yield` coroutine handle)
  propagation** — no DWARF-stable, request-identity-bearing site; not
  attemptable without upstream Ceph support.
- **`process_request` return probe** — banned (crashes RGW).
- **`correlation_source` u8 in rados ABI** — unnecessary; `cross_thread`
  derived late.

## 8. Honest recommendation

**The remaining link — execute-thread → RADOS-submission-thread for
asynchronously-dispatched data ops — is not achievable at a DWARF-stable,
identity-bearing probe site on this async 18.2.8 build without unacceptable
risk** (the `dpp`-walking that defines PR#2's failure). Concretely:

1. **Ship** Stage 3 fail-closed `--correlate-cross-thread` (default OFF) as a
   bounded, honestly-labeled improvement: it correlates the ~20–25% of ops
   submitted synchronously on the execute thread with **zero
   mis-correlations**, and strictly beats main for those. Keep
   `--correlate-inferred` for the rest.
2. **Revise the product claim** in ARCHITECTURE/RUNBOOK: cross-thread
   correlation is best-effort and build-dependent; on async-dispatch RGW
   builds most data-path ops remain `inferred`/`background` by design.
3. **[CONFIRM] on MicroCeph** before enabling by default: re-run the §2
   measurements (harness `scripts/stage0-crossthread-probe.sh`) and the
   Stage-2 role-classified cross-check to confirm the seeded fraction, its
   data-op composition, and residual ≈ 0 under fail-closed.
4. **Do not** invest in the `dpp` bridge unless a stakeholder explicitly
   accepts version-locked fragility *and* a rig test first proves `dpp ==
   req_state (+offset)` holds for the GET/PUT data path — which this rig's
   tooling could not establish.

**Confidence:** High — the load-bearing thread/pointer facts are directly
measured on the live rig (op_submit 23% seeded, op_submit→send 100%
co-threaded, aio_operate 25% seeded, handoff 20% = zero gain). The only items
flagged **[CONFIRM]** are environment-specific magnitudes on MicroCeph, not
the structural conclusion.

---

## 9. PHASE B — the per-submit re-seed (supersedes §§3, 6, 8)

### 9.1 The premise that was wrong

§8 concluded that the execute-thread → submission-thread link "is not
achievable at a DWARF-stable, identity-bearing probe site". The hidden premise
was that request context must be **seeded at a fixed set of instants** and then
*survive* to the submit. It cannot: RGW/Beast runs each S3 request as an asio
coroutine that **migrates to a different `io_context` pool thread at every
`optional_yield`**, and correlation is thread-keyed (`_send_op` reads
`rgw_requests[current_tid]`). Context written at `get_handler` and at
`rgw_process_authenticated` is abandoned at the very next yield.

**N seed sites can only ever cover N instants. A coroutine that yields M times
needs the context re-established at every submit.** That is the whole idea.

The §2 measurements were never wrong — "the RADOS submit runs off the execute
thread ~75%" is exactly the symptom of coroutine migration. They were read as a
*ceiling* when they were a *description of the problem*.

Live evidence that forced the re-read (4-request capture: GetObject 200,
GetObject 404, DeleteObject, ListObjects): **9 real request ops were lost**,
including the ENTIRE data path of the DELETE (`rgw.bucket_prepare_op`,
`rgw.obj_remove`, `rgw.bucket_complete_op`) and the metadata reads of the 404
GET. Exactly ONE cross-thread op was ever recovered, and only because that
request's cold-cache auth did I/O and thus yielded, so the
`rgw_process_authenticated` re-seed happened to land on a fresh thread. For the
other three requests the re-seed thread == the original thread, making the
Stage-3 bridge **a literal no-op**.

### 9.2 The site

**`rgw_rados_operate`** — the last common frame before a RADOS submit, keyed on
the `dpp` pointer.

Verified against the REAL radosgw binaries and DWARF (Ceph **18.2.4 reef** and
**19.2.4 squid**, both agree):

1. It exists as an **out-of-line `T` symbol**, in **two overloads**, on both
   versions:
   - `rgw_rados_operate(DoutPrefixProvider const*, IoCtx&, string const&, ObjectReadOperation*, bufferlist*, optional_yield, int)` — 18.2.4 @ `0x892da0`, 19.2.4 @ `0x9f14f0`
   - `rgw_rados_operate(DoutPrefixProvider const*, IoCtx&, string const&, ObjectWriteOperation*, optional_yield, int)` — 18.2.4 @ `0x893580`, 19.2.4 @ `0x9f19c0`
   - In both, `dpp` is **arg0** ⇒ `rdi` ⇒ **DWARF reg 5** on x86-64. The
     register is derived from DWARF, never hardcoded. (Sanity check of the same
     rule: `get_handler`'s `req_state*` is arg2 ⇒ `rdx` ⇒ reg 1;
     `rgw_process_authenticated`'s is arg3 ⇒ `rcx` ⇒ reg 2 — which is what the
     tool's export shows.)
2. **`req_state` inherits `DoutPrefixProvider` at `DW_AT_data_member_location =
   0x00`** on both versions (via `DW_TAG_inheritance` on the `req_state`
   definition DIE). Therefore **`dpp` and `req_state*` are numerically EQUAL**
   for a request's own dpp. This is what lets Phase B reuse the EXISTING bridge
   map, the EXISTING key, and the EXISTING re-seed helper — no new map, no
   inheritance-offset arithmetic, no new key type.
3. The submit is **synchronous on the calling thread**: librados'
   `aio_operate` → `op_submit` → `_send_op` all run inside this call, and only
   then does the coroutine suspend awaiting completion. (§2's "op_submit →
   _send_op is 100% same-thread synchronous" — 202/202 — is the measurement of
   exactly this.) So seeding `rgw_requests[current_tid]` at entry puts the
   context on whatever thread the coroutine is running on *at that instant*,
   immediately before the submit, no matter how many times it has migrated.

### 9.3 Why this is NOT the §7 rejected alternative

§7 rejected "seed at a SAL frame carrying `dpp`, bridged via a DWARF
inheritance offset" on three grounds. Phase B is a different design and each
ground is answered structurally, not by assertion:

| §7 objection | Phase B |
|---|---|
| (i) needs base-class-offset extraction the extractor lacks | **No offset is ever applied.** The `dpp` is used as an **opaque identity token** — a hash key, nothing more. The inheritance offset being 0 is what makes the *existing* key work; it is not *arithmetic we perform*. |
| (ii) the `dpp` passed to the data path is not guaranteed to be the request's `req_state` subobject (RGW passes op/bucket/wrapper dpps), so `req_state + offset` need not match → **silent mis-correlation** | **This is the crux, and it is inverted.** Because the pointer is never dereferenced and never type-assumed, a foreign `dpp` cannot *produce a wrong answer*: it simply **misses** the `rgw_ctx_by_reqstate` lookup and correlates nothing. Fail-closed **by construction**, not by check. The §7 design had to *know the concrete type* to be right; Phase B has to know nothing. |
| (iii) the target SAL/`aio_operate` callers are multiple, virtual/templated, and version-specific | `rgw_rados_operate` is a **plain out-of-line free function**, not virtual, not templated, present at a stable symbol on both verified versions. |

**The dpp is NEVER dereferenced.** Not directly, not through
`fetch_var_member_addr`, not with an offset. A future reader *will* be tempted;
`bpf/rgwtrace.bpf.c` says so at the probe, and `tests/bpf_source.rs`
(`rados_operate_seed_reads_the_dpp_and_never_dereferences_it`) fails the build
if anyone tries.

### 9.4 Binding both overloads (the D0/D1/D2 problem again)

Two distinct functions, at two distinct addresses, share **one demangled name**
— `demangle_function_name` strips the argument list, which is the only thing
that tells them apart. Resolving "the first symbol with that demangled name"
binds one probe to an arbitrary overload and **silently loses an entire half of
the data path** (every RADOS read, or every RADOS write).

This is isomorphic to the destructor-variant problem (D0/D1/D2 all demangle to
`req_state::~req_state`), and it reuses the same machinery:

- Two **synthetic artifact keys**, `rgw_rados_operate(read)` and
  `rgw_rados_operate(write)`, with their own hprobe bases (60, 70), their own
  `dpp` descriptors, and their own BPF programs. Separate slots so each address
  is only ever read with the descriptor extracted from **that same definition**
  — the two are expected to agree (`dpp` is arg0 in both), but nothing relies on it.
- `rados_operate_overload(mangled)` demangles **with** the argument list and
  requires: the name is exactly `rgw_rados_operate`; **arg0 is `const
  DoutPrefixProvider*`** (the load-bearing check — if upstream ever reorders the
  parameters, arg0 stops being the dpp, this returns `None`, and the probe is
  not attached, rather than keying the bridge on an `IoCtx&`); and exactly one
  of `ObjectReadOperation` / `ObjectWriteOperation` appears.
- The winning **mangled name is exported as `func2linkage`** and
  **re-verified at attach** (`DwarfInfo::rados_operate_probe`). An imported
  artifact is just a map from a name to a number: a producer that keyed on the
  demangled name could file one overload's address under both keys, and the
  address and descriptor checks would both pass. Provenance is the only thing
  that can catch it, so an unproven address is **refused**, not probed.
- Two equally-valid definitions at different addresses (a third overload added
  upstream) are **dropped with a warning**, never coin-flipped.

### 9.5 Interaction with the `_send_op` liveness gate (`docs/design-request-end-probe.md`)

The gate refuses to stamp a `trans_id` unless the context's bridge entry is
still present **and identity-matched** (`start_ns` + `tid`). Phase B seeds by
**copying the bridge value**, so the copy's `start_ns`/`tid`/`pid` are the
bridge entry's own, and the gate — which rebuilds the bridge key *from the copy*
and compares exactly those fields — matches **by construction**. Phase B ops are
stamped, not dropped.

This is not left to reasoning: if it were false the whole feature would silently
do nothing (seed hits would still be counted, every op would still come out as a
background op, nothing would look broken). `tests/crossthread_phase_b.rs`
executes the interaction against a source-pinned model of the BPF maps.

The copied `tid` stays the **`get_handler` thread**, not the seeded one — which
is exactly what makes the collector label a migrated submit `cross_thread`
(`send_tid != marker.tid`) rather than `same_thread`.

Phase B scatters context copies across many more threads than Stage 3 did, so
the gate matters *more*, not less: a copy left on a pool thread by an ENDED
request must never stamp a later op. It does not, and that is tested.

**[SUPERSEDED by §10.2 — a foreign-`dpp` miss now DOES clear the thread's
context.]** The original argument was: RGW interleaves request-`dpp` and
foreign-`dpp` operates within one request's own call chain, so clearing on miss
would destroy a correlation a hit correctly established one operate earlier.
That cost is real, but it traded a **coverage** loss for a **correctness** loss —
see §10.2.

### 9.6 Cost & capacity

- **Hot path** (`rgw_rados_operate` fires on every rados operate in the
  process): one `hprobes` lookup, one register read (**no user-memory access**),
  one bridge lookup, and — only on a hit — one stack copy plus one
  `rgw_requests` update. No `probe_read_user`, no loops. Verifier-loaded size:
  **1560B xlated / 948B jited**, against `uprobe_send_op`'s 16936B/9533B — i.e.
  ~9% of the program that already runs for the very op this call is about to
  submit, and negligible against the RADOS round-trip that follows.
- **`rgw_ctx_by_reqstate` capacity:** see §10.4 (the bridge is multi-keyed, and
  the map was resized accordingly).
- **`rgw_requests`** stays a plain **HASH** (never LRU — per-CPU freelists evict
  live entries on ≥64-CPU hosts). Phase B adds one entry per pool thread that
  submits for a traced request; bounded by thread count (hundreds), far below
  8192.

### 9.7 What remains uncovered

Object-payload I/O dispatched through **`rgw::Aio` / `aio_operate`**
(`rgw_aio.cc`) calls librados' async API **directly** and does **not** route
through `rgw_rados_operate`, so multi-stripe GET/PUT body ops are **not**
recovered by Phase B and stay `background`/`inferred`. This is consistent with
§2's finding that the data-path submit is dispatched to a decoupled worker pool.
Covered instead is everything that goes through `rgw_rados_operate`: the
metadata / bucket-index / head-object path — which is where all 9 lost ops in
the live capture came from. **[CONFIRM]** on the MicroCeph rig.

### 9.8 Gating

Folded under the existing **`--correlate-cross-thread`** (still default OFF). It
*is* the cross-thread correlation feature — finally working — and a second flag
would force operators to reason about which half of one mechanism they want. The
Stage-3 `rgw_process_authenticated` re-seed is retained under the same flag: it
costs one probe on a cold path and still covers any submit that reaches librados
without passing through `rgw_rados_operate`. Default-on remains gated on the
MicroCeph run (§8.3).

---

## 10. Review findings — what Phase B got wrong (supersedes parts of §9)

Phase B as first written was **routing-correct and identity-wrong**: it proved
that a request's RADOS submits pass through `rgw_rados_operate`, and then assumed
without checking that the `dpp` at those call sites *is the request's
`req_state*`*. Sections 10.1–10.5 are the corrections.

### 10.1 The bridge must be MULTI-KEYED, or Phase B recovers nothing

§9.2 established `dpp == req_state*` **when RGW passes the req_state as the
dpp**. Routing through `rgw_rados_operate` is **necessary, not sufficient**: what
matters is the *identity* of the pointer at each call site.

RGW threads a `const DoutPrefixProvider* dpp` down its data path, and at most
call sites *inside an op's `execute()`* that pointer is the **`RGWOp`** (`this` —
`class RGWOp : public DoutPrefixProvider`), not the `req_state`. A bridge keyed
only on `req_state*` therefore **misses on the entire op data path**: every
lookup a foreign-dpp miss, `operate_seed_hits` at ~0, every counter healthy, and
a **no-op feature shipped**. This was the single most dangerous defect in Phase
B, because nothing about it *looks* broken.

**Fix.** One request, **every dpp identity it can plausibly be passed under**:

| key | inserted at | note |
|---|---|---|
| `req_state*` | `get_handler` | **canonical** — the destructor's only handle (`this`), so it drives liveness and revocation |
| `RGWOp*` | `rgw_process_authenticated` | the identity RGW actually passes on the op data path |

Both keys map to a **byte-identical value**, so a seed through either produces a
context carrying the canonical `req_state_ptr` — which is what the `_send_op`
liveness gate re-derives and checks. No new map, no new key type.

**Reading the `RGWOp*`.** `rgw_process_authenticated`'s arg1 is `RGWOp*& op` — a
**reference to a pointer**, so the ABI register holds an `RGWOp**` and exactly
**one** `probe_read_user` of the pointee yields the `RGWOp*`
(`fetch_param_ptr_ref`). That is a read of a *pointee whose type DWARF proves*,
not a struct-field walk and not a dereference of an unknown `dpp`.

**And the identity is PROVEN, not assumed.** Native extraction emits the
descriptor only after verifying, in this build's DWARF, that:

1. the parameter's type chain really is `reference -> pointer -> RGWOp`; and
2. `RGWOp` inherits `DoutPrefixProvider` **directly, at offset 0** — i.e. that
   `(DoutPrefixProvider*)op == (void*)op`, so the pointer we read *is* the `dpp`
   RGW passes.

The same check runs for `req_state` (which §9.2 had verified only by hand, on two
builds), and it **gates the whole per-submit re-seed**: if a build's DWARF cannot
prove `req_state`'s base is at offset 0, the operate probes are not extracted and
not attached. Fail closed, loudly, rather than key the bridge on a pointer that is
off by a constant. An indirect or virtual `DoutPrefixProvider` base likewise
yields no proof and no key.

**Why `rgw_process_authenticated` is the only site for this.** The `RGWOp` is
created by `handler->get_op()` — a **return value**, and return probes are
forbidden here (a `process_request` uretprobe crashed RGW: asio switches fiber
stacks under the probe). `rgw_process_authenticated` is the first frame that takes
the constructed op as a **parameter**, and it runs *before* `op->execute()`, so
the key is in place before the op submits anything.

**Revocation (and why it is TOTAL).** The destructor knows only the `req_state*`,
so to revoke the alternate key it must first learn what that key *was*. The
obvious place to keep it — inside the canonical bridge value (`rgw_op_ptr`) — is
**not sufficient**, and this was a real defect: `rgw_ctx_by_reqstate` is an
`LRU_HASH`, and eviction is *per entry*. Evict a request's **canonical** entry
while its **alternate** entry survives, and the destructor's canonical lookup
misses, it returns early, and the alternate key it never learned about is
**stranded for the rest of the run**. The liveness gate still refuses to stamp
from such an orphan (it re-derives the canonical key, which is gone), so it was
never a mis-correlation — but it made the "every inserted key is revoked"
invariant and the `inserts - revokes` health metric **false as written**, which is
its own kind of bug: a metric that cannot detect the leak it exists to detect.

The alternate key is therefore recorded in **`rgw_op_keys`**: a **plain HASH**
(never evicts), keyed by the request's canonical key, carrying the alternate key
plus the owner's identity. It is written **before** the alternate key is inserted;
if it cannot be written (map full) the alternate key is **not inserted at all**
(`RGWTRACE_DIAG_RGWOP_KEY_INDEX_DROPS` — fail closed: never create a key nobody
can revoke); and if the key insert then fails, the record is deleted again. The
destructor reads the record **unconditionally**, including when the canonical
entry is gone. The invariant is now exact and checkable:

```
RGWOP_KEY_INSERTS == RGWOP_KEY_REVOKES          (deleted: still this request's)
                   + RGWOP_KEY_REVOKE_SKIPPED   (already re-keyed by a NEWER live request)
                   + RGWOP_KEY_REVOKE_ABSENT    (already gone: LRU-evicted)
                   + alternate keys of requests still in flight
```

The alternate entry is deleted only while it still *describes this request*
(`start_ns`/`tid`/`pid` match the record): a newer request may already have
re-keyed that recycled address to itself, and deleting then would revoke a **live**
request's key.

**Residual identity risk (honest).** Some dpps remain unkeyable — a
stack-constructed `DoutPrefix` / `DoutPrefixPipe` wrapper has no identity we can
capture at any probeable site. Submits made under one of those are **misses**:
uncorrelated, never mis-correlated.

**The one hazard pointer identity cannot close: the S3-website retarget.** If a
handler *retargets* the op (`RGWHandler_REST_S3Website::retarget`), the `RGWOp*`
read at `rgw_process_authenticated` entry is the *pre-retarget* op; RGW can free it
**while the request is still alive**. A different `DoutPrefixProvider`-derived heap
object allocated at exactly that address, passed as a `dpp`, would then hit the
stale alternate key and be seeded as this request — and the liveness gate
**passes**, because the request genuinely *is* alive. That is a true
mis-correlation, and no amount of further pointer-identity logic can fix it: the
pointer *is* the identity, and the identity has been recycled under us.

**So it is settled by measurement, not by more code.** The `RGWOp*` key exists
**only as insurance** in case RGW does not pass the `req_state` as the `dpp` at the
`rgw_rados_operate` call sites. If the `req_state*` key alone gets the hits on a
real rig, the alternate key is **deleted** and this hazard disappears entirely. To
answer that:

* seed hits are counted **by which key matched** —
  `RGWTRACE_DIAG_OPERATE_SEED_HITS_REQSTATE` vs
  `RGWTRACE_DIAG_OPERATE_SEED_HITS_RGWOP` (attribution is exact: the `dpp` is
  compared against the bridged value's own two keys, exactly one of which can
  match; `..._UNATTRIBUTED` must stay 0);
* the alternate key is **independently disableable at runtime** — the
  `RGW_OP_BRIDGE_KEY_ENABLED` BPF global, driven by `--disable-rgw-op-bridge-key`,
  published before the probe that writes the key attaches — so it can be dropped
  without a rebuild once the data says it is unnecessary;
* it defaults **ON**, because the whole point is to find out whether it fires.

The decision rule is in `RUNBOOK.md`: **if `bpf_operate_seed_hits_reqstate` is
healthy and `bpf_operate_seed_hits_rgwop` is ~0, disable the `RGWOp` key — it buys
nothing and carries the website-retarget mis-correlation risk.** Until that
measurement exists, the key stays (removing it on a hunch would silently cost the
entire op data path if RGW does pass the `RGWOp`).

### 10.2 A foreign-dpp MISS must fail closed (supersedes §9.5)

The `_send_op` liveness gate proves the cached request **still exists**. It does
**not** prove that request is the coroutine *currently executing on this thread*.
Those are different claims, and Phase B made the gap dangerous:

```
1. Request A runs an operate on pool thread T   -> A's ctx seeded on T
2. A yields (parks awaiting the RADOS completion)
3. Request B resumes on T, submits under an unkeyable dpp -> MISS
4. old rule: leave T's ctx alone -> A's ctx still on T
5. A is ALIVE, so the liveness gate PASSES it
6. B's op is stamped with A's trans_id.        <- MIS-CORRELATION
```

Phase B **amplifies** this: before it, only one or two threads ever carried A's
context; now every thread A ever ran an operate on does.

**Fix: on a miss, clear the SEEDED context on `rgw_requests[tid]`.** Nothing this
submit did not prove is assumed *about a copy Phase B itself put there*.
The op comes out uncorrelated.

> **SCOPE CORRECTION (§11).** As first shipped this clear was **unscoped** — it
> dropped *whatever* context was on the thread — and that regressed a live
> ListObjects request by 16 ops. The clear now applies **only to SEEDED contexts**
> (`ctx->tid != current tid`); a **HOME** context (`ctx->tid == current tid`, i.e.
> one `get_handler` placed on its own request's thread) is **preserved**. Read §11
> before touching `operate_drop_seeded_ctx`.

**Cost, honestly.** A request's *own* operate through an unkeyable wrapper dpp, on
a **migrated** thread, loses correlation. Counted in
`RGWTRACE_DIAG_OPERATE_MISS_CTX_CLEARED`. The multi-key bridge (§10.1) is what
keeps the cost small: a request's own operates now hit under its `req_state*`
**or** its `RGWOp*`, so the misses that remain are overwhelmingly genuine
background/wrapper dpps.

**Rejected: a "current-coroutine identity" check.** The obvious candidate is the
**stack pointer**: asio coroutines run on their own fiber stacks, and a request's
`req_state` lives on its coroutine's stack, so `req_state_ptr - SP` within some
window would say "the running coroutine is this request's". It is **unsound**:
fiber stacks are pool-allocated and can be adjacent, so a *neighbouring*
coroutine's shallow SP can fall inside any window wide enough to admit a deep
call chain of the *right* coroutine. A too-wide window produces false ACCEPTS —
mis-correlation, the exact thing we are eliminating — and the window size depends
on an unprovable stack-size constant. Rejected on the "do not invent something you
cannot prove" rule.

### 10.3 Phase B requires the END probe (gating)

`request_ctx_is_live` accepts **every** context when the END probe is absent — and
with no END probe **nothing deletes bridge entries**. A bridge nobody revokes
cannot answer "is this dpp a *live* request?": entries survive request
destruction indefinitely, so a recycled `req_state` (stack) or `RGWOp` (heap)
address, or a numerically-matching foreign dpp, HITS a long-dead request's entry
and its `trans_id` is stamped onto a live submit, with the gate failing *open*.

**Fix.** The operate probes are attached **only when the END probe actually
attached** (the real attach outcome, not the intent). Otherwise Phase B degrades
to Phase A, loudly, and `preflight`'s `cross_thread_operate_probe` check reports
the same. Two mechanisms, one gate, no silent half-state.

### 10.4 Capacity of a multi-keyed LRU on many-core hosts

Multi-keying means **2 entries per in-flight request**, not 1. `rgw_ctx_by_reqstate`
is therefore **131072** (was 65536) — the doubling exactly offsets the extra key,
so the *per-request* headroom is unchanged.

The binding constraint is not request rate but **CPU count**: BPF's `LRU_HASH`
reserves ~128 free nodes per CPU that touches the map, and a map whose capacity
those reservations approach evicts **live** entries (the regression that forced
`rados_ops` / `rgw_requests` back to plain `HASH`).

| CPUs | freelist reservation | usable entries | in-flight requests (2 keys each) |
|---|---|---|---|
| 64 | 8192 | 122880 | 61440 |
| 128 | 16384 | 114688 | 57344 |
| 256 | 32768 | 98304 | 49152 |

Insert rate is still bounded by *requests*, not op volume (a lookup never
inserts), and both keys are deleted at the destructor, so the map self-drains.
`rgw_requests` and `rados_ops` remain plain `HASH`.

### 10.5 `req_state_ptr == 0` is not proof of life

A context whose `req_state_ptr` is 0 was never bridged (`get_handler` could not
resolve the pointer from a register on that build). It can never be *found*
through the bridge — so the destructor's lookup misses and returns **before**
clearing it off the thread — and it therefore lingers on a pooled thread for the
rest of the run, ready to stamp a later op with a long-dead request's identity.

With the END probe attached it now **fails closed**
(`RGWTRACE_DIAG_SENDOP_UNBRIDGED_CTX_DROPS`), and attach warns explicitly, because
a build in this state correlates **nothing** and must not merely look like an idle
gateway. The fail-open path survives only for the no-END-probe build, where
nothing can revoke anything and the gate is switched off wholesale — there, a
context can only have been put on this thread by `get_handler` itself.

### 10.6 Attach ORDER: a bridge entry must never exist before its revoker

`get_handler` attached **before** the destructor probe, and
`REQUEST_END_PROBE_ATTACHED` was published only after *every* probe was up. Both
are ordering bugs with the same consequence.

A request could pass `get_handler` — creating its canonical bridge entry — and
then **run to completion before its destructor probe existed**. Nothing would ever
delete that entry. It would sit in `rgw_ctx_by_reqstate` for the rest of the run,
and the moment the flag flipped to 1 it would begin **passing** the `_send_op`
liveness gate's identity check: the entry and any surviving context copy came from
the same (dead) request, so their `start_ns`/`tid` match by construction. A later
`_send_op` on such a thread — or any per-submit seed that hit that entry — would
stamp a **dead request's `trans_id`** onto a live op. Permanently, and with no
counter registering anything unusual.

**Fix.** The attach sequence is now data (`ATTACH_ORDER` in `src/live/linux.rs`),
the attach loop is driven by it, and `validate_attach_order` runs **before any
probe is attached** and refuses an order in which a bridge producer or consumer
precedes the revoker or the config that gates it:

```
RequestEndProbe        the ONLY revoker of a bridge entry
PublishBpfConfig       REQUEST_END_PROBE_ATTACHED, RGW_OP_BRIDGE_KEY_ENABLED
GetHandler             creates canonical entries
ProcessAuthenticated   creates alternate entries; consumes the bridge
RadosOperate           consumes the bridge (Phase B)
ObjecterOps            consumes the seeded thread context (stamps the trans_id)
```

Every entry that can ever exist is therefore created with its revoker already
live. (Detach order does not matter: the maps die with the program.)

### 10.7 An UNRESOLVED dpp fails closed exactly like a foreign one

§10.2 established that a foreign-dpp **miss** must clear the submitting thread's
context. The zero/unresolved-dpp path did **not**: it returned early, leaving the
context in place.

That asymmetry was a mis-correlation source, not a coverage choice. If thread `T`
carries live request `A`'s context and a submit arrives with a NULL or
unresolvable `dpp`, `A`'s context survives; `A` is genuinely still **alive**, so
the liveness gate **passes** it; and the op — which may belong to a completely
different coroutine now running on `T` — is stamped as `A`. An unresolved `dpp`
proves *exactly as little* as a foreign one.

Both now clear (`operate_drop_seeded_ctx`) — and both clear a **SEEDED** context
only, leaving a **HOME** one alone (§11). The clear is counted **separately** —
`RGWTRACE_DIAG_OPERATE_UNRESOLVED_CTX_CLEARED` vs `..._MISS_CTX_CLEARED` — because
the two say completely different things: a foreign-dpp miss is the expected steady
state on a busy gateway, while an unresolved `dpp` means either that RGW passes
null dpps on this path or that this build's descriptor is broken (in which case
correlation is dead and must not look merely quiet).

### 10.8 The offset-0 proof must bind to a TYPE, not to a NAME

The `RGWOp*`/`req_state*` bridge keys are legitimate only because
`(DoutPrefixProvider*)p == (void*)p`, i.e. because those types inherit
`DoutPrefixProvider` **directly, at offset 0**. Extraction verifies that in DWARF
per build (§10.1) — but it resolved a *declaration* DIE to its definition by
searching every unit and accepting the **first class/struct with a matching
UNQUALIFIED name**.

So `namespace x { struct RGWOp : public DoutPrefixProvider { ... }; }` — an
unrelated type that merely shares a name — could supply the offset-0 "proof" for
`::RGWOp`. A proof the wrong type can satisfy is not a proof, and the thing it was
supposed to justify (treating the pointer we read as the `dpp` RGW passes) was
therefore unjustified.

**Fix.** Type identity is now the **fully-qualified DWARF path** (the enclosing
namespace/class scope chain plus the name), for the derived class *and* for the
`DoutPrefixProvider` base. `::RGWOp` and `x::RGWOp` have different paths and can
never be confused. A declaration whose definition cannot be found under the *same*
qualified path yields no proof, no key, and no probe — including the
`DW_AT_signature`/`.debug_types` case, which is not in the CU index. Fail closed.

The regression test is a two-TU fixture in which the real `::RGWOp` is only
*declared* in the CU that contains `rgw_process_authenticated` (so the definition
must be resolved across units — the vulnerable path), a decoy
`namespace decoy { struct RGWOp : DoutPrefixProvider }` is *defined* in that same
CU (so an unqualified search finds it **first**), and the real `::RGWOp` has its
`DoutPrefixProvider` base at a **non-zero** offset. Unqualified binding accepts the
decoy's 0 and emits the key; qualified binding reads the real type's non-zero
offset and refuses it. A control fixture — identical, but with the real `::RGWOp`
at offset 0 — proves the resolver still finds the right type across units, so the
refusal above is a *decision*, not a failure to look.

### 10.9 The counters that prove it works must reach the channel used to validate it

The run summary has three sinks: the JSON document, the end-of-run log, and the
OTLP resource attributes. Only the JSON one was free (serde); the other two were
**hand-curated lists**, and the OTLP list had rotted. It omitted
`bpf_operate_seed_*`, `bpf_operate_miss_ctx_cleared`, `bpf_rgw_op_key_*`,
`bpf_sendop_unbridged_ctx_drops` and `emitted_request_keys` — that is, **every
counter that says whether the cross-thread bridge is working**.

`--output otlp` never prints the JSON document. A live validation run on a real
Ceph rig therefore could not tell a **working** Phase B from an **inert** one:
seeds hitting nothing and seeds never attempted look identical in the span data.
The counters that exist to prove the feature works were exactly the ones missing
from the only channel available to check it.

**Fix.** All three sinks are generated from one function —
`TraceDiagnostics::counters()`, derived from the struct's own serde representation
— so a counter added to the struct reaches every output automatically and a
curated list cannot fall behind again. `every_diagnostics_field_reaches_every_
output_path` is the tripwire, and it fails if any field of `TraceDiagnostics` is
missing from the JSON, the log summary, or the OTLP resource.

## 11. The fail-closed clear must be SCOPED — the ListObjects regression

**[MEASURED]** on the live rig, re-running the same four S3 calls against the
Phase B build. Phase B worked: ListObjects gained 3 new `cross_thread` metadata
ops. It also **LOST all 16** of its `call(rgw.bucket_list)` shard ops, which the
PR#4 baseline had correlated as `same_thread` children. They came out as
standalone `rgw.background.rados_op` with `rgw.correlation_reason =
missing_trans_id`. **Net context LOSS for that request.**

The counters name the culprit exactly:

```
bpf_operate_seed_hits              = 10   (reqstate = 1, rgwop = 9)
bpf_operate_miss_ctx_cleared       =  1   <-- ONE clear
bpf_operate_unresolved_ctx_cleared =  0
bpf_sendop_stale_ctx_drops         =  0   (not the liveness gate)
bpf_sendop_unbridged_ctx_drops     =  0   (not a missing req_state*)
```

One clear. Sixteen lost ops.

### 11.1 Why one clear cost sixteen ops

RGW does **not** issue a sharded bucket listing through `rgw_rados_operate`. It
goes through cls_rgw's **AIO** path:

```
RGWListBucket::execute -> RGWRados::Bucket::List::list_objects
  -> cls_bucket_list_ordered -> CLSRGWIssueBucketList
     -> IoCtx::aio_operate -> Objecter::op_submit -> _send_op   [ONE PER SHARD]
```

`rgw_rados_operate` is never on that stack. So those 16 submits were **never**
correlated by Phase B at all — they were correlated in the PR#4 baseline purely
because `uprobe_rgw_get_handler` seeded `rgw_requests[T]` on the request's own
thread `T` and **nothing ever cleared it**.

The unscoped fail-closed clear changed that. A single `rgw_rados_operate` with a
foreign `dpp` (a stack `DoutPrefix` wrapper) running on that same thread `T` wiped
`rgw_requests[T]`, and every one of the 16 later AIO submits on `T` then found no
context:

```
get_handler(T)           -> rgw_requests[T] = ctx(A)      [HOME: ctx.tid == T]
rgw_rados_operate(T, foreign dpp) -> MISS -> DELETE rgw_requests[T]   <-- the bug
_send_op(T) x16          -> no context -> background, missing_trans_id
```

The blast radius is the point: the clear did not merely drop the op it fired on —
it **stranded every later submit on that thread**, on a submit path the clear
cannot even see.

And the clear bought **no soundness** on that path. An AIO submit with no preceding
operate uses whatever context is on the thread regardless; clearing at the operate
probe cannot close a window belonging to a submit that never reaches the operate
probe. It was pure cost.

### 11.2 The fix: HOME vs SEEDED

Phase B manages **only the contexts it created**:

| | definition | who put it there | on an unproven submit |
|---|---|---|---|
| **HOME** | `ctx->tid == current tid` | `uprobe_rgw_get_handler`, for a request whose `get_handler` ran on **this** thread | **PRESERVED** |
| **SEEDED** | `ctx->tid != current tid` | a re-seed (Phase B, or `rgw_process_authenticated`) migrated a **copy** here | **CLEARED** |

`ctx->tid` is the get_handler thread and is copied **verbatim** by every seed —
nothing ever rewrites it (that is also what keeps the `cross_thread` label honest,
§9). So the test is **exact**, not a heuristic.

* **Clear a SEEDED context.** It is a Phase B artifact with no ownership claim on
  this thread, and leaving it is exactly the stale-copy hazard Phase B multiplies
  (§10.2). Unchanged.
* **Do NOT clear a HOME context.** That is the pre-existing PR#4 same-thread path.
  It is what correlates the 16 shards, and Phase B must never regress what already
  worked.

Implemented in `operate_drop_seeded_ctx` (`bpf/rgwtrace.bpf.c`), used by both the
foreign-dpp miss and the unresolved/null-dpp path.

**The two outcomes are counted distinctly**, so a live run shows how often each
happens:

| counter | meaning |
|---|---|
| `bpf_operate_miss_ctx_cleared` | a foreign-dpp miss cleared a **SEEDED** copy |
| `bpf_operate_unresolved_ctx_cleared` | an unresolved/null dpp cleared a **SEEDED** copy |
| `bpf_operate_miss_home_ctx_preserved` | a foreign-dpp miss left a **HOME** context alone |
| `bpf_operate_unresolved_home_ctx_preserved` | an unresolved/null dpp left a **HOME** context alone |

On the regressed run, the first counter was 1 and the third would have been 0. On a
healthy run the *preserved* counters are expected to be **nonzero** — that is the
same-thread path continuing to work.

### 11.3 ACCEPTED RESIDUAL HAZARD (pre-existing, bounded, not papered over)

Preserving a HOME context leaves one hazard open, and it is stated plainly here
rather than hidden:

> **Another coroutine that migrates onto request A's home thread `T` and submits
> through a path that never reaches `rgw_rados_operate` (i.e. the AIO path) will
> inherit A's `trans_id`.**

Properties of this hazard:

* It is **inherent to thread-keyed correlation on the non-operate submit path**. The
  submit in question never reaches the probe that could clear or re-seed the thread,
  so **no clear at `rgw_rados_operate` can close it** — including the unscoped one
  that caused the regression. Giving up the 16 shards bought nothing against it.
* It is **PRE-EXISTING**: it shipped in PR#4 and passed the zero-mis-correlation e2e
  gate. It is **not introduced by Phase B**. `the_home_thread_aio_hazard_is_pre_
  existing_and_not_introduced_by_phase_b` (`tests/crossthread_phase_b.rs`) asserts
  exactly that, by exercising the identical scenario **with Phase B not attached at
  all** and observing the identical outcome.
* It is **bounded by the liveness gate**: a *dead* request's home context can never
  stamp anything (`request_ctx_is_live` rejects it, counted in
  `bpf_sendop_stale_ctx_drops`). The hazard is confined to two **concurrently live**
  requests sharing one thread, where one of them submits via AIO after the other's
  coroutine has migrated in.
* Phase B does add one new *source* of the same class in the opposite direction: a
  seeded copy of request B, placed on A's home thread by B's own operate (B really
  *is* running there at that instant, so the seed is correct), overwrites A's home
  context — and A's next AIO submit on `T` would then be stamped as B. This is the
  same hazard with the roles swapped, and it has the same single cure.
* **The only real cure** is a submit-path identity that does not depend on the
  thread — e.g. probing the cls_rgw/AIO submit site itself with a keyable `dpp`, or
  a per-op identity threaded through the Objecter. Both are future work, out of scope
  here, and neither is achievable by tightening the operate probe.

The tool's contract is unchanged and honest: an uncorrelated op is a known unknown;
this hazard is the one *documented* place where a correlated op can be wrong, it is
inherited rather than introduced, and it is measured by the e2e mis-correlation gate
rather than assumed away.

### 11.4 The three test gaps that let this ship

The regression was invisible to a 283-test suite. Three gaps, all now closed:

1. **No test modeled a submit that BYPASSES `rgw_rados_operate`.** Every Phase B
   test drove its submits *through* the operate probe. The AIO path — a `_send_op`
   with **no** preceding operate on that thread — was never modeled, and that is
   precisely where the clear did its damage. `tests/crossthread_phase_b.rs` now has
   an `aio_submit()` that calls `send_op` with no operate, and uses it throughout.
2. **No COVERAGE-REGRESSION test.** Every assertion was *"new ops get correlated"* or
   *"no op gets mis-correlated"*. **None** asserted *"ops that were correlated before
   must STILL be correlated."* `a_list_objects_request_keeps_all_its_bucket_list_
   shards_across_a_foreign_operate` is that test: get_handler on `T`, a foreign-dpp
   operate on `T`, then N AIO submits on `T` with no intervening operate — all N must
   correlate as `same_thread` children. It **fails against the pre-fix code**.
3. **The e2e gate never covered multi-shard LIST.** It enforced GET→read and
   PUT→write correlation and zero mis-correlation, and *nothing* about a listing.
   `check_list_shard_correlation` (`tests/e2e/verify-rgwtrace-json.py`) now requires a
   ListObjects request to correlate its `rgw.bucket_list` shard ops — guarded so it is
   enforced only when the workload actually performed a LIST **and** the run observed
   ≥ 2 shard ops (the observable definition of a sharded bucket).
