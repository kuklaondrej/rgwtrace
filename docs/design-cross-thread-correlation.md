# Cross-thread RGW→RADOS correlation: design after live Stage 0

**Status: REVISED per Stage 0 (live-measured on quay.io/ceph/ceph:v18, 18.2.8,
beast). Recommendation: ship a bounded, fail-closed, opt-in bridge; STOP short
of full cross-thread correlation — it is not achievable on this async build
without reintroducing PR#2's failure class.**
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
  preserved). `_send_op` stays byte-for-byte unchanged.
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
| reqstate LRU eviction | `reseed_misses`++ | clear-if-foreign ⇒ background. |
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
