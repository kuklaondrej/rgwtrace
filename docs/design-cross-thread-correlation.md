# Cross-thread RGW→RADOS correlation: the req_state-pointer bridge

**Status: REVISED per design review — pending Stage 0.**
Supersedes PR#2 (`rgw-rados-context-correlation`), which is not merged.

## 1. Problem statement & success criteria

Main correlates a RADOS op to a request only when `Objecter::_send_op` runs on
the *same Linux thread* that ran `RGWREST::get_handler` (context keyed by TID
in `rgw_requests`). In async beast RGW the request coroutine resumes on a
different worker between `get_handler` (frontend parse/dispatch) and op
execution, so data-path ops carry no `trans_id` and fall to
`background`/`inferred`.

**Success criteria (MicroCeph e2e, `tests/e2e/s3-workload.py`):**

- **≥90%** of direct GET/PUT **data-path** ops (rw=read for GET, write for
  PUT) carry same-request `trans_id`. Concurrent 4-thread: **≥80%**.
- **Zero mis-correlations**, enforced by the object↔request cross-check that
  lands *before* the bridge is enabled (design-review finding #3).
- **Baseline unregressed** *except two deliberately-updated tests* named in §6
  (finding #5): `same_thread` counter/semantics, slots 30/31,
  `_send_op`/`_finish_op` walks, two-value `duration_quality`, all other
  goldens.
- Missing DWARF/probe, reqstate miss, or stack-located params ⇒ degrade to
  main's behavior, **fail closed**, never mis-correlate.

## 2. Thread-hop analysis (assumptions marked — validated in Stage 0)

Data per site (BPF-verified in this repo; Ceph-internal = **[A]** to validate
in Stage 0):

- `get_handler(req_state* s,…)`: `req_state` ⇒ `trans_id` + `req_state`
  pointer (`= v`, the base register already fetched for slot 30, **iff
  register-located**). Frontend thread `T_h`.
- `_send_op(Op*)`: `(cid, op_tid)` (slots 0/1). Submit thread `T_s`. No
  `req_state`.
- `_finish_op(Op*)`: `(cid, op_tid)` (slots 20/21) — already
  thread-independent.

**[A1]** For the librados data path, `IoCtx::operate` is *synchronous* (blocks
the asio thread; `optional_yield` does not suspend). Thus **RGWOp::execute →
RGWRados/SAL → librados → op_submit → _send_op is contiguous on one thread
`T_s`.** The break vs main is *before* execute (accept/dispatch/auth yields):
`get_handler@T_h → … → execute@T_s`.

**[A2]** `rgw_process_authenticated(RGWHandler_REST*, RGWOp*&, RGWRequest*,
req_state* s, optional_yield, Driver*, bool)` exists, takes a **concrete
`req_state* s`** (same pointer value as `get_handler`'s `s`), is a
**non-virtual free function** entered **once per request immediately before
`op->execute()`**, on `T_s`.

**[A3]** At the function-entry PC (uprobes attach at entry), the `req_state*
s` parameter is in its ABI **register** (not yet spilled).
Stack-located-at-entry descriptors are unusable and skipped (finding #4).

If [A1]–[A3] hold, re-seeding at `rgw_process_authenticated` entry covers the
request's synchronous data ops. Executes that yield mid-way (large multipart)
are v1-out-of-scope (degrade). **Stage 0 measures all three plus the residual
mis-correlation rate (§5, finding #3).**

## 3. Chosen approach

A **`(tgid, req_state_ptr)`-keyed context map** populated at `get_handler`,
used to **fail-closed re-seed** the TID-keyed `rgw_requests` on the submit
thread. `_send_op` stays byte-for-byte unchanged. The bridge is **opt-in
behind `--correlate-cross-thread` (default OFF)** until the e2e gate passes on
the user's rig.

**Internal ctx struct change (no wire ABI change):** add `__u64
req_state_ptr;` to `struct rgw_request_ctx`. `emit_request_event` still copies
only the existing wire fields, so `rgwtrace_events.h`/`events.rs` are
untouched.

### Maps

- `rados_ops` — unchanged. LRU_HASH `(cid, op_tid)`. (This, not `Op*`, is
  main's robust send↔finish key.)
- `rgw_requests` — unchanged shape, now carries `req_state_ptr`; written at
  get_handler and (conditionally) at the re-seed site.
- **NEW `rgw_ctx_by_reqstate`** — LRU_HASH, key `struct reqstate_key { __u64
  req_state_ptr; __u32 tgid; __u32 _pad; }`, value `rgw_request_ctx`,
  `max_entries 8192`. **Keyed by PID** because `--pid` is optional
  (`src/cli.rs:60`) and `req_state*` can collide across address spaces
  (finding #2). (`rgw_requests` stays TID-keyed — kernel TIDs are globally
  unique, so no cross-process collision there.)

### Raw-pointer parameter descriptor (finding #4)

The BPF walker gives pointer semantics only from `fields[1]` and native
extraction rejects empty field paths (`dwarf_native.rs:523`), so a bare
`["s"]` cannot encode "the register holds the pointer." Explicit descriptor:

- **JSON / native:** `location` = the parameter's location evaluated **at the
  function low_pc (entry)**, which **must be a `DW_OP_regN` register**;
  `fields` = a single sentinel `[{"offset":0,"pointer":false}]` (satisfies the
  non-empty-path rule; ignored by the reader).
- **BPF helper:** `fetch_param_ptr(ctx, vf) = vf->varloc.stack ? 0 :
  fetch_register(ctx, vf->varloc.reg)`. Stack-located (post-prologue) ⇒ return
  0 ⇒ **skip + diagnostic + degrade**. Never touches `fetch_var_member_addr`
  (so no double-varloc risk).
- **get_handler reuse:** `req_state_ptr = v` **only when
  `!vf30->varloc.stack`**; else skip reqstate population + count
  `reqstate_base_unresolved`.

### Lifecycle (create / copy / clear — fail closed)

- `uprobe_rgw_get_handler` (edit): after the existing 30/31 walk, if
  `!vf30->varloc.stack` and `v>0`, set `request->req_state_ptr = v` and
  `bpf_map_update_elem(&rgw_ctx_by_reqstate, &{v,tgid}, request, BPF_ANY)`.
  **Overwrite-on-reuse is the aliasing cure.** Marker emission, slots 30/31,
  unchanged.
- `uprobe_rgw_process_authenticated` (**new**, base id **40**, one raw-pointer
  var_field): gated on `--correlate-cross-thread`.

  ```
  rsp = fetch_param_ptr(ctx, vf40);   if (!rsp) { count(reseed_base_unresolved); return; }
  ctx = lookup(rgw_ctx_by_reqstate, {rsp, tgid});
  if (ctx)      rgw_requests[tid] = *ctx;                    // hit: authoritative
  else {
     cur = lookup(rgw_requests, tid);
     if (cur && (cur->req_state_ptr != rsp || cur->pid != tgid))
                bpf_map_delete_elem(&rgw_requests, &tid);    // FAIL CLOSED: clear stale foreign ctx
     count(reseed_misses);
     // if cur is THIS request (same rsp+pid) we keep it → preserves same-thread baseline
  }
  ```

- `_send_op` — **unchanged**. `_finish_op` — unchanged.

**Why fail-closed, and why not the literal review fix.** Review finding #1 is
correct that a plain miss must not leave a foreign `trans_id` in place. But
the reviewer's literal remedy ("delete first, update only on hit") would
**regress main's same-thread path**: a genuinely same-thread request whose
reqstate entry is LRU-evicted between get_handler and re-seed would have its
*own fresh* context deleted. The `req_state_ptr`+`pid` identity check above
resolves both: a **foreign** lingering ctx (different req_state) is cleared
(fail closed, kills finding #1's interleave), while **this request's own** ctx
(matching req_state) is preserved (no baseline regression). Because the
re-seed lookup is a *hit* whenever get_handler populated the entry, the
keep-on-matching-miss branch only fires when we would keep our own data
anyway.

**Why race-free (hit path):** between `rgw_process_authenticated@T_s` and
`_send_op@T_s` there is no coroutine yield [A1], so `T_s` cannot be stolen and
`rgw_requests[T_s]` cannot be overwritten in-window. Overwrite each submit —
no TTL, no stack.

### Collector label — derived late (finding #6)

RADOS events can arrive before their marker, so `request.tid` is unknown at
ingest (`collector.rs:193-197`). At ingest, a non-empty `trans_id` now records
`RadosCorrelation::TransId` (thread-**unresolved**), incrementing only
`correlated_rados_ops`. At **render time in `request_spans`** (where the
marker's `tid` is known) resolve: `same_thread` if `op.send_tid ==
marker.tid`, else `cross_thread`; when the request has **no marker**
(rados_bounds reconstruction, no authoritative tid) retain `same_thread`
(preserves today's behavior; `cross_thread` requires marker evidence of a
distinct request thread). `Inferred` ops (empty trans_id, window-matched) are
untouched.

### DWARF requirements

Only additions: `rgw_process_authenticated`'s PC (`func2pc`) and its
`req_state*` **register-at-entry** location (one sentinel var_field). No
struct-member offsets anywhere.

### Slot/varid plan (30/31 sacrosanct)

`FUNCTION_BASE_IDS += ("rgw_process_authenticated", 40)`. `_send_op` 0–19,
`_finish_op` 20–29, `get_handler` 30/31 unchanged; new fn at 40. Append-only,
no remap. This deliberately changes get_handler's *reserved capacity* (see
§6/finding #5).

## 4. Why each PR#2 failure mode cannot recur

1. **Hardcoded offsets** — none. Only DWARF-derived: get_handler's reused base
   register and one register-at-entry `req_state*` location. No
   dpp/writer/aio/manifest walks, no `0x2f8` macros.
2. **Heap-pointer key aliasing** — `rados_ops` stays `(cid,op_tid)` (not a
   pointer). `rgw_ctx_by_reqstate` is pointer-keyed but **PID-scoped** and
   **overwritten by every request's get_handler before its re-seed**, so a
   reader sees the current occupant; freed-then-reused addresses are
   refreshed. Bridge consumers additionally **fail closed** on any identity
   mismatch. No `Op*` map (op_submit was thread-equivalent to `_send_op` —
   dropped).
3. **100ms TTL stack** — eliminated. Yield-free-window overwrite +
   identity-checked clear; no `expires_ns`, no depth, no cross-worker bleed
   via TTL.
4. **Remapped slots / `fetch_var_value` double-varloc** — 30/31 kept; new fn
   appended at 40; `fetch_register`+`fetch_var_member_addr` verbatim;
   `fetch_param_ptr` is a fresh, register-only helper that never composes
   varloc.

## 5. Failure-mode analysis (fail-closed semantics)

| Mode | Detection | Behavior |
|---|---|---|
| Re-seed **miss** with foreign lingering ctx (finding #1) | `reseed_misses` | ctx **cleared** (identity mismatch) ⇒ `_send_op` stamps nothing ⇒ background/inferred. **Fail closed, no mis-correlation.** |
| Re-seed miss, lingering ctx **is** this request (same-thread, entry evicted) | `reseed_misses` | ctx **kept** ⇒ same-thread op still correlated. **No baseline regression.** |
| **A1-false / lingering-context residual** (finding #3): re-seeded `rgw_requests[T_s]` persists after completion (no completion probe — banned); a *later non-request op* on `T_s`, or an op that reached submit via a hop that bypassed the re-seed site, stamps the stale `trans_id` | object↔request cross-check (Stage 2, runs first) | **Honest residual mis-correlation class.** Main *structurally has the same hazard* on frontend threads (get_handler seeds `T_h`, later ops on `T_h` inherit until the next get_handler). Bounded by: identity-checked clear on any *observed* re-seed, get_handler overwrite, and PID scoping. **Quantified as an explicit Stage 0 metric**; `--correlate-cross-thread` stays opt-in until zero-mis-correlation holds on the rig. |
| `req_state*` **stack-located at entry** / abstract_origin-only (LTO) | `reseed_base_unresolved`, hits==0 | var_field skipped ⇒ bridge inert ⇒ **baseline**. Mitigate via cephtrace JSON or Stage 5 extractor fix. |
| `rgw_process_authenticated` absent/inlined/renamed (version skew) | preflight advisory; hits==0 | probe unattached ⇒ baseline. |
| `rgw_ctx_by_reqstate` full / LRU evicts live entry | `reseed_misses`++ | miss path (clear-if-foreign) ⇒ background/inferred. Safe. |
| Cross-process `req_state*` collision (finding #2) | — | prevented by `(tgid, req_state_ptr)` key. |
| Address reuse + evicted reqstate + same-thread linger (same reused addr) | — | vanishingly rare; requires a *miss* (get_handler always overwrites the reqstate entry on reuse, so live requests hit). Documented residual. |
| Verifier rejection | `scripts/verify-bpf-load.sh` | handler = 2 lookups + 1 update/delete, no loops ⇒ passes. |

## 6. Staged implementation plan (reordered per finding #3; each landable, verify.sh green)

- **Stage 0 — validate [A1]–[A3] + residual on MicroCeph (user-run).**
  `bpftrace` harness: on `rgw_process_authenticated` record
  `@rs[tid]=arg3,@t[tid]=nsecs`; on `get_handler` record its `req_state` arg;
  on `_send_op` print `tid` + recent-seed status. Run `s3-workload.py` GET/PUT
  and `--concurrent-requests 4`. **Measure:** (a) data-path `_send_op` tid vs
  recent `process_authenticated` tid (coverage ceiling); (b)
  `get_handler.req_state == process_authenticated.req_state` per request; (c)
  tid changes site→`_send_op` ([A1]); (d) param register at entry ([A3]); (e)
  **fraction of `_send_op` on a `T_s` carrying a *stale, foreign* seeded
  context** (the finding-#3 residual). **Needs the user's environment** (root,
  live RGW). Gate coverage ≥ target and residual ≈ 0 before Stage 3.
- **Stage 1 — reqstate map + get_handler population.** Add `req_state_ptr` to
  ctx, the PID-keyed `rgw_ctx_by_reqstate`, `fetch_param_ptr`, and the guarded
  get_handler write. Map unread ⇒ no behavior change. Verify:
  `tests/bpf_source.rs` asserts map/handler exist.
- **Stage 2 — e2e zero-mis-correlation cross-check on BASELINE (was Stage 4).**
  Port PR#2's object↔request cross-check + concurrent workload +
  `--require-get-read-correlation`/`--require-put-write-correlation`, landed
  against current main behavior. **This establishes the gate before any
  cross-thread stamping exists.**
- **Stage 3 — re-seed probe behind `--correlate-cross-thread` (default OFF).**
  Add base 40, native+JSON extraction of the register-at-entry `req_state*`,
  advisory preflight, the fail-closed handler, and diagnostics
  (`reseed_hits`, `reseed_misses`, `reseed_base_unresolved`). Enable only
  after Stage 2's gate passes with the flag ON on the user's rig. Baseline
  (flag off) untouched.
- **Stage 4 — collector late-derived `cross_thread` label (was Stage 3).**
  `RadosCorrelation::TransId` at ingest; resolve `same_thread`/`cross_thread`
  in `request_spans`; add `cross_thread_correlations`; enforce
  `correlated_rados_ops == same_thread + cross_thread + inferred`; add
  `"cross_thread"` to `verify-rgwtrace-json.py` VALID sets; refresh goldens.
- **Stage 5 (optional/conditional).** If Stage 0/3 show unresolved LTO params,
  fix `dwarf_native.rs` to follow `DW_AT_abstract_origin` for
  variables/params.

**Deliberate test updates (finding #5 — not regressions):**

- `src/dwarf_json.rs:474` (`slot_capacities_match_base_id_gaps`): get_handler
  capacity changes from `8192-30` to `40-30 = 10`; add an assertion for the
  new fn's capacity `8192-40`.
- `tests/cli_dry_run.rs:29` (`hprobe_entries == 3`): the fixture gains the new
  fn's one var_field ⇒ update the expected count (→ 4 for a fixture that
  includes `rgw_process_authenticated`).

The no-regression claim in §1 is scoped to exclude exactly these two.

## 7. Rejected alternatives

- **PR#2 object-graph walking (hardcoded offsets)** — unsound,
  build/version-specific; the #1 failure.
- **`Op*`-keyed `objecter_ops` + op_submit probe** — redundant with
  `(cid,op_tid)`; op_submit is thread-equivalent to `_send_op`; adds pointer
  aliasing, no thread-independence.
- **Reviewer's literal "delete-then-update-on-hit-only"** — correct intent
  (fail closed) but regresses same-thread on eviction; superseded by the
  identity-checked clear.
- **dpp-keyed bridging via DWARF base-class offset** — DWARF-legal but needs
  base-subobject-offset extraction + MI fragility; fallback only if no
  `req_state*` site is yield-free.
- **TTL active-context stack** — arbitrary cross-worker bleed.
- **`process_request` return probe for scoping** — banned (crashes RGW).
- **Widening userspace inference only** — cannot disambiguate concurrent
  same-PID requests.
- **`correlation_source` u8 in the rados ABI** — unnecessary; `cross_thread`
  is derived late from `send_tid` vs marker `tid`.
