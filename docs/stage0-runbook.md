# Stage 0 runbook — cross-thread correlation measurement

This is the operator runbook for `scripts/stage0-crossthread-probe.sh`, the
**Stage 0** measurement harness for
[`docs/design-cross-thread-correlation.md`](./design-cross-thread-correlation.md).

Its job is to **empirically validate the design's assumptions [A1]–[A3] and the
residual mis-correlation rate on a live MicroCeph RGW before any bridge code
ships**. It attaches READ-ONLY bpftrace uprobes; it never writes to the RGW
process and changes no repository state.

Run this and get green (or understood) results **before** implementing Stage 1+.

---

## What it measures

| Metric | Question | Design gate |
|---|---|---|
| **(a) Coverage ceiling** | Fraction of `Objecter::_send_op` calls whose TID was seeded by a `rgw_process_authenticated` entry on the same TID within 1s. | **≥ 90%** single-stream, **≥ 80%** concurrent (design §1). |
| **(b) Key match** | Does the `req_state*` seen at `rgw_process_authenticated` equal a `req_state*` seen at `RGWREST::get_handler` (pointer equality, per request, within 1s)? | **~100%** ([A2] pointer identity). |
| **(c) [A1]** | Do `_send_op`s run on the same thread that ran `rgw_process_authenticated`? Reported as the unseeded (tid-hop-or-background) fraction. | Data-path unseeded fraction **≈ 0**. |
| **(d) [A3]** | Is the `req_state*` parameter register-located and holding a plausible heap pointer at entry? | **≥ 99%** plausible (with the limitation noted below). |
| **(e) Residual mis-correlation risk** | Fraction of seeded `_send_op` whose TID's most recent seed is stale (older than `STAGE0_STALE_MS`). Old seeds indicate lingering-context risk (design finding #3). | **≈ 0%**. |

The harness prints a `PASS` / `FAIL` / `WARN` / `INCONCLUSIVE` line per metric
against these gates.

---

## Prerequisites

- **Root** (uprobes need `CAP_BPF`/`CAP_PERFMON`; run with `sudo`).
- **`bpftrace`** installed. Any reasonably recent build works; the program uses
  only portable features (`uprobe`, `argN`, `tid`, `nsecs`, `interval`,
  `clear`, `delete`). Verified against the bpftrace 0.14+ syntax. Check with
  `bpftrace --version`.
- **`binutils`** on `PATH` (`nm`, `objdump`, `c++filt`) for symbol resolution.
- **Symbol table present on the RGW binaries.** The harness resolves the three
  C++ symbols from `.symtab`/`.dynsym` (via `nm`/`objdump -T`). MicroCeph's
  `radosgw` normally ships a usable symbol table. If a target symbol is not
  found the harness tells you exactly which one and suggests installing debug
  symbols or supplying the mangled name via an override env var. **Full DWARF is
  not required for Stage 0** — only the symbol names, since bpftrace reads the
  argument registers at entry itself.
- A running MicroCeph RGW (see `tests/e2e/functional-test-microceph-rgw.sh` for
  how the reference environment is stood up) and the S3 credentials it created.

The harness auto-discovers the `radosgw` PID, the `radosgw` executable, and
`libceph-common.so` using the same patterns as the e2e script (`pgrep -f
radosgw` → `/proc/<pid>/exe`, `/proc/<pid>/maps`, resolved through
`/proc/<pid>/root`). Override any of them if discovery is ambiguous (see
"Overrides").

---

## Running it

Two terminals, both on the RGW host.

### Terminal 1 — the probe

```sh
sudo ./scripts/stage0-crossthread-probe.sh
```

It prints the resolved mangled symbols, the **demangled signatures**, and the
**arg index it chose** for each `req_state*` — eyeball these (see "Verifying the
arg indices"). It then traces for `STAGE0_DURATION` seconds (default 60; Ctrl-C
also stops it and prints the summary). The generated bpftrace program and the
full log are written to `STAGE0_OUTDIR` (default `/tmp/rgwtrace-stage0/`).

To just resolve symbols and generate the program without attaching (e.g. on a
host without a live RGW):

```sh
STAGE0_DRY_RUN=1 ./scripts/stage0-crossthread-probe.sh
cat /tmp/rgwtrace-stage0/stage0.bt
```

### Terminal 2 — the workload

Use the same endpoint/keys the reference e2e uses (defaults from
`tests/e2e/functional-test-microceph-rgw.sh`: user `rgwtrace-e2e`, access key
`RGWTRACEACCESSKEY001`, secret `rgwtrace-secret-key-rgwtrace-secret-key`,
endpoint `http://127.0.0.1:8080`). Adjust to your cluster.

**Single-stream GET/PUT (the coverage-≥90% case):** the workload does a
deterministic PUT → HEAD → GET → LIST → COPY → multipart → deletes sequence.
Run it a few times back-to-back so the 60s window sees plenty of ops:

```sh
ENDPOINT=http://127.0.0.1:8080
AK=RGWTRACEACCESSKEY001
SK=rgwtrace-secret-key-rgwtrace-secret-key

for i in 1 2 3 4 5; do
  python3 tests/e2e/s3-workload.py \
    --endpoint "$ENDPOINT" --access-key "$AK" --secret-key "$SK" \
    --output "/tmp/stage0-workload-single-$i.jsonl"
done
```

**Concurrent (the coverage-≥80% case).** `s3-workload.py` supports concurrent
request streams natively via `--concurrent-requests` (added with the Stage 2
e2e gate):

```sh
python3 tests/e2e/s3-workload.py \
  --endpoint "$ENDPOINT" --access-key "$AK" --secret-key "$SK" \
  --concurrent-requests 4 --unique-keys \
  --output "/tmp/stage0-workload-concurrent.jsonl" \
  --manifest "/tmp/stage0-manifest-concurrent.json"
```

(`--unique-keys` and `--manifest` are not needed for the Stage 0 metrics
themselves, but capturing the manifest lets you reuse the same run for the
Stage 2 object↔request cross-check via
`verify-rgwtrace-json.py --workload-manifest`.)

Run the single-stream and concurrent passes as **separate probe runs** (restart
Terminal 1 for each) so metric (a) is attributable to one load shape. For the
concurrent pass, judge coverage against the 80% gate, not 90%.

### Output to capture

- The full probe log: `/tmp/rgwtrace-stage0/stage0.log` (contains the resolved
  symbols, chosen arg indices, and the `STAGE 0 SUMMARY` block).
- The generated program: `/tmp/rgwtrace-stage0/stage0.bt`.
- The workload JSONL files (they record `x_amz_request_id` per op).

---

## Verifying the arg indices (do this every run)

bpftrace reads `req_state*` from an ABI **argument register at function entry**.
The correct register depends on the function signature, so the harness derives
the arg index from the **demangled signature** and prints it:

- `RGWREST::get_handler(...)` is a **non-static member**, so bpftrace `arg0` is
  `this`; `req_state*` is expected at **`arg2`** (source parameter #1 + 1).
- `rgw_process_authenticated(...)` is a **free function**, so `req_state* s` is
  the **4th parameter = `arg3`** (0-based), matching the design's assumption.

The harness **parses the demangled signature, finds the `req_state` parameter,
and warns if the derived arg index differs from these expectations** — for
example if a version-skewed build reorders parameters or inlines a wrapper.
**Read the `resolved …` / `using bpftrace argN` lines and confirm the demangled
signature looks right.** If the derivation is wrong for your build, override it:

```sh
sudo RGW_PROC_AUTH_ARG=4 RGW_GET_HANDLER_ARG=2 ./scripts/stage0-crossthread-probe.sh
```

---

## Interpreting the results, and which assumption each failure kills

- **(a) coverage `FAIL` (< gate).** Too few data-path `_send_op`s land on a
  seeded TID. If the shortfall is genuinely on data-path ops (cross-check role
  with `rgwtrace`; see the caveat under (c)), this **kills the [A1]/[A2]
  coverage premise** — the re-seed at `rgw_process_authenticated` would not
  reach the request's ops, so the bridge cannot hit its §1 target. Do not
  proceed to Stage 3.

- **(b) key-match `FAIL/CHECK` (< ~100%).** The `req_state*` at
  `rgw_process_authenticated` is *not* the same pointer seen at `get_handler`.
  A few misses at trace start are expected (the request's `get_handler` ran
  before the probe attached). **Sustained** misses **kill [A2]** — the pointer
  is not a stable per-request identity, so the `(tgid, req_state_ptr)` context
  key is unsound. Stop.

- **(c) [A1] low seeded fraction / high unseeded.** `unseeded` counts
  `_send_op`s on a TID with no recent seed. It is a **superset** of true
  tid-hops: it also includes genuine background ops (GC, notify, sync, startup)
  that never flow through `rgw_process_authenticated`. So a nonzero unseeded
  fraction is **not by itself** an [A1] failure. The [A1]-killing signal is a
  high unseeded fraction **among data-path ops** — correlate with
  `rgw.rados_role = data` in a parallel `rgwtrace --output json` capture. If
  data-path ops routinely land on an unseeded TID, execute is **not** contiguous
  with submit on `T_s` and **[A1] is false**.

- **(d) [A3] `FAIL` (< 99% plausible).** Null / tiny / implausible `req_state*`
  values at entry mean the parameter is **not** sitting in its ABI register when
  the uprobe fires — **[A3] is at risk**. **Limitation to keep in mind:**
  bpftrace's `argN` *always* reads the ABI argument register regardless of what
  DWARF says. This check therefore confirms *non-null, heap-plausible* values;
  it does **not** prove DWARF marks the parameter register-located. A parameter
  already spilled to the stack at entry could still read an in-range (stack)
  pointer here and pass. **Confirm the DWARF location class separately** against
  rgwtrace's native extraction (the design's `fetch_param_ptr` returns 0 for
  `varloc.stack`; if that path fires in Stage 3 diagnostics —
  `reseed_base_unresolved` — [A3] is false for this build even if (d) looked
  green). Treat (d) as necessary-but-not-sufficient.

- **(e) residual `WARN` (> ~0%).** Some `_send_op`s fire on a TID whose most
  recent seed is stale (older than `STAGE0_STALE_MS`, default 50ms) — the
  finding-#3 lingering-context hazard: a later non-request op, or an op that
  reached submit via a path that bypassed the re-seed site, would inherit a
  stale `trans_id`. This is the **residual mis-correlation gate**. It must be
  **≈ 0** before `--correlate-cross-thread` is enabled. A nonzero `old>1s`
  bucket is the strongest warning sign. Note the same class exists on
  frontend threads in main today (design §5); the point is to quantify it.

- **Symbol not found.** `rgw_process_authenticated` absent → **[A2] is already
  dead** for this build (inlined/renamed/version skew); the whole approach
  degrades to baseline. `get_handler` / `_send_op` absent → binaries are
  stripped; install matching debug symbols or pass the mangled name override.

---

## Overrides (env vars)

| Var | Purpose |
|---|---|
| `RGW_PID` | radosgw PID to scope uprobes to (auto). `RGW_PID=0` = process-wide. |
| `RADOSGW_PATH` | radosgw executable (auto). |
| `LIBCEPH_COMMON_PATH` | `libceph-common.so.*` (auto). |
| `STAGE0_DURATION` | run seconds (default 60). |
| `STAGE0_STALE_MS` | stale-seed threshold for metric (e), ms (default 50). |
| `STAGE0_OUTDIR` | output dir (default `/tmp/rgwtrace-stage0`). |
| `RGW_GET_HANDLER_SYM` / `RGW_PROC_AUTH_SYM` / `RGW_SEND_OP_SYM` | override the mangled symbol (skip discovery). |
| `RGW_GET_HANDLER_ARG` / `RGW_PROC_AUTH_ARG` | override the derived `argN` index. |
| `STAGE0_COVERAGE_GATE` / `STAGE0_KEYMATCH_GATE` / `STAGE0_A3_GATE` | PASS thresholds (default 90 / 99 / 99). Set coverage to 80 for the concurrent pass. |
| `STAGE0_DRY_RUN=1` | resolve + generate only; do not attach. |

---

## Safety notes

- All probes are **uprobes that only read** argument registers and (implicitly,
  via bpftrace) nothing in the target's writable memory. Nothing is written back
  to RGW.
- bpftrace maps are **bounded**: the `req_state`-keyed map is `clear`ed every 5s
  (the `get_handler`→`rgw_process_authenticated` gap is sub-second), and the
  per-TID maps are bounded by the RGW thread count.
- No kernel-version-fragile features are used, so the same program runs across
  MicroCeph kernels.
