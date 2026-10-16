# Production Runbook

Operational notes for running `rgwtrace` against live RGW hosts.

[Documentation index](docs/README.md) · [Building and testing](docs/development.md)

---

## Requirements

- Linux host with eBPF and uprobes enabled.
- `root` or equivalent BPF/perf privileges. Running with `sudo` is the expected path today.
- The host pid namespace. In a container, start it with `--pid=host`. A `--pid` run from a nested pid namespace is refused, because the kernel's tgid would never match the namespace-local pid.
- `--pid <radosgw pid>` for every live run. The probes fire only in that process. `--all-processes` probes every process that maps the target libraries (OSDs, qemu/librbd, other gateways, CLI tools); all of them then pay the probe cost and share the ring buffer. Use it only on lab hosts.
- Ceph/RGW binaries with accessible native debug info, or matching `cephtrace` JSON fallback data.
- Reachable OTLP/HTTP or OTLP/HTTPS endpoint when using `--output otlp`.
- Linux `amd64` binary built with `./scripts/build-linux-container.sh` when building from macOS.

---

## Preflight

Run preflight before live attach:

```sh
sudo rgwtrace \
  --dwarf-source native \
  --pid "$(pidof radosgw | awk '{print $1}')" \
  --preflight
```

With `--pid`, libraries come from `/proc/<pid>/maps` and the executable from `/proc/<pid>/exe`, and every path is opened through `/proc/<pid>/root`, so the host attaches to the same file the target process sees inside its mount namespace. Symlinks inside the container are resolved inside the container root, never against the host root. If the process maps a file that was deleted or replaced on disk (for example after a package upgrade), discovery stops with an error; restart the daemon and run again. With `--pid`, discovery never falls back to a host path such as `/usr/bin/radosgw`.

Preflight, `--dry-run` and `--export-dwarf-json` attach nothing, so they do not require `--pid`.

Use explicit paths when discovery is ambiguous:

```sh
sudo rgwtrace \
  --dwarf-source native \
  --preflight \
  --librados-path /lib/librados.so.2 \
  --librbd-path /lib/librbd.so.1 \
  --libceph-common-path /usr/lib/ceph/libceph-common.so.2 \
  --radosgw-path /usr/bin/radosgw
```

Use `--import-json` when native debug info is unavailable or when comparing against the `cephtrace` oracle.

Validate an imported artifact without attaching probes:

```sh
rgwtrace --import-json /path/to/dwarf.json --dry-run --output json
```

If native mode cannot discover the Ceph version, add `--ceph-version <version>`. The major version selects the pre-Squid or Squid+ `ceph_osd_op` ABI layout. For a containerized RGW (targets under `/proc/<pid>/root`), rgwtrace never falls back to the host's `dpkg-query`/`rpm`, because the host package says nothing about the image. Without an embedded version string, extraction fails and asks for `--ceph-version`.

Native extraction refuses any file larger than `--max-debug-file-bytes` (default `4G`; accepts `K`/`M`/`G`/`T`), and refuses to decompress more than that from one file's compressed DWARF sections. This protects the node from a sparse or crafted debug file. Raise the limit only for a debug file that is genuinely larger:

```sh
sudo rgwtrace --dwarf-source native --pid <pid> --max-debug-file-bytes 8G --preflight
```

Build ID mismatches fail preflight and live attach by default. Use `--allow-build-id-mismatch` only when the mismatch is understood.

Preflight also validates every probe address against the target ELF and reports where each uprobe will attach. A probe address must be a function entry inside an executable `PT_LOAD`. It is attached at its **file offset**, which differs from the artifact's virtual address on non-PIE or lld-linked binaries:

```json
"probe_sites": [
  {
    "module": "radosgw",
    "path": "/proc/4242/root/usr/bin/radosgw",
    "function": "RGWREST::get_handler",
    "vaddr": 4198464,
    "file_offset": 4160,
    "evidence": "symbol"
  }
]
```

`evidence` is `symbol` (the target's own `.symtab`/`.dynsym`), `debug_symbol` (its verified separate debug file), or `dwarf_low_pc`. A stripped target with no matching debug info installed cannot prove any address that is not exported in `.dynsym`, and fails preflight. Install the debuginfo package for the exact running build on the node.

---

## JSON Smoke Test

Start with JSON output for a short run:

```sh
sudo rgwtrace \
  --dwarf-source native \
  --pid "$(pidof radosgw | awk '{print $1}')" \
  --timeout 30 \
  --output json
```

For fallback validation, rerun with `--import-json 18.2.8-1jammy_dwarf_traceid.json`.

Check `trace.diagnostics` for decoded events, RADOS op counts, correlation counts, truncation counters, decode errors, expired spans, and BPF-side drop/failure counters.

`--output json` holds the whole session in memory and prints one document at exit, so it is meant for **bounded runs** (`--timeout`). Its memory is capped by `--max-buffered-events` (default 100000 buffered request groups and RADOS ops, roughly 100 MB). When the cap is reached, the tracer warns once and drops new requests and ops, counted in `buffer_full_dropped_markers` and `buffer_full_dropped_rados_ops`. Without `--timeout` it warns at startup. A nonzero drop counter means the output is incomplete: shorten the window, or stream instead.

---

## Long Sessions: JSONL Streaming

For a session of any length, stream with `--output jsonl`:

```sh
sudo rgwtrace \
  --dwarf-source native \
  --pid "$(pidof radosgw | awk '{print $1}')" \
  --output jsonl \
  --flush-interval 30 \
  --correlation-ttl 120 > trace.jsonl 2> run.log
```

Every `--flush-interval` seconds, the requests and background ops that have expired are drained out of memory and written to stdout as one compact `{dwarf, trace}` line, flushed immediately. At exit, a final line carries whatever was still in flight and the final counters, even if it has no spans. Memory is bounded by request rate x (`--correlation-ttl` + flush interval), not by session length.

Each line's `trace.diagnostics` holds the **cumulative** counters at that moment, and `spans_produced` counts that line's spans only. So read the run totals from the **last** line, and count spans by summing lines. `tests/e2e/verify-rgwtrace-json.py --trace trace.jsonl` merges the lines before verifying (`--trace-format jsonl` to force it). `--max-buffered-events` is rejected with `jsonl` and `otlp`.

```sh
# Spans per drain, then the final totals.
jq -c '[.trace.diagnostics.spans_produced]' trace.jsonl
tail -n 1 trace.jsonl | jq '.trace.diagnostics | {rados_ops, correlated_rados_ops, tombstone_horizon_rejections}'
```

---

## Tempo Export

Check the OTLP endpoint from the RGW host first:

```sh
curl -v --max-time 5 http://tempo.example.net:4318/v1/traces
```

Run live OTLP export:

```sh
sudo rgwtrace \
  --import-json 18.2.8-1jammy_dwarf_traceid.json \
  --pid "$(pidof radosgw | awk '{print $1}')" \
  --output otlp \
  --otlp-endpoint https://tempo.example.net:4318/v1/traces \
  --service-name rgwtrace \
  --otlp-compression gzip \
  --otlp-max-spans-per-batch 512 \
  --otlp-flush-interval 30 \
  --correlation-ttl 120
```

Logging defaults to `info` so the `starting live tracing` / `finished live tracing` readiness lines are visible: native DWARF extraction can take ~30s+, and starting a workload before `starting live tracing` prints yields an empty trace that looks like a dead probe. Logs go to stderr, so stdout stays clean for JSON. If RADOS ops are captured but no RGW request markers, the run ends with a `no RGW request markers captured` warning pointing at exactly that timing mistake. Pass `--log-level warn` for quieter output or `RUST_LOG=rgwtrace=debug` to also see export queue summaries, export attempts, and retry details.

Use `--otlp-max-bytes-per-batch` when a collector or proxy rejects large protobuf payloads. The byte limit is checked before gzip compression; `0` disables byte-based splitting.

The exporter sends OTLP/HTTP protobuf (`Content-Type: application/x-protobuf`)
over HTTP or HTTPS. `--service-name` sets the `service.name` resource attribute.
Use `--otlp-timeout` and `--otlp-retries` to tune delivery.

### Request headers and credentials

**Do not put secrets on argv.** `--otlp-header 'Name:Value'` is visible to every
local user through `/proc/<pid>/cmdline` and `ps`; use it for non-secret headers
(a tenant id such as `X-Scope-OrgID`) only. Credentials go in one of the two
sources that are not on the command line:

```sh
# A header file: one `Name: Value` per line, `#` comments, blank lines ignored.
# Refused if world-readable -- chmod 600 (or 640 for a group) first.
sudo install -m 600 /dev/null /etc/rgwtrace/otlp-headers
printf 'X-Api-Key: %s\n' "$API_KEY" | sudo tee /etc/rgwtrace/otlp-headers >/dev/null
sudo rgwtrace ... --output otlp --otlp-header-file /etc/rgwtrace/otlp-headers

# Or the OpenTelemetry environment variable: `k=v,k2=v2`, percent-encoded.
# OTEL_EXPORTER_OTLP_TRACES_HEADERS, if set, replaces it (not merged), per the spec.
sudo OTEL_EXPORTER_OTLP_HEADERS="X-Api-Key=$API_KEY" rgwtrace ... --output otlp
```

The three sources are merged by header name (case-insensitive); for a name
present in more than one, **file > environment > `--otlp-header`**, the inverse
of how exposed each source is. A parse or permission error names the source,
the line or entry number and the header name, never a value. Header values are
never logged at any log level.

Credentials in the endpoint URL (`https://user:pass@...` or `?api-key=...`)
work but are discouraged for the same argv reason; the URL is logged with its
userinfo and query string removed, and error messages are scrubbed the same way.

### TLS and private CAs

```sh
--otlp-endpoint https://tempo.internal:4318/v1/traces --otlp-ca-cert /etc/ssl/internal-ca.pem
```

`--otlp-ca-cert` adds a PEM bundle of root certificates to trust alongside the
bundled web roots, so a collector behind an internal PKI no longer needs plain
`http://`. The file is read and validated at startup; a missing or non-PEM file
fails before DWARF loading.

**Redirects are never followed.** A `3xx` from the endpoint is a fatal export
error: following it would re-send the headers (credentials) and the trace body
to whatever host `Location` names, possibly from https down to http. Point
`--otlp-endpoint` at the final URL.

### The default endpoint is plaintext

The default `--otlp-endpoint` is `http://localhost:4318/v1/traces`: fine for a
collector on the same host, but anything crossing a network should use
`https://`. Traces carry `ceph.rados.object` values, which are S3 object keys,
`<uid>.buckets` user names, tenant names and (for `AuthMeta` objects) access-key
ids. If those must not reach the backend at all, pass **`--redact-object-names`**:
every `ceph.rados.object` becomes the FNV-1a 64 hash of the name (16 hex
digits), the span carries `rgwtrace.redacted = "ceph.rados.object"`, and
`rgw.rados_role` is still classified from the raw name on the host. The hash is
stable, so one object's ops still group together and can be joined with a hash
computed elsewhere; it applies to JSON and OTLP output alike. The
[end-to-end object correlation gate](#end-to-end-objectrequest-correlation-gate)
matches raw S3 keys, so do not combine it with this flag.

In live OTLP mode, `--otlp-flush-interval` (alias `--flush-interval`) controls how often eligible spans are
queued for the background exporter. `--correlation-ttl` governs retention of
correlation state; open requests awaiting an END marker have a separate lifetime
backstop, and requests whose END marker arrived are exported after
`--closed-request-grace` (default 5 s; capped at the TTL). `--inference-window`
governs optional inferred correlation and is independent of the retention
setting; `--inference-max-pending` (default 65536) caps the untagged ops waiting
for an inference decision. See `rgwtrace --help` for all options and
defaults.

A batch that cannot be delivered does not stop the exporter. A non-retryable
response (4xx other than 429) loses that batch and the next batch is tried.
Exhausted retries lose that batch and the rest of the same drain. Either way the
loss is counted in `otlp_export_failed_batches` / `otlp_export_failed_spans`,
a warning is logged, and the next drain is exported normally, so the tracer
recovers on its own when the endpoint does. A nonzero `otlp_export_failed_spans`
means those spans are gone: fix the endpoint (check the logged status), or use
`--output jsonl` when the backend is unreliable. The final export still dumps
the end-of-run trace to stdout if it fails. `otlp_queue_dropped_*` is a
different loss: drains dropped because the exporter fell two drains behind.

---

## Common Preflight Failures

- `--pid must be a positive process id`: pass a single live RGW PID.
- `live tracing requires --pid <radosgw pid>`: pass the RGW PID. Pass `--all-processes` only if you intend to probe every process on the host.
- `the argument '--pid <PID>' cannot be used with '--all-processes'`: pass one or the other.
- `rgwtrace is running in a nested pid namespace`: run the tracer in the host pid namespace (`docker run --pid=host`).
- `... mapped by pid N (...) was deleted or replaced on disk` or `the radosgw executable of pid N (...) was deleted or replaced on disk`: the daemon still runs the old file after an upgrade. Restart it, then trace again. Probing the new file would capture nothing.
- `pid N runs <exe>, not radosgw`: pass the radosgw PID, or `--radosgw-path` if the binary has another name.
- `too many symlink levels resolving ...` or `... resolved to ..., outside /proc/<pid>/root`: the container image has a symlink loop or a path that cannot be resolved inside its root. Pass explicit `--*-path` flags.
- `.gnu_debuglink names "...", which is not a plain filename`: the binary's debuglink is malformed or hostile. Use `--import-json` with an artifact exported from trusted binaries.
- `modules A and B both provide hprobe slot N (...) with DIFFERENT variable descriptors`: two attach-target modules describe the same probe function differently, so one shared descriptor cannot be correct at both addresses. Re-export the artifact from the binaries the process maps, or remove the extra module.
- `failed to discover ...`: pass the corresponding explicit path flag.
- `missing function address`: native debug data or imported JSON lacks a required probe PC.
- `missing variable fields`: native debug data or imported JSON lacks required variable locations or member field paths.
- `build ID mismatch`: verify native module/debug files, regenerate JSON for the exact binaries, or rerun with `--allow-build-id-mismatch` only if the mismatch is understood.
- `refusing to probe <function> in module <module>: address 0x... is not inside an executable PT_LOAD segment`: the artifact was produced for a different binary. Regenerate it from the exact running binary (`--dwarf-source native`, or re-export the JSON). No flag overrides this.
- `refusing to probe <function> ...: address 0x... is not the entry of any function`: the address is inside code but not at a function start, or the target has no symbols or matching debug info to prove it. Install the matching debuginfo package, or regenerate the artifact for this exact build. No flag overrides this, and it applies to the optional request-END probe too: an absent END address fails soft, a wrong one does not.
- `refusing separate debug info for <binary>: <debug file> (build ID ... does not match ...)` or `(.gnu_debuglink CRC ... does not match ...)`: the installed debuginfo belongs to another build (typically a debuginfo package that was not upgraded with the binary). Install the matching debuginfo. `--allow-build-id-mismatch` does not apply: a mismatched debug file yields wrong offsets with no other symptom.
- `cannot evaluate the location of member `<name>`` / `unsupported DWARF operation DW_OP_...`: the build's DWARF describes a probed member in a form rgwtrace does not evaluate (for example, through a virtual base). Native extraction fails rather than guess offset 0; report the Ceph build and the message.
- `... was not validated by preflight; refusing to attach`: internal invariant. Attach only uses offsets preflight produced; report it as a bug.

---

## Common OTLP Failures

- `connection refused`: nothing is listening on the host/port from the RGW host.
- `timed out`: firewall, routing, load balancer, or collector availability issue.
- HTTP `404`: wrong path; OTLP/HTTP traces usually use `/v1/traces`.
- HTTP `415`: receiver does not accept OTLP protobuf on that endpoint.
- TLS/certificate errors: verify the endpoint certificate chain from the RGW host; for an internal CA pass `--otlp-ca-cert <pem>`. Use `http://` only on the same host or a trusted local network.
- HTTP `3xx`: the endpoint redirects and rgwtrace refuses to follow (it would re-send credentials and the trace elsewhere); set `--otlp-endpoint` to the final URL.
- `is world-readable`: the `--otlp-header-file` must not be readable by others; `chmod 600` it.
- `invalid OTEL_EXPORTER_OTLP_HEADERS`: the variable is `k=v,k2=v2` with percent-encoding; the error gives the entry number, never the value.
- HTTP `4xx`: endpoint/auth/config issue; not retried. The response body is logged as a 1 KiB excerpt with control characters escaped.
- HTTP `429` or `5xx`: retried according to `--otlp-retries`.

---

## Background RADOS Spans

`rgw.background.rados_op` means no RGW `trans_id` was available when the RADOS op was captured.

Expected causes include RGW startup work, GC, notify/sync/config work, late async work, cross-thread work, and true background RADOS operations.

Inspect:

- `rgw.rados_role` for object classification.
- `rgw.correlation = "none"`.
- `rgw.correlation_reason`, usually `missing_trans_id` or `classified_background_role`; with `--correlate-inferred`, it can also be `no_inference_candidate` or `ambiguous_inference_candidates`.
- `trace.diagnostics.missing_trans_id_background_ops` for volume.
- `trace.diagnostics.inference_no_candidate_rados_ops` and `trace.diagnostics.inference_ambiguous_rados_ops` when inferred correlation is enabled.
- `trace.diagnostics.inference_pending_overflow_rados_ops`: untagged ops decided early because the pending queue hit `--inference-max-pending`. They are decided against the candidates present at that moment, usually ending as ambiguous/no-candidate background ops instead of waiting for a candidate to appear or drop out. Nonzero means inference coverage is being traded for bounded memory and per-marker cost; raise the cap if memory allows (each pending op is a few hundred bytes).
- `trace.diagnostics.background_rados_by_role` and `trace.diagnostics.background_rados_by_reason` for breakdowns.

Do not assume background spans are errors. A rising background ratio is useful signal for deciding whether `--correlate-inferred` is warranted.

`--correlate-inferred` can attach untagged RADOS ops to a request only when there is one conservative candidate in `--inference-window` and the role does not look like RGW background work. A unique matching RADOS send thread is preferred over same-PID/time-window candidates. Inferred spans use `rgw.correlation = "inferred"` and `rgw.correlation_reason = "pid_time_window"`. Ambiguous or out-of-window candidates remain background spans.

`--correlate-cross-thread` (default off, opt-in) enables the fail-closed cross-thread bridge described in `docs/design-cross-thread-correlation.md`.

RGW runs each S3 request as an asio coroutine that migrates to a different `io_context` pool thread at every yield, so a RADOS op submitted after a migration lands on a thread that carries no request context and shows up as `rgw.background.rados_op` (reason `missing_trans_id`). This flag re-establishes the request's context on whatever thread is about to submit, **at every RADOS submit** (`rgw_rados_operate`, both the read and write overloads), plus once on the execute thread (`rgw_process_authenticated`). Recovered ops become `cross_thread` children of their request.

It is fail-closed and zero-mis-correlation by construction: the request is identified by the pointer **value** of the `DoutPrefixProvider*` the submit carries (never dereferenced, never type-assumed). A request is registered in the bridge under **both** of the identities RGW may pass as that `dpp` -- its `req_state*` and the `RGWOp*` executing it (RGW passes the RGWOp, not the req_state, at most call sites inside `op->execute()`) -- and both are revoked when the request ends. Any other `dpp`, such as a stack `DoutPrefix`/`DoutPrefixPipe` wrapper or a GC/LC/quota background thread's, simply misses the bridge and correlates nothing.

Two rules keep it honest, and both cost coverage on purpose:

- **A miss clears the submitting thread's SEEDED request context** (`bpf_operate_miss_ctx_cleared`). A request's context can be left on every pool thread it ever ran an operate on, and another request can resume on one of those threads and submit through a `dpp` we cannot key. The first request is still *alive*, so a liveness check alone would happily stamp its `trans_id` onto the second request's op. A miss therefore assumes nothing about a copy the re-seed put there: the op comes out uncorrelated.
- **`_send_op` re-validates every context** against its request's liveness before stamping it, and refuses a context that could never be bridged at all.

#### The clear is SCOPED: it never touches a HOME context

A **HOME** context is one `RGWREST::get_handler` placed on **this very thread** for the request that started here (`ctx.tid == this tid`). A **SEEDED** context is a copy a re-seed migrated onto a thread that is *not* the request's `get_handler` thread (`ctx.tid != this tid`). **The fail-closed clear applies to SEEDED contexts only.**

This is not a nicety -- an unscoped clear shipped a **measured regression**. RGW serves a sharded bucket listing as one `call(rgw.bucket_list)` **per bucket-index shard**, submitted through the cls_rgw AIO path (`CLSRGWIssueBucketList` -> `IoCtx::aio_operate`), which **never passes through `rgw_rados_operate`**. Those submits correlate purely off the HOME context `get_handler` left on the thread. **One** foreign-`dpp` operate on that thread wiped it, and a live ListObjects request lost **all 16** of its shard ops to `rgw.background.rados_op` / `missing_trans_id`. Clearing a HOME context also buys no soundness: an AIO submit that never reaches an operate inherits the thread's context either way.

Both outcomes are counted, so a run shows how often each fired:

| counter | meaning |
| --- | --- |
| `bpf_operate_miss_ctx_cleared` | a foreign-`dpp` miss cleared a **SEEDED** copy (a coverage cost, taken on purpose) |
| `bpf_operate_unresolved_ctx_cleared` | an unresolved/null `dpp` cleared a **SEEDED** copy |
| `bpf_operate_miss_home_ctx_preserved` | a foreign-`dpp` miss left a **HOME** context alone (healthy: same-thread correlation still working) |
| `bpf_operate_unresolved_home_ctx_preserved` | an unresolved/null `dpp` left a **HOME** context alone |

**KNOWN, ACCEPTED HAZARD (pre-existing, not introduced by the re-seed).** Because a HOME context is preserved, another coroutine that migrates onto a request's home thread and submits through a path that never reaches `rgw_rados_operate` (the AIO path) can inherit that request's `trans_id`. This is inherent to thread-keyed correlation on the non-operate submit path -- the submit never reaches the probe that could clear or re-seed the thread, so **no clear at `rgw_rados_operate` can close it**. It shipped before the cross-thread work and passed the zero-mis-correlation e2e gate. It is bounded by the `_send_op` liveness gate (a *dead* request's context can never stamp anything) and documented in full in `docs/design-cross-thread-correlation.md` §11.3.

**What it does not cover:** object-payload I/O dispatched through `rgw::Aio`/`aio_operate` does not pass through `rgw_rados_operate`, so multi-stripe GET/PUT body ops stay `background`/`inferred` by design. Neither does the cls_rgw AIO path (sharded `rgw.bucket_list`), which is correlated -- when it is -- by the same-thread HOME context rather than by the re-seed. Nor does a submit whose `dpp` is a stack wrapper object, which is unkeyable by construction.

**It requires the request-END probe.** The END probe is the only thing that revokes a request's bridge entries; without it, entries live forever, and a recycled `req_state` (stack) or `RGWOp` (heap) address could hit a dead request's entry and stamp its `trans_id` onto a live op. If the END probe did not attach, the per-submit re-seed is **not attached either** -- the run warns and degrades to seed-thread-only correlation.

With the flag off no re-seed uprobe is attached and behavior is byte-for-byte identical to not having the feature. On an RGW build where the `rgw_rados_operate` symbols cannot be resolved, the run degrades (loudly, with the specific reason) to seed-thread-only correlation.

Coverage/health is visible in the informational diagnostics `bpf_operate_seed_hits` (submits that had their request's context re-established -- the win condition), `bpf_operate_seed_misses` (unkeyable/background `dpp`s: **expected**, not failures), `bpf_operate_miss_ctx_cleared` (the ops the fail-closed rule above gives up on), `bpf_operate_unresolved_ctx_cleared` (the same fail-closed clear, for a `dpp` we could not resolve at all), `bpf_operate_miss_home_ctx_preserved` / `bpf_operate_unresolved_home_ctx_preserved` (the same two paths declining to touch a HOME context -- expected to be **nonzero** on a healthy run), `bpf_operate_base_unresolved`, the multi-key accounting `bpf_rgw_op_key_inserts` / `bpf_rgw_op_key_revokes` / `bpf_rgw_op_key_revoke_skipped` / `bpf_rgw_op_key_revoke_absent` / `bpf_rgw_op_key_unresolved` / `bpf_rgw_op_key_index_drops` / `bpf_rgw_op_key_disabled`, and the `bpf_reseed_*` counters (never failure counters). Every one of these is **always** in the JSON `trace.diagnostics` and in the end-of-run log summary, **and** -- on an `--output otlp` run started with `--otlp-diagnostics` (opt-in, default off) -- in the final OTLP batch, both on its Resource and on the `rgwtrace.run_summary` span, as `rgwtrace.diag.*` (see "Where to read the final counters" below). So an `--output otlp` run can be evaluated either from the shutdown log (always) or from OTLP (with the flag). `preflight` reports `cross_thread_operate_probe` and `cross_thread_reseed_probe` as advisory `ok`/`warn` checks for whether each probe's address, descriptor, mangled-name provenance, and `DoutPrefixProvider`-base proof resolved.

### Decide the fate of the `RGWOp*` alternate key: read these two counters

The `RGWOp*` alternate key exists **only as insurance**, in case RGW does not pass the `req_state` as the `dpp` at the `rgw_rados_operate` call sites. It is also the one part of this design with a residual mis-correlation hazard that no amount of pointer-identity logic can close: `RGWHandler_REST_S3Website::retarget` can free and replace an `RGWOp` **while its request is still alive**, so another `DoutPrefixProvider` heap object can be allocated at that address, be passed as a `dpp`, and be seeded as that request -- and the liveness gate *passes*, because the request genuinely is alive (`docs/design-cross-thread-correlation.md` §10.1).

So the key's fate is a **measurement**, not an argument. Run with it ON (the default), then read:

| `bpf_operate_seed_hits_reqstate` | `bpf_operate_seed_hits_rgwop` | What it means | What to do |
| --- | --- | --- | --- |
| healthy (tracks correlated ops) | **~0** | RGW passes the `req_state` as the `dpp` on the paths we probe. The alternate key fires never or almost never, so it buys nothing and only carries the retarget hazard. | **Pass `--disable-rgw-op-bridge-key`.** The hazard disappears with no loss of coverage. |
| healthy | a large share of `bpf_operate_seed_hits` | RGW passes the executing `RGWOp` as the `dpp` on the op data path, exactly as the multi-key design assumed. The key is load-bearing. | **Keep it.** Accept the retarget hazard; it cannot be closed by pointer identity, only by dropping the key. |
| **0** | 0, with `bpf_operate_seed_misses` large | The bridge is consulted but never matches. Not a key-choice problem -- see the `bpf_operate_seed_hits` is 0 entry below. | Fix the artifact first, then re-measure. |
| any | any, with `bpf_rgw_op_key_disabled` > 0 | The key was **off** for this run. `..._rgwop` being 0 says nothing. | Re-run without `--disable-rgw-op-bridge-key` to take the measurement. |

`bpf_operate_seed_hits_unattributed` **must be 0**: every hit is attributed by comparing the `dpp` against the bridged value's own `req_state_ptr`/`rgw_op_ptr`, exactly one of which can match. A nonzero value means the split above cannot be trusted and the decision must not be made on it.

`--disable-rgw-op-bridge-key` takes effect without a rebuild (it is published to the BPF side as a global before the probe that writes the key is attached), and it does not touch anything else: `req_state`-keyed correlation, the liveness gate, and the END probe all keep working.

#### Where to read the final counters

The counters above are **run totals, read at the end of the run**. Three places carry the same numbers:

1. **The log**, on either output mode, **always** (no flag required): the `finished live tracing` and `rgwtrace shutdown summary` lines carry every counter in a `diagnostics=` field of `key=value` pairs. Logs go to stderr, so `2> run.log` keeps them even with `--output json` on stdout. **This is the recommended way to read the go/no-go numbers -- it needs no OTLP and no backend.**
2. **The JSON document**, under `trace.diagnostics` (`--output json`), always; with `--output jsonl`, on the **last** line.
3. **The final OTLP batch** (`--output otlp`), **only when you pass `--otlp-diagnostics`** (default off). With the flag, the final batch is always sent -- even when the run's last drain left no spans, which is the normal ending, because the periodic drains have already exported everything by then while the final BPF counters are merged only after the poll loop exits -- and it carries the totals on its Resource as `rgwtrace.diag.*` attributes **and** on a synthetic zero-duration span named **`rgwtrace.run_summary`** with the same `rgwtrace.diag.*` attribute names. **Without the flag, the OTLP resource carries only `service.name`, no `rgwtrace.run_summary` span is emitted, and an empty final drain sends nothing** -- so the debug counters never pollute your tracing backend.

For a validation run you have two choices. The simplest is to **read the counters straight off the shutdown log** (`grep 'shutdown summary' run.log`): `bpf_operate_seed_hits_reqstate` and `bpf_operate_seed_hits_rgwop` are there as `key=value` pairs, no flag and no backend needed. If you want them in your trace backend instead, **run with `--otlp-diagnostics`**, then search the backend for the `rgwtrace.run_summary` span and read `rgwtrace.diag.bpf_operate_seed_hits_reqstate` and `rgwtrace.diag.bpf_operate_seed_hits_rgwop` off its attributes. Prefer the span over the Resource attributes: a batch with no spans carries nothing most trace backends will store, so on a run whose final drain was empty the Resource copy can reach the collector and be dropped there. With the flag on and the endpoint unreachable, the final export fails loudly and the whole trace (including `trace.diagnostics`) is dumped to stdout as JSON rather than lost.

**`bpf_operate_seed_hits` is 0 while `bpf_operate_seed_misses` is large.** The bridge is being consulted but never matching. Check `preflight`'s `cross_thread_reseed_probe`: if it warns that the `RGWOp*&` descriptor is unavailable, requests are keyed by their `req_state*` only -- and if RGW passes the executing `RGWOp` as the `dpp` on most of an op's data path, virtually every lookup will miss. **Fix:** re-export the DWARF artifact with a current rgwtrace.

**The alternate-key revocation identity.** Every alternate key that is inserted is accounted for at its request's end:

```
bpf_rgw_op_key_inserts == bpf_rgw_op_key_revokes        (deleted: still the request's own)
                        + bpf_rgw_op_key_revoke_skipped (already re-keyed by a NEWER, live request)
                        + bpf_rgw_op_key_revoke_absent  (already gone: LRU-evicted)
                        + alternate keys of requests still in flight
```

This holds exactly, because a key is only inserted **after** its revocation record exists in `rgw_op_keys` -- a plain HASH that never evicts -- and the destructor consults that record unconditionally, including when the request's own canonical LRU entry has been evicted. A shortfall beyond the in-flight count means keys are LEAKING, and a leaked key on a recycled `RGWOp` address is a mis-correlation source: check `bpf_request_end_misses` and `bpf_request_end_base_unresolved` (the destructor is what revokes keys).

**`bpf_rgw_op_key_index_drops` is nonzero.** The `rgw_op_keys` revocation map (16384 entries, i.e. ~16x Ceph's default `rgw_max_concurrent_requests`) is full, so the alternate key was **refused** rather than created unrevocable. Fail-closed: coverage degrades on the RGWOp-dpp path, nothing is mis-attributed. It implies an implausible in-flight request count; check for a request leak first.

**`bpf_operate_unresolved_ctx_cleared` is nonzero.** A `rgw_rados_operate` call carried a `dpp` we could not resolve (a NULL argument, or a descriptor that is not register-resident at entry). The thread's SEEDED request context is dropped, exactly as on a foreign-`dpp` miss and for the same reason: an unresolved `dpp` proves nothing about which coroutine is running on this pool thread, and the copy sitting there may belong to another live request. A steady nonzero count means RGW passes null `dpp`s on this path; a large one alongside `bpf_operate_base_unresolved` means the descriptor is broken and correlation is dead (it is never silent).

**A ListObjects request's `call(rgw.bucket_list)` shard ops came out as `rgw.background.rados_op` / `missing_trans_id`.** The request's HOME context was cleared off its own thread. Check `bpf_operate_miss_home_ctx_preserved` and `bpf_operate_unresolved_home_ctx_preserved`: if they are **0** while `bpf_operate_miss_ctx_cleared` is nonzero, the fail-closed clear is running unscoped and is wiping contexts it did not create. A sharded bucket listing is submitted through the cls_rgw AIO path, which never reaches `rgw_rados_operate`, so it correlates *only* off the HOME context on the listing thread -- a single foreign-`dpp` operate on that thread is enough to strand every shard. The e2e gate (`check_list_shard_correlation`) fails on exactly this shape.

The request-END probe (`req_state::~req_state`) is ON by default and needs no flag. It is what makes `rgw.request` durations real rather than reconstructed from child RADOS bounds. It is also optional: if the destructor address, its **variant provenance**, or its `this` descriptor does not resolve on your RGW build, the probe is not attached, the run degrades to derived durations, and both the run (a `warn!` at attach time) and `preflight` (an advisory `request_end_probe` `warn`, never a failure) say so with the specific reason. Coverage is visible in the informational diagnostics `bpf_request_end_hits`, `bpf_request_end_misses`, and `bpf_request_end_base_unresolved`, and in `measured_duration_requests` / `derived_duration_requests`. See `docs/design-request-end-probe.md`.

**"artifact has a `req_state::~req_state` address but no `func2linkage` entry".** Your imported DWARF JSON predates the variant-provenance field (or came from a third-party producer). The three C++ destructor variants all demangle to the same name and the deleting one (D0) is listed first, so an address with no mangled-name provenance cannot be proven safe to probe — rgwtrace refuses it rather than risk probing D0. **Fix:** re-export the artifact with a current rgwtrace (`--export-dwarf-json`). Until then the run works exactly as it did before the end probe existed, with `rgw.duration_quality = "marker"`.

**`bpf_sendop_stale_ctx_drops` is nonzero.** These are RADOS ops that were *not* stamped with a `trans_id` because the request context left on the submitting thread belonged to a request that had already ended. They are left uncorrelated (they show up as `background`, or `inferred` with `--correlate-inferred`) instead of being attributed to the wrong request — fail-closed by design, and expected to be nonzero whenever request context is re-seeded across threads. A count that is *large* relative to `correlated_rados_ops` means live bridge entries are being evicted from `rgw_ctx_by_reqstate` (131072 entries, i.e. two keys for each of ~49k in-flight requests even on a 256-CPU host after the LRU's per-CPU freelist reservation): expect it only under extreme in-flight request counts. `bpf_sendop_unverifiable_ctx` counts ops stamped without a liveness proof, which is the whole population on a build where the END probe could not attach (nothing can revoke a context there).

**`bpf_sendop_unbridged_ctx_drops` is nonzero.** No RADOS op is being correlated, and the reason is upstream of correlation: this build's `RGWREST::get_handler` does not hold the `req_state*` in a register at entry, so no request is ever entered into the bridge. Such a context can never be verified *or revoked*, so with the END probe attached `_send_op` refuses to stamp from it (a lingering one would otherwise let a long-dead request stamp later ops on a pooled thread). Attach warns about this explicitly. **Fix:** re-export the DWARF artifact with a current rgwtrace; if the build genuinely cannot expose it, the tracer still reports RADOS ops as background spans.

**`expired_open_requests` is nonzero.** Requests whose END marker never arrived within 10x `--correlation-ttl` of the request's start, so they were force-expired with a derived end. This means END markers are being lost (ring-buffer drops — check `bpf_ringbuf_request_drops` — or destructor bridge misses, `bpf_request_end_misses`), not that requests are slow. `late_request_markers_dropped` counts markers that arrived for a request whose span had already been exported; they are dropped rather than emitting a second span with the same span id, and a nonzero count means the expiry bounds are too tight for the workload.

**Background ops with reason `request_already_emitted` rise after an upgrade.** Requests whose END marker arrived are now exported after `--closed-request-grace` (default 5 s) of inactivity instead of the full `--correlation-ttl`. A RADOS completion that lands later than that becomes a background op with this reason rather than a child span. RGW waits for its own ops before the request ends, so this should be rare; asynchronous completions (for example fire-and-forget bucket-index `complete` ops on a slow OSD) are the expected exception. If the count matters, raise `--closed-request-grace`; memory grows with it (one group per request finished within the grace).

**`tombstone_horizon_rejections` is nonzero.** Every exported request key is remembered so a straggler can never resurrect an already-exported group and emit a second span with the same span id. The memory is fixed (two 8 MiB Bloom generations, rotated every 2M exported requests, `emitted_tombstone_rotations`, plus an exact set for force-expired open requests), so its false-positive rate never climbs with session length. Forgetting old keys is made safe by a horizon: an event for a request the tracer does not hold and no longer remembers, whose request **started** before the oldest remembered generation, is rejected rather than re-grouped. Markers are dropped; RADOS ops become background spans with `rgw.correlation_reason = "request_outside_tombstone_horizon"`. Expect ~0. A steady count means requests, or stale request contexts on RGW threads (only without the END probe), outlive a whole generation of exported requests. That traffic is surfaced as background spans, never duplicated. `emitted_open_tombstone_overflows` > 0 means more than 65,536 force-expired open requests were remembered at once: END markers are being lost at a high rate (see `expired_open_requests`).

---

## Capture Quality

Request spans include `rgw.duration_quality`, which says how the span's end was obtained.

- `measured`: the request-END probe (`req_state::~req_state`) fired and BOTH span bounds ARE the request's real ones. This is a true request duration.
- `measured_extended`: the END probe fired, but a correlated RADOS child fell outside the request's real interval -- it ended after the request did (a late `_finish_op`, or an inferred child), or it started before the request marker -- so the span was stretched to keep the child inside its parent. The real interval is preserved on the `rgw.request.measured_start_ns` / `rgw.request.measured_end_ns` attributes -- use those, not `start_ns`/`end_ns`, to compute the request's true duration.
- `marker`: no END marker arrived, so the end was DERIVED from the correlated RADOS child bounds. Expect this when preflight's `request_end_probe` check warns (the destructor symbol or its `this` descriptor did not resolve on this build), or for a request that was still in flight when the trace window closed.
- `rados_bounds`: the request group was built from RADOS timestamps only (no request marker at all).

There is no `request_lifecycle` value, and no return probe anywhere: a `process_request` return probe crashes RGW.

To check end-probe coverage on a run, compare `measured_duration_requests` against `derived_duration_requests` in the diagnostics (or the `bpf_request_end_hits` / `bpf_request_end_misses` counters, which count destructor firings that did and did not resolve a request). A high `bpf_request_end_misses` count is normal when tracing starts mid-workload: those requests began before the trace window, so their `get_handler` was never seen.

RADOS child spans carry `ceph.rados.send_tid` and request spans carry `rgw.request.tid`. If they differ, the op was submitted on a different thread than the one that handled the request -- an asio coroutine migration.

RADOS spans may include `rgwtrace.truncated` when fixed BPF capture limits clipped object names, `trans_id`, acting sets, op lists, class names, or method names. Class names hold 15 bytes, enough for every in-tree Ceph object class; before this was 7, and `refcount`, `timeindex` and `2pc_queue` calls came out with garbled method names.

---

## BPF Sizing and Run Lifecycle

| Flag | Default | What it sizes |
|---|---|---|
| `--ringbuf-size` | `16M` | Events ring buffer, bytes (K/M/G suffixes). Power of two, page multiple, at most 1 GiB. Locked kernel memory. |
| `--bpf-rados-ops-entries` | `32768` | In-flight RADOS op map. ~600 bytes/entry preallocated (~20 MiB at the default). Minimum 1024. |
| `--rados-ops-stale-after` | `300` | Seconds after which a `rados_ops` entry is swept. `0` disables; otherwise at least 60. |

**`bpf_ringbuf_rados_drops` / `bpf_ringbuf_request_drops` are nonzero.** The reader fell behind the ring buffer. 16 MiB absorbs ~1.4 s of reader stall at 20k RADOS ops/s. Raise `--ringbuf-size` (for example `64M`) on very busy gateways or loaded hosts.

**`bpf_rados_map_drops` is nonzero.** `rados_ops` was full when `_send_op` fired, so those ops were not traced. Check `stale_rados_ops_swept`: if it is also climbing, clients are exiting with ops in flight faster than the sweep reclaims them; otherwise in-flight load exceeds the map. Raise `--bpf-rados-ops-entries`.

**`stale_rados_ops_swept` is nonzero.** The sweep deleted ops older than `--rados-ops-stale-after`. After a client restart this is expected and harmless. On a healthy cluster with no restarts it means ops are blocking longer than the threshold (inactive PGs, stuck OSDs); those ops emit no event when they complete and appear as `bpf_rados_finish_misses`. Raise the threshold rather than lower it.

**Stopping a run.** SIGINT, SIGTERM (`systemctl stop`, `docker stop`), SIGHUP, `--timeout`, and, with `--pid`, the target process exiting all end the run the same way: diagnostics are read, pending spans are emitted (JSON on stdout, or the final OTLP export), and the process exits 0. A target exit is logged as `target process exited; stopping the trace and writing what was collected`. Before this change SIGTERM killed the process without output, and a `--pid` run outlived its target.

## Verification

See [Building and testing](docs/development.md) for build dependencies,
container builds, and self-hosted E2E runner setup.

Run local checks before shipping changes:

```sh
./scripts/verify.sh
```

Include the Linux container build when needed:

```sh
VERIFY_CONTAINER_BUILD=1 ./scripts/verify.sh
```

Run a real BPF verifier load check on Linux when BPF code changes:

```sh
VERIFY_BPF_LOAD=1 ./scripts/verify.sh
```

Run dependency audit checks when dependency or toolchain inputs change:

```sh
VERIFY_AUDIT=1 ./scripts/verify.sh
```

---

## End-to-end object↔request correlation gate

`tests/e2e/functional-test-microceph-rgw.sh` drives `s3-workload.py` and checks
the trace with `verify-rgwtrace-json.py`. Two artifacts feed the verifier: the
per-op workload log (`--output` / `--workload`) and a machine-readable manifest
(`--manifest` / `--workload-manifest`).

The manifest records, per operation, its op class (`GET`/`PUT`/`OTHER`), `rw`
(`read`/`write`), S3 key, timestamp window, and `x_amz_request_id`. When the
verifier is given `--workload-manifest`, it maps each RADOS child span to a
workload object by matching the S3 key as a substring of `ceph.rados.object`
(RGW embeds the key in shadow/multipart RADOS names), constrained by `rw` and the
op's time window. This drives two checks:

- **Zero mis-correlation (always on with a manifest):** a correlated `rados.op`
  child span for a workload object attached to the wrong request fails the run.
- **Coverage rate (opt-in):** `--require-get-read-correlation RATE` and
  `--require-put-write-correlation RATE` fail when the fraction of GET-read /
  PUT-write data ops that carry a correctly correlated child span drops below
  `RATE`. A workload object landing as `background`/`inferred` is a coverage
  miss, not a mis-correlation.

The functional harness requires explicit `REQUIRE_GET_READ_CORRELATION` and
`REQUIRE_PUT_WRITE_CORRELATION` values in `(0, 1]`. Calibrate and record these for
each Ceph build and profile; there is no zero-coverage default. A regression is
not a reason to lower an established threshold. The standalone verifier keeps
rate checks optional when their flags are omitted.

`E2E_PROFILE=baseline` requires measured request-END activity;
`E2E_PROFILE=cross-thread` also enables `--correlate-cross-thread` and requires
actual cross-thread children and per-submit bridge hits. `E2E_PROFILE=no-end`
removes the destructor metadata from a copy of the exported artifact, requests
cross-thread correlation, and verifies the warning and fail-soft fallback:
no END markers, measured durations, or per-submit seeds. This does not test
kernel-induced attach failure; that remains a separate failure-injection case.

Every profile provisions a sharded test bucket (`REQUIRE_LIST_SHARDS=3` by
default) and checks its configured shard count. The verifier's
`--require-list-shards N` requires **every** manifest LIST to correlate at least
N distinct bucket-index objects. No LIST, fewer observed shards, or lost shard
coverage fails instead of skipping. `--unique-keys` keeps the object/request
mapping unambiguous. The harness records the source revision, kernel, profile,
thresholds, Ceph metadata, workload manifest, trace, and validation output.

See [private lab setup](docs/lab/README.md) before running privileged tests.

Without `--workload-manifest`, the verifier behaves exactly as before.


## Release downloads

Download the binary archive matching `uname -m` (`x86_64` or `aarch64`) and
`SHA256SUMS` from a versioned [GitHub Release](https://github.com/kuklaondrej/rgwtrace/releases).
On Ubuntu/Debian, install runtime dependencies with
`sudo apt-get install libelf1 zlib1g`; the standard archives require glibc
2.35 or newer. On CentOS 9, choose the archive ending in `-centos9.tar.gz`
(glibc 2.34) and install dependencies with
`sudo dnf install elfutils-libelf zlib`. Both variants are available for x86_64
and aarch64. No Rust toolchain or BPF compilation is needed on the target.

```sh
# Run in the directory containing the downloaded archive and SHA256SUMS.
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf rgwtrace-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
cd rgwtrace-v0.1.0-x86_64-unknown-linux-gnu
./rgwtrace --version
./rgwtrace --import-json minimal_dwarf.json --dry-run --output json
```

Replace the example version and architecture with the asset you downloaded.
The fixture tests the executable offline; it cannot be used against a live RGW.

For pre-generated metadata, open the same
[GitHub Releases page](https://github.com/kuklaondrej/rgwtrace/releases) and
choose a separate `dwarf-<hash>` catalog release. These catalogs are generated
by the DWARF workflow; they appear alongside the binary releases, but do not
replace the latest binary release. Inspect `index.json` for the package source,
exact package revisions, architecture, module build IDs, and optional probe
capability checks. Download and verify the matching bundle using that
catalog's `SHA256SUMS`, then extract it.

```sh
sudo ./rgwtrace --pid 12345 --import-json /path/to/native-dwarf.json --preflight
sudo ./rgwtrace --pid 12345 --import-json /path/to/native-dwarf.json --timeout 30 --output json
```

Match the binaries used by the RGW process, including libraries inside its
container. An OS/Ceph version label alone does not establish compatibility.
Never use `--allow-build-id-mismatch` to force a catalog match. If no exact
bundle exists, use native extraction with matching debug symbols as described
above. Catalog preflight validates metadata offline; it does not attest to a
successful live attach. Optional probe warnings in the catalog describe
reduced duration or correlation capabilities.
