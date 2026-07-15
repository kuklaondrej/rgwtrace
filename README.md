# rgwtrace

Traces RGW requests with RADOS child spans.

---

## Know

`rgwtrace` traces Ceph RGW request activity and exports request-oriented telemetry.

It uses C eBPF uprobes for Ceph/RGW internals and Rust userspace for decoding, aggregation, classification, and export.

Implemented today:

- Live Linux tracing with `libbpf-rs` and `libbpf-cargo`.
- Native DWARF probe extraction with `--dwarf-source native`.
- DWARF JSON import from existing `cephtrace` output as a stable fallback and comparison oracle.
- RGW request spans keyed by `trans_id`.
- Correlated RADOS operations as `rados.op` child spans.
- Background RADOS operations as standalone root spans.
- JSON output and OTLP/HTTP protobuf export with HTTPS, gzip compression, and batching controls.
- Unix epoch nanosecond timestamps for Tempo and OTLP.

---

## Use

Validate DWARF JSON parsing without attaching probes:

```sh
rgwtrace --import-json 18.2.8-1jammy_dwarf_traceid.json --dry-run --output json
```

Validate native DWARF extraction and target discovery before attaching probes:

```sh
sudo rgwtrace --dwarf-source native --preflight
```

Validate DWARF data and target discovery before attaching probes:

```sh
sudo rgwtrace \
  --import-json 18.2.8-1jammy_dwarf_traceid.json \
  --preflight
```

`--preflight` checks the requested `--pid`, explicit target paths, discovered Ceph/RGW target files, required DWARF functions, minimum variable-field counts, and ELF build IDs.

Native mode also needs a Ceph version to select the `ceph_osd_op` ABI layout. `rgwtrace` resolves this from native metadata when possible; pass `--ceph-version 18.2.8-1jammy` or `--ceph-version 19.2.0` when the version cannot be discovered.

Build ID mismatches fail preflight and live attach by default. Use `--allow-build-id-mismatch` only when the mismatch is understood.

Run live tracing and flush JSON on `Ctrl-C`:

```sh
sudo rgwtrace --import-json 18.2.8-1jammy_dwarf_traceid.json --output json
```

Run live tracing for a fixed interval:

```sh
sudo rgwtrace \
  --import-json 18.2.8-1jammy_dwarf_traceid.json \
  --timeout 30 \
  --output json
```

Target one RGW process when automatic attachment is too broad:

```sh
sudo rgwtrace \
  --pid "$(pidof radosgw | awk '{print $1}')" \
  --import-json 18.2.8-1jammy_dwarf_traceid.json \
  --timeout 30 \
  --output json
```

When `--pid` is used, discovered target paths are resolved through `/proc/<pid>/root` so attaches work for RGW processes running in a different mount namespace, including container runtimes.

---

## Export

Send traces to an OTLP/HTTP endpoint:

```sh
sudo rgwtrace \
  --import-json 18.2.8-1jammy_dwarf_traceid.json \
  --output otlp \
  --otlp-endpoint http://localhost:4318/v1/traces
```

The exporter sends OTLP protobuf with `Content-Type: application/x-protobuf`.

The exporter supports `http://` and `https://` OTLP endpoints.

Use `--service-name` to set the OTLP `service.name` resource attribute.

Tune exporter behavior when needed:

```sh
sudo rgwtrace \
  --import-json 18.2.8-1jammy_dwarf_traceid.json \
  --output otlp \
  --otlp-endpoint http://localhost:4318/v1/traces \
  --otlp-timeout 10 \
  --otlp-retries 3 \
  --otlp-compression gzip \
  --otlp-max-spans-per-batch 512 \
  --otlp-max-bytes-per-batch 0 \
  --otlp-flush-interval 30 \
  --correlation-ttl 120 \
  --otlp-header 'Authorization:Bearer local-token'
```

In OTLP mode, live tracing periodically queues spans whose correlation window has expired for a background exporter. `--otlp-flush-interval` controls how often expired spans are checked, and `--correlation-ttl` controls how long request/RADOS correlation state is retained before it is flushed.

When `--correlate-inferred` is enabled, `--inference-window` controls the conservative time window, in seconds, used for untagged RADOS inference. It is separate from `--correlation-ttl`.

`--otlp-compression gzip` compresses request bodies and sets `Content-Encoding: gzip`. `--otlp-max-spans-per-batch` limits spans per OTLP request. `--otlp-max-bytes-per-batch` limits encoded protobuf bytes before compression; `0` disables byte-based splitting.

Use `RUST_LOG=rgwtrace=debug` or `--log-level debug` for internal diagnostics.

JSON output includes `trace.diagnostics` counters for decoded events, decode errors, request START markers (`request_markers`) and END markers (`request_end_markers`), request-duration provenance (`measured_duration_requests` / `derived_duration_requests`), RADOS ops, correlated/background RADOS ops, same-thread, cross-thread, and inferred correlations, inference misses/ambiguity, missing-`trans_id` background ops, background breakdowns by role/reason, capture truncation counters, produced spans, expired request groups, open requests force-expired at the lifetime backstop (`expired_open_requests`), markers dropped for an already-exported request (`late_request_markers_dropped`), expired background RADOS ops, dropped OTLP queue spans, BPF-side ring-buffer/map/probe-read failures, and the informational re-seed (`bpf_reseed_*`), per-submit cross-thread re-seed (`bpf_operate_seed_hits`, its per-key split `bpf_operate_seed_hits_reqstate` / `bpf_operate_seed_hits_rgwop` / `bpf_operate_seed_hits_unattributed`, `bpf_operate_seed_misses`, `bpf_operate_miss_ctx_cleared`, `bpf_operate_unresolved_ctx_cleared`, `bpf_operate_miss_home_ctx_preserved`, `bpf_operate_unresolved_home_ctx_preserved`, `bpf_operate_base_unresolved`), multi-key bridge (`bpf_rgw_op_key_inserts`, `bpf_rgw_op_key_revokes`, `bpf_rgw_op_key_revoke_skipped`, `bpf_rgw_op_key_revoke_absent`, `bpf_rgw_op_key_unresolved`, `bpf_rgw_op_key_index_drops`, `bpf_rgw_op_key_disabled`), request-end probe (`bpf_request_end_*`), and `_send_op` liveness-gate (`bpf_sendop_stale_ctx_drops`, `bpf_sendop_unverifiable_ctx`, `bpf_sendop_unbridged_ctx_drops`) coverage counters, plus `emitted_request_keys` (the no-duplicate tombstone's occupancy).

**Every one of those counters reaches every output path**, and that is enforced by a test rather than by a maintained list: the log summary, the JSON `trace.diagnostics` block, and -- when opted in -- the OTLP resource attributes and OTLP run-summary span are all generated from `TraceDiagnostics`' own serde representation (`TraceDiagnostics::counters()`), so a counter added to the struct appears in every sink automatically. The complete run summary is **always** logged at end of run (`finished live tracing` / `rgwtrace shutdown summary`, as a `diagnostics=` field of `key=value` pairs) and **always** present in the JSON `trace.diagnostics` block, regardless of any flag.

**Emitting the run summary into OTLP is opt-in via `--otlp-diagnostics` (default off).** These are cumulative debug counters, not request telemetry, so by default an `--output otlp` run carries a clean resource (`service.name` only) and no run-summary span -- the tracing backend is not polluted. Because a live-validation run can always read the same counters off the shutdown log or the JSON output, the default stays clean and validation still works.

**With `--otlp-diagnostics`, `--output otlp` also delivers a guaranteed final batch** -- even when the run's last drain left no spans, which is the normal case, because the periodic drains have usually exported every span by then while the final BPF counters are only merged after the poll loop exits. That batch carries the final counters twice: on its Resource as `rgwtrace.diag.*`, and on a synthetic zero-duration span named **`rgwtrace.run_summary`** whose attributes are the same `rgwtrace.diag.*` names. Search your backend for the `rgwtrace.run_summary` span to read a run's final numbers; a span-less batch's Resource attributes reach the collector but most trace backends store nothing from a batch with no spans, which is why the span exists. One consequence, **with the flag on**: the run always contacts its endpoint, so an unreachable endpoint is reported as a failure (with the trace dumped to stdout as JSON) rather than exiting silently. **With the flag off** an empty final drain simply sends nothing.

OTLP mode logs the same trace counters plus export batches, attempts, and failures when internal logging is enabled.

If export fails with `connection refused`, `timed out`, or DNS errors, verify the endpoint from the tracing host first:

```sh
curl -v --max-time 5 http://localhost:4318/v1/traces
```

---

## Build

Build a Linux `amd64` binary from macOS or Linux with Docker or Podman:

```sh
./scripts/build-linux-container.sh
```

The script builds `docker/Dockerfile` with `--platform linux/amd64` and copies the binary to `dist/rgwtrace-linux-amd64`.

Override the runtime or output directory when needed:

```sh
CONTAINER_RUNTIME=podman OUTPUT_DIR=/tmp ./scripts/build-linux-container.sh
```

Live tracing requires Linux with eBPF support, clang, libelf development headers, and compatible kernel/libbpf headers.

---

## Test

Run the fast no-cluster verification loop before live testing:

```sh
./scripts/verify.sh
```

The default tests cover imported DWARF dry-run CLI output, synthetic collector trace golden output, raw event conversion, OTLP encoding, native DWARF parsing helpers, e2e JSON verifier self-tests, and BPF source regressions. Linux CI also covers ring-buffer event decoding without attaching probes.

CI uses the pinned Rust toolchain in `rust-toolchain.toml` and runs `cargo audit`. Run the audit locally when dependency or toolchain inputs change:

```sh
VERIFY_AUDIT=1 ./scripts/verify.sh
```

On Linux, run a real verifier load check when changing BPF code:

```sh
sudo scripts/verify-bpf-load.sh
```

The repository also has a manual `BPF Verify Linux 5.8` workflow for a self-hosted runner labeled `kernel-5.8`.

Use live RGW/Ceph testing only after the fast suite passes or when validating probe attachment against a real runtime.

The GitHub `E2E` workflow runs the privileged MicroCeph RGW test inside a fresh LXD VM sandbox on a self-hosted Linux runner. The runner host must have LXD installed and initialized ahead of time; CI does not install or initialize LXD.

Prepare the self-hosted runner host once:

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends snapd
sudo snap install lxd
sudo lxd init
sudo usermod -aG lxd <runner-user>
```

When prompted by `lxd init`, create a local bridge and choose an IPv4 subnet that does not overlap host routes, such as `10.250.0.1/24`; enable IPv4 NAT and disable IPv6 if it is not needed.

Restart the GitHub runner service so the `lxd` group membership applies.

Verify as the runner user with `lxc info`; optionally smoke-test a VM:

```sh
lxc info
lxc launch ubuntu:24.04 rgwtrace-smoke --vm
lxc delete -f rgwtrace-smoke
```

Run the privileged MicroCeph RGW e2e test directly on Linux when validating live request capture:

```sh
cargo build --release
sudo tests/e2e/functional-test-microceph-rgw.sh
```

The e2e test bootstraps MicroCeph, enables RGW, drives S3 traffic, captures `rgwtrace` JSON, and verifies request spans, RADOS child spans, diagnostics, correlation, and current role categories. It preserves `preflight.json`, `trace.json`, `workload.jsonl`, and logs under `/tmp/rgwtrace-e2e`.

By default, the e2e test installs MicroCeph from `reef/stable` and fails early unless the snap resolves to Ceph package version `18.2.4-0ubuntu1~cloud0`. It writes `microceph-version.txt`, `microceph-metadata.yaml`, `microceph-manifest.yaml`, and `microceph-manifest-ceph.txt` under `/tmp/rgwtrace-e2e` so the traced version is explicit.

Override the pin when needed:

```sh
sudo MICROCEPH_CHANNEL=reef/stable \
  MICROCEPH_EXPECTED_CEPH_VERSION=18.2.4-0ubuntu1~cloud0 \
  tests/e2e/functional-test-microceph-rgw.sh
```

If MicroCeph is already installed at a different version, the test fails rather than switching it automatically. Set `MICROCEPH_ALLOW_CHANNEL_SWITCH=1` only on disposable test hosts.

If native DWARF is unavailable for the MicroCeph snap, pass matching probe metadata explicitly:

```sh
sudo RGWTRACE_DWARF_JSON=/path/to/rgwtrace_dwarf.json tests/e2e/functional-test-microceph-rgw.sh
```

---

## Trace

A trace is one `rgw.request` parent span with a `rados.op` child per RADOS op the request issued. RADOS work that cannot be tied to a request is emitted standalone as `rgw.background.rados_op`:

```text
rgw.request                 rgw.background.rados_op
  rados.op                    (uncorrelated RADOS work)
  rados.op
```

### Worked example

The diagrams below are real captures (anonymized: bucket, key, access key, transaction ID, and thread IDs replaced; timings and structure unchanged). Each bar is a `rados.op` child on a shared time axis; `thread` is the op's submitting thread (`ceph.rados.send_tid`), and `T0 (home)` is the request marker's own thread (`rgw.request.tid`).

A `GET my-bucket/report.pdf` on a cold cache. RGW authenticates on the request's home thread, then its asio coroutine migrates across four `io_context` pool threads as each metadata read yields. The first op is `same_thread`; every op after the first migration is recovered by the cross-thread re-seed bridge and labelled `cross_thread`:

```text
rgw.request  GET my-bucket/report.pdf   trans_id=tx…e3b21-zone  tid=T0  quality=measured  49.6 ms

  child (rados.op)       correlation  thread    |0 ───────── time ─────────► 50          |
  auth stat + read       same_thread  T0 (home) |███████████                             | 13.7 ms
  bucket entrypoint rd   cross_thread T1        |                       █████            |  6.2 ms
  bucket instance read   cross_thread T2        |                            █████████   | 11.8 ms
  user info read         cross_thread T3        |                                      █ |  0.4 ms
  head stat + read       cross_thread T4        |                                       █|  0.6 ms
```

A `DELETE my-bucket/report.pdf`. This is the case the cross-thread work exists for: the head `stat` runs on the home thread, but the entire write path — the bucket-index prepare and the object removal — is dispatched onto other pool threads and would otherwise be lost:

```text
rgw.request  DELETE my-bucket/report.pdf   trans_id=tx…a1c7f-zone  tid=T0  quality=measured  41.0 ms

  child (rados.op)       correlation  thread    |0 ───────── time ─────────► 41          |
  head stat              same_thread  T0 (home) | █                                      |  0.6 ms
  index prepare_op       cross_thread T1        |  ██                                    |  1.6 ms
  obj_remove             cross_thread T2        |   ████████████████████████████████████ | 36.8 ms
```

Without `--correlate-cross-thread`, that same DELETE keeps only the `same_thread` head `stat`; `index prepare_op` and `obj_remove` fall out as standalone `rgw.background.rados_op` spans with `rgw.correlation_reason = "missing_trans_id"`, and the request span, having no later child, ends at ~1 ms instead of 41 ms.

RADOS child spans include object, op list, pool, PG, PG seed, acting set, target OSD, direction, offset, length, duration, and role attributes.

RADOS spans also include `rgw.correlation`. Correlated request children use `same_thread` when the RADOS op ran on the request's own execute thread; children recovered by the opt-in cross-thread re-seed bridge (`--correlate-cross-thread`) use `cross_thread` with `rgw.correlation_reason = "reseed_bridge"`; optional inferred children use `inferred` with `rgw.correlation_reason = "pid_time_window"`; standalone background spans use `none` with a correlation reason such as `missing_trans_id`, `classified_background_role`, `no_inference_candidate`, or `ambiguous_inference_candidates`. The `same_thread`/`cross_thread` split is derived late, when spans are built, from whether the op's send thread matches the request marker's thread, so `correlated_rados_ops == same_thread_correlations + cross_thread_correlations + inferred_correlations`. `cross_thread` ops are the ones submitted after the request's asio coroutine migrated to another `io_context` pool thread; they are recovered by re-seeding the request's context at every RADOS submit (`rgw_rados_operate`, both overloads), looking the submit's `DoutPrefixProvider*` up by pointer value in a bridge that keys each request by **both** identities RGW may pass for it (its `req_state*` and the `RGWOp*` executing it). It is opt-in and build-dependent, requires the request-END probe (the only thing that revokes bridge entries), and fails closed: object-payload I/O dispatched through `rgw::Aio`/`aio_operate` does not route through that frame, and a submit whose `dpp` is an unkeyable stack wrapper is left uncorrelated rather than guessed at — both stay `background`/`inferred` (see `docs/design-cross-thread-correlation.md`).

Request spans include `rgw.duration_quality`, which tells a real duration from a reconstructed one:

- `measured` -- the request-END probe (`req_state::~req_state`, an entry uprobe on the destructor that `process_request` runs at scope exit) fired, and **both** span bounds are the request's real ones.
- `measured_extended` -- the END probe fired, but a span bound had to be stretched to envelope a correlated RADOS child: the end pushed out past a late child, or the start pulled back to a child that began before the request marker (children are never clamped into their parent). The untouched real interval stays available on `rgw.request.measured_start_ns` / `rgw.request.measured_end_ns`.
- `marker` -- no END marker: on builds where the destructor address, its variant provenance, or its `this` descriptor cannot be resolved, the probe is not attached and the request's end is **derived** from its correlated RADOS child bounds (the pre-end-probe behavior). Preflight reports this as a `request_end_probe` warning, and so does the run itself at attach time.
- `rados_bounds` -- no request marker at all; the group was built from RADOS timestamps only, so neither bound is measured.

There is still no `request_lifecycle` value, and no return probe anywhere: a `process_request` return probe crashes RGW (a uretprobe patches the return address on the stack while asio switches fiber stacks underneath it).

RADOS spans carry `ceph.rados.send_tid` (the submitting thread) and request spans carry `rgw.request.tid` (the request marker's thread). When they differ, the op was submitted after an asio coroutine migration.

When fixed BPF capture limits truncate values, RADOS spans include `rgwtrace.truncated` with affected fields.

---

## Configure

Pass explicit target paths when discovery is not enough:

```sh
sudo rgwtrace \
  --import-json 18.2.8-1jammy_dwarf_traceid.json \
  --librados-path /lib/librados.so.2 \
  --librbd-path /lib/librbd.so.1 \
  --libceph-common-path /usr/lib/ceph/libceph-common.so.2 \
  --radosgw-path /usr/bin/radosgw
```

Native mode reads selected Ceph/RGW modules and their debug info directly. It discovers embedded DWARF, `.gnu_debuglink`, and build-id debug files. JSON mode requires `cephtrace` output that matches the traced binaries closely enough for probe PCs and field paths to stay valid.

Live attach refuses to guess the Ceph ABI layout when no version is available. Use DWARF JSON with a `version` field or pass `--ceph-version` for native mode.

`rgwtrace` validates required probe functions, field counts, and ELF build IDs. Build ID mismatches fail by default and can be downgraded with `--allow-build-id-mismatch` only when the mismatch is understood.

---

## Limit

Native DWARF support is implemented for the current live probe set: `Objecter::_send_op`, `Objecter::_finish_op`, and `RGWREST::get_handler`.

It extracts module build IDs, probe PCs, variable locations, and member field paths from local binary/debug data. `cephtrace` JSON import remains the stable fallback and oracle for validating native output.

Correlation depends on `RGWREST::get_handler` seeing a `trans_id` and `Objecter::_send_op` running with that context.

Late async, cross-thread, startup, and background operations may appear as standalone `rgw.background.rados_op` spans. `--correlate-inferred` enables conservative inference for unique candidates only. It first prefers a unique request whose Linux thread ID matches the RADOS send thread, then falls back to same-PID/time-window matching. Ambiguous candidates remain background spans and are counted separately.

---

## Read

See [Architecture](ARCHITECTURE.md) for the event pipeline, trace model, captured fields, and current limitations.

See [Production Runbook](RUNBOOK.md) for operating commands, preflight checks, OTLP troubleshooting, and background span interpretation.
