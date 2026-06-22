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

`--otlp-compression gzip` compresses request bodies and sets `Content-Encoding: gzip`. `--otlp-max-spans-per-batch` limits spans per OTLP request. `--otlp-max-bytes-per-batch` limits encoded protobuf bytes before compression; `0` disables byte-based splitting.

Use `RUST_LOG=rgwtrace=debug` or `--log-level debug` for internal diagnostics.

JSON output includes `trace.diagnostics` counters for decoded events, decode errors, request markers, RADOS ops, correlated/background RADOS ops, same-thread and inferred correlations, inference misses/ambiguity, missing-`trans_id` background ops, background breakdowns by role/reason, capture truncation counters, produced spans, expired request groups, expired background RADOS ops, dropped OTLP queue spans, and BPF-side ring-buffer/map/probe-read failures.

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

Run the privileged MicroCeph RGW e2e test on Linux when validating live request capture:

```sh
cargo build --release
sudo tests/e2e/functional-test-microceph-rgw.sh
```

The e2e test bootstraps MicroCeph, enables RGW, drives S3 traffic, captures `rgwtrace` JSON, and verifies request spans, RADOS child spans, diagnostics, correlation, and current role categories. It preserves `preflight.json`, `trace.json`, `workload.jsonl`, and logs under `/tmp/rgwtrace-e2e`.

By default, the e2e test installs MicroCeph from `reef/stable` and fails early unless the snap resolves to Ceph package version `18.2.8-1jammy`. It writes `microceph-version.txt`, `microceph-metadata.yaml`, `microceph-manifest.yaml`, and `microceph-manifest-ceph.txt` under `/tmp/rgwtrace-e2e` so the traced version is explicit.

Override the pin when needed:

```sh
sudo MICROCEPH_CHANNEL=reef/stable \
  MICROCEPH_EXPECTED_CEPH_VERSION=18.2.8-1jammy \
  tests/e2e/functional-test-microceph-rgw.sh
```

If MicroCeph is already installed at a different version, the test fails rather than switching it automatically. Set `MICROCEPH_ALLOW_CHANNEL_SWITCH=1` only on disposable test hosts.

If native DWARF is unavailable for the MicroCeph snap, pass matching probe metadata explicitly:

```sh
sudo RGWTRACE_DWARF_JSON=/path/to/rgwtrace_dwarf.json tests/e2e/functional-test-microceph-rgw.sh
```

---

## Trace

Correlated request output:

```text
rgw.request
  rados.op
  rados.op
```

Fallback output for uncorrelated RADOS work:

```text
rgw.background.rados_op
```

RADOS child spans include object, op list, pool, PG, PG seed, acting set, target OSD, direction, offset, length, duration, and role attributes.

RADOS spans also include `rgw.correlation`. Correlated request children use `same_thread`; optional inferred children use `inferred` with `rgw.correlation_reason = "pid_time_window"`; standalone background spans use `none` with a correlation reason such as `missing_trans_id`, `classified_background_role`, `no_inference_candidate`, or `ambiguous_inference_candidates`.

Request spans include `rgw.duration_quality`. Current live captures normally use `marker` because the safe RGW probe observes a request marker rather than the full lifecycle; the span still envelopes any correlated RADOS child bounds. If future start/end probes are active, the value is `request_lifecycle`; request groups built only from RADOS bounds use `rados_bounds`.

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

Late async, cross-thread, startup, and background operations may appear as standalone `rgw.background.rados_op` spans. `--correlate-inferred` enables conservative PID/time-window inference for unique candidates only; ambiguous candidates remain background spans and are counted separately.

---

## Read

See [Architecture](ARCHITECTURE.md) for the event pipeline, trace model, captured fields, and current limitations.

See [Production Runbook](RUNBOOK.md) for operating commands, preflight checks, OTLP troubleshooting, and background span interpretation.
