# Architecture

Live tracing pipeline for RGW and RADOS.

---

## Follow

`rgwtrace` starts by loading probe metadata from native DWARF or `cephtrace` JSON.

The Linux runner opens the BPF skeleton, configures Ceph ABI offsets, populates the `hprobes` map, attaches uprobes, and polls the ring buffer.

Before live attach, preflight validation checks CLI input, discovered target files, required DWARF functions, minimum variable-field counts for the probes used by the BPF program, and ELF build IDs.

Pipeline:

```text
native DWARF or cephtrace JSON -> hprobes -> eBPF uprobes -> ring buffer -> Rust events -> spans -> JSON or OTLP protobuf
```

---

## Capture

The BPF program attaches RADOS probes to `Objecter::_send_op` and `Objecter::_finish_op`.

It also attaches `RGWREST::get_handler` to read the RGW `trans_id` and seed request context.

The older `process_request` probe path is intentionally not present because live testing showed it could crash RGW on return-probe attach.

Captured request data:

- Start timestamp.
- End or marker timestamp.
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
- Class names are 8 bytes.
- Method names are 32 bytes.

BPF events carry truncation flags for these limits. Rust exposes counters in trace diagnostics and adds `rgwtrace.truncated` to affected RADOS spans. A BPF diagnostics map also counts ring-buffer reservation failures, RADOS state-map failures, missing finish state, request-context map failures, and probe-read failures.

---

## Correlate

The BPF layer stores RGW request context by Linux thread ID when it reads a `trans_id`.

`Objecter::_send_op` copies that `trans_id` into the RADOS event when the same thread context is available.

The Rust collector groups request and RADOS events by `trans_id`.

RADOS events without `trans_id` become background spans instead of being attached to a request.

Correlated RADOS spans are marked with `rgw.correlation = "same_thread"`. Background RADOS spans are marked with `rgw.correlation = "none"` and a reason such as `missing_trans_id` or `classified_background_role`.

When `--correlate-inferred` is enabled, untagged RADOS events can be attached to a request only if there is exactly one same-PID candidate in the configured correlation window and the RADOS role is not classified as RGW background work. These spans use `rgw.correlation = "inferred"` and `rgw.correlation_reason = "pid_time_window"`.

For OTLP live mode, old request groups and background RADOS ops are queued to a background exporter when their correlation TTL expires. This bounds memory growth while keeping a conservative window for late RADOS events to join a request without blocking ring-buffer polling on collector latency.

---

## Shape

Correlated traces use one root request span with RADOS child spans:

```text
rgw.request
  rados.op
  rados.op
```

The request span has `rgw.trans_id`, `rgw.request_class`, and `rgw.duration_quality` attributes.

Each `rados.op` child span uses the request trace ID and request span ID as its parent.

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

`rgw.rados_role` is classified from object names and request context.

Roles include data, bucket index, bucket metadata, user metadata, auth metadata, GC, notify, sync, config, and unknown.

---

## Export

JSON output prints a debug document with DWARF summary, trace spans, and trace diagnostics counters.

OTLP output sends OTLP/HTTP protobuf to `--otlp-endpoint` and sets `service.name` from `--service-name`.

The exporter uses a bounded blocking HTTP client with configurable timeout, retry count, extra headers, periodic flush interval, and correlation TTL.

Trace diagnostics count decoded events, decode errors, request markers, RADOS ops, correlated/background RADOS ops, same-thread and inferred correlations, missing-`trans_id` background ops, background breakdowns by role/reason, capture truncation counters, produced spans, expired request groups, expired background RADOS ops, dropped OTLP queue spans, and BPF-side drop/failure counters. OTLP export logs add export batches, attempts, and failures.

It supports HTTP and HTTPS.

It supports optional gzip compression, span-count batching, and encoded-size batching.

---

## Limit

Native DWARF parsing supports the current RGW/RADOS probe set: `Objecter::_send_op`, `Objecter::_finish_op`, and `RGWREST::get_handler`.

It discovers debug data from embedded DWARF, `.gnu_debuglink`, and build-id paths, then extracts module build IDs, probe PCs, variable locations, and member field paths into the existing probe field model.

`cephtrace` JSON import remains supported as a stable fallback and oracle for native extraction.

Build IDs are validated against discovered binaries. Mismatches fail by default and require `--allow-build-id-mismatch` to continue.

Field offsets can be wrong if native debug data or imported JSON does not match the runtime binaries.

Request correlation is intentionally conservative.

Cross-thread, late async, startup, and background RADOS operations may remain standalone spans. Optional inferred correlation never joins ambiguous candidates.

See [Production Runbook](RUNBOOK.md) for operating guidance and troubleshooting.
