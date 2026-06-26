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

The BPF program attaches RADOS probes to `Objecter::op_submit`, `Objecter::_send_op`, and `Objecter::_finish_op`.

It also attaches RGW probes to `process_request`, `RGWREST::get_handler`, `RGWOp::init`, put-object processor `prepare` methods, `rgw_rados_operate` overloads, `RadosWriter::process`, and `RadosWriter::write_exclusive`. When DWARF exposes a concrete `RadosWriter::RadosWriter` PC, rgwtrace also attaches it to cache `RadosWriter*` context from the constructor `dpp`.

`process_request` is entry-only. There is intentionally no `process_request` return probe. Scoped return probes for `rgw_rados_operate`, `RadosWriter::process`, and `RadosWriter::write_exclusive` are available through `--attach-scoped-return-probes`, but the default live attach path avoids them because some RGW/kernel combinations fault unsafe uretprobe returns. Without return probes, scoped context is bounded by short expiry and refreshed only by boundary probes.

Captured request data:

- Start timestamp.
- End or marker timestamp.
- Process ID and thread ID.
- RGW numeric request ID.
- RGW request ID string.
- RGW `trans_id`.

Captured RADOS data:

- Process ID, client ID, and operation TID.
- RGW request ID string, numeric request ID, `trans_id`, and correlation source when request context was available.
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

The BPF layer stores RGW request context by Linux thread ID at `process_request` and enriches it at `RGWREST::get_handler`.

It maps `req_state*` to request context, maps `RGWOp*` to request context in `RGWOp::init`, maps embedded put-object `RadosWriter*` instances from processor `prepare` methods, caches `RadosWriter*` request context when writer `dpp` resolves to a captured request-scoped `DoutPrefixProvider` (`RGWOp*` or `req_state*`), and narrowly falls back to the current same-thread request at the `RadosWriter` boundary when the writer `dpp` is not one of those captured request-scoped pointers. It then pushes a short-lived per-thread active request stack around scoped RGW RADOS boundary probes and maps `Objecter::Op*` to request context in `Objecter::op_submit` when an active RGW context exists.

`Objecter::_send_op` copies request identity into the RADOS event using this order:

1. `Objecter::Op*` context from `op_submit`.
2. Active per-thread RGW boundary context.
3. Same-thread request context.
4. No direct context, leaving the collector to treat the op as background or optional inferred correlation.

The Rust collector groups request and RADOS events by internal RGW request ID first (`rgw.req_id`, then numeric `rgw.request_id`), then `trans_id`, then the existing fallback request key.

Correlated RADOS spans are marked with `rgw.correlation = "op_submit_context"`, `"active_context"`, `"same_thread"`, or `"inferred"`. `rgw.correlation_source` records the BPF-side source for direct correlation. Background RADOS spans are marked with `rgw.correlation = "none"` and a reason such as `missing_trans_id`, `classified_background_role`, `no_inference_candidate`, or `ambiguous_inference_candidates`.

When `--correlate-inferred` is enabled, untagged RADOS events can be attached to a request only if there is exactly one conservative candidate in the configured inference window and the RADOS role is not classified as RGW background work. The collector first prefers a unique request whose Linux thread ID matches the RADOS send thread, then falls back to same-PID/time-window matching. Untagged RADOS ops can stay pending until request markers arrive or until expiration/final trace output makes them final background spans. Inferred spans use `rgw.correlation = "inferred"` and `rgw.correlation_reason = "pid_time_window"`. Untagged RADOS ops that are not attached remain background spans, with diagnostics distinguishing missing candidates from ambiguous candidates.

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
- `rgw.correlation_source`.
- `rgw.req_id` when captured.
- `rgw.request_id` when captured.
- `rgw.trans_id` when captured.
- `rgw.correlation_reason` when correlation is absent.
- `rgwtrace.truncated` when fixed capture limits truncated one or more fields.

`rgw.rados_role` is classified from object names and request context, including RGW data/bucket metadata, GC/notify work, realm/zone/period config objects, and RGW metadata/data sync logs.

Roles include data, bucket index, bucket metadata, user metadata, auth metadata, GC, notify, sync, config, and unknown.

---

## Export

JSON output prints a debug document with DWARF summary, trace spans, and trace diagnostics counters.

OTLP output sends OTLP/HTTP protobuf to `--otlp-endpoint` and sets `service.name` from `--service-name`.

The exporter uses a bounded blocking HTTP client with configurable timeout, retry count, extra headers, periodic flush interval, and correlation TTL.

Trace diagnostics count decoded events, decode errors, request markers, RADOS ops, correlated/background RADOS ops, `op_submit_context`, `active_context`, same-thread and inferred correlations, inference misses/ambiguity, missing-`trans_id` background ops, background breakdowns by role/reason, capture truncation counters, produced spans, expired request groups, expired background RADOS ops, dropped OTLP queue spans, and BPF-side drop/failure counters. OTLP export logs add export batches, attempts, and failures.

It supports HTTP and HTTPS.

It supports optional gzip compression, span-count batching, and encoded-size batching.

---

## Limit

Native DWARF parsing supports the current RGW/RADOS probe set: `process_request`, `RGWREST::get_handler`, `RGWOp::init`, put-object processor `prepare` methods, `rgw_rados_operate` overloads, optional `RadosWriter::RadosWriter`, `RadosWriter::process`, `RadosWriter::write_exclusive`, `Objecter::op_submit`, `Objecter::_send_op`, and `Objecter::_finish_op`.

It discovers debug data from embedded DWARF, `.gnu_debuglink`, and build-id paths, then extracts module build IDs, probe PCs, variable locations, and member field paths into the existing probe field model.

`cephtrace` JSON import remains supported as a stable fallback and oracle for native extraction.

Build IDs are validated against discovered binaries. Mismatches fail by default and require `--allow-build-id-mismatch` to continue.

Field offsets can be wrong if native debug data or imported JSON does not match the runtime binaries.

Request correlation is intentionally conservative.

Cross-thread, late async, startup, and background RADOS operations may remain standalone spans. Optional inferred correlation never joins ambiguous candidates.

See [Production Runbook](RUNBOOK.md) for operating guidance and troubleshooting.
