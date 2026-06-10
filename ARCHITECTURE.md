# Architecture

Live tracing pipeline for RGW and RADOS.

---

## Follow

`rgwtrace` starts by loading Ceph DWARF JSON with function addresses and variable field paths.

The Linux runner opens the BPF skeleton, configures Ceph ABI offsets, populates the `hprobes` map, attaches uprobes, and polls the ring buffer.

Before live attach, preflight validation checks CLI input, discovered target files, required DWARF functions, and minimum variable-field counts for the probes used by the BPF program.

Pipeline:

```text
DWARF JSON -> hprobes -> eBPF uprobes -> ring buffer -> Rust events -> spans -> JSON or OTLP protobuf
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

---

## Correlate

The BPF layer stores RGW request context by Linux thread ID when it reads a `trans_id`.

`Objecter::_send_op` copies that `trans_id` into the RADOS event when the same thread context is available.

The Rust collector groups request and RADOS events by `trans_id`.

RADOS events without `trans_id` become background spans instead of being attached to a request.

---

## Shape

Correlated traces use one root request span with RADOS child spans:

```text
rgw.request
  rados.op
  rados.op
```

The request span has `rgw.trans_id` and `rgw.request_class` attributes.

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

`rgw.rados_role` is classified from object names and request context.

Roles include data, bucket index, bucket metadata, user metadata, auth metadata, GC, notify, sync, config, and unknown.

---

## Export

JSON output prints a debug document with DWARF summary and trace spans.

OTLP output sends OTLP/HTTP protobuf to `--otlp-endpoint` and sets `service.name` from `--service-name`.

The exporter uses a bounded blocking HTTP client with configurable timeout, retry count, and extra headers.

It supports plain HTTP only.

It does not support HTTPS, compression, batching, or incremental flush yet.

---

## Limit

Native DWARF parsing is not implemented.

Use matching `cephtrace`-generated DWARF JSON for the Ceph binaries being traced.

Build IDs are parsed but not validated against discovered binaries yet.

Field offsets can be wrong if the DWARF JSON and runtime binaries do not match.

Request correlation is intentionally conservative.

Cross-thread, late async, startup, and background RADOS operations may remain standalone spans.
