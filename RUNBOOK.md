# Production Runbook

Operational notes for running `rgwtrace` against live RGW hosts.

---

## Requirements

- Linux host with eBPF and uprobes enabled.
- `root` or equivalent BPF/perf privileges. Running with `sudo` is the expected path today.
- Ceph/RGW binaries matching the imported `cephtrace` DWARF JSON.
- Reachable OTLP/HTTP endpoint when using `--output otlp`.
- Linux `amd64` binary built with `./scripts/build-linux-container.sh` when building from macOS.

---

## Preflight

Run preflight before live attach:

```sh
sudo rgwtrace \
  --import-json 18.2.8-1jammy_dwarf_traceid.json \
  --pid "$(pidof radosgw | awk '{print $1}')" \
  --preflight
```

Use explicit paths when discovery is ambiguous:

```sh
sudo rgwtrace \
  --import-json 18.2.8-1jammy_dwarf_traceid.json \
  --preflight \
  --librados-path /lib/librados.so.2 \
  --librbd-path /lib/librbd.so.1 \
  --libceph-common-path /usr/lib/ceph/libceph-common.so.2 \
  --radosgw-path /usr/bin/radosgw
```

Build ID mismatches are warnings by default. Use `--strict-build-id` to fail preflight on missing or mismatched IDs.

---

## JSON Smoke Test

Start with JSON output for a short run:

```sh
sudo rgwtrace \
  --import-json 18.2.8-1jammy_dwarf_traceid.json \
  --pid "$(pidof radosgw | awk '{print $1}')" \
  --timeout 30 \
  --output json
```

Check `trace.diagnostics` for decoded events, RADOS op counts, correlation counts, decode errors, and expired spans.

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
  --otlp-endpoint http://tempo.example.net:4318/v1/traces \
  --service-name rgwtrace \
  --otlp-flush-interval 30 \
  --correlation-ttl 120
```

Use `--log-level info` or `RUST_LOG=rgwtrace=debug` to see export summaries and retry details.

---

## Common Preflight Failures

- `--pid must be a positive process id`: pass a single live RGW PID.
- `failed to discover ...`: pass the corresponding explicit path flag.
- `missing function address`: DWARF JSON does not match the binary/module name.
- `missing variable fields`: DWARF JSON is incomplete for the probe set.
- `build ID mismatch`: regenerate DWARF JSON for the exact binaries or rerun without `--strict-build-id` only if the mismatch is understood.

---

## Common OTLP Failures

- `connection refused`: nothing is listening on the host/port from the RGW host.
- `timed out`: firewall, routing, load balancer, or collector availability issue.
- HTTP `404`: wrong path; OTLP/HTTP traces usually use `/v1/traces`.
- HTTP `415`: receiver does not accept OTLP protobuf on that endpoint.
- HTTP `4xx`: endpoint/auth/config issue; not retried.
- HTTP `429` or `5xx`: retried according to `--otlp-retries`.

---

## Background RADOS Spans

`rgw.background.rados_op` means no RGW `trans_id` was available when the RADOS op was captured.

Expected causes include RGW startup work, GC, notify/sync/config work, late async work, cross-thread work, and true background RADOS operations.

Inspect:

- `rgw.rados_role` for object classification.
- `rgw.correlation = "none"`.
- `rgw.correlation_reason = "missing_trans_id"`.
- `trace.diagnostics.missing_trans_id_background_ops` for volume.

Do not assume background spans are errors. A rising background ratio is useful signal for deciding whether a future conservative fallback correlation is warranted.

---

## Verification

Run local checks before shipping changes:

```sh
./scripts/verify.sh
```

Include the Linux container build when needed:

```sh
VERIFY_CONTAINER_BUILD=1 ./scripts/verify.sh
```
