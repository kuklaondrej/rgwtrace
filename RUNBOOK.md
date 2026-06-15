# Production Runbook

Operational notes for running `rgwtrace` against live RGW hosts.

---

## Requirements

- Linux host with eBPF and uprobes enabled.
- `root` or equivalent BPF/perf privileges. Running with `sudo` is the expected path today.
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

With `--pid`, discovered library and executable paths are opened through `/proc/<pid>/root` so the host attaches to the same inode the target process sees inside its mount namespace.

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

If native mode cannot discover the Ceph version, add `--ceph-version <version>`. The major version selects the pre-Squid or Squid+ `ceph_osd_op` ABI layout.

Build ID mismatches fail preflight and live attach by default. Use `--allow-build-id-mismatch` only when the mismatch is understood.

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

Use `--log-level info` or `RUST_LOG=rgwtrace=debug` to see export queue summaries, export attempts, and retry details.

Use `--otlp-max-bytes-per-batch` when a collector or proxy rejects large protobuf payloads. The byte limit is checked before gzip compression; `0` disables byte-based splitting.

---

## Common Preflight Failures

- `--pid must be a positive process id`: pass a single live RGW PID.
- `failed to discover ...`: pass the corresponding explicit path flag.
- `missing function address`: native debug data or imported JSON lacks a required probe PC.
- `missing variable fields`: native debug data or imported JSON lacks required variable locations or member field paths.
- `build ID mismatch`: verify native module/debug files, regenerate JSON for the exact binaries, or rerun with `--allow-build-id-mismatch` only if the mismatch is understood.

---

## Common OTLP Failures

- `connection refused`: nothing is listening on the host/port from the RGW host.
- `timed out`: firewall, routing, load balancer, or collector availability issue.
- HTTP `404`: wrong path; OTLP/HTTP traces usually use `/v1/traces`.
- HTTP `415`: receiver does not accept OTLP protobuf on that endpoint.
- TLS/certificate errors: verify the endpoint certificate chain from the RGW host and use `http://` only for trusted local networks.
- HTTP `4xx`: endpoint/auth/config issue; not retried.
- HTTP `429` or `5xx`: retried according to `--otlp-retries`.

---

## Background RADOS Spans

`rgw.background.rados_op` means no RGW `trans_id` was available when the RADOS op was captured.

Expected causes include RGW startup work, GC, notify/sync/config work, late async work, cross-thread work, and true background RADOS operations.

Inspect:

- `rgw.rados_role` for object classification.
- `rgw.correlation = "none"`.
- `rgw.correlation_reason`, usually `missing_trans_id` or `classified_background_role`.
- `trace.diagnostics.missing_trans_id_background_ops` for volume.
- `trace.diagnostics.background_rados_by_role` and `trace.diagnostics.background_rados_by_reason` for breakdowns.

Do not assume background spans are errors. A rising background ratio is useful signal for deciding whether `--correlate-inferred` is warranted.

`--correlate-inferred` can attach untagged RADOS ops to a request only when there is one same-PID candidate in the correlation window and the role does not look like RGW background work. Inferred spans use `rgw.correlation = "inferred"` and `rgw.correlation_reason = "pid_time_window"`.

---

## Capture Quality

Request spans include `rgw.duration_quality`.

- `marker`: current live probe path observed a request marker, not full lifecycle latency. The request span still envelopes correlated RADOS child bounds.
- `request_lifecycle`: both request start and end markers were observed.
- `rados_bounds`: the request group was built from RADOS timestamps only.

RADOS spans may include `rgwtrace.truncated` when fixed BPF capture limits clipped object names, `trans_id`, acting sets, op lists, class names, or method names.

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

Run a real BPF verifier load check on Linux when BPF code changes:

```sh
VERIFY_BPF_LOAD=1 ./scripts/verify.sh
```

Run dependency audit checks when dependency or toolchain inputs change:

```sh
VERIFY_AUDIT=1 ./scripts/verify.sh
```
