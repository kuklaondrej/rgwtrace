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
- `rgw.correlation_reason`, usually `missing_trans_id` or `classified_background_role`; with `--correlate-inferred`, it can also be `no_inference_candidate` or `ambiguous_inference_candidates`.
- `trace.diagnostics.missing_trans_id_background_ops` for volume.
- `trace.diagnostics.inference_no_candidate_rados_ops` and `trace.diagnostics.inference_ambiguous_rados_ops` when inferred correlation is enabled.
- `trace.diagnostics.background_rados_by_role` and `trace.diagnostics.background_rados_by_reason` for breakdowns.

Do not assume background spans are errors. A rising background ratio is useful signal for deciding whether `--correlate-inferred` is warranted.

`--correlate-inferred` can attach untagged RADOS ops to a request only when there is one conservative candidate in `--inference-window` and the role does not look like RGW background work. A unique matching RADOS send thread is preferred over same-PID/time-window candidates. Inferred spans use `rgw.correlation = "inferred"` and `rgw.correlation_reason = "pid_time_window"`. Ambiguous or out-of-window candidates remain background spans.

---

## Capture Quality

Request spans include `rgw.duration_quality`, which has exactly two values.

- `marker`: the single safe RGW probe observed a request marker, not full lifecycle latency. The request span still envelopes correlated RADOS child bounds.
- `rados_bounds`: the request group was built from RADOS timestamps only.

There is no `request_lifecycle` value. Measuring a true request lifecycle would require a request-completion probe RGW cannot safely expose (a `process_request` return probe crashes RGW), so only the single-marker and RADOS-bounds qualities occur.

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

On the current baseline (no cross-thread bridge), cross-thread data ops are not
correlated, so the coverage gates run at `0` — the functional test's
`REQUIRE_GET_READ_CORRELATION` / `REQUIRE_PUT_WRITE_CORRELATION` env vars default
to `0`, and the zero-mis-correlation check still holds. Raise those thresholds
(0.90, and 0.80 with `WORKLOAD_CONCURRENT_REQUESTS`) once Stage 3's
`--correlate-cross-thread` bridge is enabled. Use `--unique-keys` (already set by
the functional test) so the object→request mapping stays unambiguous.

Without `--workload-manifest`, the verifier behaves exactly as before.
