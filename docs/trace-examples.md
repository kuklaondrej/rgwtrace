# Reading a trace

[Documentation index](README.md) · [Project overview](../README.md)

These examples show RGW request spans and their correlated RADOS children with
`--correlate-cross-thread` enabled. That option is off by default and coverage
depends on the RGW build and submission path; see the
[runbook](../RUNBOOK.md#background-rados-spans) for prerequisites and limitations.

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

Without `--correlate-cross-thread`, that same DELETE keeps only the `same_thread` head `stat`; `index prepare_op` and `obj_remove` fall out as standalone `rgw.background.rados_op` spans with `rgw.correlation_reason = "missing_trans_id"`, If the request-END marker is also absent, the request duration is derived from its children and can end at ~1 ms instead of 41 ms. With the END marker present, losing those children does not shorten the measured request interval.


## A streamed (`--output jsonl`) capture

A long session streamed with `--output jsonl` is one `{dwarf, trace}` document
per line: one line per flush interval with the requests that expired since the
previous one, then a final line at exit. Abbreviated:

```text
{"dwarf":{...},"trace":{"diagnostics":{"rados_ops":1843,"spans_produced":912,...},"service_name":"rgwtrace","spans":[...912 spans...]}}
{"dwarf":{...},"trace":{"diagnostics":{"rados_ops":3710,"spans_produced":955,...},"service_name":"rgwtrace","spans":[...955 spans...]}}
{"dwarf":{...},"trace":{"diagnostics":{"rados_ops":3762,"spans_produced":31,...},"service_name":"rgwtrace","spans":[...31 spans...]}}
```

`rados_ops` grows line by line because every counter is cumulative; read run
totals from the last line. `spans_produced` is per line, so the run produced
912 + 955 + 31 spans. A request and all its children are always on the same line,
because a request group is drained as a whole, and no span id ever appears on two
lines.

For the span model and captured attributes, see
[Architecture](../ARCHITECTURE.md#shape). To distinguish measured request durations
from bounds derived from RADOS children, see
[Capture quality](../RUNBOOK.md#capture-quality).
