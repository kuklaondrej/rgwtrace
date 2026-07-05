# Bugfix: remove the dead request-lifecycle path

## What happened

The event ABI defined `RGWTRACE_EVENT_REQUEST_START` (in both
`bpf/rgwtrace_events.h` and `src/events.rs`), and the collector carried a full
start/end correlation path: a `starts_by_tid` staging map, a
`saw_request_start` flag, and a `rgw.duration_quality = "request_lifecycle"`
value produced when a START was matched to a later END.

None of that was reachable in production. The only request probe,
`RGWREST::get_handler` (`bpf/rgwtrace.bpf.c`), never emitted
`RGWTRACE_EVENT_REQUEST_START` — it emitted only `RGWTRACE_EVENT_REQUEST_END`,
and that END event already carries the seeded `start_ns` alongside the
probe-time `end_ns`. So in real captures the START-staging code, the
`saw_request_start` flag, and `duration_quality == "request_lifecycle"` were
dead. The unit tests, however, pushed synthetic `RequestStart` events and
asserted `request_lifecycle`, exercising a path that could never run live.

## Why it mattered

- **False confidence.** Tests validated a code path that production never
  reached, so the suite looked greener than the behavior warranted.
- **Misleading output contract.** `rgw.duration_quality = "request_lifecycle"`
  advertised a full request lifecycle measurement that the tracer cannot
  actually produce. RGW exposes no safe request-completion probe — a
  `process_request` return probe crashed RGW in live testing (see AGENTS.md and
  `ARCHITECTURE.md`) — so a genuine start-to-completion latency is unattainable
  by design. Emitting a START from the entry probe would only have doubled
  per-request ring-buffer volume (raising drop probability) to describe the same
  `get_handler` dispatch instant the END already captured.

## The fix

Adopt an explicit single-marker model and delete the dead path:

- **BPF**: `uprobe_rgw_get_handler` emits exactly one request marker
  (`RGWTRACE_EVENT_REQUEST_END`), which carries both the seeded `start_ns` and
  the probe-time `end_ns`. No START is emitted.
- **ABI**: `RGWTRACE_EVENT_REQUEST_START` stays reserved byte-for-byte in both
  `bpf/rgwtrace_events.h` and `src/events.rs` for compatibility, but there is no
  `TraceEvent::RequestStart` variant. If such an event ever arrives, the live
  decoder routes it through the existing unknown-event path (counted as a decode
  error) rather than fabricating a request span.
- **Collector**: removed `starts_by_tid`, `saw_request_start`, the
  `RequestStart` handler branch, the start/end matching helpers, and the
  `request_lifecycle` branch of `request_duration_quality`. Two honest values
  remain: `marker` (request seen via its END marker) and `rados_bounds`
  (request reconstructed only from correlated RADOS child bounds).
- **Span construction**: the request span's `end_ns` is clamped up to `start_ns`
  so an out-of-order marker can never produce a span that ends before it starts
  (the JSON validator rejects `start_ns > end_ns`). Raw event values are left
  untouched.
- **Contract narrowed**: the e2e validator
  (`tests/e2e/verify-rgwtrace-json.py`) no longer accepts `request_lifecycle`.
  README, RUNBOOK, and ARCHITECTURE describe the two-value contract.
