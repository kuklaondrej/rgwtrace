# Bound pending inference checks during request drains

The request expiry drain preserves the full TTL of any request that could still
change a pending inference decision. It previously checked that condition with
an interval index ordered by start time and grouped by interval length. Long
RADOS operations could share a length class and have already ended before a
request began, causing the drain to visit every such operation before rejecting
it. Large batches could therefore delay the ring-buffer poll thread.

`IntervalSet` now also keeps an end-ordered index. The drain guard starts at the
request's start time, skipping every pending operation that ended earlier. The
regression test builds 10,000 long intervals ending at 170 seconds and verifies
that a request at 180 seconds visits zero entries. The ignored
`collector_bench_drain_pending_no_overlap` benchmark measures this drain-guard
case.
