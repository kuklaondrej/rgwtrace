# Bound pending inference checks during request drains

The request expiry drain preserves the full TTL of any request that could still
change a pending inference decision. It previously checked that condition with
an interval index ordered by start time and grouped by interval length. Long
RADOS operations could share a length class and have already ended before a
request began, causing the drain to visit every such operation before rejecting
it. Large batches could therefore delay the ring-buffer poll thread.

`IntervalSet` now keeps an augmented interval treap with each subtree's lowest
start and highest end. A query skips a subtree if it lies wholly before or
after the request, so both old ended operations and newer not-yet-started
operations are excluded. The regression test builds 10,000 intervals on each
side of the request and checks that no query visits more than 64 tree nodes.
The ignored
`collector_bench_drain_pending_no_overlap` benchmark measures this drain-guard
case.
