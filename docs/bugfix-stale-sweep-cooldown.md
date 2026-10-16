# Pause between bounded stale-op sweep cycles

Bounding batches prevented a concurrent-delete hash iterator from monopolizing
ring-buffer consumption, but restarting immediately made map scans continuous.
Busy gateways paid up to 256 key reads and value lookups after every ring poll,
even when all entries were fresh.

Completed or failed cycles now wait for one tenth of the stale threshold,
clamped to 1–30 seconds, before the next scan. The deadline is checked before
map access. Batches within an active cycle retain their existing bounds and
continue between ring polls. Successful deletion counts survive a failed batch.

Tests check the delay bounds, deadline boundary, retained counts, and the
existing infinite-iterator batch limits.
