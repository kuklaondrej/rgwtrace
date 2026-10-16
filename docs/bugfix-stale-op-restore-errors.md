# Report stale-op restore failures

The stale `rados_ops` sweep temporarily removes a refreshed entry so it can
decide whether the value it removed is still live. It restores a live value
with `BPF_NOEXIST`, allowing a newer submit to win if it has already inserted
the same key.

Previously, every failed restore was treated as proof that a newer submit had
won. A full map can also reject the restore, though, leaving the entry lost
while the sweep reports success. The sweep now treats only `EEXIST` as a
superseding submit. Other restore failures carry context back to the poll loop
so the loss is visible in its error report.
