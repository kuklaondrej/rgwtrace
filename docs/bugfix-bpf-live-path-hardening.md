# Bug fix: BPF live-path hardening

[Back to documentation](README.md)

One audit pass over the BPF maps, the event ABI, and the live poll loop found
seven problems. This page records what each one did, why, and the fix.

## 1. Garbled cls method names for class names of 8+ bytes

**What happened.** For an OSD `call` op the BPF program reads the class and
method names out of the op's indata, which is laid out as
`class || method || payload`. It clamped the class length to the 8-byte
`cls_name` buffer and then reused the *clamped* length as the method's offset:

```c
cls_len = sizeof(event->cls_ops[i].cls_name) - 1;          /* 7 */
...
rgwtrace_probe_read_user(method_name, method_read_len, data + cls_len);
```

For `refcount` (8 bytes) the method read started at the final `t` and returned `tpu`
instead of `put`; `timeindex` and `2pc_queue` broke the same way. Only the
class carried a truncation flag, so the method looked valid.

**Fix.** `cls_len` is never rewritten: only the copy lengths (`cls_read_len`,
`method_read_len`) are clamped, and the method is read at `data + cls_len`.
`cls_name` is widened to 16 bytes (`MAX_CLS_NAME`), which holds every in-tree
Ceph class. `struct rgwtrace_rados_event` grows from 536 to 560 bytes.

## 2. `rados_ops` too small and never swept

**What happened.** `rados_ops` held 8192 entries, below Ceph's default
`objecter_inflight_ops` (24576). An op whose client exits between `_send_op` and
`_finish_op` is never deleted, so a long session slowly filled the map, after
which every new op was rejected (`bpf_rados_map_drops`).

**Fix.** The default is 32768 and `--bpf-rados-ops-entries` overrides it before
load. The poll loop sweeps the map every `min(30 s, threshold / 10)` and deletes
entries whose `sent_ns` is older than `--rados-ops-stale-after` (default 300 s).
The count is the new `stale_rados_ops_swept` diagnostic.

The sweep must never evict a live op. The threshold has a 60 s floor, twice
Ceph's 30 s slow-op complaint time, and the 300 s default is far above any
healthy op latency. An entry with `sent_ns == 0` (inserted, not yet stamped) is
never swept. An op that really is blocked past the threshold (an inactive PG) is
evicted; its late `_finish_op` shows up as `bpf_rados_finish_misses` and emits no
event. `0` turns the sweep off.

The scan and the delete are not atomic with BPF. If Ceph resends a candidate op
in between (same `cid`/`tid` key), `_send_op` replaces the entry with a fresh
`sent_ns`, and a blind delete by key would remove a live op. Each candidate is
therefore removed with an atomic lookup-and-delete and judged on the value
actually removed; a refreshed one is put back with `NO_EXIST` (a still newer
submit wins). On kernels before 5.14 the sweep re-reads and deletes only if
still stale.

## 3. Ring buffer too small, request records oversized

**What happened.** The ring buffer was a fixed 256 KiB and every record
reserved the whole 544-byte union, including request markers whose payload is
160 bytes. It held ~474 records: at 20k ops/s, a reader stall over ~25 ms
dropped events.

**Fix.** `--ringbuf-size` (power of two, page multiple, at most 1 GiB, default
16 MiB) is applied with `bpf_map__set_max_entries` before load. 16 MiB holds
~29k RADOS records, ~1.4 s of stall at 20k RADOS ops/s, and costs 16 MiB of
locked kernel memory. Request markers now reserve
`struct rgwtrace_request_record` (168 bytes). The decoder already accepted any
record at least header + payload long; new tests pin that an exactly sized
request record decodes and a byte shorter does not.

## 4. `hprobes` was a hash for a dense key space

**What happened.** `hprobes` was an 8192-entry `HASH` holding fewer than 80
small integer keys, and `_send_op` does about a dozen lookups on it per op while
RGW holds the Objecter lock.

**Fix.** It is an 80-slot `ARRAY` (keys are `function base id + var_field
index`, highest base 70). The verifier inlines an array lookup to a bounds check
and an add. Because an array lookup never misses for an in-range key, an
unpopulated slot would read as a zeroed "register 0" descriptor, so
`struct VarField` gains a `present` word (now 100 bytes), userspace sets it on
every slot it writes, and every lookup goes through `hprobe_lookup()`, which
returns NULL for `present == 0`.

## 5. Uninitialized padding sent to the kernel

**What happened.** `populate_hprobes` viewed `VarFieldKernel` as `&[u8]` with
`slice::from_raw_parts`. The struct has implicit padding after each `bool`, so
that read uninitialized memory, which is undefined behavior in Rust.

**Fix.** `VarFieldKernel::to_bytes()` writes the C layout field by field into a
zeroed buffer. The bench crate's mirror had the same read and gets the same fix.

## 6. No compile-time check of the event ABI

**What happened.** Nothing tied the `Raw*` sizes and offsets in `src/events.rs`
to the C structs. The mirror tests checked hand-picked substrings, so a field
added on one side compiled cleanly and decoded garbage.

**Fix.** The headers define the record sizes and `_Static_assert` them; Rust
const-asserts the same numbers and key offsets with `size_of` and `offset_of!`.
The diagnostics counter indices moved from `src/live/linux.rs` to
`src/events.rs`, and a test checks that every `RGWTRACE_*` constant in the
headers appears in Rust with the same value.

| Struct | Bytes |
|---|---|
| `struct rgwtrace_request_event` | 160 |
| `struct rgwtrace_rados_event` | 560 |
| `struct rgwtrace_event` (payload at 8) | 568 |
| `struct rgwtrace_request_record` | 168 |
| `struct VarField` | 100 |

## 7. SIGTERM lost the run; a dead `--pid` target was not noticed

**What happened.** `ctrlc` was built without its `termination` feature, so only
SIGINT stopped the run cleanly. `systemctl stop` sends SIGTERM, which killed the
process and lost every span not yet exported. Separately, a `--pid` session kept
polling after its target exited, capturing nothing.

**Fix.** `ctrlc` is built with `termination`, so SIGTERM and SIGHUP take the
Ctrl-C path. The poll loop watches the target with `pidfd_open` (falling back to
`/proc/<pid>/stat` when the syscall is unavailable) and, once it has exited,
drains the ring buffer one last time (records written between the last poll and
the exit would otherwise be dropped with the ring), logs a warning, and
finalizes output normally.

## Verification limits

The BPF changes compile in the Linux container (clang 14, skeleton generation),
but the container cannot load programs. The verifier check,
`scripts/verify-bpf-load.sh`, runs in CI. The changes follow the patterns the
verifier already accepts: masked copy lengths, a constant-size ring-buffer
reserve, and a presence check on an array value pointer.
