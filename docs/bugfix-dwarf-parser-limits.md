# Bugfix: bound native DWARF parsing work and memory

## What happened

Native DWARF extraction (`--dwarf-source native`) runs as root on storage nodes
and parses whatever ELF/DWARF it finds for radosgw and the Ceph libraries,
often from a container's `/proc/<pid>/root`. An audit found that a malformed or
hostile file could hang the tracer, abort it, or drive it out of memory, and
that two version/tool lookups trusted the host where they should not:

| Input | Old behavior |
|-------|--------------|
| typedef/const cycle | `peel_type_qualifiers` looped forever |
| inheritance cycle | `find_member_entry` looped forever (no visited set) |
| self-pointing pointer type in a field path | `translate_field_path_from` looped forever |
| deeply nested DIEs | recursive walkers overflowed the stack; the process aborted |
| sparse multi-GB target or debug file | `fs::read` allocated its full apparent size |
| compressed section declaring a huge size | `uncompressed_data()` reserved and inflated it |
| container target with no embedded version string | version came from the HOST `dpkg-query`/`rpm` |
| `ldconfig`, `dpkg-query`, `rpm` | resolved through `PATH` while running as root |

A wrong Ceph version is not cosmetic: it selects the `ceph_osd_op` ABI layout
the BPF side reads, so a guessed version means wrong reads. An out-of-memory
tracer on a storage node is worse than a failed one, because the OOM killer may
choose an OSD.

## The fix

**Reference cycles.** Every loop that follows DWARF references is bounded:

- `peel_type_qualifiers` and the pointer/reference hops in
  `translate_field_path_from` stop after 64 links (`TYPE_CHAIN_LIMIT`).
- `find_member_entry` searches each base class at most once (visited set) and
  at most 4096 classes (`INHERITANCE_SEARCH_LIMIT`).

A limit that is hit is an error naming the DIE, for example:

```text
type qualifier chain starting at DIE at .debug_info offset 0x2d exceeds 64
typedef/cv links (malformed DWARF: reference cycle?)
```

**Deep nesting.** The whole-unit searches (`find_type_definition`,
`entry_scopes`, `find_named_type_field_path`) are now iterative `next_dfs`
walks, so their stack use does not depend on the file. The two function walkers
(`collect_function_pcs`, `collect_function_var_fields`) stay recursive: their
`EntriesTree` skips a subprogram body through `DW_AT_sibling` without parsing
it, which a `next_dfs` walk cannot do. They only descend through scopes
(namespaces, classes), so they are capped at 256 levels (`SCOPE_NESTING_LIMIT`)
and fail with `DWARF scope nesting deeper than 256 levels at DIE ...`.

**Memory.** A new `--max-debug-file-bytes` (default `4G`) bounds:

1. every file read whole: the target, its `.gnu_debuglink` or build-id debug
   file, and its DWZ supplementary file. The size is checked before the read and
   the read itself is capped;
2. the total bytes decompressed out of one file's compressed DWARF sections.
   Each compressed section is charged with the size its header DECLARES before
   anything is inflated.

```text
target /proc/1234/root/usr/bin/radosgw is 21474836480 bytes, over the
4294967296-byte limit (raise it with --max-debug-file-bytes)

compressed DWARF section .debug_info of /usr/lib/debug/.build-id/ab/cdef.debug
declares 68719476736 uncompressed bytes; with the 0 bytes already decompressed
from this file that exceeds the 4294967296-byte limit (raise it with
--max-debug-file-bytes)
```

The default is 4 GiB. A limit that refuses a real Ceph debug file breaks the
tool, so the default leaves wide headroom over the largest module (radosgw) and
is still far below the tens of GB a crafted file could demand. No real Ceph
debug file was measured for this change. If one exceeds the default, the error
names the file and the flag to raise. A DWZ supplementary file over the limit
is skipped with a warning, the same way a missing one is.

**Version and tools.** A target under `/proc/<pid>/root` whose root is not the
host's own `/` (compared by device and inode, so an uncontainerized process
still counts as the host) no longer falls back to the host package database.
Without an embedded `ceph version` string or MicroCeph metadata, extraction
fails and asks for `--ceph-version`. `ldconfig`, `dpkg-query` and `rpm` run by
absolute path with a cleared environment and `PATH=/usr/sbin:/usr/bin:/sbin:/bin`
(`src/host_tools.rs`).

## Performance changes in the same PR

- Names are demangled only if they contain a probe's leaf identifier.
  `cpp_demangle` ran on every global text symbol and every subprogram linkage
  name. An Itanium-mangled name spells its own identifiers out verbatim, so a
  name without any probe's leaf identifier (`_send_op`, `get_handler`,
  `req_state`, `rgw_rados_operate`, ...) can never demangle to a probe key. The
  identifier set is derived from the probe table.
- Each target is read once. The embedded version string is scanned from the
  buffer `parse_module` already holds, with a search that jumps between
  occurrences of the first byte. The preflight build-ID check reads only the
  header and note ranges through `object::ReadCache`.
- Uncompressed DWARF sections are borrowed from the file buffer (`Cow`) instead
  of being copied.

Measured on a 103 MB ELF with full DWARF (rgwtrace's own Linux debug build,
used as all three targets), `--export-dwarf-json`, release build, Linux
container, 3 runs each. No real Ceph debug binary was available locally.

| | wall time | max RSS |
|---|---|---|
| before (`main`) | 2.58-2.63 s | 195 164 KiB |
| after | 1.97-2.04 s | 118 904 KiB |

The exported JSON is byte-identical. The fixture contains no probe functions,
so every walk runs to the end: this is the worst case for the walk, not the
Ceph case, where the demangling share is expected to be larger.

## Known limits (follow-ups)

- **zstd sections.** `object` 0.39 inflates a zstd section with an unbounded
  `read_to_end` and checks the declared size only afterwards. zlib (the gABI
  default, and the default of `objcopy --compress-debug-sections`) is hard-bounded by the
  declared-size check, because `flate2` writes into the reserved capacity and
  never grows it. A zstd stream that lies about its size is still inflated
  before it is rejected. Closing that requires driving `ruzstd` directly with a
  capped reader, which means a new direct dependency.
- **Repeated whole-binary searches.** `type_definition_die`,
  `translate_named_type_field_path` and `entry_scopes` still re-walk every unit
  per lookup. A one-pass name index is the fix, but it needs measurements on a
  real Ceph binary to show it pays for its memory. Reading targets through
  `ReadCache` or mmap instead of whole-file buffers is the other memory
  follow-up.
- **Double discovery.** `targets::discover` runs once in `main` and again in
  live attach (`src/live/linux.rs`). That code is outside this change.

## Tests

`src/dwarf_native_robustness_tests.rs` builds every hostile input in memory,
so these tests run on any host, with no compiler or Ceph build:

- typedef/const, inheritance and pointer cycles, built with `gimli::write`;
- a 100 000-deep DIE tree as raw `.debug_abbrev`/`.debug_info` bytes, walked on
  the default 2 MiB test-thread stack;
- hand-built ELF images (`src/test_elf.rs`) with oversized files, zlib and zstd
  compressed sections that declare 64 GiB, and a shared per-file budget;
- the prefilter's soundness over sample probe names and over the test binary's
  whole symbol table;
- `/proc/<pid>/root` detection and the `--ceph-version` error.
