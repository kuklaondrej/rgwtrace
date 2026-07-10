# Bugfix: match versioned-soname libraries to artifact modules

## What happened

On a real Ubuntu jammy Ceph 18.2.8 radosgw, live tracing produced RGW request
markers but **`rados_ops = 0`** (all drop/correlation counters zero), and — with
strict build-id checking — librbd **hard-failed** preflight with
`DWARF JSON has no build ID for this module`.

Ubuntu ships the DWARF-bearing real files under *versioned* names
(`librados.so.2.0.0`, `librbd.so.1.18.0`) reached through *soname symlinks*
(`librados.so.2`, `librbd.so.1`). The exported artifact keys its modules by the
versioned real filename:

```
"librados.so.2.0.0": { "func2pc": { "Objecter::_send_op": ... }, ... }
"librbd.so.1.18.0":  { ... }
```

rgwtrace matched an artifact module to a target library by the **exact basename**
of the discovered/target path:

- Auto-discovery without `--pid` returns the SYMLINK path
  (`/usr/lib/librados.so.2`, basename `librados.so.2`).
- An explicit `--librados-path /usr/lib/librados.so.2` (symlink) is the same.

`librados.so.2` matched no key `librados.so.2.0.0`, so
`function_addr("librados.so.2", "Objecter::_send_op")` returned `None` and the
librados `_send_op`/`_finish_op` uprobes were **silently skipped**. On jammy the
RGW data path executes librados' *local* `_send_op` (libceph-common's global copy
fires 0×), so with that probe missing nothing was captured. librbd hit the same
mismatch and, since basename `librbd.so.1` matched no key `librbd.so.1.18.0`,
had no DWARF build id to compare and hard-failed the build-id check.

`--pid` masked the bug only because `/proc/PID/maps` reports the versioned
mmap'd name (`librados.so.2.0.0`).

## Why it mattered

A completely silent, high-value failure: the tool looked healthy (it attached,
emitted request spans, exited cleanly) yet captured none of the RADOS operations
that are the whole point of the trace. The only visible symptom was
`rados_ops = 0`, easy to mistake for "no RADOS traffic" rather than "the probe
never attached".

## The fix

1. **One canonicalizing key helper.** `module_key_for_path(&Path)`
   (`src/dwarf_json.rs`) canonicalizes the path — resolving the soname symlink to
   the versioned real file — before taking the basename, falling back to the
   path as-given when canonicalize fails (e.g. a `/proc/<pid>/root` path, or a
   nonexistent path in tests). Attach (`src/live/linux.rs`), preflight and the
   build-id check (`src/preflight.rs`), and discovery (`src/targets.rs`) all route
   through it, so they agree on a module's key. Discovery also returns the
   canonicalized real path.

2. **Exact-then-unique-soname resolution.** `DwarfInfo::match_module`
   (`src/dwarf_json.rs`) tries an exact key first, then a soname-aware fallback
   matching any module sharing the same `lib<name>.so.<major>` stem, so
   `librados.so.2` resolves to `librados.so.2.0.0` and vice-versa. It never
   crosses major versions (`librados.so.2` never matches `librados.so.3`).
   `soname_stem` only accepts a well-formed numeric soname
   (`major[.minor[.patch]]`), so backup/malformed names (`libfoo.so.2.backup`,
   `libfoo.so..junk`, `foo.so.debug.anything`) stay exact-only. If two or more
   modules share the stem, the fallback **refuses to guess** — an arbitrary pick
   could pair one module's function address with another module's field
   descriptors (hprobe entries are keyed by a global function id and populated for
   every module) — and returns `Ambiguous`, which preflight surfaces as an
   explicit error naming the candidates. `function_addr`, the var-field and
   raw-pointer lookups, and the build-id lookup all go through this resolution.

3. **Preflight silent-skip warning.** When a discovered rados library resolves to
   no artifact module even though the artifact carries a `Objecter::_send_op`
   address — the exact signature that hid this bug — preflight logs an advisory
   warning.

## Result (jammy, librados given as the SYMLINK path)

| binary | librados path | rados_ops |
| --- | --- | --- |
| pre-fix, `--allow-build-id-mismatch` | `librados.so.2` (symlink) | **0** |
| pre-fix, strict build-id | `librados.so.2` (symlink) | hard-fails build-id check |
| post-fix | `librados.so.2` (symlink) | **~240** |
| post-fix | `--pid` auto-discovery (versioned) | ~240 (no regression) |
