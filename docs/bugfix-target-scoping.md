# Bugfix: scope uprobes to the target process and its mapped binaries

Four audit findings about *what* rgwtrace probes. Each one could make the
tracer probe the wrong process or the wrong file, or read the wrong field
offsets, and none of them produced an error.

## F6: uprobes were system-wide by default

### What happened

Without `--pid`, `src/live/linux.rs` attached every uprobe with `pid = -1`.
The BPF programs had no process filter, and the `rados_ops` in-flight key was
`(cid, tid)`. Every librados client on the node then ran the probes: OSDs
through libceph-common, qemu/librbd, other gateways, and CLI tools. All of them
paid the probe cost, filled the shared ring buffer and maps, and were inside
the tracer's crash radius. A failed probe read leaves the key at `{0, 0}`, so
unrelated processes could also share one `rados_ops` entry.

### Fix

- **CLI.** Live tracing requires `--pid`. `--all-processes` (which conflicts
  with `--pid`) is the explicit opt-in for system-wide probes, and it logs a
  warning. `--dry-run`, `--preflight` and `--export-dwarf-json` attach nothing,
  so they do not need `--pid`.
- **BPF.** `const volatile __u32 TARGET_TGID` (0 means any process) is written
  into `.rodata` on the open skeleton before load. Every `SEC("uprobe")` program
  starts with:

  ```c
  if (rgwtrace_foreign_process())
    return 0;
  ```

  The gate runs before any map op, probe read or ring-buffer use, so a foreign
  process costs one helper call. `tests/bpf_source.rs` asserts that every
  uprobe program starts with the gate.
- **Key.** `struct client_op_key` is now `{ cid, tid, tgid, _pad }`. The struct
  is BPF-internal (userspace never reads `rados_ops`), so it lives only in
  `bpf/ceph_abi.h` and needs no `src/events.rs` mirror.
- **PID namespace.** `bpf_get_current_pid_tgid()` reports the init-namespace
  tgid. From a nested pid namespace, `--pid` would never match, and the run
  would capture nothing without an error. A `--pid` run therefore requires
  `/proc/self/ns/pid` to be the init namespace (`pid:[4026531836]`) and fails
  otherwise. `bpf_get_ns_current_pid_tgid` could support nested namespaces; it
  is not needed for the supported deployments (host or `--pid=host`).

## F7: hprobe descriptors were last-writer-wins across all modules

### What happened

`hprobes` is keyed by a global function id. `populate_hprobes` installed the
descriptors of every module in the artifact, so a later module overwrote an
earlier one. For example, a stale `radosgw.old` module overwrote `radosgw`, or
`_send_op` came from both librados and libceph-common. The probe then fired at
one module's address but read another module's field offsets.

### Fix

`DwarfInfo::hprobe_entries_for_modules(target_keys)` uses only the modules
resolved for the discovered attach targets (exact key, then the soname
fallback). Two target modules with different descriptors for the same slot are
an error that names both modules. Identical descriptors are deduplicated. A
module with no descriptors never conflicts, so the "addresses in librados,
descriptors in libceph-common" artifact shape keeps working. Preflight runs the
same check, so `--preflight` reports the conflict before attach.

The Ubuntu jammy 18.2.7 and 18.2.8 cephtrace artifacts carry `Objecter`
descriptors in librados, libceph-common and librbd. They are byte-identical
across modules, so these artifacts still load.

## F8: discovery could bind to an inode the process does not map

### What happened

- `parse_process_maps` took the last whitespace token of each line. For
  `/usr/lib/librados.so.2.0.0 (deleted)` that token is `(deleted)`, so the line
  was skipped. Discovery then fell back to the file now on disk under
  `/proc/<pid>/root`.
- `/proc/<pid>/exe` of an upgraded daemon reads `/usr/bin/radosgw (deleted)`.
  The basename check failed, and discovery fell back to the host
  `/usr/bin/radosgw`.

After a package upgrade, the build IDs of the new files could match the
artifact. Attach then succeeded against an inode that the process does not
map, and no event arrived.

### Fix (the "minimum" option, plus confinement)

- The maps pathname is the whole text after the fifth field, so paths with
  spaces and the ` (deleted)` suffix are kept. A deleted mapping of a target
  library is flagged. If any mapping of that library is deleted, the flag is
  set.
- With `--pid`, a deleted library mapping or executable is a hard error. The
  error names the file and tells the operator to restart the daemon. An
  executable that is not `radosgw`/`ceph-radosgw` is an error that asks for
  the correct pid or `--radosgw-path`. The host-path fallback runs only without
  `--pid`.

The preferred option was to attach through
`/proc/<pid>/map_files/<start-end>`, which pins the exact mapped inode. It was
not chosen for this PR. Module keys are derived from the target's basename,
and a `map_files` or `/proc/self/fd/N` path breaks that. The change would
reach build-ID checks, artifact matching and every attach site, which sibling
PRs are also editing. This is a follow-up.

## F20: `/proc/<pid>/root` paths could escape to the host

### What happened

Paths were built as `/proc/<pid>/root` + the namespace path and opened by
name. Only the first hop through the magic link is special. The kernel
resolves any symlink below it against the caller's root, so a container's
absolute symlink (common for sonames and Debian alternatives), or `..`,
reached a host file. `.gnu_debuglink` names were also joined onto the debug
directories without validation.

### Fix

- `targets::resolve_in_root(root, path)` walks the path one component at a
  time. It expands each symlink inside `root`: an absolute target restarts at
  `root`, and `..` cannot go above `root` (the semantics of
  `openat2(RESOLVE_IN_ROOT)`). It stops after 40 symlinks, and it checks that
  the result is still under `root`, with errors on failure. Every
  `/proc/<pid>/root` path from discovery (maps, exe, common library
  directories) goes through it. Once a component is missing or is not a
  directory, the walk stops resolving. A later `..` is then an error, so a
  broken path such as `missing/../x` cannot turn into a different, existing
  `x`.
- Locations that are only *guesses* are skipped when they cannot be resolved
  (for example, a symlink loop): the common library directories used when the
  process does not map a library, and the debug-file candidates. Paths taken
  from `/proc/<pid>/maps` and `/proc/<pid>/exe` still fail hard.
- `debuglink_candidates` rejects a name that is empty, `.`, `..`, or contains
  `/` or NUL. This is an error, not a skipped candidate. Candidates under
  `/proc/<pid>/root` are resolved with `targets::confine_to_proc_root`.

### Not done here

- **TOCTOU.** A component can be swapped for a symlink between the walk and
  the later open or uprobe attach. The stronger follow-up is
  `openat2(RESOLVE_IN_ROOT)` on an fd, with parsing and attach through
  `/proc/self/fd/N`.
- **Build-ID and `.dwz` debug candidates** are not confined yet. A sibling PR
  is changing the build-ID and CRC logic next to them. They should use
  `confine_to_proc_root` in the same way.

## Tests

| Finding | Test |
| --- | --- |
| F6 | `tests/cli_dry_run.rs`: `live_tracing_without_pid_is_refused`, `all_processes_conflicts_with_pid`; `preflight::tests::live_scope_requires_pid_or_an_explicit_all_processes_opt_in`; `tests/bpf_source.rs`: `every_uprobe_program_drops_foreign_processes_before_doing_anything`, `userspace_publishes_the_target_tgid_before_load`, `rados_op_key_is_scoped_by_process`; Linux-only `live::linux::tests::process_scope_*`, `publishes_the_target_tgid_into_rodata`, `recognises_only_the_init_pid_namespace` |
| F7 | `dwarf_json::tests::hprobes_come_only_from_the_attach_target_modules`, `conflicting_hprobes_from_two_target_modules_are_refused`, `identical_hprobes_from_two_target_modules_are_deduplicated`, `hprobes_keep_the_cross_module_split_working`, `hprobe_target_keys_resolve_through_the_soname_fallback` |
| F8 | `targets::tests::process_maps_flag_deleted_mappings`, `process_maps_keep_paths_with_spaces`, `a_deleted_library_mapping_is_a_hard_error_naming_the_file`, `a_deleted_radosgw_executable_is_a_hard_error`, `a_pid_that_is_not_radosgw_is_an_error_not_a_host_fallback` |
| F20 | `targets::tests::absolute_symlinks_resolve_inside_the_root`, `dot_dot_cannot_climb_out_of_the_root`, `relative_symlinks_resolve_against_their_own_directory`, `symlink_loops_are_an_error`, `dot_dot_after_a_missing_component_does_not_resolve`, `an_unresolvable_fallback_location_is_skipped` (Linux), `only_proc_root_paths_are_confined`; `dwarf_native::tests::debuglink_names_that_are_not_a_plain_filename_are_refused`, `debuglink_candidates_under_a_proc_root_stay_inside_it`, `an_unresolvable_debuglink_location_is_skipped` (Linux) |
