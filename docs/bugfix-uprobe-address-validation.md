# Bugfix: validate and translate uprobe addresses before attach

This change fixes three faults in how probe metadata reaches the kernel. Each
one could put a breakpoint, or a field read, in the wrong place without any
error.

## 1. Virtual addresses were passed as file offsets

### What happened

`func2pc` stores ELF virtual addresses. Native extraction records
`symbol.address()` (`st_value`) or `DW_AT_low_pc`, and cephtrace JSON uses the
same convention. The attach path passed that number straight to libbpf:

```rust
attach_uprobe(prog, retprobe, pid, path, addr as usize)
// -> bpf_program__attach_uprobe(prog, retprobe, pid, path, func_offset)
```

`func_offset` is a **file offset**. The kernel places the `int3` at
`file_offset` bytes into the inode. The two numbers are equal only when the
executable `PT_LOAD` has `p_vaddr == p_offset`:

```text
GNU ld PIE        PT_LOAD R E  offset 0x01000  vaddr 0x01000   -> works by accident
non-PIE (ET_EXEC) PT_LOAD R E  offset 0x01000  vaddr 0x401000  -> int3 4 MiB too far
lld PIE           PT_LOAD R E  offset 0x01000  vaddr 0x02000   -> int3 0x1000 too far
```

Nothing checked that an address was the start of an instruction, either. The
only check on an imported JSON address was `!= 0`. A uprobe in the middle of an
instruction corrupts the instruction stream and crashes RGW.

### The fix

`func2pc` stays a virtual address, so artifacts and cephtrace compatibility are
unchanged. Preflight (`validated_probe_sites` in `src/preflight.rs`, logic in
`src/probe_sites.rs`) now checks every address the artifact carries for a probed
function in a discovered target:

1. The address must lie in the file-backed bytes of an executable `PT_LOAD`. The
   file offset is `vaddr - p_vaddr + p_offset`.
2. The address must be a function entry. That means the `st_value` of a defined
   `FUNC` symbol in the target's `.symtab` or `.dynsym`. For a stripped target,
   it can also be a `FUNC` symbol in its verified debug file (see section 2) or a
   `DW_TAG_subprogram` `DW_AT_low_pc`.

Any failure is a hard error that names the function, module, address, and file.
The `--preflight` report lists the result as `probe_sites`. The Linux attach path
gets each offset from `ProbeSites::file_offset()`, which refuses an address that
preflight did not validate. The attach path never translates an address itself.
A source-shape test (`tests/bpf_source.rs`) fails if `addr as usize` comes back.

### The request-END probe

The END probe stays optional. If the destructor address is **absent**, the probe
fails soft as before (`rgw.duration_quality = "marker"`). If the address is
**present** and fails validation, the run stops. A wrong breakpoint is worse than
a missing one: the first corrupts RGW, the second only degrades durations. The
`rgw_rados_operate` overloads follow the same rule.

`--allow-build-id-mismatch` does not override address validation. That flag
vouches for the DWARF. It cannot make an address land on an instruction
boundary.

### Operational consequence

A target with no `.symtab` and no matching debug info can prove only the
addresses it exports in `.dynsym`. If a probed function is not exported, preflight
fails. Previously the probe was attached with no proof. Install the debuginfo
package for the running build.

## 2. Separate debug info bypassed the build-ID check

### What happened

When the binary was stripped, native extraction used the first existing
`.gnu_debuglink` or `.build-id` candidate file. It discarded the debuglink CRC
and never compared the debug file's build ID with the binary's. The preflight
build-ID check could not catch the problem: `DwarfModule.build_id` is read from
the binary, so preflight compared the binary with itself. Symbol addresses from
the debug file's `.symtab` also took precedence over the binary's own symbols.

As a result, a stale debuginfo package produced wrong field offsets and wrong
addresses, and no check reported it.

### The fix

`separate_debug_file()` accepts a candidate only with proof that it matches the
binary:

- If both files carry `NT_GNU_BUILD_ID`, the IDs must be equal.
- Otherwise, the CRC-32 (ISO-HDLC, via the existing `flate2` dependency) of the
  whole debug file must match the CRC in `.gnu_debuglink`.

The build ID takes precedence because dwz can rewrite a debug file after the CRC
was recorded. If a candidate does not match, it is skipped with a warning. If no
candidate matches, extraction fails and names each rejected file. No flag
overrides this check, because a mismatched debug file has no safe use. The binary's
own symbols are now preferred for probe addresses.

## 3. Unsupported DWARF member locations became offset 0

### What happened

The member-location evaluator returned `Ok(0)` for any `DW_OP` that it did not
support. `attr_offset` mapped unsupported forms and out-of-range values to
`None`, and `translate_field_path_from` did `unwrap_or_default()`. A member that
was located through a virtual base, for example, got offset 0, and the BPF
program read the wrong bytes for every request.

An audit of the surrounding code found two more silent defaults:

- `find_member_entry` searched base classes but ignored the base's own offset.
  A member of a non-primary base got its offset inside the base, not inside the
  derived class.
- `decode_location_expression` skipped operations that it did not understand.
  For example, `DW_OP_reg5; DW_OP_deref` decoded as `reg5`.

### The fix

- Every member location that cannot be evaluated is an error. The message names
  the member and the `DW_OP`, or the form. An absent location means offset 0
  only for a plain data member, as DWARF 5 allows. A static member or a
  `DW_AT_data_bit_offset` bit-field is an error.
- An inherited member adds its base class offset. A base whose location is a
  runtime expression fails the lookup only when a probed member is reached
  through it.
- A variable location with an unsupported operation yields no location, so the
  descriptor is rejected. This follows the existing convention for
  `DW_OP_call_frame_cfa`.
- The `DoutPrefixProvider` base-offset proof treats a base it cannot evaluate as
  unproven. Before this fix, that case read as offset 0, which is the value the
  proof accepts.

## Tests

- `src/probe_sites.rs`: synthetic ELF images (`src/test_elf.rs`) for PIE, non-PIE
  `0x400000`, a mid-function address, a non-`FUNC` symbol, addresses outside
  executable segments, a stripped binary validated through its debug file, and a
  non-ELF target.
- `src/preflight.rs`: translation through preflight, an imported non-entry
  address, a present but invalid END address (hard error), and an absent one
  (soft).
- `src/dwarf_native.rs`: real compiled fixtures, including a `-no-pie` build and
  a build with no symbol table (validated from DWARF `low_pc`). These tests run on
  Linux; macOS fixtures are Mach-O.
- `src/dwarf_native.rs`: debug-file matching with synthetic images (build-ID
  mismatch, stale CRC with matching build IDs, CRC only, `.build-id` tree) and an
  objcopy debuglink pair whose debug file comes from another build.
- `src/dwarf_native.rs`: `expression_offset` and `resolve_member_offset` with
  `DW_OP_dup; DW_OP_deref`, location lists, and out-of-range values; a fixture
  with a member in the second base class (offset 24, not 8).
