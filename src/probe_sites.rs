//! Uprobe address validation and virtual-address -> file-offset translation.
//!
//! The artifact's `func2pc` holds ELF VIRTUAL addresses (the cephtrace JSON
//! contract, and what DWARF and the symbol tables record). The kernel's uprobe
//! API, and libbpf's `bpf_program__attach_uprobe(func_offset)` on top of it,
//! take a FILE OFFSET into the probed file. The two are equal only when the
//! executable PT_LOAD has `p_vaddr == p_offset`, which GNU ld happens to produce
//! for PIE text; a non-PIE (`ET_EXEC`, based at 0x400000) or lld-linked binary
//! does not, and passing the vaddr through puts the int3 somewhere else entirely.
//!
//! Nothing upstream proves an address is the START of an instruction either. A
//! breakpoint planted mid-instruction corrupts the instruction stream of a
//! production RGW. So every address is validated here, once, before attach:
//!
//! 1. it must lie inside an executable PT_LOAD's file-backed bytes, which also
//!    yields its file offset (`vaddr - p_vaddr + p_offset`);
//! 2. it must be a function ENTRY: the `st_value` of a defined FUNC symbol in the
//!    probed file's `.symtab`/`.dynsym`, or -- for a stripped file -- in its
//!    verified separate debug file, or a DWARF subprogram `DW_AT_low_pc`.
//!
//! Anything else is a hard error. This module is platform independent so it is
//! unit-tested everywhere; the Linux attach path consumes its offsets and never
//! recomputes them from raw addresses.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use object::{BinaryFormat, Object, ObjectSegment, ObjectSymbol, SegmentFlags, SymbolKind};
use serde::Serialize;

use crate::dwarf_native;

/// The file-backed part of one executable PT_LOAD.
#[derive(Clone, Copy, Debug)]
struct ExecSegment {
    vaddr: u64,
    offset: u64,
    filesz: u64,
}

/// What an address in one ELF file can be checked against.
struct ProbeImage {
    exec_segments: Vec<ExecSegment>,
    function_entries: BTreeSet<u64>,
}

impl ProbeImage {
    fn from_file(file: &object::File<'_>) -> Result<Self> {
        if file.format() != BinaryFormat::Elf {
            bail!("not an ELF file; uprobe offsets are only defined for ELF program headers");
        }
        let exec_segments = file
            .segments()
            .filter(|segment| {
                matches!(segment.flags(), SegmentFlags::Elf { p_flags, .. } if p_flags & object::elf::PF_X != object::elf::ProgramFlags(0))
            })
            .map(|segment| {
                let (offset, filesz) = segment.file_range();
                ExecSegment {
                    vaddr: segment.address(),
                    offset,
                    filesz,
                }
            })
            .collect();
        Ok(Self {
            exec_segments,
            function_entries: function_entries(file),
        })
    }

    /// File offset of `vaddr`, or `None` when it is not inside the file-backed
    /// bytes of an executable PT_LOAD (the tail `p_memsz > p_filesz` is not in the
    /// file and cannot be probed).
    fn file_offset(&self, vaddr: u64) -> Option<u64> {
        self.exec_segments.iter().find_map(|segment| {
            let delta = vaddr.checked_sub(segment.vaddr)?;
            (delta < segment.filesz).then(|| segment.offset + delta)
        })
    }
}

/// `st_value` of every defined FUNC symbol in `.symtab` and `.dynsym`.
fn function_entries(file: &object::File<'_>) -> BTreeSet<u64> {
    file.symbols()
        .chain(file.dynamic_symbols())
        .filter(|symbol| symbol.is_definition() && symbol.kind() == SymbolKind::Text)
        .map(|symbol| symbol.address())
        .filter(|address| *address != 0)
        .collect()
}

/// How a probe address was proven to be a function entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryEvidence {
    /// A FUNC symbol in the probed file itself.
    Symbol,
    /// A FUNC symbol in the probed file's verified separate debug file.
    DebugSymbol,
    /// A DWARF `DW_TAG_subprogram` `DW_AT_low_pc`.
    DwarfLowPc,
}

/// One validated uprobe site.
#[derive(Clone, Debug, Serialize)]
pub struct ProbeSite {
    pub module: String,
    pub path: PathBuf,
    pub function: String,
    /// The artifact's address (ELF virtual address).
    pub vaddr: u64,
    /// What the uprobe API takes.
    pub file_offset: u64,
    pub evidence: EntryEvidence,
}

/// Every uprobe site preflight validated. The attach path asks this for the file
/// offset and never translates a raw artifact address itself.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(transparent)]
pub struct ProbeSites(Vec<ProbeSite>);

impl ProbeSites {
    pub fn extend(&mut self, sites: Vec<ProbeSite>) {
        self.0.extend(sites);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The validated file offset for `function` at `vaddr` in `path`. An address
    /// preflight did not validate is refused rather than translated here.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // the attach path is Linux-only
    pub fn file_offset(&self, path: &Path, function: &str, vaddr: u64) -> Result<u64> {
        self.0
            .iter()
            .find(|site| site.path == path && site.function == function && site.vaddr == vaddr)
            .map(|site| site.file_offset)
            .with_context(|| {
                format!(
                    "{function} at {vaddr:#x} in {} was not validated by preflight; refusing to \
                     attach a uprobe to an unchecked address",
                    path.display()
                )
            })
    }
}

/// Validate each `(function, vaddr)` the artifact supplies for the ELF file at
/// `path` (artifact module `module`) and translate it to a file offset.
pub fn validate_target(
    path: &Path,
    module: &str,
    requests: &[(&str, u64)],
) -> Result<Vec<ProbeSite>> {
    if requests.is_empty() {
        return Ok(Vec::new());
    }
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let file = object::File::parse(data.as_slice())
        .with_context(|| format!("{} is not a supported object file", path.display()))?;
    let image = ProbeImage::from_file(&file).with_context(|| format!("{}", path.display()))?;

    let mut sites = Vec::with_capacity(requests.len());
    let mut unproven = BTreeSet::new();
    for &(function, vaddr) in requests {
        let Some(file_offset) = image.file_offset(vaddr) else {
            bail!(
                "refusing to probe {function} in module {module}: address {vaddr:#x} is not inside \
                 an executable PT_LOAD segment of {} -- the artifact does not describe this binary",
                path.display()
            );
        };
        let evidence = if image.function_entries.contains(&vaddr) {
            EntryEvidence::Symbol
        } else {
            unproven.insert(vaddr);
            // Placeholder, settled below once the debug evidence is loaded.
            EntryEvidence::DwarfLowPc
        };
        sites.push(ProbeSite {
            module: module.to_string(),
            path: path.to_path_buf(),
            function: function.to_string(),
            vaddr,
            file_offset,
            evidence,
        });
    }

    if !unproven.is_empty() {
        let (debug_symbols, low_pcs) = debug_entry_evidence(path, &file, &unproven)?;
        for site in sites
            .iter_mut()
            .filter(|site| unproven.contains(&site.vaddr))
        {
            site.evidence = if debug_symbols.contains(&site.vaddr) {
                EntryEvidence::DebugSymbol
            } else if low_pcs.contains(&site.vaddr) {
                EntryEvidence::DwarfLowPc
            } else {
                bail!(
                    "refusing to probe {} in module {}: address {:#x} is not the entry of any \
                     function in {} (no FUNC symbol in .symtab/.dynsym or its debug file, and no \
                     DWARF subprogram starts there); a uprobe there could split an instruction",
                    site.function,
                    site.module,
                    site.vaddr,
                    path.display()
                );
            };
        }
    }
    Ok(sites)
}

/// Entry evidence for a binary whose own symbol tables did not cover every
/// address: its separate debug file's FUNC symbols, then DWARF subprogram
/// `low_pc`s (from the binary itself when it carries DWARF). The debug file is
/// only used once proven to belong to the binary (build ID or debuglink CRC).
fn debug_entry_evidence(
    path: &Path,
    file: &object::File<'_>,
    wanted: &BTreeSet<u64>,
) -> Result<(BTreeSet<u64>, BTreeSet<u64>)> {
    if file.has_debug_symbols() {
        let low_pcs = dwarf_native::subprogram_low_pcs(file, wanted)
            .with_context(|| format!("failed to read DWARF of {}", path.display()))?;
        return Ok((BTreeSet::new(), low_pcs));
    }
    let Some((bytes, debug_path)) = dwarf_native::separate_debug_file(path, file)? else {
        return Ok((BTreeSet::new(), BTreeSet::new()));
    };
    let debug_file = object::File::parse(bytes.as_slice())
        .with_context(|| format!("{} is not a supported object file", debug_path.display()))?;
    let debug_symbols = function_entries(&debug_file);
    let remaining = wanted
        .difference(&debug_symbols)
        .copied()
        .collect::<BTreeSet<_>>();
    let low_pcs = if remaining.is_empty() {
        BTreeSet::new()
    } else {
        dwarf_native::subprogram_low_pcs(&debug_file, &remaining)
            .with_context(|| format!("failed to read DWARF of {}", debug_path.display()))?
    };
    Ok((debug_symbols, low_pcs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_elf::{build_id_note, debuglink, temp_dir, TestElf, STT_OBJECT};

    const TEXT_OFFSET: u64 = 0x1000;
    const TEXT_SIZE: u64 = 0x200;

    fn write(name: &str, image: &TestElf) -> PathBuf {
        let path = temp_dir(name).join("radosgw");
        fs::write(&path, image.build()).unwrap();
        path
    }

    #[test]
    fn a_pie_entry_with_equal_vaddr_and_offset_translates_to_itself() {
        let path = write(
            "pie",
            &TestElf::pie(TEXT_OFFSET, TEXT_SIZE).function("probe_me", 0x1040),
        );
        let sites = validate_target(&path, "radosgw", &[("probe_me", 0x1040)]).unwrap();
        assert_eq!(sites[0].file_offset, 0x1040);
        assert_eq!(sites[0].evidence, EntryEvidence::Symbol);
    }

    #[test]
    fn a_non_pie_entry_translates_through_its_pt_load() {
        // Linked at 0x400000: the vaddr is NOT a file offset. Passing it through
        // (the old behavior) would plant the breakpoint 4 MiB past the function.
        let vaddr = 0x40_0000 + 0x1040;
        let path = write(
            "non-pie",
            &TestElf::non_pie(TEXT_OFFSET, TEXT_SIZE).function("probe_me", vaddr),
        );
        let sites = validate_target(&path, "radosgw", &[("probe_me", vaddr)]).unwrap();
        assert_eq!(sites[0].file_offset, 0x1040);

        let mut probe_sites = ProbeSites::default();
        probe_sites.extend(sites);
        assert_eq!(
            probe_sites.file_offset(&path, "probe_me", vaddr).unwrap(),
            0x1040
        );
        assert!(probe_sites
            .file_offset(&path, "probe_me", vaddr + 1)
            .is_err());
    }

    #[test]
    fn an_address_inside_text_that_is_not_a_function_entry_is_refused() {
        let path = write(
            "mid-function",
            &TestElf::pie(TEXT_OFFSET, TEXT_SIZE).function("probe_me", 0x1040),
        );
        let err = validate_target(&path, "radosgw", &[("probe_me", 0x1043)]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("probe_me"), "message: {msg}");
        assert!(msg.contains("radosgw"), "message: {msg}");
        assert!(msg.contains("0x1043"), "message: {msg}");
        assert!(msg.contains("not the entry"), "message: {msg}");
    }

    #[test]
    fn a_data_symbol_is_not_a_function_entry() {
        let mut image = TestElf::pie(TEXT_OFFSET, TEXT_SIZE);
        image.symbols.push(crate::test_elf::Symbol {
            name: "not_code",
            value: 0x1080,
            st_type: STT_OBJECT,
        });
        let path = write("data-symbol", &image);
        assert!(validate_target(&path, "radosgw", &[("not_code", 0x1080)]).is_err());
    }

    #[test]
    fn an_address_outside_every_executable_segment_is_refused() {
        // 0x800 is inside the read-only (non-executable) first PT_LOAD; 0x9000 is in
        // no segment at all. A symbol at either does not make it probeable.
        let path = write(
            "outside-text",
            &TestElf::pie(TEXT_OFFSET, TEXT_SIZE)
                .function("in_rodata", 0x800)
                .function("nowhere", 0x9000),
        );
        for (function, vaddr) in [("in_rodata", 0x800), ("nowhere", 0x9000)] {
            let err = validate_target(&path, "radosgw", &[(function, vaddr)]).unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("executable PT_LOAD"), "message: {msg}");
            assert!(msg.contains(function), "message: {msg}");
        }
    }

    #[test]
    fn a_stripped_binary_is_validated_against_its_verified_debug_file() {
        let id = [0x5a; 20];
        let debug = TestElf::pie(TEXT_OFFSET, TEXT_SIZE)
            .section(build_id_note(&id))
            .function("probe_me", 0x1040)
            .build();
        let dir = temp_dir("stripped");
        fs::write(dir.join("radosgw.debug"), &debug).unwrap();
        let path = dir.join("radosgw");
        fs::write(
            &path,
            TestElf::pie(TEXT_OFFSET, TEXT_SIZE)
                .section(build_id_note(&id))
                .section(debuglink("radosgw.debug", 0))
                .build(),
        )
        .unwrap();

        let sites = validate_target(&path, "radosgw", &[("probe_me", 0x1040)]).unwrap();
        assert_eq!(sites[0].evidence, EntryEvidence::DebugSymbol);
        assert_eq!(sites[0].file_offset, 0x1040);

        // The same debug file from ANOTHER build proves nothing.
        let other = TestElf::pie(TEXT_OFFSET, TEXT_SIZE)
            .section(build_id_note(&[0x5b; 20]))
            .function("probe_me", 0x1040)
            .build();
        fs::write(dir.join("radosgw.debug"), other).unwrap();
        assert!(validate_target(&path, "radosgw", &[("probe_me", 0x1040)]).is_err());
    }

    #[test]
    fn a_stripped_binary_without_debug_info_cannot_prove_an_entry() {
        let path = write("stripped-no-debug", &TestElf::pie(TEXT_OFFSET, TEXT_SIZE));
        let err = validate_target(&path, "radosgw", &[("probe_me", 0x1040)]).unwrap_err();
        assert!(format!("{err:#}").contains("not the entry"));
    }

    #[test]
    fn a_non_elf_target_is_refused() {
        let path = temp_dir("not-elf").join("radosgw");
        fs::write(&path, b"#!/bin/sh\n").unwrap();
        assert!(validate_target(&path, "radosgw", &[("probe_me", 0x1040)]).is_err());
    }

    #[test]
    fn no_requests_needs_no_file() {
        let sites = validate_target(Path::new("/nonexistent/radosgw"), "radosgw", &[]).unwrap();
        assert!(sites.is_empty());
    }
}
