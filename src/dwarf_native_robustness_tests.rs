//! Adversarial-input tests for the native DWARF parser: reference cycles, deep
//! DIE nesting, oversized files and compressed-section bombs. Every input here is
//! built in memory, so the tests run on any host (no compiler, no Ceph build).

use std::{sync::mpsc, thread, time::Duration};

use gimli::{write, EndianSlice, LittleEndian, RunTimeEndian};

use super::*;
use crate::test_elf::tiny_elf;

/// Run `f` on a worker thread and fail the test if it does not finish in time. A
/// reference cycle without a guard spins forever; this turns that hang into a
/// test failure instead of a stuck test binary.
fn completes_within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(f());
    });
    receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("DWARF walk did not terminate (reference cycle not guarded?)")
}

type TestSections = write::Sections<write::EndianVec<LittleEndian>>;

/// Build a one-unit DWARF 4 image with `build` filling the unit's DIE tree.
fn written_dwarf(build: impl FnOnce(&mut write::Unit)) -> TestSections {
    let encoding = gimli::Encoding {
        format: gimli::Format::Dwarf32,
        version: 4,
        address_size: 8,
    };
    let mut dwarf = write::Dwarf::new();
    let unit_id = dwarf
        .units
        .add(write::Unit::new(encoding, write::LineProgram::none()));
    build(dwarf.units.get_mut(unit_id));
    let mut sections = write::Sections::new(write::EndianVec::new(LittleEndian));
    dwarf.write(&mut sections).unwrap();
    sections
}

fn read_dwarf(sections: &TestSections) -> Dwarf<EndianSlice<'_, RunTimeEndian>> {
    Dwarf::load(|id| -> std::result::Result<_, gimli::Error> {
        let data = sections
            .get(id)
            .map(|section| section.slice())
            .unwrap_or(&[]);
        Ok(EndianSlice::new(data, RunTimeEndian::Little))
    })
    .unwrap()
}

/// Raw `.debug_abbrev` + `.debug_info` images, for shapes `gimli::write` cannot
/// produce (its writer recurses per nesting level, so it cannot emit the
/// 100 000-deep tree these tests need).
fn raw_dwarf<'a>(abbrev: &'a [u8], info: &'a [u8]) -> Dwarf<EndianSlice<'a, RunTimeEndian>> {
    Dwarf::load(|id| -> std::result::Result<_, gimli::Error> {
        let data: &[u8] = match id {
            gimli::SectionId::DebugAbbrev => abbrev,
            gimli::SectionId::DebugInfo => info,
            _ => &[],
        };
        Ok(EndianSlice::new(data, RunTimeEndian::Little))
    })
    .unwrap()
}

fn string(value: &str) -> write::AttributeValue {
    write::AttributeValue::String(value.as_bytes().to_vec())
}

fn find_named<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    name: &str,
) -> DieRef<R::Offset> {
    for unit_index in 0..index.len() {
        let unit = index.unit(unit_index);
        let mut entries = unit.entries();
        while let Some((_, entry)) = entries.next_dfs().unwrap() {
            if die_name(dwarf, unit, entry).unwrap().as_deref() == Some(name) {
                return DieRef {
                    unit: unit_index,
                    offset: entry.offset(),
                };
            }
        }
    }
    panic!("no DIE named {name}");
}

const DEEP_NESTING: usize = 100_000;
const DW_CHILDREN_YES: u8 = 1;
const DW_CHILDREN_NO: u8 = 0;

/// `.debug_abbrev` for the deep-nesting image:
///   1: DW_TAG_compile_unit, children
///   2: DW_TAG_namespace (anonymous), children
///   3: DW_TAG_structure_type, no children, DW_AT_name(string), DW_AT_declaration(flag_present)
///   4: DW_TAG_structure_type, no children, DW_AT_name(string)
fn deep_abbrev() -> Vec<u8> {
    vec![
        1,
        gimli::DW_TAG_compile_unit.0 as u8,
        DW_CHILDREN_YES,
        0,
        0,
        2,
        gimli::DW_TAG_namespace.0 as u8,
        DW_CHILDREN_YES,
        0,
        0,
        3,
        gimli::DW_TAG_structure_type.0 as u8,
        DW_CHILDREN_NO,
        gimli::DW_AT_name.0 as u8,
        gimli::DW_FORM_string.0 as u8,
        gimli::DW_AT_declaration.0 as u8,
        gimli::DW_FORM_flag_present.0 as u8,
        0,
        0,
        4,
        gimli::DW_TAG_structure_type.0 as u8,
        DW_CHILDREN_NO,
        gimli::DW_AT_name.0 as u8,
        gimli::DW_FORM_string.0 as u8,
        0,
        0,
        0,
    ]
}

/// One CU holding a declaration `struct Deep;` at depth 1, then `depth` nested
/// anonymous namespaces with a `struct Leaf {}` definition at the bottom.
fn deep_info(depth: usize) -> Vec<u8> {
    let mut body = vec![1];
    body.push(3);
    body.extend_from_slice(b"Deep\0");
    body.extend(std::iter::repeat_n(2, depth));
    body.push(4);
    body.extend_from_slice(b"Leaf\0");
    body.extend(std::iter::repeat_n(0, depth));
    body.push(0);

    let mut info = Vec::new();
    let unit_length = (2 + 4 + 1 + body.len()) as u32;
    info.extend_from_slice(&unit_length.to_le_bytes());
    info.extend_from_slice(&4u16.to_le_bytes());
    info.extend_from_slice(&0u32.to_le_bytes());
    info.push(8);
    info.extend_from_slice(&body);
    info
}

#[test]
fn typedef_cycle_is_an_error_not_a_hang() {
    let result = completes_within(|| {
        let sections = written_dwarf(|unit| {
            let root = unit.root();
            let a = unit.add(root, gimli::DW_TAG_typedef);
            let b = unit.add(root, gimli::DW_TAG_const_type);
            unit.get_mut(a).set(gimli::DW_AT_name, string("LoopA"));
            unit.get_mut(a)
                .set(gimli::DW_AT_type, write::AttributeValue::UnitRef(b));
            unit.get_mut(b)
                .set(gimli::DW_AT_type, write::AttributeValue::UnitRef(a));
        });
        let dwarf = read_dwarf(&sections);
        let index = DwarfUnitIndex::load(&dwarf).unwrap();
        let start = find_named(&dwarf, &index, "LoopA");
        peel_type_qualifiers(&index, start)
            .map(|_| ())
            .map_err(|err| format!("{err:#}"))
    });

    let err = result.expect_err("a typedef/const cycle must be refused");
    assert!(err.contains("type qualifier chain"), "{err}");
    assert!(err.contains("DIE at .debug_info offset 0x"), "{err}");
}

#[test]
fn inheritance_cycle_terminates() {
    let found = completes_within(|| {
        let sections = written_dwarf(|unit| {
            let root = unit.root();
            let a = unit.add(root, gimli::DW_TAG_structure_type);
            let b = unit.add(root, gimli::DW_TAG_structure_type);
            unit.get_mut(a).set(gimli::DW_AT_name, string("CycleA"));
            unit.get_mut(b).set(gimli::DW_AT_name, string("CycleB"));
            let a_base = unit.add(a, gimli::DW_TAG_inheritance);
            unit.get_mut(a_base)
                .set(gimli::DW_AT_type, write::AttributeValue::UnitRef(b));
            let b_base = unit.add(b, gimli::DW_TAG_inheritance);
            unit.get_mut(b_base)
                .set(gimli::DW_AT_type, write::AttributeValue::UnitRef(a));
            let member = unit.add(b, gimli::DW_TAG_member);
            unit.get_mut(member)
                .set(gimli::DW_AT_name, string("present"));
        });
        let dwarf = read_dwarf(&sections);
        let index = DwarfUnitIndex::load(&dwarf).unwrap();
        let start = find_named(&dwarf, &index, "CycleA");
        let missing = find_member_entry(&dwarf, &index, start, "missing")
            .unwrap()
            .is_some();
        let present = find_member_entry(&dwarf, &index, start, "present")
            .unwrap()
            .is_some();
        (missing, present)
    });

    // The cycle neither hangs nor hides a member reachable through it.
    assert_eq!(found, (false, true));
}

#[test]
fn pointer_cycle_in_field_path_is_an_error_not_a_hang() {
    let result = completes_within(|| {
        let sections = written_dwarf(|unit| {
            let root = unit.root();
            let pointer = unit.add(root, gimli::DW_TAG_pointer_type);
            unit.get_mut(pointer)
                .set(gimli::DW_AT_type, write::AttributeValue::UnitRef(pointer));
            let variable = unit.add(root, gimli::DW_TAG_variable);
            unit.get_mut(variable).set(gimli::DW_AT_name, string("var"));
            unit.get_mut(variable)
                .set(gimli::DW_AT_type, write::AttributeValue::UnitRef(pointer));
        });
        let dwarf = read_dwarf(&sections);
        let index = DwarfUnitIndex::load(&dwarf).unwrap();
        let variable = find_named(&dwarf, &index, "var");
        translate_field_path(&dwarf, &index, variable, &["var", "field"])
            .map_err(|err| format!("{err:#}"))
    });

    let err = result.expect_err("a self-referencing pointer type must be refused");
    assert!(err.contains("type chain"), "{err}");
}

#[test]
fn deep_die_nesting_does_not_overflow_the_stack_in_type_lookups() {
    // Runs on the default 2 MiB test-thread stack: a recursive walker would
    // overflow (and abort the whole test binary) long before depth 100 000.
    let abbrev = deep_abbrev();
    let info = deep_info(DEEP_NESTING);
    let dwarf = raw_dwarf(&abbrev, &info);
    let index = DwarfUnitIndex::load(&dwarf).unwrap();

    let declaration = find_named(&dwarf, &index, "Deep");
    // No definition of `Deep` exists: the full-tree search must finish and say so.
    assert!(type_definition_die(&dwarf, &index, declaration)
        .unwrap()
        .is_none());

    let leaf = find_named(&dwarf, &index, "Leaf");
    assert_eq!(
        qualified_type_path(&dwarf, &index, leaf).unwrap(),
        Some(vec!["Leaf".to_string()])
    );
    assert_eq!(
        entry_scopes(&dwarf, &index, leaf).unwrap(),
        Some(Vec::new())
    );

    let search = translate_named_type_field_path(
        &dwarf,
        &index,
        "Leaf",
        &[FieldJson::default(), FieldJson::default()],
        1,
        &["var", "missing"],
        &mut Vec::new(),
    )
    .unwrap();
    assert!(search.is_none());
}

#[test]
fn deep_scope_nesting_is_an_error_in_function_walks() {
    let abbrev = deep_abbrev();
    let info = deep_info(DEEP_NESTING);
    let dwarf = raw_dwarf(&abbrev, &info);
    let index = DwarfUnitIndex::load(&dwarf).unwrap();

    let err = format!(
        "{:#}",
        function_pcs(&dwarf, &index, PROBE_FUNCTIONS)
            .map(|_| ())
            .unwrap_err()
    );
    assert!(err.contains("nesting"), "{err}");
    assert!(err.contains("DIE at .debug_info offset 0x"), "{err}");

    let err = format!(
        "{:#}",
        function_var_fields(&dwarf, &index, PROBE_FUNCTIONS, &BTreeMap::new())
            .map(|_| ())
            .unwrap_err()
    );
    assert!(err.contains("nesting"), "{err}");
}

#[test]
fn moderate_scope_nesting_is_still_walked() {
    // Real C++ scope nesting (namespaces within classes within namespaces) is a
    // few dozen levels at most; the cap must leave that untouched.
    let abbrev = deep_abbrev();
    let info = deep_info(64);
    let dwarf = raw_dwarf(&abbrev, &info);
    let index = DwarfUnitIndex::load(&dwarf).unwrap();

    assert!(function_pcs(&dwarf, &index, PROBE_FUNCTIONS)
        .unwrap()
        .is_empty());
}

// ---------------------------------------------------------------------------
// Bounded reads and decompression.
// ---------------------------------------------------------------------------

const SHT_PROGBITS: u32 = 1;
const SHF_COMPRESSED: u64 = 0x800;
const ELFCOMPRESS_ZLIB: u32 = 1;
const ELFCOMPRESS_ZSTD: u32 = 2;

/// An `SHF_COMPRESSED` section body: `Elf64_Chdr` declaring `declared_size`
/// uncompressed bytes, followed by `payload`.
fn compressed_section(kind: u32, declared_size: u64, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&kind.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&declared_size.to_le_bytes());
    data.extend_from_slice(&1u64.to_le_bytes());
    data.extend_from_slice(payload);
    data
}

fn zlib(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn temp_file(name: &str, contents: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rgwtrace-dwarf-limits-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    fs::write(&path, contents).unwrap();
    path
}

#[test]
fn bounded_read_refuses_a_file_over_the_limit_and_names_it() {
    let path = temp_file("radosgw", &[0u8; 4096]);

    assert_eq!(
        read_file_bounded(&path, 4096, "target").unwrap().len(),
        4096
    );
    let err = format!(
        "{:#}",
        read_file_bounded(&path, 4095, "target").unwrap_err()
    );
    assert!(err.contains(&path.display().to_string()), "{err}");
    assert!(err.contains("4096 bytes"), "{err}");
    assert!(err.contains("4095"), "{err}");
    assert!(err.contains("--max-debug-file-bytes"), "{err}");
}

#[test]
fn native_extraction_refuses_a_target_over_the_limit() {
    let path = temp_file("radosgw", &tiny_elf(&[]));
    let options = NativeOptions {
        max_debug_file_bytes: 64,
        ..NativeOptions::default()
    };

    let err = format!(
        "{:#}",
        from_paths_with_options(&[&path], &options).unwrap_err()
    );
    assert!(err.contains("--max-debug-file-bytes"), "{err}");
    assert!(err.contains(&path.display().to_string()), "{err}");
}

#[test]
fn compressed_section_declaring_more_than_the_limit_is_refused_before_inflating() {
    for kind in [ELFCOMPRESS_ZLIB, ELFCOMPRESS_ZSTD] {
        // 64 GiB declared: inflating it (or even reserving it) is the bomb.
        let elf = tiny_elf(&[(
            ".debug_info",
            SHT_PROGBITS,
            SHF_COMPRESSED,
            compressed_section(kind, 64 << 30, &zlib(b"tiny")),
        )]);
        let file = object::File::parse(elf.as_slice()).unwrap();
        let mut budget = SectionBudget::new(Path::new("/x/radosgw.debug"), 1 << 20);

        let err = format!(
            "{:#}",
            load_section(&file, gimli::SectionId::DebugInfo, &mut budget).unwrap_err()
        );
        assert!(err.contains(".debug_info"), "{err}");
        assert!(err.contains("/x/radosgw.debug"), "{err}");
        assert!(err.contains("68719476736"), "{err}");
        assert!(err.contains("--max-debug-file-bytes"), "{err}");
    }
}

#[test]
fn decompressed_sections_share_one_budget_per_file() {
    let contents = vec![7u8; 1000];
    let section = compressed_section(ELFCOMPRESS_ZLIB, 1000, &zlib(&contents));
    let elf = tiny_elf(&[
        (".debug_info", SHT_PROGBITS, SHF_COMPRESSED, section.clone()),
        (".debug_abbrev", SHT_PROGBITS, SHF_COMPRESSED, section),
    ]);
    let file = object::File::parse(elf.as_slice()).unwrap();

    // Each section alone fits; both together do not.
    let mut budget = SectionBudget::new(Path::new("radosgw"), 1500);
    let info = load_section(&file, gimli::SectionId::DebugInfo, &mut budget).unwrap();
    assert_eq!(&*info, contents.as_slice());
    let err = format!(
        "{:#}",
        load_section(&file, gimli::SectionId::DebugAbbrev, &mut budget).unwrap_err()
    );
    assert!(err.contains(".debug_abbrev"), "{err}");
}

#[test]
fn uncompressed_sections_are_borrowed_not_copied() {
    let elf = tiny_elf(&[(".debug_info", SHT_PROGBITS, 0, vec![1, 2, 3])]);
    let file = object::File::parse(elf.as_slice()).unwrap();
    let mut budget = SectionBudget::new(Path::new("radosgw"), 0);

    let info = load_section(&file, gimli::SectionId::DebugInfo, &mut budget).unwrap();
    assert!(matches!(info, Cow::Borrowed(_)));
    assert_eq!(&*info, &[1, 2, 3]);
}

#[test]
fn embedded_version_comes_from_the_single_parsed_buffer() {
    let path = temp_file(
        "radosgw",
        &tiny_elf(&[(
            ".rodata",
            SHT_PROGBITS,
            0,
            b"\0ceph versio\0ceph version 18.2.8 (abc) reef (stable)\0".to_vec(),
        )]),
    );

    let info = from_paths_with_options(&[&path], &NativeOptions::default()).unwrap();
    assert_eq!(info.version.as_deref(), Some("18.2.8"));
}

#[test]
fn version_search_handles_needle_edges() {
    assert_eq!(
        ceph_version_from_bytes(b"ceph version 17.2.7 (x)").as_deref(),
        Some("17.2.7")
    );
    assert_eq!(
        ceph_version_from_bytes(b"ccceph versionceph version 19.2.1").as_deref(),
        Some("19.2.1")
    );
    assert_eq!(ceph_version_from_bytes(b"ceph version "), None);
    assert_eq!(ceph_version_from_bytes(b"ceph versio"), None);
    assert_eq!(ceph_version_from_bytes(b""), None);
    // The first occurrence wins even when it is not a version (unchanged behavior).
    assert_eq!(
        ceph_version_from_bytes(b"ceph version x\0ceph version 18.2.0").as_deref(),
        None
    );
}

// ---------------------------------------------------------------------------
// Ceph version resolution for containerized targets.
// ---------------------------------------------------------------------------

#[test]
fn recognises_proc_pid_root_paths() {
    assert_eq!(
        proc_pid_root(Path::new("/proc/42/root/usr/bin/radosgw")),
        Some(PathBuf::from("/proc/42/root"))
    );
    assert_eq!(proc_pid_root(Path::new("/usr/bin/radosgw")), None);
    assert_eq!(
        proc_pid_root(Path::new("/proc/self/root/usr/bin/radosgw")),
        None
    );
    assert_eq!(
        proc_pid_root(Path::new("/proc/42/rootfs/usr/bin/radosgw")),
        None
    );
    assert_eq!(
        proc_pid_root(Path::new("proc/42/root/usr/bin/radosgw")),
        None
    );
}

#[test]
fn containerized_target_without_embedded_version_asks_for_ceph_version() {
    // No such pid: its root cannot be proven to be the host's, so the host
    // package database must not be consulted.
    let path = PathBuf::from("/proc/4294967295/root/usr/bin/radosgw");

    let err = format!("{:#}", resolve_ceph_version(&[&path]).unwrap_err());
    assert!(err.contains("--ceph-version"), "{err}");
    assert!(
        err.contains("/proc/4294967295/root/usr/bin/radosgw"),
        "{err}"
    );
}

#[test]
fn host_rooted_targets_keep_the_package_lookup() {
    assert!(shares_host_root(Path::new("/usr/bin/radosgw")));
    assert!(resolve_ceph_version(&[Path::new("/usr/bin/radosgw")]).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn own_pid_root_is_the_host_root() {
    let path = PathBuf::from(format!("/proc/{}/root/usr/bin/radosgw", std::process::id()));
    assert!(shares_host_root(&path));
}

#[test]
fn explicit_version_needs_no_lookup_for_a_containerized_target() {
    let path = temp_file("radosgw", &tiny_elf(&[]));
    let options = NativeOptions {
        ceph_version: Some("18.2.8".to_string()),
        ..NativeOptions::default()
    };

    let info = from_paths_with_options(&[&path], &options).unwrap();
    assert_eq!(info.version.as_deref(), Some("18.2.8"));
}

// ---------------------------------------------------------------------------
// Demangling prefilter.
// ---------------------------------------------------------------------------

/// Probe-relevant and unrelated mangled names, including the variants the
/// linkage-name gate must still see (D0/D1/D2 destructors, both
/// `rgw_rados_operate` overloads) and a Mach-O style leading underscore.
const MANGLED_SAMPLES: &[&str] = &[
    "_ZN8Objecter8_send_opEPNS_2OpE",
    "_ZN8Objecter10_finish_opEPNS_2OpEi",
    "_ZN7RGWREST11get_handlerEPN3rgw3sal6DriverEP9req_stateRKNS0_4auth16StrategyRegistryERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEERi",
    "_Z25rgw_process_authenticatedP15RGWHandler_RESTRP5RGWOpP10RGWRequestP9req_stateoN5boost4asio...",
    "_ZN9req_stateD0Ev",
    "_ZN9req_stateD1Ev",
    "_ZN9req_stateD2Ev",
    "__ZN9req_stateD2Ev",
    "_Z17rgw_rados_operatePK18DoutPrefixProviderRN8librados7v14_2_09IoCtxEERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPNS3_16ObjectReadOperationEPN4ceph6buffer7v15_2_04listEN5boost4asio...",
    "_Z17rgw_rados_operatePK18DoutPrefixProviderRN8librados7v14_2_09IoCtxEERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPNS3_17ObjectWriteOperationEN5boost4asio...",
    "_ZN8Objecter9op_submitEPNS_2OpEPmPi",
    "_ZNSt6vectorIiSaIiEE9push_backERKi",
    "_ZN5boost4asio6detail9scheduler3runERNS_6system10error_codeE",
    "main",
    "_ZN3foo3barEv",
];

/// The prefilter may only skip names that could never yield a probe key: for
/// every name it rejects, demangling must produce nothing the matchers accept.
fn assert_prefilter_is_sound(names: impl IntoIterator<Item = String>) -> usize {
    let mut checked = 0;
    for name in names {
        if may_name_probe(&name, PROBE_FUNCTIONS) {
            continue;
        }
        if let Some(demangled) = demangle_function_name(&name) {
            assert!(
                probe_keys(&demangled, PROBE_FUNCTIONS).is_empty()
                    && !is_probe_demangled_name(&demangled),
                "prefilter skipped {name}, which demangles to probe name {demangled}"
            );
        }
        checked += 1;
    }
    checked
}

#[test]
fn prefilter_keeps_every_probe_definition() {
    for name in MANGLED_SAMPLES {
        let Some(demangled) = demangle_function_name(name) else {
            continue;
        };
        if !probe_keys(&demangled, PROBE_FUNCTIONS).is_empty() {
            assert!(may_name_probe(name, PROBE_FUNCTIONS), "{name}");
        }
    }
    assert!(!may_name_probe(
        "_ZN5boost4asio6detail9scheduler3runERNS_6system10error_codeE",
        PROBE_FUNCTIONS
    ));
    assert!(!may_name_probe(
        "_ZN8Objecter9op_submitEPNS_2OpEPmPi",
        PROBE_FUNCTIONS
    ));
    assert_prefilter_is_sound(MANGLED_SAMPLES.iter().map(|name| name.to_string()));
}

#[test]
fn prefilter_is_sound_over_a_real_symbol_table() {
    // This test binary's own symbol table: thousands of real mangled Rust/C++
    // names the prefilter must not mis-skip.
    let data = fs::read(std::env::current_exe().unwrap()).unwrap();
    let file = object::File::parse(data.as_slice()).unwrap();
    let names: Vec<String> = file
        .symbols()
        .chain(file.dynamic_symbols())
        .filter_map(|symbol| symbol.name().ok().map(str::to_string))
        .collect();
    assert!(assert_prefilter_is_sound(names) > 1000);
}

#[test]
fn leaf_identifier_table_covers_every_probe_function() {
    for key in PROBE_FUNCTIONS {
        let identifier = probe_leaf_identifier(key);
        assert!(
            !identifier.is_empty() && !identifier.contains("::"),
            "{key}"
        );
        assert!(
            PROBE_FUNCTION_LEAF_NAMES
                .iter()
                .any(|leaf| leaf.trim_start_matches('~') == identifier),
            "{key}: leaf {identifier} missing from PROBE_FUNCTION_LEAF_NAMES"
        );
    }
    assert_eq!(probe_leaf_identifier(REQ_STATE_DTOR), "req_state");
    assert_eq!(
        probe_leaf_identifier(RGW_RADOS_OPERATE_READ),
        RGW_RADOS_OPERATE
    );
}
