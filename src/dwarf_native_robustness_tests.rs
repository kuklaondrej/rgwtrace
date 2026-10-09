//! Adversarial-input tests for the native DWARF parser: reference cycles, deep
//! DIE nesting, oversized files and compressed-section bombs. Every input here is
//! built in memory, so the tests run on any host (no compiler, no Ceph build).

use std::{sync::mpsc, thread, time::Duration};

use gimli::{write, EndianSlice, LittleEndian, RunTimeEndian};

use super::*;

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
