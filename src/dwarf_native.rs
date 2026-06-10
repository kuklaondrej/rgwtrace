use std::{
    borrow::Cow,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use gimli::{
    AttributeValue, DebuggingInformationEntry, Dwarf, EndianSlice, EntriesTreeNode, Operation,
    Reader, RunTimeEndian,
};
use object::{Architecture, Object, ObjectSection, ObjectSymbol};

use crate::dwarf_json::{basename, DwarfInfo, DwarfModule, FieldJson, VarLocationJson};

const PROBE_FUNCTIONS: &[&str] = &[
    "Objecter::_send_op",
    "Objecter::_finish_op",
    "RGWREST::get_handler",
];

pub fn from_paths(paths: &[impl AsRef<Path>]) -> Result<DwarfInfo> {
    let mut modules = BTreeMap::new();
    let mut arch = None;

    for path in paths {
        let path = path.as_ref();
        let module_name = basename(path)
            .with_context(|| format!("native DWARF target {} has no file name", path.display()))?
            .to_string();
        let module = parse_module(path, &mut arch)
            .with_context(|| format!("failed to parse native DWARF from {}", path.display()))?;
        modules.insert(module_name, module);
    }

    Ok(DwarfInfo {
        version: None,
        arch,
        modules,
    })
}

fn parse_module(path: &Path, arch: &mut Option<String>) -> Result<DwarfModule> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let file = object::File::parse(data.as_slice())
        .with_context(|| format!("{} is not a supported object file", path.display()))?;

    if arch.is_none() {
        *arch = arch_name(file.architecture());
    }

    let build_id = file.build_id()?.map(hex_string);
    let debug_data = debug_data(path, &file, data.as_slice(), build_id.as_deref())?;
    let debug_file = object::File::parse(debug_data.as_ref()).with_context(|| {
        format!(
            "debug info for {} is not a supported object file",
            path.display()
        )
    })?;
    let endian = if debug_file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let dwarf_cow = Dwarf::load(|section| load_section(&debug_file, section))?;
    #[allow(deprecated)]
    let dwarf = dwarf_cow.borrow(|section| EndianSlice::new(section, endian));
    let mut func2pc = function_pcs(&dwarf)?;
    for (function, pc) in symbol_function_pcs(&debug_file) {
        func2pc.entry(function).or_insert(pc);
    }
    for (function, pc) in symbol_function_pcs(&file) {
        func2pc.entry(function).or_insert(pc);
    }

    Ok(DwarfModule {
        build_id,
        func2pc,
        func2vf: BTreeMap::new(),
    })
}

fn function_pcs<R: Reader>(dwarf: &Dwarf<R>) -> Result<BTreeMap<String, u64>> {
    let mut result = BTreeMap::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;
        collect_function_pcs(dwarf, &unit, root, &mut Vec::new(), &mut result)?;
    }
    Ok(result)
}

fn symbol_function_pcs(file: &object::File<'_>) -> BTreeMap<String, u64> {
    let mut result = BTreeMap::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if !symbol.is_definition() || symbol.address() == 0 {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        let Some(function) = demangle_function_name(name) else {
            continue;
        };
        if PROBE_FUNCTIONS.contains(&function.as_str()) {
            result.entry(function).or_insert(symbol.address());
        }
    }
    result
}

fn collect_function_pcs<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    node: EntriesTreeNode<R>,
    scopes: &mut Vec<String>,
    result: &mut BTreeMap<String, u64>,
) -> Result<()> {
    let entry = node.entry();
    let scope = scope_name(dwarf, unit, entry)?;
    if let Some(scope) = &scope {
        scopes.push(scope.clone());
    }

    if entry.tag() == gimli::DW_TAG_subprogram {
        for fullname in function_names(dwarf, unit, entry, scopes)? {
            if PROBE_FUNCTIONS.contains(&fullname.as_str()) {
                if let Some(pc) = entry_pc(dwarf, unit, entry)? {
                    result.entry(fullname).or_insert(pc);
                }
            }
        }
    }

    let mut children = node.children();
    while let Some(child) = children.next()? {
        collect_function_pcs(dwarf, unit, child, scopes, result)?;
    }

    if scope.is_some() {
        scopes.pop();
    }
    Ok(())
}

fn function_names<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    scopes: &[String],
) -> Result<Vec<String>> {
    let mut names = Vec::new();
    add_entry_function_names(dwarf, unit, entry, scopes, &mut names)?;
    add_referenced_function_names(dwarf, unit, entry, gimli::DW_AT_abstract_origin, &mut names)?;
    add_referenced_function_names(dwarf, unit, entry, gimli::DW_AT_specification, &mut names)?;
    names.sort();
    names.dedup();
    Ok(names)
}

fn add_referenced_function_names<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    attr: gimli::DwAt,
    names: &mut Vec<String>,
) -> Result<()> {
    let Some(referenced) = referenced_entry(unit, entry, attr)? else {
        return Ok(());
    };
    let referenced_scopes = entry_scopes(dwarf, unit, referenced.offset())?.unwrap_or_default();
    add_entry_function_names(dwarf, unit, &referenced, &referenced_scopes, names)?;

    if attr == gimli::DW_AT_abstract_origin {
        add_referenced_function_names(dwarf, unit, &referenced, gimli::DW_AT_specification, names)?;
    }

    Ok(())
}

fn add_entry_function_names<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    scopes: &[String],
    names: &mut Vec<String>,
) -> Result<()> {
    if let Some(name) = die_name(dwarf, unit, entry)? {
        names.push(match scopes.last() {
            Some(scope) => format!("{scope}::{name}"),
            None => name,
        });
    }
    if let Some(linkage_name) = linkage_name(dwarf, unit, entry)? {
        if let Some(demangled) = demangle_function_name(&linkage_name) {
            names.push(demangled);
        }
    }
    Ok(())
}

fn referenced_entry<'unit, R: Reader>(
    unit: &'unit gimli::Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    attr: gimli::DwAt,
) -> Result<Option<DebuggingInformationEntry<'unit, 'unit, R>>> {
    let Some(attr) = entry.attr(attr)? else {
        return Ok(None);
    };
    match attr.value() {
        AttributeValue::UnitRef(offset) => Ok(Some(unit.entry(offset)?)),
        _ => Ok(None),
    }
}

fn entry_scopes<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    offset: gimli::UnitOffset<R::Offset>,
) -> Result<Option<Vec<String>>> {
    let mut tree = unit.entries_tree(None)?;
    let root = tree.root()?;
    find_entry_scopes(dwarf, unit, root, offset, &mut Vec::new())
}

fn find_entry_scopes<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    node: EntriesTreeNode<R>,
    offset: gimli::UnitOffset<R::Offset>,
    scopes: &mut Vec<String>,
) -> Result<Option<Vec<String>>> {
    let entry = node.entry();
    if entry.offset() == offset {
        return Ok(Some(scopes.clone()));
    }

    let scope = scope_name(dwarf, unit, entry)?;
    if let Some(scope) = &scope {
        scopes.push(scope.clone());
    }

    let mut children = node.children();
    while let Some(child) = children.next()? {
        if let Some(found) = find_entry_scopes(dwarf, unit, child, offset, scopes)? {
            return Ok(Some(found));
        }
    }

    if scope.is_some() {
        scopes.pop();
    }

    Ok(None)
}

#[allow(dead_code)]
fn translate_field_path<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    variable: &DebuggingInformationEntry<R>,
    path: &[&str],
) -> Result<Option<Vec<FieldJson>>> {
    let Some(mut typedie) = die_type(unit, variable)? else {
        return Ok(None);
    };
    let mut fields = vec![FieldJson::default(); path.len()];
    let mut index = 1;

    while index < path.len() {
        typedie = peel_type_qualifiers(unit, typedie)?;
        match typedie.tag() {
            gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type
            | gimli::DW_TAG_pointer_type => {
                fields[index].pointer = true;
                let Some(next_type) = die_type(unit, &typedie)? else {
                    return Ok(None);
                };
                typedie = next_type;
            }
            gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type | gimli::DW_TAG_class_type => {
                let Some(member) = find_member_entry(dwarf, unit, &typedie, path[index])? else {
                    return Ok(None);
                };
                fields[index].offset = member_offset(unit, &member)?.unwrap_or_default();
                let Some(next_type) = die_type(unit, &member)? else {
                    return Ok(None);
                };
                typedie = next_type;
                index += 1;
            }
            _ => return Ok(None),
        }
    }

    Ok(Some(fields))
}

#[allow(dead_code)]
fn variable_location<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    function: &DebuggingInformationEntry<R>,
    variable: &DebuggingInformationEntry<R>,
    pc: u64,
) -> Result<Option<VarLocationJson>> {
    let Some(attr) = variable.attr(gimli::DW_AT_location)? else {
        return Ok(None);
    };
    let frame_base = function
        .attr(gimli::DW_AT_frame_base)?
        .and_then(|attr| match attr.value() {
            AttributeValue::Exprloc(expression) => Some(expression),
            _ => None,
        });

    if let AttributeValue::Exprloc(expression) = attr.value() {
        return decode_location_expression(unit, frame_base, expression);
    }

    let Some(mut locations) = dwarf.attr_locations(unit, attr.value())? else {
        return Ok(None);
    };
    while let Some(location) = locations.next()? {
        if pc >= location.range.begin && pc < location.range.end {
            return decode_location_expression(unit, frame_base, location.data);
        }
    }

    Ok(None)
}

fn decode_location_expression<R: Reader>(
    unit: &gimli::Unit<R>,
    frame_base: Option<gimli::Expression<R>>,
    expression: gimli::Expression<R>,
) -> Result<Option<VarLocationJson>> {
    let mut location = VarLocationJson {
        reg: -1,
        offset: 0,
        stack: false,
    };
    let mut seen_location = false;
    let mut operations = expression.operations(unit.encoding());

    while let Some(operation) = operations.next()? {
        match operation {
            Operation::Register { register } => {
                location.reg = register.0 as i32;
                seen_location = true;
            }
            Operation::RegisterOffset {
                register, offset, ..
            } => {
                location.reg = register.0 as i32;
                add_location_offset(&mut location, offset)?;
                seen_location = true;
            }
            Operation::FrameOffset { offset } => {
                let Some(frame_base) = frame_base else {
                    return Ok(None);
                };
                let Some(mut frame_location) = decode_location_expression(unit, None, frame_base)?
                else {
                    return Ok(None);
                };
                add_location_offset(&mut frame_location, offset)?;
                frame_location.stack = true;
                return Ok(Some(frame_location));
            }
            Operation::PlusConstant { value } | Operation::UnsignedConstant { value } => {
                add_location_offset(&mut location, value as i64)?;
            }
            Operation::SignedConstant { value } => {
                add_location_offset(&mut location, value)?;
            }
            Operation::Nop => {}
            Operation::CallFrameCFA => return Ok(None),
            _ => {}
        }
    }

    Ok(seen_location.then_some(location))
}

fn add_location_offset(location: &mut VarLocationJson, offset: i64) -> Result<()> {
    let offset = i32::try_from(offset).context("DWARF location offset does not fit i32")?;
    location.offset = location
        .offset
        .checked_add(offset)
        .context("DWARF location offset overflow")?;
    Ok(())
}

fn peel_type_qualifiers<'unit, R: Reader>(
    unit: &'unit gimli::Unit<R>,
    mut typedie: DebuggingInformationEntry<'unit, 'unit, R>,
) -> Result<DebuggingInformationEntry<'unit, 'unit, R>> {
    while matches!(
        typedie.tag(),
        gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
    ) {
        let Some(next_type) = die_type(unit, &typedie)? else {
            break;
        };
        typedie = next_type;
    }
    Ok(typedie)
}

fn find_member_entry<'unit, R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &'unit gimli::Unit<R>,
    typedie: &DebuggingInformationEntry<R>,
    member_name: &str,
) -> Result<Option<DebuggingInformationEntry<'unit, 'unit, R>>> {
    let mut queue = vec![typedie.offset()];
    while let Some(offset) = queue.pop() {
        let mut tree = unit.entries_tree(Some(offset))?;
        let root = tree.root()?;
        let mut children = root.children();
        while let Some(child) = children.next()? {
            let entry = child.entry();
            match entry.tag() {
                gimli::DW_TAG_member => {
                    if die_name(dwarf, unit, entry)?.as_deref() == Some(member_name) {
                        return Ok(Some(unit.entry(entry.offset())?));
                    }
                }
                gimli::DW_TAG_inheritance => {
                    if let Some(parent_type) = die_type(unit, entry)? {
                        queue.push(parent_type.offset());
                    }
                }
                _ => {}
            }
        }
    }
    Ok(None)
}

#[allow(dead_code)]
fn find_child_entry_by_name<'unit, R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &'unit gimli::Unit<R>,
    parent_offset: gimli::UnitOffset<R::Offset>,
    tags: &[gimli::DwTag],
    name: &str,
) -> Result<Option<DebuggingInformationEntry<'unit, 'unit, R>>> {
    let mut tree = unit.entries_tree(Some(parent_offset))?;
    let root = tree.root()?;
    let mut children = root.children();
    while let Some(child) = children.next()? {
        let entry = child.entry();
        if tags.contains(&entry.tag()) && die_name(dwarf, unit, entry)?.as_deref() == Some(name) {
            return Ok(Some(unit.entry(entry.offset())?));
        }
    }
    Ok(None)
}

fn die_type<'unit, R: Reader>(
    unit: &'unit gimli::Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Result<Option<DebuggingInformationEntry<'unit, 'unit, R>>> {
    referenced_entry(unit, entry, gimli::DW_AT_type)
}

fn member_offset<R: Reader>(
    unit: &gimli::Unit<R>,
    member: &DebuggingInformationEntry<R>,
) -> Result<Option<i32>> {
    let Some(attr) = member.attr(gimli::DW_AT_data_member_location)? else {
        return Ok(None);
    };
    attr_offset(unit, attr.value())
}

fn attr_offset<R: Reader>(unit: &gimli::Unit<R>, value: AttributeValue<R>) -> Result<Option<i32>> {
    let offset = match value {
        AttributeValue::Data1(value) => value as i64,
        AttributeValue::Data2(value) => value as i64,
        AttributeValue::Data4(value) => value as i64,
        AttributeValue::Data8(value) => value as i64,
        AttributeValue::Sdata(value) => value,
        AttributeValue::Udata(value) => value as i64,
        AttributeValue::Exprloc(expression) => expression_offset(unit, expression)?,
        _ => return Ok(None),
    };
    Ok(i32::try_from(offset).ok())
}

fn expression_offset<R: Reader>(
    unit: &gimli::Unit<R>,
    expression: gimli::Expression<R>,
) -> Result<i64> {
    let mut offset = 0;
    let mut operations = expression.operations(unit.encoding());
    while let Some(operation) = operations.next()? {
        match operation {
            Operation::PlusConstant { value } | Operation::UnsignedConstant { value } => {
                offset += value as i64;
            }
            Operation::SignedConstant { value } | Operation::FrameOffset { offset: value } => {
                offset += value;
            }
            Operation::Nop => {}
            _ => return Ok(0),
        }
    }
    Ok(offset)
}

fn scope_name<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Result<Option<String>> {
    match entry.tag() {
        gimli::DW_TAG_class_type | gimli::DW_TAG_structure_type | gimli::DW_TAG_namespace => {
            die_name(dwarf, unit, entry)
        }
        _ => Ok(None),
    }
}

fn die_name<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Result<Option<String>> {
    let Some(attr) = entry.attr(gimli::DW_AT_name)? else {
        return Ok(None);
    };
    let name = dwarf.attr_string(unit, attr.value())?;
    Ok(Some(name.to_string_lossy()?.into_owned()))
}

fn linkage_name<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Result<Option<String>> {
    let Some(attr) = entry
        .attr(gimli::DW_AT_linkage_name)?
        .or(entry.attr(gimli::DW_AT_MIPS_linkage_name)?)
    else {
        return Ok(None);
    };
    let name = dwarf.attr_string(unit, attr.value())?;
    Ok(Some(name.to_string_lossy()?.into_owned()))
}

fn demangle_function_name(linkage_name: &str) -> Option<String> {
    let symbol = cpp_demangle::Symbol::new(linkage_name)
        .or_else(|_| {
            cpp_demangle::Symbol::new(linkage_name.strip_prefix('_').unwrap_or(linkage_name))
        })
        .ok()?;
    let demangled = symbol.to_string();
    let without_args = demangled
        .split_once('(')
        .map_or(demangled.as_str(), |(name, _)| name);
    Some(without_args.trim().to_string())
}

fn entry_pc<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Result<Option<u64>> {
    if let Some(attr) = entry.attr(gimli::DW_AT_low_pc)? {
        if let Some(pc) = dwarf.attr_address(unit, attr.value())? {
            if pc != 0 {
                return Ok(Some(pc));
            }
        }
    }

    if let Some(attr) = entry.attr(gimli::DW_AT_ranges)? {
        let Some(mut ranges) = dwarf.attr_ranges(unit, attr.value())? else {
            return Ok(None);
        };
        while let Some(range) = ranges.next()? {
            if range.begin != 0 {
                return Ok(Some(range.begin));
            }
        }
    }

    Ok(None)
}

fn load_section<'data>(
    file: &object::File<'data>,
    section: gimli::SectionId,
) -> Result<Cow<'data, [u8]>> {
    let Some(section) = file
        .section_by_name(section.name())
        .or_else(|| file.section_by_name(&macho_section_name(section.name())))
    else {
        return Ok(Cow::Borrowed(&[]));
    };
    section
        .uncompressed_data()
        .with_context(|| format!("failed to read {}", section.name().unwrap_or("<unknown>")))
}

fn debug_data<'data>(
    path: &Path,
    file: &object::File<'data>,
    data: &'data [u8],
    build_id: Option<&str>,
) -> Result<Cow<'data, [u8]>> {
    if file.has_debug_symbols() {
        return Ok(Cow::Borrowed(data));
    }

    if let Some(debug_path) = debuglink_file(path, file)? {
        return fs::read(&debug_path)
            .map(Cow::Owned)
            .with_context(|| format!("failed to read debuglink file {}", debug_path.display()));
    }

    if let Some(build_id) = build_id {
        if let Some(debug_path) = build_id_debug_file(path, build_id) {
            return fs::read(&debug_path).map(Cow::Owned).with_context(|| {
                format!(
                    "failed to read build-id debug file {}",
                    debug_path.display()
                )
            });
        }
    }

    Ok(Cow::Borrowed(data))
}

fn debuglink_file(path: &Path, file: &object::File<'_>) -> Result<Option<PathBuf>> {
    let Some((filename, _crc)) = file.gnu_debuglink()? else {
        return Ok(None);
    };
    let filename = std::str::from_utf8(filename).context(".gnu_debuglink filename is not UTF-8")?;
    Ok(first_existing(debuglink_candidates(path, filename)))
}

fn build_id_debug_file(path: &Path, build_id: &str) -> Option<PathBuf> {
    first_existing(build_id_debug_candidates(path, build_id))
}

fn first_existing(candidates: Vec<PathBuf>) -> Option<PathBuf> {
    candidates.into_iter().find(|candidate| candidate.is_file())
}

fn debuglink_candidates(path: &Path, filename: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let filename = Path::new(filename);
    let Some(parent) = path.parent() else {
        return candidates;
    };

    push_unique(&mut candidates, parent.join(filename));
    push_unique(&mut candidates, parent.join(".debug").join(filename));

    for ancestor in parent.ancestors() {
        if let Ok(relative_parent) = parent.strip_prefix(ancestor) {
            push_unique(
                &mut candidates,
                ancestor
                    .join("usr/lib/debug")
                    .join(relative_parent)
                    .join(filename),
            );
        }
    }

    candidates
}

fn build_id_debug_candidates(path: &Path, build_id: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if build_id.len() < 3 {
        return candidates;
    }

    let prefix = &build_id[..2];
    let filename = format!("{}.debug", &build_id[2..]);
    push_unique(
        &mut candidates,
        Path::new("/usr/lib/debug/.build-id")
            .join(prefix)
            .join(&filename),
    );

    if let Some(parent) = path.parent() {
        for ancestor in parent.ancestors() {
            push_unique(
                &mut candidates,
                ancestor
                    .join("usr/lib/debug/.build-id")
                    .join(prefix)
                    .join(&filename),
            );
        }
    }

    candidates
}

fn push_unique(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.contains(&path) {
        paths.push(path);
    }
}

fn macho_section_name(dwarf_section_name: &str) -> String {
    dwarf_section_name.replacen('.', "__", 1)
}

fn arch_name(arch: Architecture) -> Option<String> {
    match arch {
        Architecture::X86_64 => Some("amd64".to_string()),
        Architecture::Aarch64 => Some("arm64".to_string()),
        Architecture::I386 => Some("x86".to_string()),
        other => Some(format!("{other:?}")),
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dwarf_json::{
        DwarfInfo, DwarfModule, FieldJson, FunctionVarFields, VarFieldJson, VarLocationJson,
    };

    #[test]
    fn parses_probe_function_pcs_from_cpp_fixture_when_compiler_is_available() {
        let Some(binary) = compile_cpp_fixture() else {
            return;
        };

        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();

        assert!(module.function_addr("Objecter::_send_op").is_some());
        assert!(module.function_addr("Objecter::_finish_op").is_some());
        assert!(module.function_addr("RGWREST::get_handler").is_some());
    }

    #[test]
    fn parses_probe_function_pcs_from_gnu_debuglink_when_objcopy_is_available() {
        let Some(binary) = compile_cpp_fixture() else {
            return;
        };
        let objcopy = std::env::var_os("OBJCOPY").unwrap_or_else(|| "objcopy".into());
        let debug_file = binary.with_extension("debug");
        let stripped = binary.with_file_name("fixture-stripped");

        if !std::process::Command::new(&objcopy)
            .args(["--only-keep-debug"])
            .arg(&binary)
            .arg(&debug_file)
            .status()
            .is_ok_and(|status| status.success())
        {
            return;
        }
        if std::fs::copy(&binary, &stripped).is_err() {
            return;
        }
        if !std::process::Command::new(&objcopy)
            .args(["--strip-all"])
            .arg(format!(
                "--add-gnu-debuglink={}",
                debug_file.to_string_lossy()
            ))
            .arg(&stripped)
            .status()
            .is_ok_and(|status| status.success())
        {
            return;
        }

        let info = from_paths(&[stripped.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();

        assert!(module.function_addr("Objecter::_send_op").is_some());
        assert!(module.function_addr("Objecter::_finish_op").is_some());
        assert!(module.function_addr("RGWREST::get_handler").is_some());
    }

    #[test]
    fn debuglink_candidates_include_local_and_debug_trees() {
        let candidates =
            debuglink_candidates(Path::new("/tmp/root/usr/bin/radosgw"), "radosgw.debug");

        assert!(candidates.contains(&PathBuf::from("/tmp/root/usr/bin/radosgw.debug")));
        assert!(candidates.contains(&PathBuf::from("/tmp/root/usr/bin/.debug/radosgw.debug")));
        assert!(candidates.contains(&PathBuf::from(
            "/tmp/root/usr/lib/debug/usr/bin/radosgw.debug"
        )));
    }

    #[test]
    fn build_id_candidates_include_host_and_rooted_debug_trees() {
        let candidates =
            build_id_debug_candidates(Path::new("/tmp/root/usr/bin/radosgw"), "abcdef");

        assert!(candidates.contains(&PathBuf::from("/usr/lib/debug/.build-id/ab/cdef.debug")));
        assert!(candidates.contains(&PathBuf::from(
            "/tmp/root/usr/lib/debug/.build-id/ab/cdef.debug"
        )));
    }

    #[test]
    fn translates_nested_member_offsets_from_cpp_fixture() {
        let Some(binary) = compile_field_fixture() else {
            return;
        };

        let Some(fields) = field_offsets_from_fixture(&binary).unwrap() else {
            return;
        };

        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].offset, 0);
        assert!(!fields[0].pointer);
        assert_eq!(fields[1].offset, 4);
        assert!(!fields[1].pointer);
        assert_eq!(fields[2].offset, 4);
        assert!(!fields[2].pointer);
    }

    #[test]
    fn decodes_parameter_location_from_cpp_fixture() {
        let Some(binary) = compile_field_fixture() else {
            return;
        };

        let Some(location) = parameter_location_from_fixture(&binary).unwrap() else {
            return;
        };

        assert!(location.reg >= 0);
    }

    #[test]
    fn oracle_comparison_reports_function_pc_mismatch() {
        let mut expected = DwarfInfo {
            version: None,
            arch: Some("amd64".to_string()),
            modules: BTreeMap::new(),
        };
        expected.modules.insert(
            "libceph-common.so.2".to_string(),
            module_with_func("Objecter::_send_op", 123),
        );
        let mut actual = expected.clone();
        actual
            .modules
            .get_mut("libceph-common.so.2")
            .unwrap()
            .func2pc
            .insert("Objecter::_send_op".to_string(), 456);

        let error = compare_dwarf_oracle(&expected, &actual, false).unwrap_err();

        assert!(error.contains("func2pc mismatch"));
        assert!(error.contains("Objecter::_send_op"));
    }

    #[test]
    fn oracle_comparison_can_include_var_fields() {
        let mut expected = DwarfInfo {
            version: None,
            arch: Some("amd64".to_string()),
            modules: BTreeMap::new(),
        };
        let mut module = module_with_func("RGWREST::get_handler", 100);
        module.func2vf.insert(
            "RGWREST::get_handler".to_string(),
            FunctionVarFields {
                var_fields: vec![VarFieldJson {
                    location: VarLocationJson {
                        reg: 4,
                        offset: 0,
                        stack: false,
                    },
                    fields: vec![FieldJson {
                        offset: 16,
                        pointer: true,
                    }],
                }],
            },
        );
        expected
            .modules
            .insert("radosgw".to_string(), module.clone());
        let mut actual = expected.clone();
        actual.modules.get_mut("radosgw").unwrap().func2vf.clear();

        assert!(compare_dwarf_oracle(&expected, &actual, false).is_ok());
        let error = compare_dwarf_oracle(&expected, &actual, true).unwrap_err();

        assert!(error.contains("func2vf"));
        assert!(error.contains("RGWREST::get_handler"));
    }

    #[test]
    fn compares_native_output_to_cephtrace_json_oracle_when_configured() {
        let Some((oracle_json, target_paths, compare_var_fields)) = oracle_config() else {
            return;
        };

        let expected = DwarfInfo::from_path(&oracle_json).unwrap();
        let actual = from_paths(&target_paths).unwrap();

        compare_dwarf_oracle(&expected, &actual, compare_var_fields).unwrap();
    }

    fn compare_dwarf_oracle(
        expected: &DwarfInfo,
        actual: &DwarfInfo,
        compare_var_fields: bool,
    ) -> Result<(), String> {
        let mut errors = Vec::new();

        if expected.arch != actual.arch {
            errors.push(format!(
                "arch mismatch: expected {:?}, actual {:?}",
                expected.arch, actual.arch
            ));
        }

        for (module_name, expected_module) in &expected.modules {
            let Some(actual_module) = actual.modules.get(module_name) else {
                errors.push(format!("missing module {module_name}"));
                continue;
            };
            compare_module(
                module_name,
                expected_module,
                actual_module,
                compare_var_fields,
                &mut errors,
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("\n"))
        }
    }

    fn compare_module(
        module_name: &str,
        expected: &DwarfModule,
        actual: &DwarfModule,
        compare_var_fields: bool,
        errors: &mut Vec<String>,
    ) {
        if expected.build_id != actual.build_id {
            errors.push(format!(
                "{module_name} build_id mismatch: expected {:?}, actual {:?}",
                expected.build_id, actual.build_id
            ));
        }

        for (function, expected_pc) in &expected.func2pc {
            match actual.func2pc.get(function) {
                Some(actual_pc) if actual_pc == expected_pc => {}
                Some(actual_pc) => errors.push(format!(
                    "{module_name} func2pc mismatch for {function}: expected {expected_pc}, actual {actual_pc}"
                )),
                None => errors.push(format!("{module_name} missing func2pc for {function}")),
            }
        }

        if compare_var_fields {
            for (function, expected_fields) in &expected.func2vf {
                match actual.func2vf.get(function) {
                    Some(actual_fields) if same_var_fields(expected_fields, actual_fields) => {}
                    Some(_) => {
                        errors.push(format!("{module_name} func2vf mismatch for {function}"))
                    }
                    None => errors.push(format!("{module_name} missing func2vf for {function}")),
                }
            }
        }
    }

    fn same_var_fields(left: &FunctionVarFields, right: &FunctionVarFields) -> bool {
        if left.var_fields.len() != right.var_fields.len() {
            return false;
        }
        left.var_fields
            .iter()
            .zip(&right.var_fields)
            .all(|(left, right)| {
                left.location.reg == right.location.reg
                    && left.location.offset == right.location.offset
                    && left.location.stack == right.location.stack
                    && left.fields.len() == right.fields.len()
                    && left.fields.iter().zip(&right.fields).all(|(left, right)| {
                        left.offset == right.offset && left.pointer == right.pointer
                    })
            })
    }

    fn oracle_config() -> Option<(std::path::PathBuf, Vec<std::path::PathBuf>, bool)> {
        let oracle_json = std::env::var_os("RGWTRACE_ORACLE_JSON")?.into();
        let target_paths = std::env::var_os("RGWTRACE_ORACLE_TARGETS")?;
        let target_paths = std::env::split_paths(&target_paths).collect::<Vec<_>>();
        if target_paths.is_empty() {
            return None;
        }
        let compare_var_fields = std::env::var_os("RGWTRACE_ORACLE_COMPARE_FUNC2VF").is_some();
        Some((oracle_json, target_paths, compare_var_fields))
    }

    fn module_with_func(function: &str, pc: u64) -> DwarfModule {
        let mut module = DwarfModule {
            build_id: Some("abc".to_string()),
            func2pc: BTreeMap::new(),
            func2vf: BTreeMap::new(),
        };
        module.func2pc.insert(function.to_string(), pc);
        module
    }

    fn compile_cpp_fixture() -> Option<std::path::PathBuf> {
        compile_cpp_source(
            "fixture",
            r#"
            class Objecter {
            public:
              __attribute__((noinline)) void _send_op(int op);
              __attribute__((noinline)) void _finish_op(int op);
              volatile int sink = 0;
            };
            class RGWREST {
            public:
              __attribute__((noinline)) void get_handler(int s);
              volatile int sink = 0;
            };
            void Objecter::_send_op(int op) { sink += op; }
            void Objecter::_finish_op(int op) { sink += op; }
            void RGWREST::get_handler(int s) { sink += s; }
            int main() {
              Objecter objecter;
              RGWREST rest;
              objecter._send_op(1);
              objecter._finish_op(2);
              rest.get_handler(3);
              return 0;
            }
            "#,
        )
    }

    fn compile_field_fixture() -> Option<std::path::PathBuf> {
        compile_cpp_source(
            "field-fixture",
            r#"
            struct Leaf {
              int prefix;
              int value;
            };
            struct Outer {
              int pad;
              Leaf leaf;
            };
            __attribute__((noinline)) int inspect(Outer outer) {
              return outer.leaf.value;
            }
            int main() {
              Outer outer = {1, {2, 3}};
              return inspect(outer);
            }
            "#,
        )
    }

    fn compile_cpp_source(name: &str, contents: &str) -> Option<std::path::PathBuf> {
        let compiler = std::env::var_os("CXX").unwrap_or_else(|| "c++".into());
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "rgwtrace-dwarf-native-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).ok()?;
        let source = dir.join(format!("{name}.cc"));
        let binary = dir.join(name);
        std::fs::write(&source, contents).ok()?;
        let status = std::process::Command::new(compiler)
            .args(["-g", "-O0", "-fno-inline"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .ok()?;
        status.success().then_some(binary)
    }

    fn field_offsets_from_fixture(binary: &Path) -> Result<Option<Vec<FieldJson>>> {
        let data = std::fs::read(binary)?;
        let file = object::File::parse(data.as_slice())?;
        let endian = if file.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let dwarf_cow = Dwarf::load(|section| load_section(&file, section))?;
        #[allow(deprecated)]
        let dwarf = dwarf_cow.borrow(|section| EndianSlice::new(section, endian));

        let mut units = dwarf.units();
        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let Some(function) = find_subprogram_by_name(&dwarf, &unit, "inspect")? else {
                continue;
            };
            let Some(param) = find_child_entry_by_name(
                &dwarf,
                &unit,
                function.offset(),
                &[gimli::DW_TAG_formal_parameter],
                "outer",
            )?
            else {
                continue;
            };
            return translate_field_path(&dwarf, &unit, &param, &["outer", "leaf", "value"]);
        }

        Ok(None)
    }

    fn parameter_location_from_fixture(binary: &Path) -> Result<Option<VarLocationJson>> {
        let data = std::fs::read(binary)?;
        let file = object::File::parse(data.as_slice())?;
        let endian = if file.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let dwarf_cow = Dwarf::load(|section| load_section(&file, section))?;
        #[allow(deprecated)]
        let dwarf = dwarf_cow.borrow(|section| EndianSlice::new(section, endian));

        let mut units = dwarf.units();
        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let Some(function) = find_subprogram_by_name(&dwarf, &unit, "inspect")? else {
                continue;
            };
            let Some(param) = find_child_entry_by_name(
                &dwarf,
                &unit,
                function.offset(),
                &[gimli::DW_TAG_formal_parameter],
                "outer",
            )?
            else {
                continue;
            };
            let Some(pc) = entry_pc(&dwarf, &unit, &function)? else {
                continue;
            };
            return variable_location(&dwarf, &unit, &function, &param, pc);
        }

        Ok(None)
    }

    fn find_subprogram_by_name<'unit, R: Reader>(
        dwarf: &Dwarf<R>,
        unit: &'unit gimli::Unit<R>,
        name: &str,
    ) -> Result<Option<DebuggingInformationEntry<'unit, 'unit, R>>> {
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;
        find_subprogram_node(dwarf, unit, root, &mut Vec::new(), name)
    }

    fn find_subprogram_node<'unit, R: Reader>(
        dwarf: &Dwarf<R>,
        unit: &'unit gimli::Unit<R>,
        node: EntriesTreeNode<R>,
        scopes: &mut Vec<String>,
        name: &str,
    ) -> Result<Option<DebuggingInformationEntry<'unit, 'unit, R>>> {
        let entry = node.entry();
        let scope = scope_name(dwarf, unit, entry)?;
        if let Some(scope) = &scope {
            scopes.push(scope.clone());
        }

        if entry.tag() == gimli::DW_TAG_subprogram
            && function_names(dwarf, unit, entry, scopes)?
                .iter()
                .any(|candidate| candidate == name)
        {
            return Ok(Some(unit.entry(entry.offset())?));
        }

        let mut children = node.children();
        while let Some(child) = children.next()? {
            if let Some(found) = find_subprogram_node(dwarf, unit, child, scopes, name)? {
                return Ok(Some(found));
            }
        }

        if scope.is_some() {
            scopes.pop();
        }

        Ok(None)
    }

    trait TestModuleExt {
        fn function_addr(&self, function: &str) -> Option<u64>;
    }

    impl TestModuleExt for DwarfModule {
        fn function_addr(&self, function: &str) -> Option<u64> {
            self.func2pc
                .get(function)
                .copied()
                .filter(|addr| *addr != 0)
        }
    }
}
