use std::{
    borrow::Cow,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result};
use gimli::{
    AttributeValue, DebuggingInformationEntry, Dwarf, EndianSlice, EntriesTreeNode, Operation,
    Reader, RunTimeEndian,
};
use object::{Architecture, Object, ObjectSection, ObjectSymbol, SymbolKind};
use tracing::debug;

use crate::dwarf_json::{
    basename, function_key_matches, DwarfInfo, DwarfModule, FieldJson, FunctionVarFields,
    VarFieldJson, VarLocationJson,
};

const PROBE_FUNCTIONS: &[&str] = &[
    "Objecter::_send_op",
    "Objecter::_finish_op",
    "Objecter::op_submit",
    "process_request",
    "RGWREST::get_handler",
    "RGWOp::init",
    "rgw_rados_operate",
    "RadosWriter::RadosWriter",
    "RadosWriter::process",
    "RadosWriter::write_exclusive",
    "AtomicObjectProcessor::prepare",
    "MultipartObjectProcessor::prepare",
    "AppendObjectProcessor::prepare",
    "AtomicObjectProcessor::process_first_chunk",
    "MultipartObjectProcessor::process_first_chunk",
    "AppendObjectProcessor::process_first_chunk",
    "HeadObjectProcessor::process",
    "AtomicObjectProcessor::complete",
    "MultipartObjectProcessor::complete",
    "AppendObjectProcessor::complete",
    "RGWRados::Object::Write::write_meta",
    "RGWRados::Object::Write::_do_write_meta",
];
const OBJECTER_PROBE_FUNCTIONS: &[&str] = &[
    "Objecter::_send_op",
    "Objecter::_finish_op",
    "Objecter::op_submit",
];
const RGW_PROBE_FUNCTIONS: &[&str] = &[
    "process_request",
    "RGWREST::get_handler",
    "RGWOp::init",
    "rgw_rados_operate",
    "RadosWriter::RadosWriter",
    "RadosWriter::process",
    "RadosWriter::write_exclusive",
    "AtomicObjectProcessor::prepare",
    "MultipartObjectProcessor::prepare",
    "AppendObjectProcessor::prepare",
    "AtomicObjectProcessor::process_first_chunk",
    "MultipartObjectProcessor::process_first_chunk",
    "AppendObjectProcessor::process_first_chunk",
    "HeadObjectProcessor::process",
    "AtomicObjectProcessor::complete",
    "MultipartObjectProcessor::complete",
    "AppendObjectProcessor::complete",
    "RGWRados::Object::Write::write_meta",
    "RGWRados::Object::Write::_do_write_meta",
];
const PROBE_FUNCTION_LEAF_NAMES: &[&str] = &[
    "_send_op",
    "_finish_op",
    "op_submit",
    "process_request",
    "get_handler",
    "init",
    "rgw_rados_operate",
    "RadosWriter",
    "process",
    "write_exclusive",
    "prepare",
    "process_first_chunk",
    "complete",
    "write_meta",
    "_do_write_meta",
];
const OBJECTER_FINISH_OP_FIELDS: &[&[&str]] = &[
    &["op", "tid"],
    &["this", "monc", "global_id"],
    &["op", "target", "osd"],
];
const OBJECTER_SEND_OP_FIELDS: &[&[&str]] = &[
    &["op", "tid"],
    &["this", "monc", "global_id"],
    &["op", "target", "osd"],
    &["op", "target", "base_oid", "name", "_M_string_length"],
    &["op", "target", "base_oid", "name", "_M_dataplus", "_M_p"],
    &["op", "target", "flags"],
    &["op", "target", "actual_pgid", "pgid", "m_pool"],
    &["op", "target", "actual_pgid", "pgid", "m_seed"],
    &["op", "target", "acting", "_M_impl", "_M_start"],
    &["op", "target", "acting", "_M_impl", "_M_finish"],
    &["op", "ops", "m_holder", "m_start"],
    &["op", "ops", "m_holder", "m_size"],
];
const RGWREST_GET_HANDLER_FIELDS: &[&[&str]] = &[
    &["s", "id"],
    &["s", "req_id", "_M_string_length"],
    &["s", "req_id", "_M_dataplus", "_M_p"],
    &["s", "trans_id", "_M_string_length"],
    &["s", "trans_id", "_M_dataplus", "_M_p"],
];
const PROCESS_REQUEST_FIELDS: &[&[&str]] = &[&["req", "id"]];
const RGW_OP_INIT_FIELDS: &[&[&str]] = &[&["this"], &["s"]];
const RGW_RADOS_OPERATE_FIELDS: &[&[&str]] = &[&["dpp"]];
const RADOS_WRITER_CTOR_FIELDS: &[&[&str]] = &[&["this"], &["dpp"]];
const RADOS_WRITER_PROCESS_FIELDS: &[&[&str]] = &[&["this"], &["this", "dpp"]];
const RADOS_WRITER_WRITE_EXCLUSIVE_FIELDS: &[&[&str]] = &[&["this"], &["this", "dpp"]];
const PUT_PROCESSOR_PREPARE_FIELDS: &[&[&str]] = &[&["this"]];
const PUT_PROCESSOR_PROCESS_FIRST_CHUNK_FIELDS: &[&[&str]] =
    &[&["this"], &["processor"], &["this", "dpp"]];
const HEAD_OBJECT_PROCESSOR_PROCESS_FIELDS: &[&[&str]] = &[&["this"]];
const PUT_PROCESSOR_COMPLETE_FIELDS: &[&[&str]] = &[&["this"], &["this", "dpp"]];
const RGW_WRITE_META_FIELDS: &[&[&str]] = &[&["dpp"]];
const OBJECTER_OP_SUBMIT_FIELDS: &[&[&str]] = &[&["op"]];

#[allow(dead_code)]
pub fn from_paths(paths: &[impl AsRef<Path>]) -> Result<DwarfInfo> {
    from_paths_with_version(paths, None)
}

pub fn from_paths_with_version(
    paths: &[impl AsRef<Path>],
    version_override: Option<&str>,
) -> Result<DwarfInfo> {
    let mut modules = BTreeMap::new();
    let mut arch = None;

    for path in paths {
        let path = path.as_ref();
        let module_name = basename(path)
            .with_context(|| format!("native DWARF target {} has no file name", path.display()))?
            .to_string();
        let module = parse_module(path, &module_name, &mut arch)
            .with_context(|| format!("failed to parse native DWARF from {}", path.display()))?;
        modules.insert(module_name, module);
    }

    let version = version_override
        .and_then(clean_version)
        .or_else(|| resolve_ceph_version(paths));

    Ok(DwarfInfo {
        version,
        arch,
        modules,
    })
}

fn resolve_ceph_version(paths: &[impl AsRef<Path>]) -> Option<String> {
    embedded_ceph_version(paths)
        .or_else(|| microceph_ceph_version(paths))
        .or_else(package_manager_ceph_version)
}

fn embedded_ceph_version(paths: &[impl AsRef<Path>]) -> Option<String> {
    paths
        .iter()
        .filter_map(|path| fs::read(path).ok())
        .find_map(|data| ceph_version_from_bytes(&data))
}

fn ceph_version_from_bytes(bytes: &[u8]) -> Option<String> {
    let needle = b"ceph version ";
    let start = bytes
        .windows(needle.len())
        .position(|window| window == needle)?
        + needle.len();
    let len = bytes[start..]
        .iter()
        .position(|byte| byte.is_ascii_whitespace() || *byte == 0)
        .unwrap_or(bytes.len() - start);
    let version = std::str::from_utf8(&bytes[start..start + len]).ok()?;
    clean_version(version)
}

fn microceph_ceph_version(paths: &[impl AsRef<Path>]) -> Option<String> {
    paths
        .iter()
        .flat_map(|path| microceph_metadata_candidates(path.as_ref()))
        .filter_map(|path| fs::read_to_string(path).ok())
        .find_map(|contents| ceph_version_from_text(&contents))
}

fn microceph_metadata_candidates(path: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    for ancestor in path.ancestors() {
        push_unique(&mut candidates, ancestor.join("share/metadata.yaml"));
        push_unique(&mut candidates, ancestor.join("snap/manifest.yaml"));
    }
    candidates
}

fn ceph_version_from_text(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("ceph-version") {
            if let Some(version) = version_from_line_value(line) {
                return Some(version);
            }
        }
        for package in ["radosgw", "librados2", "ceph-common", "ceph-osd"] {
            if line.starts_with(package) {
                if let Some(version) = version_from_line_value(line) {
                    return Some(version);
                }
            }
        }
    }
    text.find("ceph version ")
        .and_then(|idx| first_version_token(&text[idx + "ceph version ".len()..]))
}

fn version_from_line_value(line: &str) -> Option<String> {
    let value = line
        .split_once(':')
        .or_else(|| line.split_once('='))
        .map(|(_, value)| value)?;
    first_version_token(value)
}

fn first_version_token(value: &str) -> Option<String> {
    value
        .split(|ch: char| ch.is_whitespace() || ch == ',' || ch == '"' || ch == '\'')
        .find_map(clean_version)
}

fn clean_version(version: &str) -> Option<String> {
    let version = version.trim().trim_matches(['"', '\'', '[', ']']);
    let starts_with_digit = version
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_digit());
    (starts_with_digit && version.contains('.')).then(|| version.to_string())
}

fn package_manager_ceph_version() -> Option<String> {
    for package in ["radosgw", "librados2", "ceph-common"] {
        if let Some(version) =
            command_output_version("dpkg-query", &["-W", "-f=${Version}", package])
        {
            return Some(version);
        }
    }
    for package in ["ceph-radosgw", "librados2", "ceph-common"] {
        if let Some(version) =
            command_output_version("rpm", &["-q", "--qf", "%{VERSION}-%{RELEASE}", package])
        {
            return Some(version);
        }
    }
    None
}

fn command_output_version(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
        .and_then(|stdout| first_version_token(&stdout))
}

fn parse_module(path: &Path, module_name: &str, arch: &mut Option<String>) -> Result<DwarfModule> {
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
    let wanted = probe_functions_for_module(module_name);
    let mut func2pc = symbol_function_pcs(&debug_file, wanted);
    for (function, pc) in symbol_function_pcs(&file, wanted) {
        func2pc.entry(function).or_insert(pc);
    }
    if !has_all_functions(&func2pc, wanted) {
        for (function, pc) in function_pcs(&dwarf, wanted)? {
            func2pc.entry(function).or_insert(pc);
        }
    }
    let func2vf = function_var_fields(&dwarf, wanted)?;

    Ok(DwarfModule {
        build_id,
        func2pc,
        func2vf,
    })
}

fn probe_functions_for_module(module_name: &str) -> &'static [&'static str] {
    if module_name == "radosgw" || module_name.contains("radosgw") {
        RGW_PROBE_FUNCTIONS
    } else if module_name.starts_with("libceph-common") {
        OBJECTER_PROBE_FUNCTIONS
    } else {
        PROBE_FUNCTIONS
    }
}

fn has_all_functions<T>(result: &BTreeMap<String, T>, wanted: &[&str]) -> bool {
    wanted
        .iter()
        .all(|function| result.keys().any(|key| function_key_matches(key, function)))
}

fn can_stop_function_search<T>(result: &BTreeMap<String, T>, wanted: &[&str]) -> bool {
    has_all_functions(result, wanted) && !wanted.contains(&"rgw_rados_operate")
}

fn canonical_probe_function_name(function: &str, wanted: &[&str]) -> Option<String> {
    wanted.iter().find_map(|candidate| {
        (function == *candidate || function.ends_with(&format!("::{candidate}")))
            .then(|| (*candidate).to_string())
    })
}

fn insert_function_pc(result: &mut BTreeMap<String, u64>, function: String, pc: u64) {
    if let std::collections::btree_map::Entry::Vacant(entry) = result.entry(function.clone()) {
        entry.insert(pc);
        return;
    }
    for idx in 1..256 {
        let key = format!("{function}#{idx}");
        if let std::collections::btree_map::Entry::Vacant(entry) = result.entry(key) {
            entry.insert(pc);
            return;
        }
    }
}

fn function_pcs<R: Reader>(dwarf: &Dwarf<R>, wanted: &[&str]) -> Result<BTreeMap<String, u64>> {
    let mut result = BTreeMap::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;
        collect_function_pcs(dwarf, &unit, root, &mut Vec::new(), &mut result, wanted)?;
        if can_stop_function_search(&result, wanted) {
            break;
        }
    }
    Ok(result)
}

fn function_var_fields<R: Reader>(
    dwarf: &Dwarf<R>,
    wanted: &[&str],
) -> Result<BTreeMap<String, FunctionVarFields>> {
    let mut result = BTreeMap::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;
        collect_function_var_fields(dwarf, &unit, root, &mut Vec::new(), &mut result, wanted)?;
        if can_stop_function_search(&result, wanted) {
            break;
        }
    }
    Ok(result)
}

fn collect_function_var_fields<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    node: EntriesTreeNode<R>,
    scopes: &mut Vec<String>,
    result: &mut BTreeMap<String, FunctionVarFields>,
    wanted: &[&str],
) -> Result<()> {
    if can_stop_function_search(result, wanted) {
        return Ok(());
    }

    let entry = node.entry();
    let scope = scope_name(dwarf, unit, entry)?;
    if let Some(scope) = &scope {
        scopes.push(scope.clone());
    }

    if entry.tag() == gimli::DW_TAG_subprogram {
        for fullname in function_names(dwarf, unit, entry, scopes)? {
            let Some(canonical_name) = canonical_probe_function_name(&fullname, wanted) else {
                continue;
            };
            if let Some(paths) = probe_field_paths(&canonical_name) {
                if let Some(fields) =
                    probe_function_var_fields(dwarf, unit, entry, &canonical_name, paths)?
                {
                    insert_function_var_fields(result, canonical_name, fields);
                }
            }
        }
        if scope.is_some() {
            scopes.pop();
        }
        return Ok(());
    }

    let mut children = node.children();
    while let Some(child) = children.next()? {
        collect_function_var_fields(dwarf, unit, child, scopes, result, wanted)?;
        if can_stop_function_search(result, wanted) {
            break;
        }
    }

    if scope.is_some() {
        scopes.pop();
    }
    Ok(())
}

fn insert_function_var_fields(
    result: &mut BTreeMap<String, FunctionVarFields>,
    function: String,
    fields: FunctionVarFields,
) {
    if let std::collections::btree_map::Entry::Vacant(entry) = result.entry(function.clone()) {
        entry.insert(fields);
        return;
    }
    for idx in 1..256 {
        let key = format!("{function}#{idx}");
        if let std::collections::btree_map::Entry::Vacant(entry) = result.entry(key) {
            entry.insert(fields);
            return;
        }
    }
}

fn probe_function_var_fields<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    function: &DebuggingInformationEntry<R>,
    function_name: &str,
    paths: &[&[&str]],
) -> Result<Option<FunctionVarFields>> {
    let Some(pc) = entry_pc(dwarf, unit, function)? else {
        debug!(
            function = function_name,
            "native DWARF probe rejected: missing function PC"
        );
        return Ok(None);
    };
    let mut var_fields = Vec::new();

    for path in paths {
        let Some(variable_name) = path.first() else {
            debug!(
                function = function_name,
                "native DWARF probe rejected: empty field path"
            );
            return Ok(None);
        };
        let Some(variable) = find_function_variable(dwarf, unit, function, variable_name)? else {
            debug!(
                function = function_name,
                variable = *variable_name,
                "native DWARF probe rejected: missing variable"
            );
            return Ok(None);
        };
        let Some(location) = variable_location(dwarf, unit, function, &variable, pc)? else {
            debug!(
                function = function_name,
                variable = *variable_name,
                "native DWARF probe rejected: missing variable location"
            );
            return Ok(None);
        };
        let Some(fields) = translate_field_path(dwarf, unit, &variable, path)? else {
            debug!(
                function = function_name,
                path = path.join("."),
                "native DWARF probe rejected: field path translation failed"
            );
            return Ok(None);
        };
        var_fields.push(VarFieldJson { location, fields });
    }

    Ok(Some(FunctionVarFields { var_fields }))
}

fn probe_field_paths(function: &str) -> Option<&'static [&'static [&'static str]]> {
    match function {
        "Objecter::_send_op" => Some(OBJECTER_SEND_OP_FIELDS),
        "Objecter::_finish_op" => Some(OBJECTER_FINISH_OP_FIELDS),
        "Objecter::op_submit" => Some(OBJECTER_OP_SUBMIT_FIELDS),
        "process_request" => Some(PROCESS_REQUEST_FIELDS),
        "RGWREST::get_handler" => Some(RGWREST_GET_HANDLER_FIELDS),
        "RGWOp::init" => Some(RGW_OP_INIT_FIELDS),
        "rgw_rados_operate" => Some(RGW_RADOS_OPERATE_FIELDS),
        "RadosWriter::RadosWriter" => Some(RADOS_WRITER_CTOR_FIELDS),
        "RadosWriter::process" => Some(RADOS_WRITER_PROCESS_FIELDS),
        "RadosWriter::write_exclusive" => Some(RADOS_WRITER_WRITE_EXCLUSIVE_FIELDS),
        "AtomicObjectProcessor::prepare" => Some(PUT_PROCESSOR_PREPARE_FIELDS),
        "MultipartObjectProcessor::prepare" => Some(PUT_PROCESSOR_PREPARE_FIELDS),
        "AppendObjectProcessor::prepare" => Some(PUT_PROCESSOR_PREPARE_FIELDS),
        "AtomicObjectProcessor::process_first_chunk" => {
            Some(PUT_PROCESSOR_PROCESS_FIRST_CHUNK_FIELDS)
        }
        "MultipartObjectProcessor::process_first_chunk" => {
            Some(PUT_PROCESSOR_PROCESS_FIRST_CHUNK_FIELDS)
        }
        "AppendObjectProcessor::process_first_chunk" => {
            Some(PUT_PROCESSOR_PROCESS_FIRST_CHUNK_FIELDS)
        }
        "HeadObjectProcessor::process" => Some(HEAD_OBJECT_PROCESSOR_PROCESS_FIELDS),
        "AtomicObjectProcessor::complete" => Some(PUT_PROCESSOR_COMPLETE_FIELDS),
        "MultipartObjectProcessor::complete" => Some(PUT_PROCESSOR_COMPLETE_FIELDS),
        "AppendObjectProcessor::complete" => Some(PUT_PROCESSOR_COMPLETE_FIELDS),
        "RGWRados::Object::Write::write_meta" => Some(RGW_WRITE_META_FIELDS),
        "RGWRados::Object::Write::_do_write_meta" => Some(RGW_WRITE_META_FIELDS),
        _ => None,
    }
}

fn symbol_function_pcs(file: &object::File<'_>, wanted: &[&str]) -> BTreeMap<String, u64> {
    let mut result = BTreeMap::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if !symbol.is_definition()
            || !symbol.is_global()
            || symbol.kind() != SymbolKind::Text
            || symbol.address() == 0
        {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        if let Some(canonical_name) = symbol_probe_function_name(name, wanted) {
            insert_function_pc(&mut result, canonical_name, symbol.address());
        }
    }
    result
}

fn symbol_probe_function_name(name: &str, wanted: &[&str]) -> Option<String> {
    demangle_function_name(name)
        .and_then(|function| canonical_probe_function_name(&function, wanted))
        .or_else(|| canonical_probe_function_name(name, wanted))
        .or_else(|| canonical_probe_function_name(name.strip_prefix('_').unwrap_or(name), wanted))
}

fn collect_function_pcs<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    node: EntriesTreeNode<R>,
    scopes: &mut Vec<String>,
    result: &mut BTreeMap<String, u64>,
    wanted: &[&str],
) -> Result<()> {
    if can_stop_function_search(result, wanted) {
        return Ok(());
    }

    let entry = node.entry();
    let scope = scope_name(dwarf, unit, entry)?;
    if let Some(scope) = &scope {
        scopes.push(scope.clone());
    }

    if entry.tag() == gimli::DW_TAG_subprogram {
        for fullname in function_names(dwarf, unit, entry, scopes)? {
            if let Some(canonical_name) = canonical_probe_function_name(&fullname, wanted) {
                if let Some(pc) = entry_pc(dwarf, unit, entry)? {
                    insert_function_pc(result, canonical_name, pc);
                }
            }
        }
        if scope.is_some() {
            scopes.pop();
        }
        return Ok(());
    }

    let mut children = node.children();
    while let Some(child) = children.next()? {
        collect_function_pcs(dwarf, unit, child, scopes, result, wanted)?;
        if can_stop_function_search(result, wanted) {
            break;
        }
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
    let before = names.len();
    add_entry_function_names(dwarf, unit, &referenced, &[], names)?;

    let already_qualified = names[before..]
        .iter()
        .any(|name| canonical_probe_function_name(name, PROBE_FUNCTIONS).is_some());
    if !already_qualified {
        if let Some(name) = die_name(dwarf, unit, &referenced)? {
            if PROBE_FUNCTION_LEAF_NAMES.contains(&name.as_str()) {
                let referenced_scopes =
                    entry_scopes(dwarf, unit, referenced.offset())?.unwrap_or_default();
                add_entry_function_names(dwarf, unit, &referenced, &referenced_scopes, names)?;
            }
        }
    }

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
        AttributeValue::DebugInfoRef(offset) => Ok(offset
            .to_unit_offset(&unit.header)
            .map(|offset| unit.entry(offset))
            .transpose()?),
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
    let Some(typedie) = die_type(unit, variable)? else {
        return Ok(None);
    };
    let mut fields = vec![FieldJson::default(); path.len()];
    let mut resolving = Vec::new();
    translate_field_path_from(dwarf, unit, typedie, &mut fields, 1, path, &mut resolving)
}

fn translate_field_path_from<'unit, R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &'unit gimli::Unit<R>,
    mut typedie: DebuggingInformationEntry<'unit, 'unit, R>,
    fields: &mut [FieldJson],
    mut index: usize,
    path: &[&str],
    resolving: &mut Vec<String>,
) -> Result<Option<Vec<FieldJson>>> {
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
                    if let Some(fields) = translate_declared_type_field_path(
                        dwarf, unit, &typedie, fields, index, path, resolving,
                    )? {
                        return Ok(Some(fields));
                    }
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

    Ok(Some(fields.to_vec()))
}

fn translate_declared_type_field_path<'unit, R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &'unit gimli::Unit<R>,
    typedie: &DebuggingInformationEntry<'unit, 'unit, R>,
    fields: &[FieldJson],
    index: usize,
    path: &[&str],
    resolving: &mut Vec<String>,
) -> Result<Option<Vec<FieldJson>>> {
    if !entry_flag(typedie, gimli::DW_AT_declaration)? {
        return Ok(None);
    }
    let Some(type_name) = die_name(dwarf, unit, typedie)? else {
        return Ok(None);
    };
    if resolving.contains(&type_name) {
        return Ok(None);
    }

    resolving.push(type_name.clone());
    let result = translate_named_type_field_path(dwarf, &type_name, fields, index, path, resolving);
    resolving.pop();
    result
}

fn translate_named_type_field_path<R: Reader>(
    dwarf: &Dwarf<R>,
    type_name: &str,
    fields: &[FieldJson],
    index: usize,
    path: &[&str],
    resolving: &mut Vec<String>,
) -> Result<Option<Vec<FieldJson>>> {
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;
        let search = NamedTypeFieldSearch { type_name, path };
        if let Some(fields) =
            find_named_type_field_path(dwarf, &unit, root, fields, index, &search, resolving)?
        {
            return Ok(Some(fields));
        }
    }
    Ok(None)
}

struct NamedTypeFieldSearch<'a> {
    type_name: &'a str,
    path: &'a [&'a str],
}

fn find_named_type_field_path<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    node: EntriesTreeNode<R>,
    fields: &[FieldJson],
    index: usize,
    search: &NamedTypeFieldSearch<'_>,
    resolving: &mut Vec<String>,
) -> Result<Option<Vec<FieldJson>>> {
    let entry = node.entry();
    if matches!(
        entry.tag(),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type | gimli::DW_TAG_class_type
    ) && die_name(dwarf, unit, entry)?.as_deref() == Some(search.type_name)
        && !entry_flag(entry, gimli::DW_AT_declaration)?
    {
        let typedie = unit.entry(entry.offset())?;
        let mut fields = fields.to_vec();
        if let Some(fields) = translate_field_path_from(
            dwarf,
            unit,
            typedie,
            &mut fields,
            index,
            search.path,
            resolving,
        )? {
            return Ok(Some(fields));
        }
    }

    let mut children = node.children();
    while let Some(child) = children.next()? {
        if let Some(fields) =
            find_named_type_field_path(dwarf, unit, child, fields, index, search, resolving)?
        {
            return Ok(Some(fields));
        }
    }

    Ok(None)
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

fn find_function_variable<'unit, R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &'unit gimli::Unit<R>,
    function: &DebuggingInformationEntry<R>,
    name: &str,
) -> Result<Option<DebuggingInformationEntry<'unit, 'unit, R>>> {
    let variable_tags = &[gimli::DW_TAG_formal_parameter, gimli::DW_TAG_variable];
    if let Some(variable) =
        find_child_entry_by_name(dwarf, unit, function.offset(), variable_tags, name)?
    {
        return Ok(Some(variable));
    }

    if let Some(origin) = referenced_entry(unit, function, gimli::DW_AT_abstract_origin)? {
        if let Some(variable) =
            find_child_entry_by_name(dwarf, unit, origin.offset(), variable_tags, name)?
        {
            return Ok(Some(variable));
        }
        if let Some(specification) = referenced_entry(unit, &origin, gimli::DW_AT_specification)? {
            if let Some(variable) =
                find_child_entry_by_name(dwarf, unit, specification.offset(), variable_tags, name)?
            {
                return Ok(Some(variable));
            }
        }
    }

    if let Some(specification) = referenced_entry(unit, function, gimli::DW_AT_specification)? {
        if let Some(variable) =
            find_child_entry_by_name(dwarf, unit, specification.offset(), variable_tags, name)?
        {
            return Ok(Some(variable));
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

fn entry_flag<R: Reader>(entry: &DebuggingInformationEntry<R>, attr: gimli::DwAt) -> Result<bool> {
    let Some(attr) = entry.attr(attr)? else {
        return Ok(false);
    };
    Ok(match attr.value() {
        AttributeValue::Flag(value) => value,
        AttributeValue::Data1(value) => value != 0,
        AttributeValue::Data2(value) => value != 0,
        AttributeValue::Data4(value) => value != 0,
        AttributeValue::Data8(value) => value != 0,
        AttributeValue::Udata(value) => value != 0,
        _ => false,
    })
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
    attr_string_value(dwarf, unit, attr.value())
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
    attr_string_value(dwarf, unit, attr.value())
}

fn attr_string_value<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    value: AttributeValue<R>,
) -> Result<Option<String>> {
    if !is_string_attribute_value(&value) {
        return Ok(None);
    }
    let string = match dwarf.attr_string(unit, value) {
        Ok(string) => string,
        Err(gimli::Error::ExpectedStringAttributeValue) => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    Ok(Some(string.to_string_lossy()?.into_owned()))
}

fn is_string_attribute_value<R: Reader>(value: &AttributeValue<R>) -> bool {
    matches!(
        value,
        AttributeValue::String(_)
            | AttributeValue::DebugStrRef(_)
            | AttributeValue::DebugStrRefSup(_)
            | AttributeValue::DebugLineStrRef(_)
            | AttributeValue::DebugStrOffsetsIndex(_)
    )
}

fn demangle_function_name(linkage_name: &str) -> Option<String> {
    let symbol = cpp_demangle::Symbol::new(linkage_name)
        .or_else(|_| {
            cpp_demangle::Symbol::new(linkage_name.strip_prefix('_').unwrap_or(linkage_name))
        })
        .ok()?;
    let demangled = symbol
        .demangle(&cpp_demangle::DemangleOptions::default())
        .ok()?;
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
    if let Some(debug_path) = dsym_debug_file(path) {
        return fs::read(&debug_path)
            .map(Cow::Owned)
            .with_context(|| format!("failed to read dSYM file {}", debug_path.display()));
    }

    if has_dwarf_sections(file) {
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

fn has_dwarf_sections(file: &object::File<'_>) -> bool {
    file.section_by_name(gimli::SectionId::DebugInfo.name())
        .or_else(|| file.section_by_name(&macho_section_name(gimli::SectionId::DebugInfo.name())))
        .is_some()
}

fn debuglink_file(path: &Path, file: &object::File<'_>) -> Result<Option<PathBuf>> {
    let Some((filename, _crc)) = file.gnu_debuglink()? else {
        return Ok(None);
    };
    let filename = std::str::from_utf8(filename).context(".gnu_debuglink filename is not UTF-8")?;
    Ok(first_existing(debuglink_candidates(path, filename)))
}

fn dsym_debug_file(path: &Path) -> Option<PathBuf> {
    let filename = path.file_name()?;
    let dsym_name = format!("{}.dSYM", filename.to_string_lossy());
    let candidate = path
        .with_file_name(dsym_name)
        .join("Contents")
        .join("Resources")
        .join("DWARF")
        .join(filename);
    candidate.is_file().then_some(candidate)
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
    fn string_attribute_classifier_rejects_non_string_forms() {
        let string = EndianSlice::new(b"name", RunTimeEndian::Little);

        assert!(is_string_attribute_value(&AttributeValue::String(string)));
        assert!(!is_string_attribute_value(&AttributeValue::<
            EndianSlice<'_, RunTimeEndian>,
        >::Data1(1)));
    }

    #[test]
    fn extracts_ceph_version_from_embedded_version_string() {
        let data = b"prefix\0ceph version 19.2.0 (hash) squid\0suffix";

        assert_eq!(ceph_version_from_bytes(data).as_deref(), Some("19.2.0"));
    }

    #[test]
    fn extracts_ceph_version_from_microceph_metadata_text() {
        let text = "name: microceph\nceph-version: 18.2.8-1jammy\n";

        assert_eq!(
            ceph_version_from_text(text).as_deref(),
            Some("18.2.8-1jammy")
        );
    }

    #[test]
    fn extracts_ceph_version_from_microceph_manifest_text() {
        let text = "packages:\n  radosgw=18.2.8-1jammy\n";

        assert_eq!(
            ceph_version_from_text(text).as_deref(),
            Some("18.2.8-1jammy")
        );
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
    fn resolves_declared_member_type_from_another_compilation_unit() {
        let Some(binary) = compile_declared_type_fixture() else {
            return;
        };

        let Some(fields) = field_offsets_from_fixture(&binary).unwrap() else {
            return;
        };

        assert_eq!(fields.len(), 3);
        assert_eq!(fields[1].offset, 8);
        assert!(!fields[1].pointer);
        assert_eq!(fields[2].offset, 4);
        assert!(fields[2].pointer);
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
    fn extracts_rgw_get_handler_var_fields_from_cpp_fixture() {
        let Some(binary) = compile_rgw_fixture() else {
            return;
        };

        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();
        let Some(fields) = module.func2vf.get("RGWREST::get_handler") else {
            return;
        };

        assert_eq!(fields.var_fields.len(), 5);
        assert_eq!(fields.var_fields[0].fields.len(), 2);
        assert!(fields.var_fields[0].fields[1].pointer);
        assert_eq!(fields.var_fields[1].fields.len(), 3);
        assert!(fields.var_fields[1].fields[1].pointer);
        assert_eq!(fields.var_fields[2].fields.len(), 4);
        assert!(fields.var_fields[2].fields[1].pointer);
        assert_eq!(fields.var_fields[3].fields.len(), 3);
        assert!(fields.var_fields[3].fields[1].pointer);
        assert_eq!(fields.var_fields[4].fields.len(), 4);
        assert!(fields.var_fields[4].fields[1].pointer);
    }

    #[test]
    fn extracts_rgw_request_context_var_fields_from_cpp_fixture() {
        let Some(binary) = compile_rgw_fixture() else {
            return;
        };

        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();

        let process_request = module.func2vf.get("process_request").unwrap();
        assert_eq!(process_request.var_fields.len(), 1);
        assert_eq!(process_request.var_fields[0].fields.len(), 2);
        assert!(process_request.var_fields[0].fields[1].pointer);

        let init = module.func2vf.get("RGWOp::init").unwrap();
        assert_eq!(init.var_fields.len(), 2);
        assert_eq!(init.var_fields[0].fields.len(), 1);
        assert_eq!(init.var_fields[1].fields.len(), 1);

        let operate = module.func2vf.get("rgw_rados_operate").unwrap();
        assert_eq!(operate.var_fields.len(), 1);
        assert_eq!(operate.var_fields[0].fields.len(), 1);

        let writer_ctor = module.func2vf.get("RadosWriter::RadosWriter").unwrap();
        assert_eq!(writer_ctor.var_fields.len(), 2);
        assert_eq!(writer_ctor.var_fields[0].fields.len(), 1);
        assert_eq!(writer_ctor.var_fields[1].fields.len(), 1);

        let writer_process = module.func2vf.get("RadosWriter::process").unwrap();
        assert_eq!(writer_process.var_fields.len(), 2);
        assert_eq!(writer_process.var_fields[0].fields.len(), 1);
        assert_eq!(writer_process.var_fields[1].fields.len(), 2);
        assert!(writer_process.var_fields[1].fields[1].pointer);

        let writer_write_exclusive = module.func2vf.get("RadosWriter::write_exclusive").unwrap();
        assert_eq!(writer_write_exclusive.var_fields.len(), 2);
        assert_eq!(writer_write_exclusive.var_fields[0].fields.len(), 1);
        assert_eq!(writer_write_exclusive.var_fields[1].fields.len(), 2);
        assert!(writer_write_exclusive.var_fields[1].fields[1].pointer);
    }

    #[test]
    fn preserves_rgw_rados_operate_overload_addresses_from_cpp_fixture() {
        let Some(binary) = compile_rgw_fixture() else {
            return;
        };

        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();
        let addrs = module
            .func2pc
            .keys()
            .filter(|function| function_key_matches(function, "rgw_rados_operate"))
            .count();

        assert!(addrs >= 2);
        let fields = module
            .func2vf
            .keys()
            .filter(|function| function_key_matches(function, "rgw_rados_operate"))
            .count();
        assert!(fields >= 2);
        let hprobe_keys = info
            .hprobe_entries()
            .into_iter()
            .filter(|entry| function_key_matches(&entry.function, "rgw_rados_operate"))
            .map(|entry| entry.key)
            .collect::<Vec<_>>();
        assert!(hprobe_keys.contains(&60));
        assert!(hprobe_keys.contains(&61));
    }

    #[test]
    fn extracts_objecter_finish_op_var_fields_from_cpp_fixture() {
        let Some(binary) = compile_objecter_fixture() else {
            return;
        };

        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();
        let Some(fields) = module.func2vf.get("Objecter::_finish_op") else {
            return;
        };

        assert_eq!(fields.var_fields.len(), 3);
        assert_eq!(fields.var_fields[0].fields.len(), 2);
        assert!(fields.var_fields[0].fields[1].pointer);
        assert_eq!(fields.var_fields[1].fields.len(), 3);
        assert!(fields.var_fields[1].fields[1].pointer);
        assert_eq!(fields.var_fields[2].fields.len(), 3);
        assert!(fields.var_fields[2].fields[1].pointer);
    }

    #[test]
    fn extracts_objecter_op_submit_var_fields_from_cpp_fixture() {
        let Some(binary) = compile_objecter_fixture() else {
            return;
        };

        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();
        let Some(fields) = module.func2vf.get("Objecter::op_submit") else {
            return;
        };

        assert_eq!(fields.var_fields.len(), 1);
        assert_eq!(fields.var_fields[0].fields.len(), 1);
    }

    #[test]
    fn extracts_objecter_send_op_var_fields_from_cpp_fixture() {
        let Some(binary) = compile_objecter_fixture() else {
            return;
        };

        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();
        let Some(fields) = module.func2vf.get("Objecter::_send_op") else {
            return;
        };

        assert_eq!(fields.var_fields.len(), 12);
        assert_eq!(fields.var_fields[0].fields.len(), 2);
        assert_eq!(fields.var_fields[3].fields.len(), 5);
        assert_eq!(fields.var_fields[4].fields.len(), 6);
        assert_eq!(fields.var_fields[10].fields.len(), 4);
        assert_eq!(fields.var_fields[11].fields.len(), 4);
        assert!(fields
            .var_fields
            .iter()
            .all(|field| field.location.reg >= 0));
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

    fn compile_rgw_fixture() -> Option<std::path::PathBuf> {
        compile_cpp_source(
            "rgw-fixture",
            r#"
            struct DataPtr {
              char* _M_p;
            };
            struct StringLike {
              DataPtr _M_dataplus;
              unsigned long _M_string_length;
            };
            struct RGWRequest {
              unsigned long id;
            };
            struct ReqState {
              unsigned long id;
              StringLike req_id;
              StringLike trans_id;
            };
            struct DoutPrefixProvider {
              unsigned long marker;
            };
            class RGWREST {
            public:
              __attribute__((noinline)) void get_handler(ReqState* s);
              volatile unsigned long sink = 0;
            };
            class RGWHandler {};
            class Driver {};
            class RGWOp {
            public:
              __attribute__((noinline)) void init(Driver* driver, ReqState* s, RGWHandler* handler);
              volatile unsigned long sink = 0;
            };
            class RadosWriter {
              DoutPrefixProvider* dpp;
            public:
              __attribute__((noinline)) explicit RadosWriter(DoutPrefixProvider* dpp) : dpp(dpp) {}
              __attribute__((noinline)) int process();
              __attribute__((noinline)) int write_exclusive();
            };
            __attribute__((noinline)) int process_request(RGWRequest* const req) {
              return req->id;
            }
            void RGWREST::get_handler(ReqState* s) {
              sink += s->id;
              sink += s->req_id._M_string_length;
              sink += (unsigned long)s->req_id._M_dataplus._M_p;
              sink += s->trans_id._M_string_length;
              sink += (unsigned long)s->trans_id._M_dataplus._M_p;
            }
            void RGWOp::init(Driver* driver, ReqState* s, RGWHandler* handler) {
              sink += (unsigned long)driver;
              sink += (unsigned long)s;
              sink += (unsigned long)handler;
            }
            __attribute__((noinline)) int rgw_rados_operate(DoutPrefixProvider* dpp, int op) {
              return dpp->marker + op;
            }
            __attribute__((noinline)) int rgw_rados_operate(DoutPrefixProvider* dpp, long op) {
              return dpp->marker + op;
            }
            int RadosWriter::process() {
              return dpp->marker;
            }
            int RadosWriter::write_exclusive() {
              return dpp->marker + 1;
            }
            int main() {
              char value = 0;
              RGWRequest request = {42};
              ReqState state = {42, {{&value}, 7}, {{&value}, 12}};
              DoutPrefixProvider dpp = {5};
              Driver driver;
              RGWHandler handler;
              RGWREST rest;
              RGWOp op;
              RadosWriter writer(&dpp);
              unsigned long result = process_request(&request);
              rest.get_handler(&state);
              op.init(&driver, &state, &handler);
              result += rgw_rados_operate(&dpp, 1);
              result += rgw_rados_operate(&dpp, 2L);
              result += writer.process();
              result += writer.write_exclusive();
              return result == 0;
            }
            "#,
        )
    }

    fn compile_objecter_fixture() -> Option<std::path::PathBuf> {
        compile_cpp_source(
            "objecter-fixture",
            r#"
            struct DataPtr {
              char* _M_p;
            };
            struct StringLike {
              DataPtr _M_dataplus;
              unsigned long _M_string_length;
            };
            struct ObjectId {
              StringLike name;
            };
            struct PgidInner {
              long m_pool;
              unsigned int m_seed;
            };
            struct Pgid {
              PgidInner pgid;
            };
            struct ActingImpl {
              int* _M_start;
              int* _M_finish;
            };
            struct Acting {
              ActingImpl _M_impl;
            };
            struct OpsHolder {
              char* m_start;
              unsigned long m_size;
            };
            struct Ops {
              OpsHolder m_holder;
            };
            struct Target {
              int osd;
              ObjectId base_oid;
              unsigned int flags;
              Pgid actual_pgid;
              Acting acting;
            };
            struct Op {
              unsigned long tid;
              Target target;
              Ops ops;
            };
            struct MonClient {
              unsigned long global_id;
            };
            class Objecter {
            public:
              __attribute__((noinline)) void _send_op(Op* op);
              __attribute__((noinline)) void _finish_op(Op* op);
              __attribute__((noinline)) void op_submit(Op* op);
              MonClient monc;
              volatile unsigned long sink = 0;
            };
            void Objecter::_send_op(Op* op) {
              sink += op->tid;
              sink += monc.global_id;
              sink += op->target.osd;
              sink += op->target.base_oid.name._M_string_length;
              sink += (unsigned long)op->target.base_oid.name._M_dataplus._M_p;
              sink += op->target.flags;
              sink += op->target.actual_pgid.pgid.m_pool;
              sink += op->target.actual_pgid.pgid.m_seed;
              sink += (unsigned long)op->target.acting._M_impl._M_start;
              sink += (unsigned long)op->target.acting._M_impl._M_finish;
              sink += (unsigned long)op->ops.m_holder.m_start;
              sink += op->ops.m_holder.m_size;
            }
            void Objecter::_finish_op(Op* op) {
              sink += op->tid;
              sink += monc.global_id;
              sink += op->target.osd;
            }
            void Objecter::op_submit(Op* op) {
              sink += op->tid;
            }
            int main() {
              char name = 0;
              char ops = 0;
              int acting[2] = {1, 2};
              Op op = {
                12,
                {3, {{{&name}, 4}}, 5, {{6, 7}}, {{&acting[0], &acting[1]}}},
                {{&ops, 8}}
              };
              Objecter objecter;
              objecter.monc.global_id = 9;
              objecter.op_submit(&op);
              objecter._send_op(&op);
              objecter._finish_op(&op);
              return 0;
            }
            "#,
        )
    }

    fn compile_declared_type_fixture() -> Option<std::path::PathBuf> {
        compile_cpp_sources(
            "declared-type-fixture",
            &[
                (
                    "inspect",
                    r#"
                    struct Leaf;
                    struct Outer {
                      int pad;
                      Leaf* leaf;
                    };
                    __attribute__((noinline)) int inspect(Outer outer) {
                      return outer.leaf != 0;
                    }
                    int main() {
                      Outer outer = {1, 0};
                      return inspect(outer);
                    }
                    "#,
                ),
                (
                    "leaf",
                    r#"
                    struct Leaf {
                      int prefix;
                      int value;
                    };
                    Leaf leaf = {1, 2};
                    int use_leaf() { return leaf.value; }
                    "#,
                ),
            ],
        )
    }

    fn compile_cpp_source(name: &str, contents: &str) -> Option<std::path::PathBuf> {
        compile_cpp_sources(name, &[(name, contents)])
    }

    fn compile_cpp_sources(name: &str, sources: &[(&str, &str)]) -> Option<std::path::PathBuf> {
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
        let binary = dir.join(name);
        let sources = sources
            .iter()
            .map(|(source_name, contents)| {
                let source = dir.join(format!("{source_name}.cc"));
                std::fs::write(&source, contents).ok()?;
                Some(source)
            })
            .collect::<Option<Vec<_>>>()?;
        let mut command = std::process::Command::new(compiler);
        command.args(["-g", "-O0", "-fno-inline"]);
        for source in &sources {
            command.arg(source);
        }
        let status = command.arg("-o").arg(&binary).status().ok()?;
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
