use std::{
    borrow::Cow,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result};
use gimli::{
    AttributeValue, DebugInfoOffset, DebuggingInformationEntry, Dwarf, EndianSlice,
    EntriesTreeNode, Operation, Reader, RunTimeEndian, UnitOffset,
};
use object::{Architecture, Object, ObjectSection, ObjectSymbol, SymbolKind};
use tracing::{debug, warn};

use crate::dwarf_json::{
    basename, DwarfInfo, DwarfModule, FieldJson, FunctionVarFields, VarFieldJson, VarLocationJson,
};

const PROBE_FUNCTIONS: &[&str] = &[
    "Objecter::_send_op",
    "Objecter::_finish_op",
    "RGWREST::get_handler",
];
const OBJECTER_PROBE_FUNCTIONS: &[&str] = &["Objecter::_send_op", "Objecter::_finish_op"];
const RGW_PROBE_FUNCTIONS: &[&str] = &["RGWREST::get_handler"];
const PROBE_FUNCTION_LEAF_NAMES: &[&str] = &["_send_op", "_finish_op", "get_handler"];
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
    &["s", "trans_id", "_M_string_length"],
    &["s", "trans_id", "_M_dataplus", "_M_p"],
];

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
    // Load every compilation unit once and share it across both extraction
    // passes; cross-CU reference resolution needs all units resident anyway.
    let index = DwarfUnitIndex::load(&dwarf)?;
    if !has_all_functions(&func2pc, wanted) {
        for (function, pc) in function_pcs(&dwarf, &index, wanted)? {
            func2pc.entry(function).or_insert(pc);
        }
    }
    let func2vf = function_var_fields(&dwarf, &index, wanted)?;

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
    wanted.iter().all(|function| result.contains_key(*function))
}

/// Location of a DWARF DIE that identifies both the owning compilation unit and
/// the offset within it. This lets reference resolution span compilation units,
/// which is required for real Ceph binaries where a probed function's parameter
/// type (or a member/base type) is frequently defined in a different CU and is
/// reached through a `DW_FORM_ref_addr` (`DebugInfoRef`) attribute.
#[derive(Clone, Copy)]
struct DieRef<Offset> {
    unit: usize,
    offset: UnitOffset<Offset>,
}

/// Eagerly parsed set of compilation units, kept alive together so that DIEs
/// resolved in one unit can be borrowed while walking another. Cross-CU
/// reference resolution needs stable ownership of every unit; parsing units
/// on demand (as the previous single-unit code did) cannot return a DIE that
/// outlives the temporary unit it came from.
struct DwarfUnitIndex<R: Reader> {
    units: Vec<gimli::Unit<R>>,
    /// `(.debug_info start offset, index into `units`)` for every loaded unit,
    /// sorted ascending by start offset. Lets `debug_info_ref` binary-search the
    /// owning unit instead of scanning every unit per reference. The stored
    /// index maps back to the surviving unit, so gaps left by skipped
    /// (malformed) units resolve correctly.
    unit_offsets: Vec<(R::Offset, usize)>,
}

impl<R: Reader> DwarfUnitIndex<R> {
    fn load(dwarf: &Dwarf<R>) -> Result<Self> {
        let mut units = Vec::new();
        let mut headers = dwarf.units();
        loop {
            let header = match headers.next() {
                Ok(Some(header)) => header,
                Ok(None) => break,
                Err(err) => {
                    // The unit-header cursor cannot be advanced past a malformed
                    // header, so stop enumerating but keep what we have rather
                    // than aborting the whole extraction.
                    warn!(error = %err, "stopping DWARF unit scan at malformed unit header");
                    break;
                }
            };
            let section_offset = header.offset();
            match dwarf.unit(header) {
                Ok(unit) => units.push(unit),
                Err(err) => {
                    // Tolerate individual malformed CUs (matching main's
                    // direction of ignoring bad DWARF); references into a
                    // skipped unit simply resolve to None.
                    warn!(
                        ?section_offset,
                        error = %err,
                        "skipping malformed DWARF compilation unit"
                    );
                }
            }
        }

        let mut unit_offsets: Vec<(R::Offset, usize)> = units
            .iter()
            .enumerate()
            .filter_map(|(index, unit)| {
                unit.header
                    .offset()
                    .as_debug_info_offset()
                    .map(|offset| (offset.0, index))
            })
            .collect();
        // dwarf.units() yields headers in section order, but sort defensively so
        // the binary search never depends on that assumption.
        unit_offsets.sort_by_key(|(offset, _)| *offset);

        Ok(Self {
            units,
            unit_offsets,
        })
    }

    fn len(&self) -> usize {
        self.units.len()
    }

    fn unit(&self, index: usize) -> &gimli::Unit<R> {
        &self.units[index]
    }

    fn entry(&self, die: DieRef<R::Offset>) -> Result<DebuggingInformationEntry<'_, '_, R>> {
        self.unit(die.unit)
            .entry(die.offset)
            .context("failed to resolve DWARF entry")
    }

    /// Follows attribute `attr` on `entry` (which lives in unit `unit_index`) to
    /// the DIE it references. Intra-unit references (`UnitRef`) preserve the
    /// existing behavior; `DebugInfoRef` references are resolved against the
    /// owning unit so that cross-CU references are followed.
    fn referenced_die(
        &self,
        unit_index: usize,
        entry: &DebuggingInformationEntry<R>,
        attr: gimli::DwAt,
    ) -> Result<Option<DieRef<R::Offset>>> {
        let Some(attr) = entry.attr(attr)? else {
            return Ok(None);
        };
        match attr.value() {
            AttributeValue::UnitRef(offset) => Ok(Some(DieRef {
                unit: unit_index,
                offset,
            })),
            AttributeValue::DebugInfoRef(offset) => Ok(self.debug_info_ref(offset)),
            _ => Ok(None),
        }
    }

    fn debug_info_ref(&self, offset: DebugInfoOffset<R::Offset>) -> Option<DieRef<R::Offset>> {
        // Find the unit whose start offset is the greatest that is <= the target,
        // then confirm the target actually lands inside that unit's range. A
        // target in a gap (e.g. a skipped unit) or past the last unit fails the
        // confirmation and resolves to None, matching the prior silent-miss.
        let unit_index = owning_unit_index(&self.unit_offsets, offset.0)?;
        let unit = &self.units[unit_index];
        offset.to_unit_offset(&unit.header).map(|offset| DieRef {
            unit: unit_index,
            offset,
        })
    }
}

/// Returns the index (into the surviving `units` vec) of the unit whose start
/// offset is the greatest that does not exceed `target`, or `None` if `target`
/// precedes the first unit. `unit_offsets` must be sorted ascending by start
/// offset. This is a candidate only; callers confirm the target falls within
/// the chosen unit's range.
fn owning_unit_index<O: Ord + Copy>(unit_offsets: &[(O, usize)], target: O) -> Option<usize> {
    let position = unit_offsets.partition_point(|(start, _)| *start <= target);
    (position != 0).then(|| unit_offsets[position - 1].1)
}

fn function_pcs<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    wanted: &[&str],
) -> Result<BTreeMap<String, u64>> {
    let mut result = BTreeMap::new();
    for unit_index in 0..index.len() {
        let unit = index.unit(unit_index);
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;
        collect_function_pcs(
            dwarf,
            index,
            unit_index,
            root,
            &mut Vec::new(),
            &mut result,
            wanted,
        )?;
        if has_all_functions(&result, wanted) {
            break;
        }
    }
    Ok(result)
}

fn function_var_fields<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    wanted: &[&str],
) -> Result<BTreeMap<String, FunctionVarFields>> {
    let mut result = BTreeMap::new();
    for unit_index in 0..index.len() {
        let unit = index.unit(unit_index);
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;
        collect_function_var_fields(
            dwarf,
            index,
            unit_index,
            root,
            &mut Vec::new(),
            &mut result,
            wanted,
        )?;
        if has_all_functions(&result, wanted) {
            break;
        }
    }
    Ok(result)
}

fn collect_function_var_fields<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    node: EntriesTreeNode<R>,
    scopes: &mut Vec<String>,
    result: &mut BTreeMap<String, FunctionVarFields>,
    wanted: &[&str],
) -> Result<()> {
    if has_all_functions(result, wanted) {
        return Ok(());
    }

    let unit = index.unit(unit_index);
    let entry = node.entry();
    let scope = scope_name(dwarf, unit, entry)?;
    if let Some(scope) = &scope {
        scopes.push(scope.clone());
    }

    if entry.tag() == gimli::DW_TAG_subprogram {
        for fullname in function_names(dwarf, index, unit_index, entry, scopes)? {
            if !wanted.contains(&fullname.as_str()) {
                continue;
            }
            if let Some(paths) = probe_field_paths(&fullname) {
                if let Some(fields) =
                    probe_function_var_fields(dwarf, index, unit_index, entry, &fullname, paths)?
                {
                    result.entry(fullname).or_insert(fields);
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
        collect_function_var_fields(dwarf, index, unit_index, child, scopes, result, wanted)?;
        if has_all_functions(result, wanted) {
            break;
        }
    }

    if scope.is_some() {
        scopes.pop();
    }
    Ok(())
}

fn probe_function_var_fields<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    function: &DebuggingInformationEntry<R>,
    function_name: &str,
    paths: &[&[&str]],
) -> Result<Option<FunctionVarFields>> {
    let unit = index.unit(unit_index);
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
        let Some(variable) =
            find_function_variable(dwarf, index, unit_index, function, variable_name)?
        else {
            debug!(
                function = function_name,
                variable = *variable_name,
                "native DWARF probe rejected: missing variable"
            );
            return Ok(None);
        };
        let variable_unit = index.unit(variable.unit);
        let variable_entry = variable_unit.entry(variable.offset)?;
        let Some(location) =
            variable_location(dwarf, variable_unit, function, &variable_entry, pc)?
        else {
            debug!(
                function = function_name,
                variable = *variable_name,
                "native DWARF probe rejected: missing variable location"
            );
            return Ok(None);
        };
        let Some(fields) = translate_field_path(dwarf, index, variable, path)? else {
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
        "RGWREST::get_handler" => Some(RGWREST_GET_HANDLER_FIELDS),
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
        let Some(function) = demangle_function_name(name) else {
            continue;
        };
        if wanted.contains(&function.as_str()) {
            result.entry(function).or_insert(symbol.address());
        }
    }
    result
}

fn collect_function_pcs<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    node: EntriesTreeNode<R>,
    scopes: &mut Vec<String>,
    result: &mut BTreeMap<String, u64>,
    wanted: &[&str],
) -> Result<()> {
    if has_all_functions(result, wanted) {
        return Ok(());
    }

    let unit = index.unit(unit_index);
    let entry = node.entry();
    let scope = scope_name(dwarf, unit, entry)?;
    if let Some(scope) = &scope {
        scopes.push(scope.clone());
    }

    if entry.tag() == gimli::DW_TAG_subprogram {
        for fullname in function_names(dwarf, index, unit_index, entry, scopes)? {
            if wanted.contains(&fullname.as_str()) {
                if let Some(pc) = entry_pc(dwarf, unit, entry)? {
                    result.entry(fullname).or_insert(pc);
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
        collect_function_pcs(dwarf, index, unit_index, child, scopes, result, wanted)?;
        if has_all_functions(result, wanted) {
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
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    entry: &DebuggingInformationEntry<R>,
    scopes: &[String],
) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let unit = index.unit(unit_index);
    add_entry_function_names(dwarf, unit, entry, scopes, &mut names)?;
    add_referenced_function_names(
        dwarf,
        index,
        unit_index,
        entry,
        gimli::DW_AT_abstract_origin,
        &mut names,
    )?;
    add_referenced_function_names(
        dwarf,
        index,
        unit_index,
        entry,
        gimli::DW_AT_specification,
        &mut names,
    )?;
    names.sort();
    names.dedup();
    Ok(names)
}

fn add_referenced_function_names<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    entry: &DebuggingInformationEntry<R>,
    attr: gimli::DwAt,
    names: &mut Vec<String>,
) -> Result<()> {
    let Some(referenced) = index.referenced_die(unit_index, entry, attr)? else {
        return Ok(());
    };
    let referenced_unit = index.unit(referenced.unit);
    let referenced_entry = referenced_unit.entry(referenced.offset)?;
    let before = names.len();
    add_entry_function_names(dwarf, referenced_unit, &referenced_entry, &[], names)?;

    let already_qualified = names[before..]
        .iter()
        .any(|name| PROBE_FUNCTIONS.contains(&name.as_str()));
    if !already_qualified {
        if let Some(name) = die_name(dwarf, referenced_unit, &referenced_entry)? {
            if PROBE_FUNCTION_LEAF_NAMES.contains(&name.as_str()) {
                let referenced_scopes = entry_scopes(dwarf, index, referenced)?.unwrap_or_default();
                add_entry_function_names(
                    dwarf,
                    referenced_unit,
                    &referenced_entry,
                    &referenced_scopes,
                    names,
                )?;
            }
        }
    }

    if attr == gimli::DW_AT_abstract_origin {
        add_referenced_function_names(
            dwarf,
            index,
            referenced.unit,
            &referenced_entry,
            gimli::DW_AT_specification,
            names,
        )?;
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

fn entry_scopes<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    die: DieRef<R::Offset>,
) -> Result<Option<Vec<String>>> {
    let unit = index.unit(die.unit);
    let mut tree = unit.entries_tree(None)?;
    let root = tree.root()?;
    find_entry_scopes(dwarf, unit, root, die.offset, &mut Vec::new())
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
    index: &DwarfUnitIndex<R>,
    variable: DieRef<R::Offset>,
    path: &[&str],
) -> Result<Option<Vec<FieldJson>>> {
    let Some(typedie) = die_type(index, variable)? else {
        return Ok(None);
    };
    let mut fields = vec![FieldJson::default(); path.len()];
    let mut resolving = Vec::new();
    translate_field_path_from(dwarf, index, typedie, &mut fields, 1, path, &mut resolving)
}

fn translate_field_path_from<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    mut typedie: DieRef<R::Offset>,
    fields: &mut [FieldJson],
    mut field_index: usize,
    path: &[&str],
    resolving: &mut Vec<String>,
) -> Result<Option<Vec<FieldJson>>> {
    while field_index < path.len() {
        typedie = peel_type_qualifiers(index, typedie)?;
        let typedie_unit = index.unit(typedie.unit);
        let typedie_entry = typedie_unit.entry(typedie.offset)?;
        match typedie_entry.tag() {
            gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type
            | gimli::DW_TAG_pointer_type => {
                fields[field_index].pointer = true;
                let Some(next_type) = die_type(index, typedie)? else {
                    return Ok(None);
                };
                typedie = next_type;
            }
            gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type | gimli::DW_TAG_class_type => {
                let Some(member) = find_member_entry(dwarf, index, typedie, path[field_index])?
                else {
                    if let Some(fields) = translate_declared_type_field_path(
                        dwarf,
                        index,
                        typedie,
                        fields,
                        field_index,
                        path,
                        resolving,
                    )? {
                        return Ok(Some(fields));
                    }
                    return Ok(None);
                };
                let member_unit = index.unit(member.unit);
                let member_entry = member_unit.entry(member.offset)?;
                fields[field_index].offset =
                    member_offset(member_unit, &member_entry)?.unwrap_or_default();
                let Some(next_type) = die_type(index, member)? else {
                    return Ok(None);
                };
                typedie = next_type;
                field_index += 1;
            }
            _ => return Ok(None),
        }
    }

    Ok(Some(fields.to_vec()))
}

fn translate_declared_type_field_path<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    typedie: DieRef<R::Offset>,
    fields: &[FieldJson],
    field_index: usize,
    path: &[&str],
    resolving: &mut Vec<String>,
) -> Result<Option<Vec<FieldJson>>> {
    let unit = index.unit(typedie.unit);
    let entry = unit.entry(typedie.offset)?;
    if !entry_flag(&entry, gimli::DW_AT_declaration)? {
        return Ok(None);
    }
    let Some(type_name) = die_name(dwarf, unit, &entry)? else {
        return Ok(None);
    };
    if resolving.contains(&type_name) {
        return Ok(None);
    }

    resolving.push(type_name.clone());
    let result = translate_named_type_field_path(
        dwarf,
        index,
        &type_name,
        fields,
        field_index,
        path,
        resolving,
    );
    resolving.pop();
    result
}

fn translate_named_type_field_path<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    type_name: &str,
    fields: &[FieldJson],
    field_index: usize,
    path: &[&str],
    resolving: &mut Vec<String>,
) -> Result<Option<Vec<FieldJson>>> {
    let search = NamedTypeFieldSearch {
        type_name,
        path,
        fields,
        field_index,
    };
    for unit_index in 0..index.len() {
        let unit = index.unit(unit_index);
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;
        if let Some(fields) =
            find_named_type_field_path(dwarf, index, unit_index, root, &search, resolving)?
        {
            return Ok(Some(fields));
        }
    }
    Ok(None)
}

struct NamedTypeFieldSearch<'a> {
    type_name: &'a str,
    path: &'a [&'a str],
    fields: &'a [FieldJson],
    field_index: usize,
}

fn find_named_type_field_path<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    node: EntriesTreeNode<R>,
    search: &NamedTypeFieldSearch<'_>,
    resolving: &mut Vec<String>,
) -> Result<Option<Vec<FieldJson>>> {
    let unit = index.unit(unit_index);
    let entry = node.entry();
    if matches!(
        entry.tag(),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type | gimli::DW_TAG_class_type
    ) && die_name(dwarf, unit, entry)?.as_deref() == Some(search.type_name)
        && !entry_flag(entry, gimli::DW_AT_declaration)?
    {
        let typedie = DieRef {
            unit: unit_index,
            offset: entry.offset(),
        };
        let mut fields = search.fields.to_vec();
        if let Some(fields) = translate_field_path_from(
            dwarf,
            index,
            typedie,
            &mut fields,
            search.field_index,
            search.path,
            resolving,
        )? {
            return Ok(Some(fields));
        }
    }

    let mut children = node.children();
    while let Some(child) = children.next()? {
        if let Some(fields) =
            find_named_type_field_path(dwarf, index, unit_index, child, search, resolving)?
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

fn peel_type_qualifiers<R: Reader>(
    index: &DwarfUnitIndex<R>,
    mut typedie: DieRef<R::Offset>,
) -> Result<DieRef<R::Offset>> {
    while matches!(
        index.entry(typedie)?.tag(),
        gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
    ) {
        let Some(next_type) = die_type(index, typedie)? else {
            break;
        };
        typedie = next_type;
    }
    Ok(typedie)
}

fn find_member_entry<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    typedie: DieRef<R::Offset>,
    member_name: &str,
) -> Result<Option<DieRef<R::Offset>>> {
    let mut queue = vec![typedie];
    while let Some(parent) = queue.pop() {
        let unit = index.unit(parent.unit);
        let mut tree = unit.entries_tree(Some(parent.offset))?;
        let root = tree.root()?;
        let mut children = root.children();
        while let Some(child) = children.next()? {
            let entry = child.entry();
            let child_ref = DieRef {
                unit: parent.unit,
                offset: entry.offset(),
            };
            match entry.tag() {
                gimli::DW_TAG_member => {
                    if die_name(dwarf, unit, entry)?.as_deref() == Some(member_name) {
                        return Ok(Some(child_ref));
                    }
                }
                gimli::DW_TAG_inheritance => {
                    if let Some(parent_type) = die_type(index, child_ref)? {
                        queue.push(parent_type);
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

fn find_function_variable<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    function: &DebuggingInformationEntry<R>,
    name: &str,
) -> Result<Option<DieRef<R::Offset>>> {
    let function_ref = DieRef {
        unit: unit_index,
        offset: function.offset(),
    };
    if let Some(variable) = find_function_child_variable(dwarf, index, function_ref, name)? {
        return Ok(Some(variable));
    }

    if let Some(origin) =
        index.referenced_die(unit_index, function, gimli::DW_AT_abstract_origin)?
    {
        if let Some(variable) = find_function_child_variable(dwarf, index, origin, name)? {
            return Ok(Some(variable));
        }
        let origin_unit = index.unit(origin.unit);
        let origin_entry = origin_unit.entry(origin.offset)?;
        if let Some(specification) =
            index.referenced_die(origin.unit, &origin_entry, gimli::DW_AT_specification)?
        {
            if let Some(variable) = find_function_child_variable(dwarf, index, specification, name)?
            {
                return Ok(Some(variable));
            }
        }
    }

    if let Some(specification) =
        index.referenced_die(unit_index, function, gimli::DW_AT_specification)?
    {
        if let Some(variable) = find_function_child_variable(dwarf, index, specification, name)? {
            return Ok(Some(variable));
        }
    }

    Ok(None)
}

fn find_function_child_variable<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    parent: DieRef<R::Offset>,
    name: &str,
) -> Result<Option<DieRef<R::Offset>>> {
    let unit = index.unit(parent.unit);
    let mut tree = unit.entries_tree(Some(parent.offset))?;
    let root = tree.root()?;
    let mut children = root.children();
    while let Some(child) = children.next()? {
        let entry = child.entry();
        if matches!(
            entry.tag(),
            gimli::DW_TAG_formal_parameter | gimli::DW_TAG_variable
        ) && die_name(dwarf, unit, entry)?.as_deref() == Some(name)
        {
            return Ok(Some(DieRef {
                unit: parent.unit,
                offset: entry.offset(),
            }));
        }
    }
    Ok(None)
}

fn die_type<R: Reader>(
    index: &DwarfUnitIndex<R>,
    die: DieRef<R::Offset>,
) -> Result<Option<DieRef<R::Offset>>> {
    let unit = index.unit(die.unit);
    let entry = unit.entry(die.offset)?;
    index.referenced_die(die.unit, &entry, gimli::DW_AT_type)
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

        assert_eq!(fields.var_fields.len(), 2);
        assert_eq!(fields.var_fields[0].fields.len(), 3);
        assert!(fields.var_fields[0].fields[1].pointer);
        assert_eq!(fields.var_fields[0].fields[2].offset, 8);
        assert_eq!(fields.var_fields[1].fields.len(), 4);
        assert!(fields.var_fields[1].fields[1].pointer);
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
            struct ReqState {
              StringLike trans_id;
            };
            class RGWREST {
            public:
              __attribute__((noinline)) void get_handler(ReqState* s);
              volatile unsigned long sink = 0;
            };
            void RGWREST::get_handler(ReqState* s) {
              sink += s->trans_id._M_string_length;
              sink += (unsigned long)s->trans_id._M_dataplus._M_p;
            }
            int main() {
              char value = 0;
              ReqState state = {{{&value}, 12}};
              RGWREST rest;
              rest.get_handler(&state);
              return 0;
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

    /// Cross-compilation-unit probe fixture. The `Objecter::_finish_op`
    /// definition lives in one translation unit and `main` (its only caller) in
    /// another, then both are compiled with `-flto`. Under LTO the concrete
    /// out-of-line `_finish_op` instance (which carries the `DW_AT_low_pc`) only
    /// reaches its abstract instance -- and therefore its name and parameters --
    /// through a `DW_AT_abstract_origin` encoded as `DW_FORM_ref_addr`
    /// (`DebugInfoRef`) that points into a different unit. Resolving the probe
    /// from DWARF alone thus requires cross-CU reference resolution.
    fn compile_cross_unit_probe_fixture() -> Option<std::path::PathBuf> {
        let structs = r#"
            struct DataPtr { char* _M_p; };
            struct StringLike { DataPtr _M_dataplus; unsigned long _M_string_length; };
            struct ObjectId { StringLike name; };
            struct Target { int osd; ObjectId base_oid; };
            struct Op { unsigned long tid; Target target; };
            struct MonClient { unsigned long global_id; };
            class Objecter {
            public:
              __attribute__((noinline)) void _finish_op(Op* op);
              MonClient monc;
              volatile unsigned long sink = 0;
            };
        "#;
        let impl_source = format!(
            "{structs}\n\
            void Objecter::_finish_op(Op* op) {{\n\
              sink += op->tid;\n\
              sink += monc.global_id;\n\
              sink += op->target.osd;\n\
            }}\n"
        );
        let main_source = format!(
            "{structs}\n\
            int main() {{\n\
              char name = 0;\n\
              Op op = {{12, {{3, {{{{{{&name}}, 4}}}}}}}};\n\
              Objecter objecter;\n\
              objecter.monc.global_id = 9;\n\
              objecter._finish_op(&op);\n\
              return 0;\n\
            }}\n"
        );
        compile_cpp_sources_with_flags(
            "cross-unit-fixture",
            &[("cross_impl", &impl_source), ("cross_main", &main_source)],
            &["-flto"],
        )
    }

    fn compile_cpp_source(name: &str, contents: &str) -> Option<std::path::PathBuf> {
        compile_cpp_sources(name, &[(name, contents)])
    }

    fn compile_cpp_sources(name: &str, sources: &[(&str, &str)]) -> Option<std::path::PathBuf> {
        compile_cpp_sources_with_flags(name, sources, &[])
    }

    fn compile_cpp_sources_with_flags(
        name: &str,
        sources: &[(&str, &str)],
        extra_flags: &[&str],
    ) -> Option<std::path::PathBuf> {
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
        command.args(extra_flags);
        for source in &sources {
            command.arg(source);
        }
        let status = command.arg("-o").arg(&binary).status().ok()?;
        status.success().then_some(binary)
    }

    /// Returns whether the DWARF contains at least one attribute encoded as a
    /// `DebugInfoRef` (`DW_FORM_ref_addr`) that resolves to a *different*
    /// compilation unit. Used to assert that a fixture genuinely exercises
    /// cross-CU reference resolution before making hard assertions about it.
    fn has_cross_unit_reference<R: Reader>(dwarf: &Dwarf<R>) -> Result<bool> {
        let index = DwarfUnitIndex::load(dwarf)?;
        for unit_index in 0..index.len() {
            let unit = index.unit(unit_index);
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs()? {
                let mut attrs = entry.attrs();
                while let Some(attr) = attrs.next()? {
                    if let AttributeValue::DebugInfoRef(offset) = attr.value() {
                        if let Some(target) = index.debug_info_ref(offset) {
                            if target.unit != unit_index {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    #[test]
    fn resolves_probe_function_across_units_via_debug_info_ref() {
        let Some(binary) = compile_cross_unit_probe_fixture() else {
            return;
        };

        let data = std::fs::read(&binary).unwrap();
        let file = object::File::parse(data.as_slice()).unwrap();
        let endian = if file.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let dwarf_cow = Dwarf::load(|section| load_section(&file, section)).unwrap();
        #[allow(deprecated)]
        let dwarf = dwarf_cow.borrow(|section| EndianSlice::new(section, endian));

        if !has_cross_unit_reference(&dwarf).unwrap() {
            // The toolchain did not emit cross-unit DW_FORM_ref_addr references
            // (e.g. no LTO linker plugin), so there is nothing to exercise here.
            // Announce loudly so this does not look like a genuine pass.
            eprintln!(
                "SKIPPED resolves_probe_function_across_units_via_debug_info_ref: \
                 toolchain emitted no cross-CU DebugInfoRef"
            );
            return;
        }

        // `function_pcs` reads only DWARF (not the ELF symbol table), so
        // resolving the qualified name requires following the concrete
        // instance's cross-CU DW_AT_abstract_origin to its abstract instance.
        let index = DwarfUnitIndex::load(&dwarf).unwrap();
        let pcs = function_pcs(&dwarf, &index, OBJECTER_PROBE_FUNCTIONS).unwrap();
        let pc = pcs
            .get("Objecter::_finish_op")
            .expect("cross-unit DWARF reference should resolve the probe function name");
        assert_ne!(*pc, 0);
    }

    #[test]
    fn owning_unit_index_maps_offsets_to_the_correct_surviving_unit() {
        // Starts are sorted ascending; the second tuple element is the index in
        // the surviving `units` vec and is intentionally out of order to prove
        // the search maps back to the right unit (as happens after skipping a
        // malformed CU or a defensive re-sort).
        let unit_offsets: &[(u64, usize)] = &[(100, 2), (300, 0), (700, 1)];

        // Before the first unit: no owner.
        assert_eq!(owning_unit_index(unit_offsets, 0), None);
        assert_eq!(owning_unit_index(unit_offsets, 99), None);
        // First byte of a unit maps to that unit.
        assert_eq!(owning_unit_index(unit_offsets, 100), Some(2));
        assert_eq!(owning_unit_index(unit_offsets, 300), Some(0));
        assert_eq!(owning_unit_index(unit_offsets, 700), Some(1));
        // Last byte before the next unit's start stays with the current unit.
        assert_eq!(owning_unit_index(unit_offsets, 299), Some(2));
        assert_eq!(owning_unit_index(unit_offsets, 699), Some(0));
        // An offset inside a gap (e.g. a skipped unit between 300 and 700) or
        // past the final unit resolves to the preceding start's unit; the range
        // confirmation via `to_unit_offset` rejects it in real use.
        assert_eq!(owning_unit_index(unit_offsets, 500), Some(0));
        assert_eq!(owning_unit_index(unit_offsets, 10_000), Some(1));

        // Empty table never yields an owner.
        assert_eq!(owning_unit_index::<u64>(&[], 42), None);
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

        let index = DwarfUnitIndex::load(&dwarf)?;
        for unit_index in 0..index.len() {
            let unit = index.unit(unit_index);
            let Some(function) = find_subprogram_by_name(&dwarf, &index, unit_index, "inspect")?
            else {
                continue;
            };
            let Some(param) = find_child_entry_by_name(
                &dwarf,
                unit,
                function.offset(),
                &[gimli::DW_TAG_formal_parameter],
                "outer",
            )?
            else {
                continue;
            };
            return translate_field_path(
                &dwarf,
                &index,
                DieRef {
                    unit: unit_index,
                    offset: param.offset(),
                },
                &["outer", "leaf", "value"],
            );
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

        let index = DwarfUnitIndex::load(&dwarf)?;
        for unit_index in 0..index.len() {
            let unit = index.unit(unit_index);
            let Some(function) = find_subprogram_by_name(&dwarf, &index, unit_index, "inspect")?
            else {
                continue;
            };
            let Some(param) = find_child_entry_by_name(
                &dwarf,
                unit,
                function.offset(),
                &[gimli::DW_TAG_formal_parameter],
                "outer",
            )?
            else {
                continue;
            };
            let Some(pc) = entry_pc(&dwarf, unit, &function)? else {
                continue;
            };
            return variable_location(&dwarf, unit, &function, &param, pc);
        }

        Ok(None)
    }

    fn find_subprogram_by_name<'unit, R: Reader>(
        dwarf: &Dwarf<R>,
        index: &'unit DwarfUnitIndex<R>,
        unit_index: usize,
        name: &str,
    ) -> Result<Option<DebuggingInformationEntry<'unit, 'unit, R>>> {
        let unit = index.unit(unit_index);
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;
        find_subprogram_node(dwarf, index, unit_index, root, &mut Vec::new(), name)
    }

    fn find_subprogram_node<'unit, R: Reader>(
        dwarf: &Dwarf<R>,
        index: &'unit DwarfUnitIndex<R>,
        unit_index: usize,
        node: EntriesTreeNode<R>,
        scopes: &mut Vec<String>,
        name: &str,
    ) -> Result<Option<DebuggingInformationEntry<'unit, 'unit, R>>> {
        let unit = index.unit(unit_index);
        let entry = node.entry();
        let scope = scope_name(dwarf, unit, entry)?;
        if let Some(scope) = &scope {
            scopes.push(scope.clone());
        }

        if entry.tag() == gimli::DW_TAG_subprogram
            && function_names(dwarf, index, unit_index, entry, scopes)?
                .iter()
                .any(|candidate| candidate == name)
        {
            return Ok(Some(unit.entry(entry.offset())?));
        }

        let mut children = node.children();
        while let Some(child) = children.next()? {
            if let Some(found) =
                find_subprogram_node(dwarf, index, unit_index, child, scopes, name)?
            {
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
