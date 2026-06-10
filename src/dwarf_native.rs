use std::{borrow::Cow, collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result};
use gimli::{
    DebuggingInformationEntry, Dwarf, EndianSlice, EntriesTreeNode, Reader, RunTimeEndian,
};
use object::{Architecture, Object, ObjectSection, ObjectSymbol};

use crate::dwarf_json::{basename, DwarfInfo, DwarfModule};

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
    let endian = if file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let dwarf_cow = Dwarf::load(|section| load_section(&file, section))?;
    #[allow(deprecated)]
    let dwarf = dwarf_cow.borrow(|section| EndianSlice::new(section, endian));
    let mut func2pc = function_pcs(&dwarf)?;
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
    names.sort();
    names.dedup();
    Ok(names)
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

    fn compile_cpp_fixture() -> Option<std::path::PathBuf> {
        let compiler = std::env::var_os("CXX").unwrap_or_else(|| "c++".into());
        let dir =
            std::env::temp_dir().join(format!("rgwtrace-dwarf-native-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        let source = dir.join("fixture.cc");
        let binary = dir.join("fixture");
        std::fs::write(
            &source,
            r#"
            class Objecter {
            public:
              __attribute__((noinline)) void _send_op(int op) { sink += op; }
              __attribute__((noinline)) void _finish_op(int op) { sink += op; }
              volatile int sink = 0;
            };
            class RGWREST {
            public:
              __attribute__((noinline)) void get_handler(int s) { sink += s; }
              volatile int sink = 0;
            };
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
        .ok()?;
        let status = std::process::Command::new(compiler)
            .args(["-g", "-O0", "-fno-inline"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .ok()?;
        status.success().then_some(binary)
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
