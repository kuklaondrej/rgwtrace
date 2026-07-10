use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize)]
pub struct DwarfInfo {
    pub version: Option<String>,
    pub arch: Option<String>,
    pub modules: BTreeMap<String, DwarfModule>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DwarfModule {
    pub build_id: Option<String>,
    #[serde(default)]
    pub func2pc: BTreeMap<String, u64>,
    #[serde(default)]
    pub func2vf: BTreeMap<String, FunctionVarFields>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FunctionVarFields {
    #[serde(default)]
    pub var_fields: Vec<VarFieldJson>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VarFieldJson {
    pub location: VarLocationJson,
    #[serde(default)]
    pub fields: Vec<FieldJson>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct VarLocationJson {
    pub reg: i32,
    pub offset: i32,
    pub stack: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct FieldJson {
    pub offset: i32,
    pub pointer: bool,
}

/// Outcome of resolving a path-derived module key against the artifact's
/// modules. `Unique` covers both an exact key hit and a single soname-stem
/// fallback; `Ambiguous` names every candidate when two or more share the stem
/// so the caller never has to pick arbitrarily.
#[derive(Debug)]
pub enum ModuleMatch<'a> {
    None,
    Unique(&'a DwarfModule),
    Ambiguous(Vec<String>),
}

#[derive(Clone, Debug, Serialize)]
pub struct HprobeEntry {
    pub module: String,
    pub function: String,
    pub key: i32,
    pub field: VarFieldKernel,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct VarLocationKernel {
    pub reg: i32,
    pub offset: i32,
    pub stack: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct FieldKernel {
    pub offset: i32,
    pub pointer: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct VarFieldKernel {
    pub varloc: VarLocationKernel,
    pub fields: [FieldKernel; 10],
    pub size: i32,
}

const FUNCTION_BASE_IDS: &[(&str, i32)] = &[
    ("Objecter::_send_op", 0),
    ("Objecter::_finish_op", 20),
    ("RGWREST::get_handler", 30),
    (RGW_PROCESS_AUTHENTICATED, 40),
];

/// Probe functions whose var_fields MUST resolve for an artifact to be usable
/// for live tracing. Without them the `hprobes` map stays empty, the RGW/RADOS
/// uprobes (e.g. `uprobe_rgw_get_handler`) return before emitting, and the
/// tracer captures nothing while looking healthy. Mirrors the required set
/// preflight enforces (`Objecter::_send_op`/`Objecter::_finish_op` in a RADOS
/// module, `RGWREST::get_handler` in radosgw). `rgw_process_authenticated` is
/// intentionally excluded: it only powers the optional
/// `--correlate-cross-thread` bridge, whose absence merely degrades to
/// same-thread correlation.
pub const REQUIRED_HPROBE_FUNCTIONS: &[&str] = &[
    "Objecter::_send_op",
    "Objecter::_finish_op",
    "RGWREST::get_handler",
];

/// Required functions with zero total var_fields, i.e. functions the artifact
/// cannot probe at all. `totals` maps each required function to its var_field
/// count SUMMED across every module, so a function that one module leaves empty
/// but another module supplies (the Ubuntu librados-vs-libceph-common split) is
/// NOT reported -- only a function empty in every module is returned. A non-empty
/// result means the artifact/import is silently unusable for live tracing.
pub fn required_functions_missing_var_fields(totals: &BTreeMap<&str, usize>) -> Vec<&'static str> {
    REQUIRED_HPROBE_FUNCTIONS
        .iter()
        .copied()
        .filter(|function| totals.get(function).copied().unwrap_or(0) == 0)
        .collect()
}

/// The one function whose hprobe slot carries a raw-pointer descriptor rather
/// than a member-deref chain. Its var_field is read register-only by the BPF
/// cross-thread re-seed handler (`fetch_param_ptr` in bpf/rgwtrace.bpf.c), which
/// consumes `location.reg` and ignores `fields`. Any other var_field shape here
/// would make the handler read a wrong parameter, so we pin the shape at import.
pub const RGW_PROCESS_AUTHENTICATED: &str = "rgw_process_authenticated";

/// Whether `var_field` is the exact raw-pointer sentinel that native extraction
/// emits for `rgw_process_authenticated` (see `probe_function_var_fields` in
/// `src/dwarf_native.rs`): register-located (`!stack`) with a single
/// `{offset: 0, pointer: false}` field. The BPF re-seed handler reads only
/// `location.reg`; anything else (stack-located, extra fields, a nonzero offset,
/// or a `pointer: true` deref) means the descriptor was hand-edited or produced
/// by a different toolchain and cannot be trusted to name the req_state pointer.
pub fn is_raw_pointer_descriptor(var_field: &VarFieldJson) -> bool {
    !var_field.location.stack
        && var_field.fields.len() == 1
        && var_field.fields[0].offset == 0
        && !var_field.fields[0].pointer
}

/// Number of slots in the kernel `hprobes` map. Mirrors `max_entries, 8192` on
/// the `hprobes` BPF_MAP_TYPE_HASH in `bpf/rgwtrace.bpf.c`. hprobe keys are
/// `base_id + idx`, so the highest base's var_fields must stay below this.
const HPROBES_MAP_CAPACITY: i32 = 8192;

/// Maximum length of a nested field-deref chain per var_field. Bounded by the
/// fixed kernel array `struct Field fields[10]` in `bpf/ceph_abi.h`, walked by
/// `for (int i = 2; i < 10; i++)` in `fetch_var_member_addr` (bpf/bpf_utils.h).
/// Longer chains cannot be represented, so we reject rather than truncate: a
/// dropped trailing deref yields a wrong final address and garbage reads.
const MAX_VAR_FIELD_CHAIN: usize = 10;

/// Sane inclusive bound (bytes) for DWARF location and struct-member offsets.
/// These are added to a resolved base address in `fetch_var_member_addr`
/// (bpf/bpf_utils.h). Real C++ member offsets and DWARF frame offsets are small;
/// we accept a very generous +/-16 MiB window (stack offsets may be negative)
/// and reject anything larger as corrupt before it can form a wild kernel read.
const MAX_OFFSET: i32 = 16 * 1024 * 1024;

impl DwarfInfo {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read DWARF JSON {}", path.display()))?;
        Self::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
    }

    pub fn from_str(contents: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(contents)?;
        let object = value
            .as_object()
            .context("DWARF JSON root must be an object")?;

        let version = object
            .get("version")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let arch = object
            .get("arch")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        let mut modules = BTreeMap::new();
        for (name, module_value) in object {
            if name == "version" || name == "arch" {
                continue;
            }
            if !module_value.is_object() {
                continue;
            }
            if module_value.get("func2pc").is_none() && module_value.get("func2vf").is_none() {
                continue;
            }
            let module: DwarfModule = serde_json::from_value(module_value.clone())
                .with_context(|| format!("invalid module entry {name}"))?;
            modules.insert(name.clone(), module);
        }

        let info = Self {
            version,
            arch,
            modules,
        };
        info.validate()?;
        Ok(info)
    }

    /// Reject malformed/oversized probe metadata before it can silently corrupt
    /// the `hprobes` map or produce wrong in-kernel offsets. Only functions that
    /// map to an hprobe base id are written to the kernel, so validation is
    /// scoped to those; other exported functions are ignored by `hprobe_entries`.
    fn validate(&self) -> Result<()> {
        let max_reg = arch_max_reg(self.arch.as_deref());
        for (module_name, module) in &self.modules {
            for (function, vars) in &module.func2vf {
                let Some(capacity) = function_slot_capacity(function) else {
                    continue;
                };

                // F6: keys are `base_id + idx`; more var_fields than the reserved
                // slot range would spill into the next function or past the map.
                if vars.var_fields.len() > capacity {
                    bail!(
                        "module {module_name} function {function}: {} var_fields exceed the \
                         {capacity} hprobe map slots reserved for it; keys (base_id + idx) would \
                         spill into the next function's range or past the {HPROBES_MAP_CAPACITY}-entry map",
                        vars.var_fields.len()
                    );
                }

                for (idx, var_field) in vars.var_fields.iter().enumerate() {
                    // F1: rgw_process_authenticated's slot is read register-only by
                    // the BPF cross-thread re-seed handler (it consumes
                    // `location.reg` and ignores `fields`). A stale or hand-edited
                    // JSON with any other shape -- a stack location, extra fields, a
                    // nonzero offset, or a `pointer:true` deref -- would silently
                    // name a wrong parameter and, on a bridge match, re-seed request
                    // context from the wrong entry. Fail closed at import: this slot
                    // only ever carries the raw-pointer sentinel.
                    if function == RGW_PROCESS_AUTHENTICATED
                        && !is_raw_pointer_descriptor(var_field)
                    {
                        bail!(
                            "module {module_name} function {function} var_field {idx}: expected the \
                             raw-pointer descriptor (register-located, exactly one \
                             {{offset:0, pointer:false}} field) that the BPF re-seed handler reads \
                             register-only, but got location {:?} with {} field(s) {:?}; refusing a \
                             descriptor that could read a wrong parameter",
                            var_field.location,
                            var_field.fields.len(),
                            var_field.fields
                        );
                    }

                    // F7: nested chain must fit the fixed kernel array; refuse to
                    // truncate because a dropped deref reads garbage.
                    if var_field.fields.len() > MAX_VAR_FIELD_CHAIN {
                        bail!(
                            "module {module_name} function {function} var_field {idx}: nested field \
                             chain length {} exceeds kernel cap {MAX_VAR_FIELD_CHAIN} \
                             (struct Field fields[{MAX_VAR_FIELD_CHAIN}] in bpf/ceph_abi.h)",
                            var_field.fields.len()
                        );
                    }

                    let reg = var_field.location.reg;
                    if !(0..=max_reg).contains(&reg) {
                        bail!(
                            "module {module_name} function {function} var_field {idx}: register {reg} \
                             is outside the valid DWARF register range 0..={max_reg} for arch {}",
                            self.arch.as_deref().unwrap_or("unknown")
                        );
                    }

                    let loc_offset = var_field.location.offset;
                    if !(-MAX_OFFSET..=MAX_OFFSET).contains(&loc_offset) {
                        bail!(
                            "module {module_name} function {function} var_field {idx}: location offset \
                             {loc_offset} is outside the sane range +/-{MAX_OFFSET}"
                        );
                    }

                    // F-B: the per-offset bound above is not cumulative. In
                    // `fetch_var_member_addr` (bpf/bpf_utils.h) a run of NON-pointer
                    // fields accumulates displacement onto `cur_addr`
                    // (`cur_addr += fields[i].offset`), while a `pointer:true` field
                    // derefs and RESETS `cur_addr` to a freshly read pointer value
                    // (`cur_addr = tmpaddr + fields[i].offset`). So N non-pointer
                    // fields each at the per-field limit walk N*MAX_OFFSET from the
                    // base before any deref -- a drift the independent per-field
                    // check never catches. Track the cumulative displacement between
                    // derefs and reject if it exceeds a single MAX_OFFSET. The
                    // location offset seeds the running sum because BPF applies it to
                    // the register-relative base (`cur_addr += varloc.offset`) before
                    // the first deref; seeding it unconditionally is a safe (stricter)
                    // over-approximation of the `if (varloc.stack)` guard. Every
                    // `pointer:true` field resets the accumulator because BPF rereads
                    // `cur_addr` from process memory there.
                    let mut running = loc_offset as i64;
                    for (fidx, field) in var_field.fields.iter().enumerate() {
                        // Individual-offset bound (preserved from prior behavior): a
                        // single field may never exceed MAX_OFFSET on its own.
                        if !(-MAX_OFFSET..=MAX_OFFSET).contains(&field.offset) {
                            bail!(
                                "module {module_name} function {function} var_field {idx} field {fidx}: \
                                 offset {} is outside the sane range +/-{MAX_OFFSET}",
                                field.offset
                            );
                        }

                        if field.pointer {
                            // The deref reads at the accumulated `running` displacement
                            // (already bounded by the previous iteration's check), then
                            // `cur_addr` resets to the read pointer plus this field's
                            // offset -- so a new accumulation run starts here.
                            running = field.offset as i64;
                        } else {
                            running += field.offset as i64;
                        }

                        if !(-(MAX_OFFSET as i64)..=MAX_OFFSET as i64).contains(&running) {
                            bail!(
                                "module {module_name} function {function} var_field {idx} field {fidx}: \
                                 cumulative non-pointer displacement {running} exceeds the sane range \
                                 +/-{MAX_OFFSET} between pointer derefs (fetch_var_member_addr in \
                                 bpf/bpf_utils.h walks non-pointer fields additively before a deref \
                                 resets the address)"
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn hprobe_entries(&self) -> Vec<HprobeEntry> {
        let mut entries = Vec::new();
        for (module_name, module) in &self.modules {
            for (function, vars) in &module.func2vf {
                let Some(base_id) = function_base_id(function) else {
                    continue;
                };
                for (idx, var_field) in vars.var_fields.iter().enumerate() {
                    entries.push(HprobeEntry {
                        module: module_name.clone(),
                        function: function.clone(),
                        key: base_id + idx as i32,
                        field: var_field.to_kernel(),
                    });
                }
            }
        }
        entries
    }

    /// Classify a module-key lookup: exact match first, then a soname-aware
    /// fallback. Ubuntu ships DWARF-bearing real files under versioned names
    /// (`librados.so.2.0.0`) reached through soname symlinks (`librados.so.2`);
    /// auto-discovery and explicit `--*-path` flags may yield either form, while
    /// the artifact keys modules by whichever name was seen at export time.
    /// Matching only on exact basename silently skips the librados
    /// `_send_op`/`_finish_op` uprobes (and hard-fails the librbd build-id check).
    ///
    /// The fallback matches any module whose key shares the same
    /// `lib<name>.so.<major>` soname stem, so `librados.so.2` resolves to
    /// `librados.so.2.0.0` and vice-versa. Exact match always wins; the fallback
    /// never crosses major versions (`librados.so.2` never matches
    /// `librados.so.3`) because the stem includes the major.
    ///
    /// When two or more modules share the key's stem (e.g. both
    /// `librados.so.2.0.0` and `librados.so.2.1.0` present) the fallback refuses
    /// to guess: an arbitrary pick could pair one module's function address with
    /// another module's field descriptors (hprobe entries are keyed by a GLOBAL
    /// function id and populated for every module). It returns
    /// [`ModuleMatch::Ambiguous`] naming the candidates so the caller can surface
    /// an explicit error, and is treated as unresolved everywhere a lookup is a
    /// plain `Option`.
    pub fn match_module(&self, module_key: &str) -> ModuleMatch<'_> {
        if let Some(module) = self.modules.get(module_key) {
            return ModuleMatch::Unique(module);
        }
        let Some(stem) = soname_stem(module_key) else {
            return ModuleMatch::None;
        };
        let mut matches = self
            .modules
            .iter()
            .filter(|(name, _)| soname_stem(name) == Some(stem));
        let Some((_, first)) = matches.next() else {
            return ModuleMatch::None;
        };
        if matches.next().is_none() {
            return ModuleMatch::Unique(first);
        }
        // Two or more share the stem: name every candidate and refuse to pick.
        let keys = self
            .modules
            .keys()
            .filter(|name| soname_stem(name) == Some(stem))
            .cloned()
            .collect();
        ModuleMatch::Ambiguous(keys)
    }

    /// The single module for `module_key`, or `None` when nothing matches OR the
    /// soname fallback is ambiguous. An ambiguous multi-match is deliberately
    /// treated as unresolved rather than an arbitrary pick; preflight surfaces
    /// it as an explicit named error via [`Self::match_module`].
    pub fn resolve_module(&self, module_key: &str) -> Option<&DwarfModule> {
        match self.match_module(module_key) {
            ModuleMatch::Unique(module) => Some(module),
            ModuleMatch::None | ModuleMatch::Ambiguous(_) => None,
        }
    }

    /// Whether exactly one artifact module resolves for `module_key` (exact or a
    /// unique soname-fallback). An ambiguous multi-match counts as unresolved, so
    /// the preflight silent-skip warning fires rather than being suppressed by a
    /// would-be arbitrary pick.
    pub fn has_module(&self, module_key: &str) -> bool {
        self.resolve_module(module_key).is_some()
    }

    /// Whether any module in the artifact exposes a `func2pc` address for
    /// `function`. Used to distinguish "the artifact simply lacks this probe"
    /// from "the artifact has it but the discovered library did not resolve to
    /// the module that carries it" (the silent-skip preflight warning).
    pub fn any_module_has_func2pc(&self, function: &str) -> bool {
        self.modules
            .values()
            .any(|module| module.func2pc.contains_key(function))
    }

    #[allow(dead_code)]
    pub fn function_addr(&self, module_basename: &str, function: &str) -> Option<u64> {
        self.resolve_module(module_basename)
            .and_then(|module| module.func2pc.get(function).copied())
            .filter(|addr| *addr != 0)
    }

    pub fn function_var_field_count(&self, module_basename: &str, function: &str) -> Option<usize> {
        self.resolve_module(module_basename)
            .and_then(|module| module.func2vf.get(function))
            .map(|vars| vars.var_fields.len())
    }

    /// Total var_fields for `function` summed across every module. Summing is
    /// what lets a function one module leaves empty count as covered when
    /// another module supplies it.
    fn total_var_field_count(&self, function: &str) -> usize {
        self.modules
            .values()
            .filter_map(|module| module.func2vf.get(function))
            .map(|vars| vars.var_fields.len())
            .sum()
    }

    /// Required probe functions that resolved no var_fields in ANY module. A
    /// non-empty result means the artifact is unusable for live tracing: those
    /// functions' hprobes never populate and their uprobes emit nothing. See
    /// [`required_functions_missing_var_fields`].
    pub fn required_functions_without_var_fields(&self) -> Vec<&'static str> {
        let totals = REQUIRED_HPROBE_FUNCTIONS
            .iter()
            .map(|function| (*function, self.total_var_field_count(function)))
            .collect();
        required_functions_missing_var_fields(&totals)
    }

    /// Modules that expose a `func2pc` address for `function` but no var_fields
    /// for it -- the silent empty-extraction signature (`func2vf: {}` while
    /// `func2pc` is populated). Used to name the offending modules in the export
    /// warning.
    pub fn modules_with_addr_but_empty_var_fields(&self, function: &str) -> Vec<&str> {
        self.modules
            .iter()
            .filter(|(_, module)| {
                module.func2pc.contains_key(function)
                    && module
                        .func2vf
                        .get(function)
                        .is_none_or(|vars| vars.var_fields.is_empty())
            })
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Whether `function` in `module_basename` carries a single valid raw-pointer
    /// descriptor (see [`is_raw_pointer_descriptor`]). The attach gate and the
    /// `cross_thread_reseed_probe` preflight check use this instead of a mere
    /// presence test so that only a descriptor the BPF re-seed handler can read
    /// register-only (`fetch_param_ptr`) enables the bridge -- keeping the path
    /// fail-closed even if `validate` is ever bypassed.
    pub fn function_has_raw_pointer_descriptor(
        &self,
        module_basename: &str,
        function: &str,
    ) -> bool {
        self.resolve_module(module_basename)
            .and_then(|module| module.func2vf.get(function))
            .is_some_and(|vars| {
                vars.var_fields.len() == 1 && is_raw_pointer_descriptor(&vars.var_fields[0])
            })
    }

    pub fn module_build_id(&self, module_basename: &str) -> Option<&str> {
        self.resolve_module(module_basename)
            .and_then(|module| module.build_id.as_deref())
            .filter(|build_id| !build_id.is_empty())
    }

    pub fn summary(&self) -> DwarfSummary {
        let hprobe_entries = self.hprobe_entries().len();
        DwarfSummary {
            version: self.version.clone(),
            arch: self.arch.clone(),
            module_count: self.modules.len(),
            hprobe_entries,
        }
    }
}

#[allow(dead_code)]
pub fn basename(path: &Path) -> Option<&str> {
    path.file_name().and_then(|name| name.to_str())
}

/// The single "path -> artifact module key" mapping used everywhere a basename
/// is matched against the DWARF module map (attach, preflight, build-id).
///
/// Canonicalizes the path first so a soname symlink (`/usr/lib/librados.so.2`)
/// resolves to the versioned real file (`librados.so.2.0.0`) the artifact keys
/// modules by -- the same versioned name `--pid`/maps discovery already yields
/// from the mmap'd path. If canonicalization fails (e.g. a `/proc/<pid>/root`
/// path, or a nonexistent path in unit tests) it falls back to the path as
/// given, so callers never panic and preflight/attach still agree via the
/// soname-fallback in [`DwarfInfo::resolve_module`]. Routing every lookup
/// through this one helper keeps attach, preflight, and the build-id check from
/// disagreeing about a module's key.
pub fn module_key_for_path(path: &Path) -> Option<String> {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    canonical
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
}

/// The `lib<name>.so.<major>` soname stem of a WELL-FORMED numeric soname, used
/// for soname-aware fallback matching. Returns `Some("librados.so.2")` for
/// `librados.so.2.0.0`, `librados.so.2`, and `librados.so.2.99` (all major 2),
/// but `Some("librados.so.3")` for `librados.so.3` (different major, no cross).
///
/// Returns `None` for anything that is not a numeric soname, so malformed or
/// "backup" names stay exact-only and never participate in the fallback:
/// - no `.so.` marker (`radosgw`)                        -> None
/// - a non-numeric major (`foo.so.debug.anything`, `libx.so.2x`) -> None
/// - an empty component (`libfoo.so..junk`)              -> None
/// - a non-numeric minor/patch (`libfoo.so.2.backup`)    -> None
///
/// The version after `.so.` must be a dot-separated run of non-empty ASCII-digit
/// components (`major[.minor[.patch...]]`); the stem keeps only the major.
fn soname_stem(name: &str) -> Option<&str> {
    const MARKER: &str = ".so.";
    let idx = name.find(MARKER)?;
    let version_start = idx + MARKER.len();
    let mut components = name[version_start..].split('.');
    let major = components.next()?;
    if major.is_empty() || !major.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    for component in components {
        if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
    }
    Some(&name[..version_start + major.len()])
}

impl VarFieldJson {
    fn to_kernel(&self) -> VarFieldKernel {
        // `DwarfInfo::validate` rejects chains longer than MAX_VAR_FIELD_CHAIN
        // before construction, so the `take(10)` / `min(10)` below are defensive
        // backstops that never truncate real data (they only prevent an
        // out-of-bounds index on the fixed-size kernel array).
        let mut fields = [FieldKernel::default(); MAX_VAR_FIELD_CHAIN];
        for (idx, field) in self.fields.iter().take(MAX_VAR_FIELD_CHAIN).enumerate() {
            fields[idx] = FieldKernel {
                offset: field.offset,
                pointer: field.pointer,
            };
        }

        VarFieldKernel {
            varloc: VarLocationKernel {
                reg: self.location.reg,
                offset: self.location.offset,
                stack: self.location.stack,
            },
            fields,
            size: self.fields.len().min(MAX_VAR_FIELD_CHAIN) as i32,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DwarfSummary {
    pub version: Option<String>,
    pub arch: Option<String>,
    pub module_count: usize,
    pub hprobe_entries: usize,
}

fn function_base_id(function: &str) -> Option<i32> {
    FUNCTION_BASE_IDS
        .iter()
        .find_map(|(name, id)| (*name == function).then_some(*id))
}

/// How many contiguous hprobe map slots are reserved for `function`, i.e. how
/// many var_fields it may contribute before its keys (`base_id + idx`) collide
/// with the next function's base or overrun the map. The highest base extends to
/// the map capacity; returns `None` for functions with no reserved base id.
fn function_slot_capacity(function: &str) -> Option<usize> {
    let base = function_base_id(function)?;
    let next = FUNCTION_BASE_IDS
        .iter()
        .map(|(_, id)| *id)
        .filter(|id| *id > base)
        .min()
        .unwrap_or(HPROBES_MAP_CAPACITY);
    Some((next - base) as usize)
}

/// Highest valid DWARF register number for `arch`, matching the register tables
/// in `fetch_register` (bpf/bpf_utils.h): x86 uses DWARF regs 0..=15, arm64 uses
/// 0..=31 (x0..x30 plus sp=31). When arch is unknown we accept the wider arm64
/// range so a valid file is never rejected, while still catching garbage regs.
fn arch_max_reg(arch: Option<&str>) -> i32 {
    let arch = arch.unwrap_or_default().to_ascii_lowercase();
    if arch.contains("amd64") || arch.contains("x86") || arch.contains("x64") || arch == "i386" {
        15
    } else {
        31
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cephtrace_dwarf_json_shape() {
        let json = r#"
        {
          "version": "18.2.8-1jammy",
          "arch": "amd64",
          "libceph-common.so.2": {
            "build_id": "abc",
            "func2pc": {"Objecter::_send_op": 123},
            "func2vf": {
              "Objecter::_send_op": {
                "var_fields": [
                  {
                    "location": {"reg": 4, "offset": 0, "stack": false},
                    "fields": [
                      {"offset": 0, "pointer": false},
                      {"offset": 1144, "pointer": true}
                    ]
                  }
                ]
              }
            }
          }
        }
        "#;

        let info = DwarfInfo::from_str(json).unwrap();
        let entries = info.hprobe_entries();

        assert_eq!(info.version.as_deref(), Some("18.2.8-1jammy"));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, 0);
        assert_eq!(entries[0].field.size, 2);
        assert_eq!(entries[0].field.fields[1].offset, 1144);
    }

    /// Builds a single var_field with a `chain_len`-long field list, `reg`, and
    /// location `offset`, all under the same simple location shape.
    fn var_field_json(reg: i32, offset: i32, chain_len: usize) -> String {
        let fields: Vec<String> = (0..chain_len)
            .map(|_| r#"{"offset": 8, "pointer": true}"#.to_string())
            .collect();
        format!(
            r#"{{"location": {{"reg": {reg}, "offset": {offset}, "stack": false}}, "fields": [{}]}}"#,
            fields.join(",")
        )
    }

    /// Wraps `count` copies of a valid var_field under `function` in one module.
    fn json_with_var_fields(arch: &str, function: &str, count: usize) -> String {
        let vf = var_field_json(4, 0, 1);
        let var_fields = vec![vf; count].join(",");
        format!(
            r#"{{"version": "v", "arch": "{arch}", "libceph-common.so.2": {{"build_id": "abc", "func2vf": {{"{function}": {{"var_fields": [{var_fields}]}}}}}}}}"#
        )
    }

    /// Wraps a single var_field (given as raw JSON) under `function`.
    fn json_with_single_var_field(arch: &str, function: &str, var_field: &str) -> String {
        format!(
            r#"{{"version": "v", "arch": "{arch}", "libceph-common.so.2": {{"build_id": "abc", "func2vf": {{"{function}": {{"var_fields": [{var_field}]}}}}}}}}"#
        )
    }

    /// Builds a var_field with `location.offset == loc_offset` and an explicit
    /// `fields` chain given as `(offset, pointer)` pairs. Unlike `var_field_json`,
    /// this exposes per-field `pointer` so cumulative-displacement resets can be
    /// exercised.
    fn var_field_with_chain(loc_offset: i32, chain: &[(i32, bool)]) -> String {
        let fields: Vec<String> = chain
            .iter()
            .map(|(offset, pointer)| format!(r#"{{"offset": {offset}, "pointer": {pointer}}}"#))
            .collect();
        format!(
            r#"{{"location": {{"reg": 4, "offset": {loc_offset}, "stack": false}}, "fields": [{}]}}"#,
            fields.join(",")
        )
    }

    #[test]
    fn slot_capacities_match_base_id_gaps() {
        // _send_op base 0 -> _finish_op base 20 => 20 slots.
        assert_eq!(function_slot_capacity("Objecter::_send_op"), Some(20));
        // _finish_op base 20 -> get_handler base 30 => 10 slots.
        assert_eq!(function_slot_capacity("Objecter::_finish_op"), Some(10));
        // get_handler base 30 -> rgw_process_authenticated base 40 => 10 slots.
        assert_eq!(function_slot_capacity("RGWREST::get_handler"), Some(10));
        // Highest base (rgw_process_authenticated, 40) extends to the map capacity.
        assert_eq!(
            function_slot_capacity("rgw_process_authenticated"),
            Some((HPROBES_MAP_CAPACITY - 40) as usize)
        );
        assert_eq!(function_slot_capacity("Unknown::function"), None);
    }

    #[test]
    fn send_op_var_fields_at_limit_pass() {
        // 20 slots (base 0 .. next base 20) is exactly-at-limit.
        let json = json_with_var_fields("amd64", "Objecter::_send_op", 20);
        let info = DwarfInfo::from_str(&json).unwrap();
        assert_eq!(info.hprobe_entries().len(), 20);
    }

    #[test]
    fn send_op_var_fields_over_limit_fail() {
        let json = json_with_var_fields("amd64", "Objecter::_send_op", 21);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Objecter::_send_op"), "message: {msg}");
        assert!(msg.contains("spill"), "message: {msg}");
    }

    #[test]
    fn finish_op_var_fields_at_limit_pass() {
        // 10 slots (base 20 .. next base 30) is exactly-at-limit.
        let json = json_with_var_fields("amd64", "Objecter::_finish_op", 10);
        DwarfInfo::from_str(&json).unwrap();
    }

    #[test]
    fn finish_op_var_fields_over_limit_fail() {
        let json = json_with_var_fields("amd64", "Objecter::_finish_op", 11);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Objecter::_finish_op"), "message: {msg}");
        assert!(msg.contains("11"), "message: {msg}");
    }

    #[test]
    fn nested_chain_at_limit_passes() {
        let vf = var_field_json(4, 0, MAX_VAR_FIELD_CHAIN);
        let json = json_with_single_var_field("amd64", "Objecter::_send_op", &vf);
        let info = DwarfInfo::from_str(&json).unwrap();
        assert_eq!(
            info.hprobe_entries()[0].field.size as usize,
            MAX_VAR_FIELD_CHAIN
        );
    }

    #[test]
    fn nested_chain_over_limit_fails() {
        let vf = var_field_json(4, 0, MAX_VAR_FIELD_CHAIN + 1);
        let json = json_with_single_var_field("amd64", "Objecter::_send_op", &vf);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Objecter::_send_op"), "message: {msg}");
        assert!(msg.contains("nested field"), "message: {msg}");
        assert!(
            msg.contains(&(MAX_VAR_FIELD_CHAIN + 1).to_string()),
            "message: {msg}"
        );
    }

    #[test]
    fn register_out_of_range_for_x86_fails() {
        // reg 20 is valid on arm64 but not on x86 (regs 0..=15).
        let vf = var_field_json(20, 0, 1);
        let json = json_with_single_var_field("amd64", "Objecter::_send_op", &vf);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Objecter::_send_op"), "message: {msg}");
        assert!(msg.contains("register 20"), "message: {msg}");
        assert!(msg.contains("0..=15"), "message: {msg}");
    }

    #[test]
    fn register_negative_fails() {
        let vf = var_field_json(-1, 0, 1);
        let json = json_with_single_var_field("amd64", "Objecter::_send_op", &vf);
        assert!(DwarfInfo::from_str(&json).is_err());
    }

    #[test]
    fn arm64_allows_wider_register_range() {
        // reg 31 (sp) is valid on arm64.
        let vf = var_field_json(31, 0, 1);
        let json = json_with_single_var_field("arm64", "Objecter::_send_op", &vf);
        DwarfInfo::from_str(&json).unwrap();

        // reg 32 exceeds even the arm64 range.
        let vf = var_field_json(32, 0, 1);
        let json = json_with_single_var_field("arm64", "Objecter::_send_op", &vf);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        assert!(format!("{err:#}").contains("0..=31"));
    }

    #[test]
    fn location_offset_out_of_range_fails() {
        let vf = var_field_json(4, MAX_OFFSET + 1, 1);
        let json = json_with_single_var_field("amd64", "Objecter::_send_op", &vf);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("location offset"), "message: {msg}");
    }

    #[test]
    fn field_offset_out_of_range_fails() {
        let vf = format!(
            r#"{{"location": {{"reg": 4, "offset": 0, "stack": false}}, "fields": [{{"offset": {}, "pointer": false}}]}}"#,
            MAX_OFFSET + 1
        );
        let json = json_with_single_var_field("amd64", "Objecter::_send_op", &vf);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("field 0"), "message: {msg}");
    }

    #[test]
    fn cumulative_non_pointer_displacement_over_limit_fails() {
        // F-B: 9 non-pointer fields, each individually AT the per-field limit
        // (so every per-field check passes), accumulate ~9*MAX_OFFSET onto the
        // base before any deref. Without the cumulative check this walks ~144
        // MiB from the register base yet slips past the independent bounds.
        let chain: Vec<(i32, bool)> = (0..9).map(|_| (MAX_OFFSET, false)).collect();
        let vf = var_field_with_chain(0, &chain);
        let json = json_with_single_var_field("amd64", "Objecter::_send_op", &vf);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("cumulative"), "message: {msg}");
        assert!(msg.contains("Objecter::_send_op"), "message: {msg}");
    }

    #[test]
    fn cumulative_displacement_reset_by_pointer_derefs_passes() {
        // Same-magnitude per-field offsets as the failing case, but each is
        // separated by a `pointer:true` deref that resets `cur_addr`, so no
        // single between-deref run exceeds MAX_OFFSET. This must still pass.
        let mut chain: Vec<(i32, bool)> = Vec::new();
        for _ in 0..5 {
            chain.push((MAX_OFFSET, false)); // run reaches exactly the limit
            chain.push((0, true)); // deref resets the accumulator to 0
        }
        let vf = var_field_with_chain(0, &chain);
        let json = json_with_single_var_field("amd64", "Objecter::_send_op", &vf);
        DwarfInfo::from_str(&json).unwrap();
    }

    #[test]
    fn single_field_over_limit_still_fails() {
        // Existing per-field behavior is preserved: one oversized field is
        // rejected on its own, independent of the cumulative check.
        let vf = var_field_with_chain(0, &[(MAX_OFFSET + 1, false)]);
        let json = json_with_single_var_field("amd64", "Objecter::_send_op", &vf);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("field 0"), "message: {msg}");
        assert!(msg.contains("sane range"), "message: {msg}");
    }

    #[test]
    fn rgw_process_authenticated_valid_sentinel_passes() {
        // The exact raw-pointer descriptor native extraction emits: register-
        // located, single {offset:0, pointer:false} field.
        let vf = r#"{"location": {"reg": 4, "offset": 0, "stack": false}, "fields": [{"offset": 0, "pointer": false}]}"#;
        let json = json_with_single_var_field("amd64", RGW_PROCESS_AUTHENTICATED, vf);
        let info = DwarfInfo::from_str(&json).unwrap();
        assert!(info
            .function_has_raw_pointer_descriptor("libceph-common.so.2", RGW_PROCESS_AUTHENTICATED));
    }

    #[test]
    fn rgw_process_authenticated_stack_located_rejected() {
        let vf = r#"{"location": {"reg": 4, "offset": 0, "stack": true}, "fields": [{"offset": 0, "pointer": false}]}"#;
        let json = json_with_single_var_field("amd64", RGW_PROCESS_AUTHENTICATED, vf);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(RGW_PROCESS_AUTHENTICATED), "message: {msg}");
        assert!(msg.contains("raw-pointer descriptor"), "message: {msg}");
    }

    #[test]
    fn rgw_process_authenticated_multi_field_rejected() {
        let vf = r#"{"location": {"reg": 4, "offset": 0, "stack": false}, "fields": [{"offset": 0, "pointer": false}, {"offset": 8, "pointer": true}]}"#;
        let json = json_with_single_var_field("amd64", RGW_PROCESS_AUTHENTICATED, vf);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        assert!(format!("{err:#}").contains("raw-pointer descriptor"));
    }

    #[test]
    fn rgw_process_authenticated_nonzero_offset_rejected() {
        let vf = r#"{"location": {"reg": 4, "offset": 0, "stack": false}, "fields": [{"offset": 8, "pointer": false}]}"#;
        let json = json_with_single_var_field("amd64", RGW_PROCESS_AUTHENTICATED, vf);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        assert!(format!("{err:#}").contains("raw-pointer descriptor"));
    }

    #[test]
    fn rgw_process_authenticated_pointer_true_rejected() {
        let vf = r#"{"location": {"reg": 4, "offset": 0, "stack": false}, "fields": [{"offset": 0, "pointer": true}]}"#;
        let json = json_with_single_var_field("amd64", RGW_PROCESS_AUTHENTICATED, vf);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        assert!(format!("{err:#}").contains("raw-pointer descriptor"));
    }

    #[test]
    fn rgw_process_authenticated_empty_fields_rejected() {
        // The preflight test helper's `fields:[]` shape must not qualify.
        let vf = r#"{"location": {"reg": 4, "offset": 0, "stack": false}, "fields": []}"#;
        let json = json_with_single_var_field("amd64", RGW_PROCESS_AUTHENTICATED, vf);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        assert!(format!("{err:#}").contains("raw-pointer descriptor"));
    }

    #[test]
    fn has_raw_pointer_descriptor_false_when_absent() {
        let vf = var_field_json(4, 0, 1);
        let json = json_with_single_var_field("amd64", "Objecter::_send_op", &vf);
        let info = DwarfInfo::from_str(&json).unwrap();
        assert!(!info
            .function_has_raw_pointer_descriptor("libceph-common.so.2", RGW_PROCESS_AUTHENTICATED));
    }

    #[test]
    fn non_object_root_errors_cleanly() {
        let err = DwarfInfo::from_str("[1, 2, 3]").unwrap_err();
        assert!(format!("{err:#}").contains("root must be an object"));
    }

    #[test]
    fn missing_location_errors_cleanly() {
        // A var_field without the required `location` must error, not panic.
        let json = r#"{"version": "v", "arch": "amd64", "libceph-common.so.2": {"build_id": "abc", "func2vf": {"Objecter::_send_op": {"var_fields": [{"fields": []}]}}}}"#;
        let err = DwarfInfo::from_str(json).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("libceph-common.so.2"), "message: {msg}");
    }

    #[test]
    fn invalid_module_shape_errors_cleanly() {
        // func2pc present but with the wrong value type must error, not panic.
        let json =
            r#"{"version": "v", "arch": "amd64", "libceph-common.so.2": {"func2pc": "not-a-map"}}"#;
        let err = DwarfInfo::from_str(json).unwrap_err();
        assert!(format!("{err:#}").contains("invalid module entry"));
    }

    #[test]
    fn minimal_fixture_is_valid() {
        let json = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/minimal_dwarf.json"
        ))
        .unwrap();
        DwarfInfo::from_str(&json).unwrap();
    }

    fn sample_var_field() -> VarFieldJson {
        VarFieldJson {
            location: VarLocationJson {
                reg: 4,
                offset: 0,
                stack: false,
            },
            fields: vec![FieldJson {
                offset: 0,
                pointer: false,
            }],
        }
    }

    /// Builds a module with the given func2pc addresses and func2vf var_field
    /// counts. A function present in `func2pc` but not `func2vf` is the silent
    /// empty-extraction case.
    fn module_with(func2pc: &[(&str, u64)], func2vf: &[(&str, usize)]) -> DwarfModule {
        DwarfModule {
            build_id: Some("bid".to_string()),
            func2pc: func2pc
                .iter()
                .map(|(function, addr)| (function.to_string(), *addr))
                .collect(),
            func2vf: func2vf
                .iter()
                .map(|(function, count)| {
                    (
                        function.to_string(),
                        FunctionVarFields {
                            var_fields: vec![sample_var_field(); *count],
                        },
                    )
                })
                .collect(),
        }
    }

    // --- exporter/import empty-var-field warn logic (pure helper) ---

    #[test]
    fn required_function_empty_in_every_module_warns() {
        // Cross-module totals: get_handler is 0 everywhere -> reported so the
        // caller warns. The other two are covered, so only get_handler comes back.
        let totals = BTreeMap::from([
            ("Objecter::_send_op", 12),
            ("Objecter::_finish_op", 3),
            ("RGWREST::get_handler", 0),
        ]);
        assert_eq!(
            required_functions_missing_var_fields(&totals),
            vec!["RGWREST::get_handler"]
        );
    }

    #[test]
    fn redundant_module_empty_does_not_warn() {
        // Every required function has a nonzero cross-module total (one module
        // left _send_op empty but another supplied it), so nothing is reported.
        let totals = BTreeMap::from([
            ("Objecter::_send_op", 12),
            ("Objecter::_finish_op", 3),
            ("RGWREST::get_handler", 2),
        ]);
        assert!(required_functions_missing_var_fields(&totals).is_empty());
    }

    #[test]
    fn missing_required_function_key_is_treated_as_empty() {
        // A required function absent from the totals map counts as 0 var_fields.
        let totals = BTreeMap::from([("Objecter::_send_op", 12)]);
        assert_eq!(
            required_functions_missing_var_fields(&totals),
            vec!["Objecter::_finish_op", "RGWREST::get_handler"]
        );
    }

    // --- import-side equivalent (DwarfInfo over real module structure) ---

    #[test]
    fn dwarf_with_redundant_module_coverage_is_usable() {
        // Ubuntu split: librados carries the addresses, libceph-common carries the
        // var_fields, radosgw carries get_handler. No required function is empty
        // everywhere, so the artifact is usable.
        let info = DwarfInfo {
            version: Some("v".to_string()),
            arch: Some("amd64".to_string()),
            modules: BTreeMap::from([
                (
                    "librados.so.2".to_string(),
                    module_with(
                        &[("Objecter::_send_op", 1), ("Objecter::_finish_op", 1)],
                        &[],
                    ),
                ),
                (
                    "libceph-common.so.2".to_string(),
                    module_with(
                        &[],
                        &[("Objecter::_send_op", 12), ("Objecter::_finish_op", 3)],
                    ),
                ),
                (
                    "radosgw".to_string(),
                    module_with(&[], &[("RGWREST::get_handler", 2)]),
                ),
            ]),
        };
        assert!(info.required_functions_without_var_fields().is_empty());
    }

    #[test]
    fn dwarf_missing_required_var_fields_everywhere_is_flagged_and_names_modules() {
        // librados has a func2pc address for _send_op but empty func2vf (the silent
        // empty-extraction signature), and no other module covers it.
        let info = DwarfInfo {
            version: Some("v".to_string()),
            arch: Some("amd64".to_string()),
            modules: BTreeMap::from([
                (
                    "librados.so.2".to_string(),
                    module_with(&[("Objecter::_send_op", 1)], &[]),
                ),
                (
                    "libceph-common.so.2".to_string(),
                    module_with(&[], &[("Objecter::_finish_op", 3)]),
                ),
                (
                    "radosgw".to_string(),
                    module_with(&[], &[("RGWREST::get_handler", 2)]),
                ),
            ]),
        };
        assert_eq!(
            info.required_functions_without_var_fields(),
            vec!["Objecter::_send_op"]
        );
        assert_eq!(
            info.modules_with_addr_but_empty_var_fields("Objecter::_send_op"),
            vec!["librados.so.2"]
        );
    }

    // --- soname-aware module resolution + path -> module key ---

    /// Builds a DwarfInfo whose only module is `module_key`, exposing a
    /// `_send_op` func2pc address and a build id so both lookups can be exercised.
    fn info_with_module(module_key: &str) -> DwarfInfo {
        DwarfInfo {
            version: Some("v".to_string()),
            arch: Some("amd64".to_string()),
            modules: BTreeMap::from([(
                module_key.to_string(),
                module_with(&[("Objecter::_send_op", 42)], &[("Objecter::_send_op", 1)]),
            )]),
        }
    }

    #[test]
    fn soname_stem_truncates_after_major() {
        assert_eq!(soname_stem("librados.so.2.0.0"), Some("librados.so.2"));
        assert_eq!(soname_stem("librados.so.2"), Some("librados.so.2"));
        assert_eq!(soname_stem("librbd.so.1.18.0"), Some("librbd.so.1"));
        assert_eq!(soname_stem("librbd.so.1"), Some("librbd.so.1"));
        // No minor suffix -> stem is the whole name (major only).
        assert_eq!(
            soname_stem("libceph-common.so.2"),
            Some("libceph-common.so.2")
        );
    }

    #[test]
    fn soname_stem_rejects_malformed_and_non_numeric() {
        // No `.so.` marker at all -> exact-only.
        assert_eq!(soname_stem("radosgw"), None);
        // Non-numeric major.
        assert_eq!(soname_stem("foo.so.debug.anything"), None);
        assert_eq!(soname_stem("libx.so.2x"), None);
        // Empty component right after `.so.`.
        assert_eq!(soname_stem("libfoo.so..junk"), None);
        // Numeric major but a non-numeric ("backup") minor.
        assert_eq!(soname_stem("libfoo.so.2.backup"), None);
        // Trailing dot leaves an empty final component.
        assert_eq!(soname_stem("libfoo.so.2."), None);
    }

    #[test]
    fn ambiguous_soname_fallback_is_rejected_not_guessed() {
        // Two patch-level modules share the same major stem. A symlink-style key
        // must NOT resolve to an arbitrary one -- it is reported ambiguous and
        // treated as unresolved by the Option-returning lookups.
        let info = DwarfInfo {
            version: Some("v".to_string()),
            arch: Some("amd64".to_string()),
            modules: BTreeMap::from([
                (
                    "librados.so.2.0.0".to_string(),
                    module_with(&[("Objecter::_send_op", 1)], &[]),
                ),
                (
                    "librados.so.2.1.0".to_string(),
                    module_with(&[("Objecter::_send_op", 2)], &[]),
                ),
            ]),
        };

        match info.match_module("librados.so.2") {
            ModuleMatch::Ambiguous(mut keys) => {
                keys.sort();
                assert_eq!(keys, vec!["librados.so.2.0.0", "librados.so.2.1.0"]);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
        // Every Option-returning lookup treats ambiguity as unresolved (no pick).
        assert!(info.resolve_module("librados.so.2").is_none());
        assert!(!info.has_module("librados.so.2"));
        assert_eq!(
            info.function_addr("librados.so.2", "Objecter::_send_op"),
            None
        );
        // An EXACT key still resolves that specific module (exact wins).
        assert_eq!(
            info.function_addr("librados.so.2.1.0", "Objecter::_send_op"),
            Some(2)
        );
    }

    #[test]
    fn soname_fallback_resolves_versioned_and_symlink_forms() {
        // Artifact keyed by the versioned real name; a symlink-style lookup key
        // resolves to it via the shared soname stem, and vice-versa.
        let versioned = info_with_module("librados.so.2.0.0");
        assert_eq!(
            versioned.function_addr("librados.so.2", "Objecter::_send_op"),
            Some(42)
        );

        let symlinked = info_with_module("librados.so.2");
        assert_eq!(
            symlinked.function_addr("librados.so.2.0.0", "Objecter::_send_op"),
            Some(42)
        );

        // librbd major-1 versioned <-> soname, both directions.
        let rbd = info_with_module("librbd.so.1.18.0");
        assert_eq!(
            rbd.function_addr("librbd.so.1", "Objecter::_send_op"),
            Some(42)
        );
        assert!(rbd.module_build_id("librbd.so.1").is_some());
    }

    #[test]
    fn soname_fallback_never_crosses_major() {
        let info = info_with_module("librados.so.2.0.0");
        // A different major must NOT resolve to the major-2 module.
        assert_eq!(
            info.function_addr("librados.so.3", "Objecter::_send_op"),
            None
        );
        assert!(info.module_build_id("librados.so.3").is_none());
        assert!(!info.has_module("librados.so.3"));
        assert!(info.has_module("librados.so.2"));
    }

    #[test]
    fn exact_match_takes_precedence_over_soname_fallback() {
        // Two modules sharing a soname stem: an exact key must return the exact
        // module, not the first soname-stem match.
        let info = DwarfInfo {
            version: Some("v".to_string()),
            arch: Some("amd64".to_string()),
            modules: BTreeMap::from([
                (
                    "librados.so.2".to_string(),
                    module_with(&[("Objecter::_send_op", 1)], &[]),
                ),
                (
                    "librados.so.2.0.0".to_string(),
                    module_with(&[("Objecter::_send_op", 2)], &[]),
                ),
            ]),
        };
        assert_eq!(
            info.function_addr("librados.so.2.0.0", "Objecter::_send_op"),
            Some(2)
        );
        assert_eq!(
            info.function_addr("librados.so.2", "Objecter::_send_op"),
            Some(1)
        );
    }

    #[test]
    fn libceph_common_without_version_suffix_still_matches() {
        let info = info_with_module("libceph-common.so.2");
        assert_eq!(
            info.function_addr("libceph-common.so.2", "Objecter::_send_op"),
            Some(42)
        );
    }

    #[test]
    fn module_key_for_path_canonicalizes_symlink_to_versioned() {
        let dir = std::env::temp_dir().join(format!("rgwtrace-mkfp-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let real = dir.join("librados.so.2.0.0");
        fs::write(&real, b"\x7fELF").unwrap();
        let link = dir.join("librados.so.2");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // The symlink path resolves to the versioned real basename.
        assert_eq!(
            module_key_for_path(&link).as_deref(),
            Some("librados.so.2.0.0")
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn module_key_for_path_falls_back_when_canonicalize_fails() {
        // A nonexistent path cannot be canonicalized; the helper falls back to
        // the path's own file name rather than panicking or returning None.
        let path = Path::new("/nonexistent/dir/librados.so.2");
        assert_eq!(module_key_for_path(path).as_deref(), Some("librados.so.2"));
    }
}
