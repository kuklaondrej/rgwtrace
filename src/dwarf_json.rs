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
];

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

    #[allow(dead_code)]
    pub fn function_addr(&self, module_basename: &str, function: &str) -> Option<u64> {
        self.modules
            .get(module_basename)
            .and_then(|module| module.func2pc.get(function).copied())
            .filter(|addr| *addr != 0)
    }

    pub fn function_var_field_count(&self, module_basename: &str, function: &str) -> Option<usize> {
        self.modules
            .get(module_basename)
            .and_then(|module| module.func2vf.get(function))
            .map(|vars| vars.var_fields.len())
    }

    pub fn module_build_id(&self, module_basename: &str) -> Option<&str> {
        self.modules
            .get(module_basename)
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
        // Highest base extends to the map capacity.
        assert_eq!(
            function_slot_capacity("RGWREST::get_handler"),
            Some((HPROBES_MAP_CAPACITY - 30) as usize)
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
}
