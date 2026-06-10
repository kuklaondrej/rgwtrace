use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result};
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

        Ok(Self {
            version,
            arch,
            modules,
        })
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
        let mut fields = [FieldKernel::default(); 10];
        for (idx, field) in self.fields.iter().take(10).enumerate() {
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
            size: self.fields.len().min(10) as i32,
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
}
