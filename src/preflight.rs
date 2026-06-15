use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use object::Object;
use serde::Serialize;

use crate::{
    cli::Cli,
    dwarf_json::{basename, DwarfInfo, DwarfSummary},
    targets::{self, ProbeTargets},
};

const SEND_OP: &str = "Objecter::_send_op";
const FINISH_OP: &str = "Objecter::_finish_op";
const GET_HANDLER: &str = "RGWREST::get_handler";

const SEND_OP_FIELDS: usize = 12;
const FINISH_OP_FIELDS: usize = 3;
const GET_HANDLER_FIELDS: usize = 2;

#[derive(Debug, Serialize)]
pub struct PreflightReport {
    pub ok: bool,
    pub dwarf: DwarfSummary,
    pub targets: ProbeTargets,
    pub checks: Vec<PreflightCheck>,
    pub build_ids: Vec<BuildIdCheck>,
}

#[derive(Debug, Serialize)]
pub struct PreflightCheck {
    pub name: String,
    pub status: &'static str,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct BuildIdCheck {
    pub module: String,
    pub path: String,
    pub status: &'static str,
    pub dwarf_build_id: Option<String>,
    pub target_build_id: Option<String>,
    pub detail: String,
}

pub fn run(cli: &Cli, dwarf: &DwarfInfo) -> Result<PreflightReport> {
    let targets = validated_targets(cli, dwarf)?;
    let build_ids = build_id_checks(dwarf, &targets)?;
    Ok(PreflightReport {
        ok: true,
        dwarf: dwarf.summary(),
        checks: checks(dwarf, &targets),
        build_ids,
        targets,
    })
}

pub fn validated_targets(cli: &Cli, dwarf: &DwarfInfo) -> Result<ProbeTargets> {
    validate_cli(cli)?;
    validate_ceph_version(dwarf)?;
    let targets = targets::discover(cli)?;
    validate_target_paths(&targets)?;
    validate_dwarf_targets(dwarf, &targets)?;
    validate_build_ids(
        dwarf,
        &targets,
        !cli.allow_build_id_mismatch || cli.strict_build_id,
    )?;
    Ok(targets)
}

pub fn validate_cli(cli: &Cli) -> Result<()> {
    if let Some(pid) = cli.pid {
        if pid <= 0 {
            bail!("--pid must be a positive process id")
        }
    }

    validate_explicit_path("--librados-path", cli.librados_path.as_deref())?;
    validate_explicit_path("--librbd-path", cli.librbd_path.as_deref())?;
    validate_explicit_path("--libceph-common-path", cli.libceph_common_path.as_deref())?;
    validate_explicit_path("--radosgw-path", cli.radosgw_path.as_deref())?;
    Ok(())
}

fn validate_explicit_path(flag: &str, path: Option<&Path>) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    validate_file_path(flag, path)
}

fn validate_target_paths(targets: &ProbeTargets) -> Result<()> {
    validate_file_path("librados target", &targets.librados)?;
    if let Some(librbd) = &targets.librbd {
        validate_file_path("librbd target", librbd)?;
    }
    validate_file_path("libceph-common target", &targets.libceph_common)?;
    validate_file_path("radosgw target", &targets.radosgw)?;
    Ok(())
}

fn validate_file_path(label: &str, path: &Path) -> Result<()> {
    let metadata = path
        .metadata()
        .with_context(|| format!("{label} {} is not accessible", path.display()))?;
    if !metadata.is_file() {
        bail!("{label} {} is not a file", path.display());
    }
    Ok(())
}

fn validate_dwarf_targets(dwarf: &DwarfInfo, targets: &ProbeTargets) -> Result<()> {
    let rados_modules = targets
        .rados_libraries()
        .into_iter()
        .filter_map(basename)
        .filter(|module| module_supports_rados(dwarf, module))
        .collect::<Vec<_>>();
    if rados_modules.is_empty() {
        bail!(
            "DWARF data has no RADOS module matching discovered libraries with required {SEND_OP}/{FINISH_OP} data"
        );
    }

    let radosgw = target_basename(&targets.radosgw, "radosgw target")?;
    require_function(dwarf, radosgw, GET_HANDLER, GET_HANDLER_FIELDS)?;
    Ok(())
}

fn module_supports_rados(dwarf: &DwarfInfo, module: &str) -> bool {
    require_function(dwarf, module, SEND_OP, SEND_OP_FIELDS).is_ok()
        && require_function(dwarf, module, FINISH_OP, FINISH_OP_FIELDS).is_ok()
}

fn require_function(
    dwarf: &DwarfInfo,
    module: &str,
    function: &str,
    min_fields: usize,
) -> Result<()> {
    if dwarf.function_addr(module, function).is_none() {
        bail!("DWARF data module {module} is missing function address for {function}");
    }
    let Some(fields) = dwarf.function_var_field_count(module, function) else {
        bail!("DWARF data module {module} is missing variable fields for {function}");
    };
    if fields < min_fields {
        bail!(
            "DWARF data module {module} has {fields} variable fields for {function}; need at least {min_fields}"
        );
    }
    Ok(())
}

fn checks(dwarf: &DwarfInfo, targets: &ProbeTargets) -> Vec<PreflightCheck> {
    let rados_modules = targets
        .rados_libraries()
        .into_iter()
        .filter_map(basename)
        .filter(|module| module_supports_rados(dwarf, module))
        .collect::<Vec<_>>();
    let radosgw = basename(&targets.radosgw).unwrap_or("<invalid>");

    vec![
        PreflightCheck {
            name: "ceph_abi".to_string(),
            status: "ok",
            detail: format!(
                "Ceph {} uses {} ceph_osd_op layout",
                dwarf.version.as_deref().unwrap_or("<unknown>"),
                ceph_abi_layout(dwarf.version.as_deref().unwrap_or_default()).unwrap_or("unknown")
            ),
        },
        PreflightCheck {
            name: "target_paths".to_string(),
            status: "ok",
            detail: "all discovered target paths are accessible files".to_string(),
        },
        PreflightCheck {
            name: "rados_probes".to_string(),
            status: "ok",
            detail: format!("RADOS probes available in {}", rados_modules.join(", ")),
        },
        PreflightCheck {
            name: "rgw_probe".to_string(),
            status: "ok",
            detail: format!("{GET_HANDLER} available in {radosgw}"),
        },
    ]
}

fn validate_ceph_version(dwarf: &DwarfInfo) -> Result<()> {
    let version = dwarf.version.as_deref().context(
        "Ceph version is required to select ceph_osd_op ABI offsets; pass --ceph-version or use DWARF JSON with a version",
    )?;
    ceph_abi_layout(version)
        .with_context(|| format!("failed to parse Ceph version {version:?}"))?;
    Ok(())
}

fn ceph_abi_layout(version: &str) -> Option<&'static str> {
    let major = version
        .split(['.', '-'])
        .next()
        .and_then(|major| major.parse::<u64>().ok())?;
    if major >= 19 {
        Some("squid+")
    } else {
        Some("pre-squid")
    }
}

fn validate_build_ids(dwarf: &DwarfInfo, targets: &ProbeTargets, strict: bool) -> Result<()> {
    let checks = build_id_checks(dwarf, targets)?;
    if strict {
        if let Some(check) = checks.iter().find(|check| check.status != "ok") {
            bail!(
                "build ID check failed for {} at {}: {}",
                check.module,
                check.path,
                check.detail
            );
        }
    }
    Ok(())
}

fn build_id_checks(dwarf: &DwarfInfo, targets: &ProbeTargets) -> Result<Vec<BuildIdCheck>> {
    targets
        .all_paths()
        .into_iter()
        .map(|path| build_id_check(dwarf, path))
        .collect()
}

fn build_id_check(dwarf: &DwarfInfo, path: &Path) -> Result<BuildIdCheck> {
    let module = target_basename(path, "target")?.to_string();
    let dwarf_build_id = dwarf.module_build_id(&module).map(ToOwned::to_owned);
    let target_build_id = elf_build_id(path)
        .with_context(|| format!("failed to read build ID from {}", path.display()))?;
    let (status, detail) = match (dwarf_build_id.as_deref(), target_build_id.as_deref()) {
        (Some(expected), Some(actual)) if expected.eq_ignore_ascii_case(actual) => {
            ("ok", "build IDs match".to_string())
        }
        (Some(expected), Some(actual)) => (
            "warn",
            format!("build ID mismatch: DWARF has {expected}, target has {actual}"),
        ),
        (None, Some(_)) => (
            "warn",
            "DWARF JSON has no build ID for this module".to_string(),
        ),
        (Some(_), None) => ("warn", "target has no readable build ID".to_string()),
        (None, None) => (
            "warn",
            "neither DWARF JSON nor target has a build ID".to_string(),
        ),
    };

    Ok(BuildIdCheck {
        module,
        path: path.display().to_string(),
        status,
        dwarf_build_id,
        target_build_id,
        detail,
    })
}

fn elf_build_id(path: &Path) -> Result<Option<String>> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let file = object::File::parse(data.as_slice())
        .with_context(|| format!("{} is not a supported object file", path.display()))?;
    Ok(file.build_id()?.map(hex_string))
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn target_basename<'a>(path: &'a Path, label: &str) -> Result<&'a str> {
    basename(path).with_context(|| format!("{label} {} has no file name", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_required_dwarf_targets() {
        let dwarf = DwarfInfo::from_str(&dwarf_json("libceph-common.so.2", "radosgw")).unwrap();
        let targets = ProbeTargets {
            librados: "/tmp/librados.so.2".into(),
            librbd: None,
            libceph_common: "/tmp/libceph-common.so.2".into(),
            radosgw: "/tmp/radosgw".into(),
        };

        validate_dwarf_targets(&dwarf, &targets).unwrap();
    }

    #[test]
    fn rejects_missing_rgw_probe() {
        let dwarf = DwarfInfo::from_str(&dwarf_json("libceph-common.so.2", "other-rgw")).unwrap();
        let targets = ProbeTargets {
            librados: "/tmp/librados.so.2".into(),
            librbd: None,
            libceph_common: "/tmp/libceph-common.so.2".into(),
            radosgw: "/tmp/radosgw".into(),
        };

        assert!(validate_dwarf_targets(&dwarf, &targets).is_err());
    }

    #[test]
    fn rejects_incomplete_finish_op_fields() {
        let dwarf = DwarfInfo::from_str(&dwarf_json_with_field_counts(
            "libceph-common.so.2",
            "radosgw",
            SEND_OP_FIELDS,
            FINISH_OP_FIELDS - 1,
            GET_HANDLER_FIELDS,
        ))
        .unwrap();
        let targets = ProbeTargets {
            librados: "/tmp/librados.so.2".into(),
            librbd: None,
            libceph_common: "/tmp/libceph-common.so.2".into(),
            radosgw: "/tmp/radosgw".into(),
        };

        assert!(validate_dwarf_targets(&dwarf, &targets).is_err());
    }

    #[test]
    fn rejects_missing_ceph_version() {
        let mut dwarf = DwarfInfo::from_str(&dwarf_json("libceph-common.so.2", "radosgw")).unwrap();
        dwarf.version = None;

        let err = validate_ceph_version(&dwarf).unwrap_err();

        assert!(err.to_string().contains("Ceph version is required"));
    }

    #[test]
    fn reports_ceph_abi_layout_from_version() {
        assert_eq!(ceph_abi_layout("18.2.8-1jammy"), Some("pre-squid"));
        assert_eq!(ceph_abi_layout("19.2.0"), Some("squid+"));
        assert_eq!(ceph_abi_layout("not-a-version"), None);
    }

    fn dwarf_json(rados_module: &str, rgw_module: &str) -> String {
        dwarf_json_with_field_counts(
            rados_module,
            rgw_module,
            SEND_OP_FIELDS,
            FINISH_OP_FIELDS,
            GET_HANDLER_FIELDS,
        )
    }

    fn dwarf_json_with_field_counts(
        rados_module: &str,
        rgw_module: &str,
        send_field_count: usize,
        finish_field_count: usize,
        handler_field_count: usize,
    ) -> String {
        format!(
            r#"{{
              "version": "18.2.8-1jammy",
              "arch": "amd64",
              "{rados_module}": {{
                "func2pc": {{"{SEND_OP}": 1, "{FINISH_OP}": 2}},
                "func2vf": {{
                  "{SEND_OP}": {{"var_fields": {send_fields}}},
                  "{FINISH_OP}": {{"var_fields": {finish_fields}}}
                }}
              }},
              "{rgw_module}": {{
                "func2pc": {{"{GET_HANDLER}": 3}},
                "func2vf": {{"{GET_HANDLER}": {{"var_fields": {handler_fields}}}}}
              }}
            }}"#,
            send_fields = var_fields(send_field_count),
            finish_fields = var_fields(finish_field_count),
            handler_fields = var_fields(handler_field_count),
        )
    }

    fn var_fields(count: usize) -> String {
        let field = r#"{"location":{"reg":4,"offset":0,"stack":false},"fields":[]}"#;
        format!("[{}]", vec![field; count].join(","))
    }
}
