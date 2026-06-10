use std::path::Path;

use anyhow::{bail, Context, Result};
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
const FINISH_OP_FIELDS: usize = 2;
const GET_HANDLER_FIELDS: usize = 2;

#[derive(Debug, Serialize)]
pub struct PreflightReport {
    pub ok: bool,
    pub dwarf: DwarfSummary,
    pub targets: ProbeTargets,
    pub checks: Vec<PreflightCheck>,
}

#[derive(Debug, Serialize)]
pub struct PreflightCheck {
    pub name: String,
    pub status: &'static str,
    pub detail: String,
}

pub fn run(cli: &Cli, dwarf: &DwarfInfo) -> Result<PreflightReport> {
    let targets = validated_targets(cli, dwarf)?;
    Ok(PreflightReport {
        ok: true,
        dwarf: dwarf.summary(),
        checks: checks(dwarf, &targets),
        targets,
    })
}

pub fn validated_targets(cli: &Cli, dwarf: &DwarfInfo) -> Result<ProbeTargets> {
    validate_cli(cli)?;
    let targets = targets::discover(cli)?;
    validate_target_paths(&targets)?;
    validate_dwarf_targets(dwarf, &targets)?;
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
    validate_file_path("librbd target", &targets.librbd)?;
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
            "DWARF JSON has no RADOS module matching discovered libraries with required {SEND_OP}/{FINISH_OP} data"
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
        bail!("DWARF JSON module {module} is missing function address for {function}");
    }
    let Some(fields) = dwarf.function_var_field_count(module, function) else {
        bail!("DWARF JSON module {module} is missing variable fields for {function}");
    };
    if fields < min_fields {
        bail!(
            "DWARF JSON module {module} has {fields} variable fields for {function}; need at least {min_fields}"
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
            librbd: "/tmp/librbd.so.1".into(),
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
            librbd: "/tmp/librbd.so.1".into(),
            libceph_common: "/tmp/libceph-common.so.2".into(),
            radosgw: "/tmp/radosgw".into(),
        };

        assert!(validate_dwarf_targets(&dwarf, &targets).is_err());
    }

    fn dwarf_json(rados_module: &str, rgw_module: &str) -> String {
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
            send_fields = var_fields(SEND_OP_FIELDS),
            finish_fields = var_fields(FINISH_OP_FIELDS),
            handler_fields = var_fields(GET_HANDLER_FIELDS),
        )
    }

    fn var_fields(count: usize) -> String {
        let field = r#"{"location":{"reg":4,"offset":0,"stack":false},"fields":[]}"#;
        format!("[{}]", vec![field; count].join(","))
    }
}
