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
const OP_SUBMIT: &str = "Objecter::op_submit";
const PROCESS_REQUEST: &str = "process_request";
const GET_HANDLER: &str = "RGWREST::get_handler";
const RGW_OP_INIT: &str = "RGWOp::init";
const RGW_RADOS_OPERATE: &str = "rgw_rados_operate";
const RADOS_WRITER_PROCESS: &str = "RadosWriter::process";
const RADOS_WRITER_WRITE_EXCLUSIVE: &str = "RadosWriter::write_exclusive";
const ATOMIC_OBJECT_PROCESSOR_PREPARE: &str = "AtomicObjectProcessor::prepare";
const MULTIPART_OBJECT_PROCESSOR_PREPARE: &str = "MultipartObjectProcessor::prepare";
const APPEND_OBJECT_PROCESSOR_PREPARE: &str = "AppendObjectProcessor::prepare";
const ATOMIC_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK: &str =
    "AtomicObjectProcessor::process_first_chunk";
const MULTIPART_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK: &str =
    "MultipartObjectProcessor::process_first_chunk";
const APPEND_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK: &str =
    "AppendObjectProcessor::process_first_chunk";
const HEAD_OBJECT_PROCESSOR_PROCESS: &str = "HeadObjectProcessor::process";
const ATOMIC_OBJECT_PROCESSOR_COMPLETE: &str = "AtomicObjectProcessor::complete";
const MULTIPART_OBJECT_PROCESSOR_COMPLETE: &str = "MultipartObjectProcessor::complete";
const APPEND_OBJECT_PROCESSOR_COMPLETE: &str = "AppendObjectProcessor::complete";
const RGW_WRITE_META: &str = "RGWRados::Object::Write::write_meta";
const RGW_DO_WRITE_META: &str = "RGWRados::Object::Write::_do_write_meta";

const SEND_OP_FIELDS: usize = 12;
const FINISH_OP_FIELDS: usize = 3;
const OP_SUBMIT_FIELDS: usize = 1;
const PROCESS_REQUEST_FIELDS: usize = 1;
const GET_HANDLER_FIELDS: usize = 5;
const RGW_OP_INIT_FIELDS: usize = 2;
const RGW_RADOS_OPERATE_FIELDS: usize = 1;
const RADOS_WRITER_PROCESS_FIELDS: usize = 2;
const RADOS_WRITER_WRITE_EXCLUSIVE_FIELDS: usize = 2;
const PUT_PROCESSOR_PREPARE_FIELDS: usize = 1;
const PUT_PROCESSOR_PROCESS_FIRST_CHUNK_FIELDS: usize = 3;
const HEAD_OBJECT_PROCESSOR_PROCESS_FIELDS: usize = 1;
const PUT_PROCESSOR_COMPLETE_FIELDS: usize = 2;
const RGW_WRITE_META_FIELDS: usize = 1;

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
    require_function(dwarf, radosgw, PROCESS_REQUEST, PROCESS_REQUEST_FIELDS)?;
    require_function(dwarf, radosgw, GET_HANDLER, GET_HANDLER_FIELDS)?;
    require_function(dwarf, radosgw, RGW_OP_INIT, RGW_OP_INIT_FIELDS)?;
    require_function(dwarf, radosgw, RGW_RADOS_OPERATE, RGW_RADOS_OPERATE_FIELDS)?;
    require_function(
        dwarf,
        radosgw,
        RADOS_WRITER_PROCESS,
        RADOS_WRITER_PROCESS_FIELDS,
    )?;
    require_function(
        dwarf,
        radosgw,
        RADOS_WRITER_WRITE_EXCLUSIVE,
        RADOS_WRITER_WRITE_EXCLUSIVE_FIELDS,
    )?;
    require_function(
        dwarf,
        radosgw,
        ATOMIC_OBJECT_PROCESSOR_PREPARE,
        PUT_PROCESSOR_PREPARE_FIELDS,
    )?;
    require_function(
        dwarf,
        radosgw,
        MULTIPART_OBJECT_PROCESSOR_PREPARE,
        PUT_PROCESSOR_PREPARE_FIELDS,
    )?;
    require_function(
        dwarf,
        radosgw,
        APPEND_OBJECT_PROCESSOR_PREPARE,
        PUT_PROCESSOR_PREPARE_FIELDS,
    )?;
    require_function(
        dwarf,
        radosgw,
        ATOMIC_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK,
        PUT_PROCESSOR_PROCESS_FIRST_CHUNK_FIELDS,
    )?;
    require_function(
        dwarf,
        radosgw,
        MULTIPART_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK,
        PUT_PROCESSOR_PROCESS_FIRST_CHUNK_FIELDS,
    )?;
    require_function(
        dwarf,
        radosgw,
        APPEND_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK,
        PUT_PROCESSOR_PROCESS_FIRST_CHUNK_FIELDS,
    )?;
    require_function(
        dwarf,
        radosgw,
        HEAD_OBJECT_PROCESSOR_PROCESS,
        HEAD_OBJECT_PROCESSOR_PROCESS_FIELDS,
    )?;
    require_function(
        dwarf,
        radosgw,
        ATOMIC_OBJECT_PROCESSOR_COMPLETE,
        PUT_PROCESSOR_COMPLETE_FIELDS,
    )?;
    require_function(
        dwarf,
        radosgw,
        MULTIPART_OBJECT_PROCESSOR_COMPLETE,
        PUT_PROCESSOR_COMPLETE_FIELDS,
    )?;
    require_function(
        dwarf,
        radosgw,
        APPEND_OBJECT_PROCESSOR_COMPLETE,
        PUT_PROCESSOR_COMPLETE_FIELDS,
    )?;
    require_function(dwarf, radosgw, RGW_WRITE_META, RGW_WRITE_META_FIELDS)?;
    require_function(dwarf, radosgw, RGW_DO_WRITE_META, RGW_WRITE_META_FIELDS)?;
    Ok(())
}

fn module_supports_rados(dwarf: &DwarfInfo, module: &str) -> bool {
    require_function(dwarf, module, SEND_OP, SEND_OP_FIELDS).is_ok()
        && require_function(dwarf, module, FINISH_OP, FINISH_OP_FIELDS).is_ok()
        && require_function(dwarf, module, OP_SUBMIT, OP_SUBMIT_FIELDS).is_ok()
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
            detail: format!(
                "{PROCESS_REQUEST}, {GET_HANDLER}, {RGW_OP_INIT}, {RGW_RADOS_OPERATE}, {RADOS_WRITER_PROCESS}, {RADOS_WRITER_WRITE_EXCLUSIVE}, {ATOMIC_OBJECT_PROCESSOR_PREPARE}, {MULTIPART_OBJECT_PROCESSOR_PREPARE}, {APPEND_OBJECT_PROCESSOR_PREPARE}, {ATOMIC_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK}, {MULTIPART_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK}, {APPEND_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK}, and {HEAD_OBJECT_PROCESSOR_PROCESS} available in {radosgw}"
            ),
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
        let counts = ProbeFieldCounts {
            finish_op: FINISH_OP_FIELDS - 1,
            ..ProbeFieldCounts::default()
        };
        let dwarf = DwarfInfo::from_str(&dwarf_json_with_field_counts(
            "libceph-common.so.2",
            "radosgw",
            counts,
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
        dwarf_json_with_field_counts(rados_module, rgw_module, ProbeFieldCounts::default())
    }

    struct ProbeFieldCounts {
        send_op: usize,
        finish_op: usize,
        op_submit: usize,
        process_request: usize,
        get_handler: usize,
        rgw_op_init: usize,
        rgw_rados_operate: usize,
        rados_writer_process: usize,
        rados_writer_write_exclusive: usize,
        atomic_object_processor_prepare: usize,
        multipart_object_processor_prepare: usize,
        append_object_processor_prepare: usize,
        atomic_object_processor_process_first_chunk: usize,
        multipart_object_processor_process_first_chunk: usize,
        append_object_processor_process_first_chunk: usize,
        head_object_processor_process: usize,
        atomic_object_processor_complete: usize,
        multipart_object_processor_complete: usize,
        append_object_processor_complete: usize,
        rgw_write_meta: usize,
        rgw_do_write_meta: usize,
    }

    impl Default for ProbeFieldCounts {
        fn default() -> Self {
            Self {
                send_op: SEND_OP_FIELDS,
                finish_op: FINISH_OP_FIELDS,
                op_submit: OP_SUBMIT_FIELDS,
                process_request: PROCESS_REQUEST_FIELDS,
                get_handler: GET_HANDLER_FIELDS,
                rgw_op_init: RGW_OP_INIT_FIELDS,
                rgw_rados_operate: RGW_RADOS_OPERATE_FIELDS,
                rados_writer_process: RADOS_WRITER_PROCESS_FIELDS,
                rados_writer_write_exclusive: RADOS_WRITER_WRITE_EXCLUSIVE_FIELDS,
                atomic_object_processor_prepare: PUT_PROCESSOR_PREPARE_FIELDS,
                multipart_object_processor_prepare: PUT_PROCESSOR_PREPARE_FIELDS,
                append_object_processor_prepare: PUT_PROCESSOR_PREPARE_FIELDS,
                atomic_object_processor_process_first_chunk:
                    PUT_PROCESSOR_PROCESS_FIRST_CHUNK_FIELDS,
                multipart_object_processor_process_first_chunk:
                    PUT_PROCESSOR_PROCESS_FIRST_CHUNK_FIELDS,
                append_object_processor_process_first_chunk:
                    PUT_PROCESSOR_PROCESS_FIRST_CHUNK_FIELDS,
                head_object_processor_process: HEAD_OBJECT_PROCESSOR_PROCESS_FIELDS,
                atomic_object_processor_complete: PUT_PROCESSOR_COMPLETE_FIELDS,
                multipart_object_processor_complete: PUT_PROCESSOR_COMPLETE_FIELDS,
                append_object_processor_complete: PUT_PROCESSOR_COMPLETE_FIELDS,
                rgw_write_meta: RGW_WRITE_META_FIELDS,
                rgw_do_write_meta: RGW_WRITE_META_FIELDS,
            }
        }
    }

    fn dwarf_json_with_field_counts(
        rados_module: &str,
        rgw_module: &str,
        counts: ProbeFieldCounts,
    ) -> String {
        format!(
            r#"{{
              "version": "18.2.8-1jammy",
              "arch": "amd64",
              "{rados_module}": {{
                "func2pc": {{"{SEND_OP}": 1, "{FINISH_OP}": 2, "{OP_SUBMIT}": 3}},
                "func2vf": {{
                  "{SEND_OP}": {{"var_fields": {send_fields}}},
                  "{FINISH_OP}": {{"var_fields": {finish_fields}}},
                  "{OP_SUBMIT}": {{"var_fields": {op_submit_fields}}}
                }}
              }},
              "{rgw_module}": {{
                "func2pc": {{
                  "{PROCESS_REQUEST}": 4,
                  "{GET_HANDLER}": 5,
                  "{RGW_OP_INIT}": 6,
                  "{RGW_RADOS_OPERATE}": 7,
                  "{RADOS_WRITER_PROCESS}": 8,
                  "{RADOS_WRITER_WRITE_EXCLUSIVE}": 9,
                  "{ATOMIC_OBJECT_PROCESSOR_PREPARE}": 10,
                  "{MULTIPART_OBJECT_PROCESSOR_PREPARE}": 11,
                  "{APPEND_OBJECT_PROCESSOR_PREPARE}": 12,
                  "{ATOMIC_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK}": 13,
                  "{MULTIPART_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK}": 14,
                  "{APPEND_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK}": 15,
                  "{HEAD_OBJECT_PROCESSOR_PROCESS}": 16,
                  "{ATOMIC_OBJECT_PROCESSOR_COMPLETE}": 17,
                  "{MULTIPART_OBJECT_PROCESSOR_COMPLETE}": 18,
                  "{APPEND_OBJECT_PROCESSOR_COMPLETE}": 19,
                  "{RGW_WRITE_META}": 20,
                  "{RGW_DO_WRITE_META}": 21
                }},
                "func2vf": {{
                  "{PROCESS_REQUEST}": {{"var_fields": {process_request_fields}}},
                  "{GET_HANDLER}": {{"var_fields": {handler_fields}}},
                  "{RGW_OP_INIT}": {{"var_fields": {rgw_op_init_fields}}},
                  "{RGW_RADOS_OPERATE}": {{"var_fields": {rgw_rados_operate_fields}}},
                  "{RADOS_WRITER_PROCESS}": {{"var_fields": {rados_writer_process_fields}}},
                  "{RADOS_WRITER_WRITE_EXCLUSIVE}": {{"var_fields": {rados_writer_write_exclusive_fields}}},
                  "{ATOMIC_OBJECT_PROCESSOR_PREPARE}": {{"var_fields": {atomic_object_processor_prepare_fields}}},
                  "{MULTIPART_OBJECT_PROCESSOR_PREPARE}": {{"var_fields": {multipart_object_processor_prepare_fields}}},
                  "{APPEND_OBJECT_PROCESSOR_PREPARE}": {{"var_fields": {append_object_processor_prepare_fields}}},
                  "{ATOMIC_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK}": {{"var_fields": {atomic_object_processor_process_first_chunk_fields}}},
                  "{MULTIPART_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK}": {{"var_fields": {multipart_object_processor_process_first_chunk_fields}}},
                  "{APPEND_OBJECT_PROCESSOR_PROCESS_FIRST_CHUNK}": {{"var_fields": {append_object_processor_process_first_chunk_fields}}},
                  "{HEAD_OBJECT_PROCESSOR_PROCESS}": {{"var_fields": {head_object_processor_process_fields}}},
                  "{ATOMIC_OBJECT_PROCESSOR_COMPLETE}": {{"var_fields": {atomic_object_processor_complete_fields}}},
                  "{MULTIPART_OBJECT_PROCESSOR_COMPLETE}": {{"var_fields": {multipart_object_processor_complete_fields}}},
                  "{APPEND_OBJECT_PROCESSOR_COMPLETE}": {{"var_fields": {append_object_processor_complete_fields}}},
                  "{RGW_WRITE_META}": {{"var_fields": {rgw_write_meta_fields}}},
                  "{RGW_DO_WRITE_META}": {{"var_fields": {rgw_do_write_meta_fields}}}
                }}
              }}
            }}"#,
            send_fields = var_fields(counts.send_op),
            finish_fields = var_fields(counts.finish_op),
            op_submit_fields = var_fields(counts.op_submit),
            process_request_fields = var_fields(counts.process_request),
            handler_fields = var_fields(counts.get_handler),
            rgw_op_init_fields = var_fields(counts.rgw_op_init),
            rgw_rados_operate_fields = var_fields(counts.rgw_rados_operate),
            rados_writer_process_fields = var_fields(counts.rados_writer_process),
            rados_writer_write_exclusive_fields = var_fields(counts.rados_writer_write_exclusive),
            atomic_object_processor_prepare_fields =
                var_fields(counts.atomic_object_processor_prepare),
            multipart_object_processor_prepare_fields =
                var_fields(counts.multipart_object_processor_prepare),
            append_object_processor_prepare_fields =
                var_fields(counts.append_object_processor_prepare),
            atomic_object_processor_process_first_chunk_fields =
                var_fields(counts.atomic_object_processor_process_first_chunk),
            multipart_object_processor_process_first_chunk_fields =
                var_fields(counts.multipart_object_processor_process_first_chunk),
            append_object_processor_process_first_chunk_fields =
                var_fields(counts.append_object_processor_process_first_chunk),
            head_object_processor_process_fields = var_fields(counts.head_object_processor_process),
            atomic_object_processor_complete_fields =
                var_fields(counts.atomic_object_processor_complete),
            multipart_object_processor_complete_fields =
                var_fields(counts.multipart_object_processor_complete),
            append_object_processor_complete_fields =
                var_fields(counts.append_object_processor_complete),
            rgw_write_meta_fields = var_fields(counts.rgw_write_meta),
            rgw_do_write_meta_fields = var_fields(counts.rgw_do_write_meta),
        )
    }

    fn var_fields(count: usize) -> String {
        let field = r#"{"location":{"reg":4,"offset":0,"stack":false},"fields":[]}"#;
        format!("[{}]", vec![field; count].join(","))
    }
}
