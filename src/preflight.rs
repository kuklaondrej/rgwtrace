use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use object::Object;
use serde::Serialize;
use tracing::warn;

use crate::{
    cli::Cli,
    dwarf_json::{
        module_key_for_path, DwarfInfo, DwarfSummary, ModuleMatch, RadosOperateProbe,
        RequestEndProbe, REQ_STATE_DTOR, RGWREST_GET_HANDLER, RGW_PROCESS_AUTHENTICATED,
        RGW_RADOS_OPERATE, RGW_RADOS_OPERATE_OVERLOADS, RGW_RADOS_OPERATE_READ,
        RGW_RADOS_OPERATE_WRITE,
    },
    probe_sites::{self, ProbeSites},
    targets::{self, ProbeTargets},
};

const SEND_OP: &str = "Objecter::_send_op";
const FINISH_OP: &str = "Objecter::_finish_op";
const GET_HANDLER: &str = RGWREST_GET_HANDLER;

const SEND_OP_FIELDS: usize = 12;
const FINISH_OP_FIELDS: usize = 3;
const GET_HANDLER_FIELDS: usize = 2;

/// Every function rgwtrace may attach a uprobe to. Each address the artifact
/// carries for one of these, in a discovered target's module, is validated and
/// translated before anything attaches -- including optional probes, because an
/// address that is present but wrong would be probed, not skipped.
const PROBED_FUNCTIONS: &[&str] = &[
    SEND_OP,
    FINISH_OP,
    GET_HANDLER,
    RGW_PROCESS_AUTHENTICATED,
    REQ_STATE_DTOR,
    RGW_RADOS_OPERATE_READ,
    RGW_RADOS_OPERATE_WRITE,
];

#[derive(Debug, Serialize)]
pub struct PreflightReport {
    pub ok: bool,
    pub dwarf: DwarfSummary,
    pub targets: ProbeTargets,
    pub checks: Vec<PreflightCheck>,
    pub build_ids: Vec<BuildIdCheck>,
    pub probe_sites: ProbeSites,
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
    let probe_sites = validated_probe_sites(dwarf, &targets)?;
    let mut checks = checks(dwarf, &targets);
    checks.push(PreflightCheck {
        name: "probe_addresses".to_string(),
        status: "ok",
        detail: format!(
            "{} probe address(es) are function entries inside executable PT_LOAD segments; \
             uprobes attach at the file offsets listed in probe_sites",
            probe_sites.len()
        ),
    });
    Ok(PreflightReport {
        ok: true,
        dwarf: dwarf.summary(),
        checks,
        build_ids,
        targets,
        probe_sites,
    })
}

/// Validate every probe address the artifact supplies for a discovered target
/// and translate it to the file offset the uprobe API takes. Any address that is
/// not a function entry inside an executable PT_LOAD of that target is a hard
/// error naming the function, module and address (see `probe_sites`).
///
/// An ABSENT address is not validated -- it simply does not attach, and the
/// optional probes keep failing soft for it. A PRESENT address that fails is
/// fatal even for an optional probe: a breakpoint in the wrong place corrupts
/// the traced process, which no amount of degraded output is worth.
///
/// `--allow-build-id-mismatch` does not relax this: it vouches for the DWARF,
/// it cannot make an address land on an instruction boundary.
pub fn validated_probe_sites(dwarf: &DwarfInfo, targets: &ProbeTargets) -> Result<ProbeSites> {
    let mut sites = ProbeSites::default();
    for path in targets.all_paths() {
        let module = target_basename(path, "target")?;
        let Some(artifact) = dwarf.resolve_module(&module) else {
            continue;
        };
        let requests = PROBED_FUNCTIONS
            .iter()
            .filter_map(|function| {
                artifact
                    .func2pc
                    .get(*function)
                    .copied()
                    .filter(|addr| *addr != 0)
                    .map(|addr| (*function, addr))
            })
            .collect::<Vec<_>>();
        sites.extend(probe_sites::validate_target(path, &module, &requests)?);
    }
    Ok(sites)
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
    reject_ambiguous_modules(dwarf, targets)?;

    let rados_modules = rados_module_keys(targets)
        .into_iter()
        .filter(|module| module_supports_rados(dwarf, module))
        .collect::<Vec<_>>();
    if rados_modules.is_empty() {
        bail!(
            "DWARF data has no RADOS module matching discovered libraries with required {SEND_OP}/{FINISH_OP} data"
        );
    }

    warn_on_silent_rados_skip(dwarf, targets);

    let radosgw = target_basename(&targets.radosgw, "radosgw target")?;
    require_function(dwarf, &radosgw, GET_HANDLER, GET_HANDLER_FIELDS)?;
    Ok(())
}

/// Fail preflight when a discovered target's module key resolves ambiguously --
/// two or more artifact modules share its `lib<name>.so.<major>` soname stem
/// (e.g. both `librados.so.2.0.0` and `librados.so.2.1.0` present). The
/// soname-fallback deliberately refuses to guess in that case, so rather than
/// silently skipping the probe we surface an explicit, named error naming the
/// ambiguous keys and the offending target path.
fn reject_ambiguous_modules(dwarf: &DwarfInfo, targets: &ProbeTargets) -> Result<()> {
    for path in targets.all_paths() {
        let Some(key) = module_key_for_path(path) else {
            continue;
        };
        if let ModuleMatch::Ambiguous(candidates) = dwarf.match_module(&key) {
            bail!(
                "target {} (module key {key}) matches multiple DWARF modules sharing its soname \
                 stem: {}; refusing to pick one -- pass an explicit --*-path to the versioned \
                 real file or prune the duplicate module from the artifact",
                path.display(),
                candidates.join(", ")
            );
        }
    }
    Ok(())
}

/// Canonicalized artifact module keys for the discovered rados libraries, in the
/// same order as [`ProbeTargets::rados_libraries`]. Routing every rados-library
/// basename through [`module_key_for_path`] keeps this in agreement with attach
/// (`attach_if_present`) and the build-id check about each module's key.
fn rados_module_keys(targets: &ProbeTargets) -> Vec<String> {
    targets
        .rados_libraries()
        .into_iter()
        .filter_map(module_key_for_path)
        .collect()
}

/// Advisory warning for the exact silent-skip that hid the versioned-soname bug:
/// a discovered rados library whose module key resolves to NO artifact module,
/// even though the artifact carries a `Objecter::_send_op` `func2pc` in some
/// module. That combination means the librados uprobes would be skipped at
/// attach (request markers, but `rados_ops = 0`). It is advisory only -- if the
/// artifact genuinely lacks `_send_op` anywhere the required-module check above
/// already fails -- so this is a `warn!`, not a hard error.
fn warn_on_silent_rados_skip(dwarf: &DwarfInfo, targets: &ProbeTargets) {
    if !dwarf.any_module_has_func2pc(SEND_OP) {
        return;
    }
    for (path, module) in targets
        .rados_libraries()
        .into_iter()
        .zip(rados_module_keys(targets))
    {
        if !dwarf.has_module(&module) {
            warn!(
                module = %module,
                path = %path.display(),
                "discovered rados library resolves to no artifact module even though the \
                 artifact has a {SEND_OP} address; its uprobes will be silently skipped \
                 (check for a versioned/soname basename mismatch)"
            );
        }
    }
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
    let rados_modules = rados_module_keys(targets)
        .into_iter()
        .filter(|module| module_supports_rados(dwarf, module))
        .collect::<Vec<_>>();
    let radosgw = module_key_for_path(&targets.radosgw).unwrap_or_else(|| "<invalid>".to_string());

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
        request_end_probe_check(dwarf, &radosgw),
        reseed_probe_check(dwarf, &radosgw),
        rados_operate_probe_check(dwarf, &radosgw),
    ]
}

/// PHASE B, advisory (non-fatal): can the per-submit re-seed attach to BOTH
/// `rgw_rados_operate` overloads?
///
/// This is the check that says whether `--correlate-cross-thread` will actually
/// correlate anything beyond the seed threads. Without it, a RADOS op submitted
/// after the request's coroutine migrated off its seed thread -- which is most of
/// them -- has no request context on its thread and is reported as a background
/// op. So a `warn` here is the difference between "cross-thread correlation" and
/// "cross-thread correlation in name only", and it names which overload is
/// missing: losing the read overload loses GET/HEAD metadata reads, losing the
/// write overload loses the entire PUT/DELETE data path.
///
/// It stays advisory because an RGW build without these symbols must still trace:
/// it degrades to the pre-Phase-B behavior, exactly as it did before.
///
/// It ALSO reports the probe as unavailable when the request-END probe is not
/// available, even if both overloads resolve perfectly: the per-submit re-seed
/// looks every rados operate's `dpp` up in the bridge, and that is only safe while
/// bridge entries are REVOKED at request end -- which only the END probe does.
/// Without it, a recycled req_state/RGWOp address would hit a long-dead request's
/// entry and stamp its trans_id onto a live op. The live attach gate makes the
/// same call, so preflight can never advertise a probe the run will refuse.
fn rados_operate_probe_check(dwarf: &DwarfInfo, radosgw: &str) -> PreflightCheck {
    let mut gaps: Vec<String> = RGW_RADOS_OPERATE_OVERLOADS
        .iter()
        .filter_map(
            |function| match dwarf.rados_operate_probe(radosgw, function) {
                RadosOperateProbe::Available { .. } => None,
                RadosOperateProbe::Unavailable(gap) => Some(gap.reason()),
            },
        )
        .collect();

    if matches!(
        dwarf.request_end_probe(radosgw),
        RequestEndProbe::Unavailable(_)
    ) {
        gaps.push(format!(
            "the request-END probe ({REQ_STATE_DTOR}) is unavailable, and it is the ONLY thing that \
             revokes a request's bridge entries -- without it a recycled req_state/RGWOp address \
             could seed a DEAD request's trans_id onto a live RADOS op, so the per-submit re-seed \
             is refused rather than risk mis-correlation"
        ));
    }

    if gaps.is_empty() {
        PreflightCheck {
            name: "cross_thread_operate_probe".to_string(),
            status: "ok",
            detail: format!(
                "both {RGW_RADOS_OPERATE} overloads available in {radosgw}; \
                 --correlate-cross-thread can re-seed request context at every RADOS submit, so \
                 ops submitted after a coroutine migration still correlate"
            ),
        }
    } else {
        PreflightCheck {
            name: "cross_thread_operate_probe".to_string(),
            status: "warn",
            detail: format!(
                "{}; --correlate-cross-thread will not re-seed at those submits, so RADOS ops \
                 submitted after a coroutine migration stay uncorrelated (background/inferred)",
                gaps.join("; ")
            ),
        }
    }
}

/// Advisory (non-fatal) availability of the request-END probe
/// (`req_state::~req_state`). Present => request spans carry a MEASURED end
/// (`rgw.duration_quality = "measured"`). Absent => the tracer keeps working
/// exactly as it did before the probe existed, deriving each request's end from
/// its correlated RADOS child bounds (`rgw.duration_quality = "marker"`), so this
/// is a `warn`, never a hard failure.
///
/// All THREE halves must resolve, and the check reports exactly which one did
/// not: the destructor ADDRESS, the variant PROVENANCE proving that address is
/// the complete/base destructor (D1/D2) and not the deleting one (D0), and the
/// register-only raw-pointer descriptor for its `this` parameter. See
/// [`DwarfInfo::request_end_probe`] -- this check and the live attach gate ask
/// the same question of the same artifact, so preflight can never advertise a
/// probe the run will refuse to attach.
fn request_end_probe_check(dwarf: &DwarfInfo, radosgw: &str) -> PreflightCheck {
    match dwarf.request_end_probe(radosgw) {
        RequestEndProbe::Available { linkage, .. } => PreflightCheck {
            name: "request_end_probe".to_string(),
            status: "ok",
            detail: format!(
                "{REQ_STATE_DTOR} available in {radosgw} (linkage {linkage}); request spans will \
                 carry a measured end (rgw.duration_quality=\"measured\")"
            ),
        },
        RequestEndProbe::Unavailable(gap) => PreflightCheck {
            name: "request_end_probe".to_string(),
            status: "warn",
            detail: format!(
                "{}; request ends will be derived from RADOS child bounds \
                 (rgw.duration_quality=\"marker\")",
                gap.reason()
            ),
        },
    }
}

/// Advisory (non-fatal) availability of the Stage 3 cross-thread re-seed probe,
/// and of the ALTERNATE bridge key it registers.
///
/// A missing `rgw_process_authenticated` raw-pointer descriptor only degrades
/// `--correlate-cross-thread` to same-thread behavior, so it is reported as a
/// `warn` rather than failing preflight -- consistent with the build-id advisory
/// style.
///
/// A missing `RGWOp*&` descriptor is warned about SEPARATELY and just as loudly,
/// because it is the difference between correlating an op's data path and not:
/// RGW passes the executing RGWOp -- not the req_state -- as the `dpp` at most
/// call sites inside `op->execute()`, so without that key the per-submit re-seed
/// misses on exactly the ops the feature exists to recover, while every counter
/// still looks healthy.
fn reseed_probe_check(dwarf: &DwarfInfo, radosgw: &str) -> PreflightCheck {
    let present = dwarf
        .function_addr(radosgw, RGW_PROCESS_AUTHENTICATED)
        .is_some()
        && dwarf.function_has_raw_pointer_descriptor(radosgw, RGW_PROCESS_AUTHENTICATED);
    if !present {
        return PreflightCheck {
            name: "cross_thread_reseed_probe".to_string(),
            status: "warn",
            detail: format!(
                "{RGW_PROCESS_AUTHENTICATED} raw-pointer descriptor unavailable in {radosgw}; \
                 --correlate-cross-thread will fall back to same-thread correlation"
            ),
        };
    }
    if !dwarf.function_has_rgw_op_descriptor(radosgw) {
        return PreflightCheck {
            name: "cross_thread_reseed_probe".to_string(),
            status: "warn",
            detail: format!(
                "{RGW_PROCESS_AUTHENTICATED} available in {radosgw}, but its `RGWOp*&` descriptor \
                 is not (the parameter is not register-resident at entry, or RGWOp's \
                 DoutPrefixProvider base could not be proven to sit at offset 0). Requests will be \
                 keyed by their req_state* ONLY -- and RGW passes the executing RGWOp, not the \
                 req_state, as the dpp at most call sites in an op's data path, so those RADOS ops \
                 will stay uncorrelated. Re-export the DWARF artifact with a current rgwtrace"
            ),
        };
    }
    PreflightCheck {
        name: "cross_thread_reseed_probe".to_string(),
        status: "ok",
        detail: format!(
            "{RGW_PROCESS_AUTHENTICATED} available in {radosgw} with both bridge-key descriptors \
             (req_state* and RGWOp*&); --correlate-cross-thread can attach the re-seed bridge and \
             key each request by both dpp identities"
        ),
    }
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
    let module = target_basename(path, "target")?;
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

fn target_basename(path: &Path, label: &str) -> Result<String> {
    module_key_for_path(path)
        .with_context(|| format!("{label} {} has no file name", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dwarf_json::{RGW_RADOS_OPERATE_READ, RGW_RADOS_OPERATE_WRITE};

    /// Real ELF targets in a temp dir: a non-PIE `radosgw` (so a raw vaddr is
    /// visibly NOT the file offset) with FUNC symbols at `functions`, plus empty
    /// RADOS libraries the artifact carries no addresses for.
    fn elf_targets(name: &str, functions: &[(&'static str, u64)]) -> ProbeTargets {
        use crate::test_elf::{temp_dir, TestElf};
        let dir = temp_dir(name);
        let mut radosgw = TestElf::non_pie(0x1000, 0x1000);
        for (function, vaddr) in functions {
            radosgw = radosgw.function(function, *vaddr);
        }
        fs::write(dir.join("radosgw"), radosgw.build()).unwrap();
        for library in ["librados.so.2", "libceph-common.so.2"] {
            fs::write(dir.join(library), TestElf::pie(0x1000, 0x100).build()).unwrap();
        }
        ProbeTargets {
            librados: dir.join("librados.so.2"),
            librbd: None,
            libceph_common: dir.join("libceph-common.so.2"),
            radosgw: dir.join("radosgw"),
        }
    }

    fn radosgw_artifact(func2pc: &[(&str, u64)]) -> DwarfInfo {
        let module = crate::dwarf_json::DwarfModule {
            build_id: None,
            func2pc: func2pc
                .iter()
                .map(|(function, addr)| (function.to_string(), *addr))
                .collect(),
            func2vf: Default::default(),
            func2linkage: Default::default(),
        };
        DwarfInfo {
            version: Some("19.2.0".into()),
            arch: Some("amd64".into()),
            modules: [("radosgw".to_string(), module)].into(),
        }
    }

    const HANDLER_VADDR: u64 = 0x40_0000 + 0x1040;
    const DTOR_VADDR: u64 = 0x40_0000 + 0x1100;

    #[test]
    fn probe_sites_translate_artifact_vaddrs_to_target_file_offsets() {
        let targets = elf_targets(
            "preflight-translate",
            &[
                ("_ZN7RGWREST11get_handlerEv", HANDLER_VADDR),
                ("_ZN9req_stateD1Ev", DTOR_VADDR),
            ],
        );
        let dwarf = radosgw_artifact(&[(GET_HANDLER, HANDLER_VADDR), (REQ_STATE_DTOR, DTOR_VADDR)]);

        let sites = validated_probe_sites(&dwarf, &targets).unwrap();
        assert_eq!(sites.len(), 2);
        assert_eq!(
            sites
                .file_offset(&targets.radosgw, GET_HANDLER, HANDLER_VADDR)
                .unwrap(),
            0x1040
        );
        assert_eq!(
            sites
                .file_offset(&targets.radosgw, REQ_STATE_DTOR, DTOR_VADDR)
                .unwrap(),
            0x1100
        );
    }

    #[test]
    fn an_artifact_address_that_is_not_a_function_entry_fails_preflight() {
        // An imported (cephtrace-style) artifact is just names and numbers: its
        // address is checked against the target exactly like a native one.
        let targets = elf_targets(
            "preflight-mid-function",
            &[("_ZN7RGWREST11get_handlerEv", HANDLER_VADDR)],
        );
        let dwarf = radosgw_artifact(&[(GET_HANDLER, HANDLER_VADDR + 4)]);

        let msg = format!("{:#}", validated_probe_sites(&dwarf, &targets).unwrap_err());
        assert!(msg.contains(GET_HANDLER), "message: {msg}");
        assert!(msg.contains("not the entry"), "message: {msg}");
    }

    #[test]
    fn a_present_but_invalid_request_end_address_is_a_hard_error() {
        // The END probe is optional when ABSENT, but a wrong breakpoint is worse
        // than no probe: an address that is there and fails validation must stop
        // the run, not quietly degrade to derived durations.
        let targets = elf_targets(
            "preflight-bad-dtor",
            &[("_ZN7RGWREST11get_handlerEv", HANDLER_VADDR)],
        );
        let dwarf = radosgw_artifact(&[(GET_HANDLER, HANDLER_VADDR), (REQ_STATE_DTOR, DTOR_VADDR)]);

        let msg = format!("{:#}", validated_probe_sites(&dwarf, &targets).unwrap_err());
        assert!(msg.contains(REQ_STATE_DTOR), "message: {msg}");
    }

    #[test]
    fn an_absent_request_end_address_is_not_an_error() {
        let targets = elf_targets(
            "preflight-no-dtor",
            &[("_ZN7RGWREST11get_handlerEv", HANDLER_VADDR)],
        );
        let dwarf = radosgw_artifact(&[(GET_HANDLER, HANDLER_VADDR)]);

        let sites = validated_probe_sites(&dwarf, &targets).unwrap();
        assert_eq!(sites.len(), 1);
        assert!(sites
            .file_offset(&targets.radosgw, REQ_STATE_DTOR, DTOR_VADDR)
            .is_err());
    }

    #[test]
    fn functions_rgwtrace_never_attaches_are_not_validated() {
        let targets = elf_targets(
            "preflight-unprobed",
            &[("_ZN7RGWREST11get_handlerEv", HANDLER_VADDR)],
        );
        let dwarf = radosgw_artifact(&[(GET_HANDLER, HANDLER_VADDR), ("Some::other", 1)]);

        assert_eq!(validated_probe_sites(&dwarf, &targets).unwrap().len(), 1);
    }

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
    fn soname_target_matches_versioned_artifact_module() {
        // The production bug: artifact keys the RADOS module by the versioned
        // real name, but the discovered/explicit target is the soname symlink.
        // With soname-aware resolution the symlink basename must still validate.
        let dwarf = DwarfInfo::from_str(&dwarf_json("librados.so.2.0.0", "radosgw")).unwrap();
        let targets = ProbeTargets {
            librados: "/tmp/librados.so.2".into(),
            librbd: None,
            libceph_common: "/tmp/libceph-common.so.2".into(),
            radosgw: "/tmp/radosgw".into(),
        };

        validate_dwarf_targets(&dwarf, &targets).unwrap();
    }

    #[test]
    fn rejects_ambiguous_soname_module_match() {
        // Two patch-level librados modules share the `librados.so.2` stem. A
        // symlink-basename target (/tmp/librados.so.2 -> canonicalize fails ->
        // key `librados.so.2`) must NOT be resolved to an arbitrary one; preflight
        // fails with an explicit error naming both candidates.
        let json = format!(
            r#"{{
              "version": "18.2.8-1jammy",
              "arch": "amd64",
              "librados.so.2.0.0": {{
                "func2pc": {{"{SEND_OP}": 1, "{FINISH_OP}": 2}},
                "func2vf": {{
                  "{SEND_OP}": {{"var_fields": {send}}},
                  "{FINISH_OP}": {{"var_fields": {finish}}}
                }}
              }},
              "librados.so.2.1.0": {{
                "func2pc": {{"{SEND_OP}": 3, "{FINISH_OP}": 4}},
                "func2vf": {{
                  "{SEND_OP}": {{"var_fields": {send}}},
                  "{FINISH_OP}": {{"var_fields": {finish}}}
                }}
              }},
              "radosgw": {{
                "func2pc": {{"{GET_HANDLER}": 5}},
                "func2vf": {{"{GET_HANDLER}": {{"var_fields": {handler}}}}}
              }}
            }}"#,
            send = var_fields(SEND_OP_FIELDS),
            finish = var_fields(FINISH_OP_FIELDS),
            handler = var_fields(GET_HANDLER_FIELDS),
        );
        let dwarf = DwarfInfo::from_str(&json).unwrap();
        let targets = ProbeTargets {
            librados: "/tmp/librados.so.2".into(),
            librbd: None,
            libceph_common: "/tmp/libceph-common.so.2".into(),
            radosgw: "/tmp/radosgw".into(),
        };

        let err = validate_dwarf_targets(&dwarf, &targets).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("multiple DWARF modules"), "message: {msg}");
        assert!(msg.contains("librados.so.2.0.0"), "message: {msg}");
        assert!(msg.contains("librados.so.2.1.0"), "message: {msg}");
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
    fn request_end_probe_check_is_ok_when_the_dtor_resolves() {
        // All three halves present: the destructor address, the register-only
        // raw-pointer descriptor for its `this` parameter, and the mangled
        // linkage name PROVING the address is the complete-object destructor.
        let dwarf = DwarfInfo::from_str(&dwarf_json_with_request_end_probe(
            Some("_ZN9req_stateD1Ev"),
            RAW_POINTER_VAR_FIELD,
        ))
        .unwrap();

        let check = request_end_probe_check(&dwarf, "radosgw");

        assert_eq!(check.name, "request_end_probe");
        assert_eq!(check.status, "ok");
        assert!(check.detail.contains("measured"), "{}", check.detail);
        assert!(
            check.detail.contains("_ZN9req_stateD1Ev"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn request_end_probe_check_warns_but_never_fails_without_the_dtor() {
        // BACKWARD COMPATIBILITY: an RGW build whose destructor cannot be
        // resolved must still pass preflight. The missing end probe is advisory
        // only -- the run degrades to derived request durations.
        let dwarf = DwarfInfo::from_str(&dwarf_json("libceph-common.so.2", "radosgw")).unwrap();
        let targets = ProbeTargets {
            librados: "/tmp/librados.so.2".into(),
            librbd: None,
            libceph_common: "/tmp/libceph-common.so.2".into(),
            radosgw: "/tmp/radosgw".into(),
        };

        // Not a hard error...
        validate_dwarf_targets(&dwarf, &targets).unwrap();

        // ...but surfaced as a warning that names the fallback behavior.
        let check = request_end_probe_check(&dwarf, "radosgw");
        assert_eq!(check.status, "warn");
        assert!(check.detail.contains("marker"), "{}", check.detail);
    }

    #[test]
    fn request_end_probe_check_warns_when_only_the_address_resolves() {
        // A destructor address without a usable `this` descriptor cannot be
        // probed (the BPF handler reads the register-only descriptor), so it must
        // not be advertised as available.
        let json = format!(
            r#"{{
              "version": "18.2.8-1jammy",
              "arch": "amd64",
              "libceph-common.so.2": {{
                "func2pc": {{"{SEND_OP}": 1, "{FINISH_OP}": 2}},
                "func2vf": {{
                  "{SEND_OP}": {{"var_fields": {send}}},
                  "{FINISH_OP}": {{"var_fields": {finish}}}
                }}
              }},
              "radosgw": {{
                "func2pc": {{"{GET_HANDLER}": 3, "{REQ_STATE_DTOR}": 4}},
                "func2vf": {{"{GET_HANDLER}": {{"var_fields": {handler}}}}}
              }}
            }}"#,
            send = var_fields(SEND_OP_FIELDS),
            finish = var_fields(FINISH_OP_FIELDS),
            handler = var_fields(GET_HANDLER_FIELDS),
        );
        let dwarf = DwarfInfo::from_str(&json).unwrap();

        assert!(dwarf.function_addr("radosgw", REQ_STATE_DTOR).is_some());
        assert_eq!(request_end_probe_check(&dwarf, "radosgw").status, "warn");
    }

    #[test]
    fn request_end_probe_check_warns_when_the_variant_provenance_is_missing() {
        // An artifact exported before `func2linkage` existed (or by a
        // third-party producer): address + descriptor both resolve, but nothing
        // proves the address is the complete/base destructor rather than the
        // DELETING one. Preflight must warn, and the run must not attach.
        let dwarf = DwarfInfo::from_str(&dwarf_json_with_request_end_probe(
            None,
            RAW_POINTER_VAR_FIELD,
        ))
        .unwrap();

        let check = request_end_probe_check(&dwarf, "radosgw");

        assert_eq!(check.status, "warn");
        assert!(check.detail.contains("func2linkage"), "{}", check.detail);
        assert!(check.detail.contains("marker"), "{}", check.detail);
    }

    #[test]
    fn request_end_probe_check_warns_when_the_provenance_names_the_deleting_dtor() {
        // The hazard this gate exists for: a producer that resolved the FIRST
        // destructor with that demangled name hands us D0 (g++ emits it first).
        // The address and descriptor checks both pass, so only the linkage name
        // can catch it -- and it must, because probing D0 probes a function that
        // never runs for a stack-allocated req_state.
        let dwarf = DwarfInfo::from_str(&dwarf_json_with_request_end_probe(
            Some("_ZN9req_stateD0Ev"),
            RAW_POINTER_VAR_FIELD,
        ))
        .unwrap();

        let check = request_end_probe_check(&dwarf, "radosgw");

        assert_eq!(check.status, "warn");
        assert!(
            check.detail.contains("_ZN9req_stateD0Ev"),
            "{}",
            check.detail
        );
    }

    /// Artifact carrying the request-END probe: the destructor address, the
    /// raw-pointer `this` descriptor (register-located, single sentinel field),
    /// and -- when `linkage` is `Some` -- the `func2linkage` variant provenance
    /// for the address.
    fn dwarf_json_with_request_end_probe(linkage: Option<&str>, descriptor: &str) -> String {
        let func2linkage = match linkage {
            Some(linkage) => format!(r#", "func2linkage": {{"{REQ_STATE_DTOR}": "{linkage}"}}"#),
            None => String::new(),
        };
        format!(
            r#"{{
              "version": "18.2.8-1jammy",
              "arch": "amd64",
              "libceph-common.so.2": {{
                "func2pc": {{"{SEND_OP}": 1, "{FINISH_OP}": 2}},
                "func2vf": {{
                  "{SEND_OP}": {{"var_fields": {send}}},
                  "{FINISH_OP}": {{"var_fields": {finish}}}
                }}
              }},
              "radosgw": {{
                "func2pc": {{"{GET_HANDLER}": 3, "{REQ_STATE_DTOR}": 4}},
                "func2vf": {{
                  "{GET_HANDLER}": {{"var_fields": {handler}}},
                  "{REQ_STATE_DTOR}": {{"var_fields": [{descriptor}]}}
                }}{func2linkage}
              }}
            }}"#,
            send = var_fields(SEND_OP_FIELDS),
            finish = var_fields(FINISH_OP_FIELDS),
            handler = var_fields(GET_HANDLER_FIELDS),
        )
    }

    /// The exact raw-pointer descriptor shape native extraction emits for a
    /// pointer parameter: register-located, one `{offset: 0, pointer: false}`.
    const RAW_POINTER_VAR_FIELD: &str = r#"{"location":{"reg":5,"offset":0,"stack":false},"fields":[{"offset":0,"pointer":false}]}"#;

    /// The reference-to-pointer descriptor: register-located, one
    /// `{offset: 0, pointer: true}` -- the `RGWOp*& op` alternate bridge key.
    const POINTER_REF_VAR_FIELD: &str =
        r#"{"location":{"reg":4,"offset":0,"stack":false},"fields":[{"offset":0,"pointer":true}]}"#;

    /// The mangled names of the two `rgw_rados_operate` overloads, as g++ emits
    /// them. Used to give an artifact real, verifiable overload provenance.
    const OPERATE_READ_LINKAGE: &str = "_Z17rgw_rados_operatePK18DoutPrefixProviderRN8librados7v14_2_05IoCtxERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPNS3_19ObjectReadOperationEPN4ceph6buffer7v15_2_04listE14optional_yieldi";
    const OPERATE_WRITE_LINKAGE: &str = "_Z17rgw_rados_operatePK18DoutPrefixProviderRN8librados7v14_2_05IoCtxERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPNS3_20ObjectWriteOperationE14optional_yieldi";

    /// A radosgw artifact carrying the full cross-thread feature set: the END probe
    /// (address + D1 provenance + `this` descriptor), both `rgw_rados_operate`
    /// overloads (addresses + overload provenance + `dpp` descriptors), and
    /// `rgw_process_authenticated` with BOTH bridge-key descriptors. Knobs let each
    /// half be removed so a check can be tested in isolation.
    fn dwarf_json_with_cross_thread(end_probe: bool, rgw_op_descriptor: bool) -> String {
        let (dtor_pc, dtor_vf, dtor_linkage) = if end_probe {
            (
                format!(r#", "{REQ_STATE_DTOR}": 4"#),
                format!(r#", "{REQ_STATE_DTOR}": {{"var_fields": [{RAW_POINTER_VAR_FIELD}]}}"#),
                format!(r#""{REQ_STATE_DTOR}": "_ZN9req_stateD1Ev", "#),
            )
        } else {
            (String::new(), String::new(), String::new())
        };
        let authenticated_vf = if rgw_op_descriptor {
            format!("[{RAW_POINTER_VAR_FIELD},{POINTER_REF_VAR_FIELD}]")
        } else {
            format!("[{RAW_POINTER_VAR_FIELD}]")
        };
        format!(
            r#"{{
              "version": "18.2.8-1jammy",
              "arch": "amd64",
              "libceph-common.so.2": {{
                "func2pc": {{"{SEND_OP}": 1, "{FINISH_OP}": 2}},
                "func2vf": {{
                  "{SEND_OP}": {{"var_fields": {send}}},
                  "{FINISH_OP}": {{"var_fields": {finish}}}
                }}
              }},
              "radosgw": {{
                "func2pc": {{
                  "{GET_HANDLER}": 3{dtor_pc},
                  "{RGW_PROCESS_AUTHENTICATED}": 5,
                  "{read}": 6,
                  "{write}": 7
                }},
                "func2vf": {{
                  "{GET_HANDLER}": {{"var_fields": {handler}}},
                  "{RGW_PROCESS_AUTHENTICATED}": {{"var_fields": {authenticated_vf}}},
                  "{read}": {{"var_fields": [{RAW_POINTER_VAR_FIELD}]}},
                  "{write}": {{"var_fields": [{RAW_POINTER_VAR_FIELD}]}}{dtor_vf}
                }},
                "func2linkage": {{
                  {dtor_linkage}"{read}": "{OPERATE_READ_LINKAGE}",
                  "{write}": "{OPERATE_WRITE_LINKAGE}"
                }}
              }}
            }}"#,
            send = var_fields(SEND_OP_FIELDS),
            finish = var_fields(FINISH_OP_FIELDS),
            handler = var_fields(GET_HANDLER_FIELDS),
            read = RGW_RADOS_OPERATE_READ,
            write = RGW_RADOS_OPERATE_WRITE,
        )
    }

    #[test]
    fn operate_probe_check_is_ok_when_both_overloads_and_the_end_probe_resolve() {
        let dwarf = DwarfInfo::from_str(&dwarf_json_with_cross_thread(true, true)).unwrap();

        let check = rados_operate_probe_check(&dwarf, "radosgw");

        assert_eq!(check.status, "ok", "{}", check.detail);
        assert_eq!(check.name, "cross_thread_operate_probe");
    }

    #[test]
    fn operate_probe_check_warns_without_the_end_probe_even_when_both_overloads_resolve() {
        // FINDING 3, preflight half. The per-submit re-seed looks EVERY rados
        // operate's dpp up in the bridge, and only the END probe revokes bridge
        // entries. Without it, entries live forever and a recycled req_state/RGWOp
        // address (or a numerically-matching foreign dpp) hits a DEAD request's
        // entry and stamps its trans_id. The live attach gate refuses to attach in
        // that state, so preflight must not advertise the probe as available.
        let dwarf = DwarfInfo::from_str(&dwarf_json_with_cross_thread(false, true)).unwrap();

        let check = rados_operate_probe_check(&dwarf, "radosgw");

        assert_eq!(
            check.status, "warn",
            "the operate probe must not be advertised without a revoking END probe: {}",
            check.detail
        );
        assert!(
            check.detail.contains("revokes a request's bridge entries"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn reseed_probe_check_warns_when_the_rgw_op_bridge_key_is_missing() {
        // Without the `RGWOp*&` descriptor a request is keyed by its req_state*
        // alone -- and RGW passes the executing RGWOp, not the req_state, as the dpp
        // at most call sites in an op's data path. The re-seed then misses on
        // exactly the ops it exists to recover, while every counter looks healthy.
        // That must be visible BEFORE a live run, not inferred from an empty trace.
        let with_key = DwarfInfo::from_str(&dwarf_json_with_cross_thread(true, true)).unwrap();
        assert_eq!(reseed_probe_check(&with_key, "radosgw").status, "ok");

        let without_key = DwarfInfo::from_str(&dwarf_json_with_cross_thread(true, false)).unwrap();
        let check = reseed_probe_check(&without_key, "radosgw");

        assert_eq!(check.status, "warn", "{}", check.detail);
        assert!(check.detail.contains("RGWOp*&"), "{}", check.detail);
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
