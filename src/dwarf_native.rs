use std::{
    borrow::Cow,
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use gimli::{
    AttributeValue, DebugInfoOffset, DebuggingInformationEntry, Dwarf, EndianSlice,
    EntriesTreeNode, Operation, Reader, ReaderOffset, RunTimeEndian, UnitOffset,
};
use object::{Architecture, CompressionFormat, Object, ObjectSection, ObjectSymbol, SymbolKind};
use tracing::{debug, warn};

#[cfg(test)]
use crate::dwarf_json::dtor_variant_rank;
use crate::dwarf_json::{
    basename, provenance_rank, DwarfInfo, DwarfModule, FieldJson, FunctionVarFields, VarFieldJson,
    VarLocationJson, REQ_STATE_DTOR, RGWREST_GET_HANDLER, RGW_PROCESS_AUTHENTICATED,
    RGW_RADOS_OPERATE, RGW_RADOS_OPERATE_OVERLOADS, RGW_RADOS_OPERATE_READ,
    RGW_RADOS_OPERATE_WRITE, VARIANT_PROVENANCE_FUNCTIONS,
};

const PROBE_FUNCTIONS: &[&str] = &[
    "Objecter::_send_op",
    "Objecter::_finish_op",
    RGWREST_GET_HANDLER,
    RGW_PROCESS_AUTHENTICATED,
    REQ_STATE_DTOR,
    RGW_RADOS_OPERATE_READ,
    RGW_RADOS_OPERATE_WRITE,
];
const OBJECTER_PROBE_FUNCTIONS: &[&str] = &["Objecter::_send_op", "Objecter::_finish_op"];
const RGW_PROBE_FUNCTIONS: &[&str] = &[
    RGWREST_GET_HANDLER,
    RGW_PROCESS_AUTHENTICATED,
    REQ_STATE_DTOR,
    RGW_RADOS_OPERATE_READ,
    RGW_RADOS_OPERATE_WRITE,
];
const PROBE_FUNCTION_LEAF_NAMES: &[&str] = &[
    "_send_op",
    "_finish_op",
    "get_handler",
    RGW_PROCESS_AUTHENTICATED,
    "~req_state",
    RGW_RADOS_OPERATE,
];

/// The probe KEYS a definition whose demangled name is `demangled` could be a
/// definition of, restricted to the `wanted` set.
///
/// For every function but one the demangled name IS the key, so this is just an
/// equality filter and the previous `wanted.contains(&fullname)` behavior is
/// preserved exactly. The exception is `rgw_rados_operate`: its two overloads are
/// distinct out-of-line functions at distinct addresses that collapse onto ONE
/// demangled name (the argument list, the only thing that distinguishes them, is
/// stripped by `demangle_function_name`). Such a definition is therefore a
/// candidate for BOTH synthetic overload keys, and [`definition_ranking`] -- which
/// consults the MANGLED linkage name -- accepts it for exactly one of them and
/// rejects it for the other. That is what makes the binding deterministic instead
/// of "whichever overload the symbol table lists first".
fn probe_keys<'w>(demangled: &str, wanted: &[&'w str]) -> Vec<&'w str> {
    if demangled == RGW_RADOS_OPERATE {
        return wanted
            .iter()
            .copied()
            .filter(|key| RGW_RADOS_OPERATE_OVERLOADS.contains(key))
            .collect();
    }
    wanted
        .iter()
        .copied()
        // The SYNTHETIC overload keys are reachable ONLY through the branch above.
        // They are not C++ names and can never equal a demangled one (in practice
        // `demangle_function_name` truncates at `(`, so it cannot even produce a
        // string of this shape) -- but a definition must never be able to claim one
        // of them by name alone, bypassing the mangled-signature gate that is the
        // entire point of splitting the overloads.
        .filter(|key| !RGW_RADOS_OPERATE_OVERLOADS.contains(key))
        .filter(|key| *key == demangled)
        .collect()
}

/// The source identifier a definition of probe `key` must spell out in its
/// MANGLED name: the key's last `::` component without a destructor's `~`
/// (`req_state::~req_state` -> `req_state`, mangled `_ZN9req_stateD2Ev`), and the
/// real function name for the synthetic `rgw_rados_operate` overload keys.
///
/// Derived from the probe keys themselves so the prefilter cannot drift from
/// the probe table.
fn probe_leaf_identifier(key: &str) -> &str {
    let key = if RGW_RADOS_OPERATE_OVERLOADS.contains(&key) {
        RGW_RADOS_OPERATE
    } else {
        key
    };
    key.rsplit("::")
        .next()
        .unwrap_or(key)
        .trim_start_matches('~')
}

/// Cheap prefilter run before demangling `mangled`: can it name any of `wanted`?
///
/// Demangling every global text symbol and every subprogram linkage name was
/// the dominant cost of native extraction. An Itanium-mangled name spells each
/// source identifier of its own nested name out as `<length><identifier>` --
/// substitutions (`S_`, `S0_`) only abbreviate a prefix or type seen EARLIER in
/// the same name -- so a name whose demangled form ends in a probe's leaf must
/// contain that identifier verbatim. A substring miss therefore proves the name
/// can never match, and skipping it changes no result; a hit is just demangled
/// as before.
fn may_name_probe(mangled: &str, wanted: &[&str]) -> bool {
    wanted
        .iter()
        .any(|key| mangled.contains(probe_leaf_identifier(key)))
}

/// Whether `name` is a DEMANGLED name that could belong to a probe function.
/// Distinct from `PROBE_FUNCTIONS.contains(..)`, which since Phase B also holds
/// the two SYNTHETIC `rgw_rados_operate` overload keys -- names that never appear
/// in a binary and can never equal a demangled name.
fn is_probe_demangled_name(name: &str) -> bool {
    PROBE_FUNCTIONS.contains(&name) || name == RGW_RADOS_OPERATE
}
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
/// Cross-thread re-seed bridge (design Stage 3) AND the multi-key bridge's second
/// key.
///
/// * `s`  -- the `req_state* s` parameter's own pointer value with no member
///   access (the raw-pointer descriptor): the request's CANONICAL bridge key.
/// * `op` -- the `RGWOp*& op` parameter: the ALTERNATE bridge key. RGW threads a
///   `const DoutPrefixProvider*` down its data path, and inside an op's
///   `execute()` that pointer is usually the RGWOp (`this`), not the req_state,
///   so without this key the per-submit re-seed misses the whole op data path.
///
/// `op` is a REFERENCE to a pointer, so its descriptor is the reference-to-pointer
/// shape (one `{offset:0, pointer:true}` field): the register holds an `RGWOp**`
/// and the BPF handler reads the pointee exactly once. It is emitted ONLY when
/// DWARF PROVES both halves of that claim -- the parameter really is
/// `reference -> pointer -> RGWOp`, and `RGWOp` really does inherit
/// `DoutPrefixProvider` at offset 0 -- and it is OPTIONAL: a build where the proof
/// fails keeps the `s` descriptor and simply loses the alternate key (see
/// `optional_trailing_var_field`).
const RGW_PROCESS_AUTHENTICATED_FIELDS: &[&[&str]] = &[&["s"], &["op"]];
/// Request-END probe. `req_state::~req_state`'s only parameter is the implicit
/// `this` (a `req_state*`), described by the same single-element raw-pointer path:
/// the pointer's own value, register-only, no dereference. The register itself
/// comes from DWARF -- nothing here assumes the x86-64 `rdi`/DWARF-reg-5 ABI.
///
/// The name here is documentation only (as for `rgw_rados_operate` below): `this`
/// is resolved POSITIONALLY, as formal parameter 0 (see
/// [`FIRST_PARAM_PROBE_FUNCTIONS`]) -- it is `DW_AT_artificial` and its concrete
/// DIE has no `DW_AT_name` to look up.
const REQ_STATE_DTOR_FIELDS: &[&[&str]] = &[&["this"]];
/// PHASE B. Both `rgw_rados_operate` overloads take the request's
/// `const DoutPrefixProvider *dpp` as their FIRST parameter, and that pointer --
/// used purely as an opaque identity token, never dereferenced -- is all the BPF
/// handler needs. Same single-element raw-pointer path shape as the two above.
///
/// The name here is documentation only: these two functions resolve the parameter
/// POSITIONALLY (see [`FIRST_PARAM_PROBE_FUNCTIONS`]), so an upstream rename of
/// `dpp` cannot silently disable the feature.
const RGW_RADOS_OPERATE_FIELDS: &[&[&str]] = &[&["dpp"]];

/// The C++ types the cross-thread bridge's KEY IDENTITY depends on.
///
/// The whole design rests on one claim: the `const DoutPrefixProvider* dpp` RGW
/// passes to `rgw_rados_operate` for a request is NUMERICALLY EQUAL to a pointer
/// we captured elsewhere (its `req_state*`, or the `RGWOp*` executing it). That is
/// only true if the `DoutPrefixProvider` base subobject sits at offset 0 of both
/// types. On every Ceph build seen so far it does (both use single inheritance
/// with `DoutPrefixProvider` as the first and only base) -- but "seen so far" is
/// not a proof, and a nonzero base offset would silently key the bridge on a
/// pointer that is not the dpp. So it is VERIFIED in DWARF, per build, and the
/// features that depend on it are disabled (loudly) when the verification fails.
const REQ_STATE_TYPE: &str = "req_state";
const RGW_OP_TYPE: &str = "RGWOp";
const DOUT_PREFIX_PROVIDER_TYPE: &str = "DoutPrefixProvider";

/// The `DoutPrefixProvider` base offsets proven from this module's DWARF, gathered
/// while the probe parameters are resolved (each is reached through a parameter we
/// already have to walk, so no extra scan of the type tree is needed).
///
/// `None` means "not proven", which is treated exactly like "proven nonzero":
/// fail closed.
#[derive(Clone, Copy, Debug, Default)]
struct DppFacts {
    /// From `req_state* s` (get_handler / rgw_process_authenticated) or the
    /// destructor's `this`. Gates the per-submit re-seed probes entirely: without
    /// it, a `dpp` cannot be assumed to be a `req_state*`.
    req_state_base: Option<i64>,
    /// From the `RGWOp*& op` parameter of rgw_process_authenticated. Gates only
    /// the ALTERNATE bridge key.
    rgw_op_base: Option<i64>,
}

impl DppFacts {
    /// Is a request's `dpp` provably its `req_state*`?
    fn req_state_dpp_identity_holds(&self) -> bool {
        self.req_state_base == Some(0)
    }
}

/// Probe functions whose single raw-pointer parameter is resolved POSITIONALLY --
/// the subprogram's FIRST `DW_TAG_formal_parameter` -- rather than by name.
///
/// * The `rgw_rados_operate` overloads, because their mangled signature has
///   ALREADY been checked (`rados_operate_overload` requires arg0 to be
///   `const DoutPrefixProvider*` before the definition is accepted at all). Given
///   that proof, position 0 IS the dpp, so we do not additionally have to trust
///   that upstream keeps spelling the parameter `dpp` -- nor risk a name lookup
///   matching a same-named local `DW_TAG_variable` inside an optimized body.
/// * `req_state::~req_state`, whose only parameter is the IMPLICIT OBJECT
///   POINTER. A member function's parameter 0 is its `this` by language rule, and
///   the definition has already been proven to be `req_state`'s destructor by its
///   mangled linkage name (D1/D2), so position 0 IS the `req_state*` -- no weaker
///   an argument than the one above. Position also happens to be the only thing
///   that is reliably THERE: `this` is `DW_AT_artificial`, the concrete instance's
///   parameter DIE carries no `DW_AT_name` of its own, and on an LTO build its
///   name sits two `DW_AT_abstract_origin` hops away behind GCC's cdtor clones.
///
/// `RGWREST::get_handler` and `Objecter::*` keep name-based lookup: they want a
/// LATER parameter (`get_handler`'s `req_state*` is its third), so position 0
/// means nothing there.
const FIRST_PARAM_PROBE_FUNCTIONS: &[&str] = &[
    RGW_RADOS_OPERATE_READ,
    RGW_RADOS_OPERATE_WRITE,
    REQ_STATE_DTOR,
];

/// Default for `--max-debug-file-bytes`: 4 GiB. See [`NativeOptions`].
pub const DEFAULT_MAX_DEBUG_FILE_BYTES: u64 = 4 << 30;

/// Inputs to native DWARF extraction beyond the target paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeOptions {
    /// Explicit Ceph version (`--ceph-version`); wins over every probe of the
    /// target.
    pub ceph_version: Option<String>,
    /// Upper bound, in bytes, on (a) the on-disk size of every file read whole --
    /// a target, its separate debug file, its DWZ supplementary file -- and (b)
    /// the total bytes DECOMPRESSED out of one such file's compressed DWARF
    /// sections. Together they bound extraction's peak memory at a small multiple
    /// of this value per module, whatever a sparse file or a compressed-section
    /// bomb declares.
    pub max_debug_file_bytes: u64,
}

impl Default for NativeOptions {
    fn default() -> Self {
        Self {
            ceph_version: None,
            max_debug_file_bytes: DEFAULT_MAX_DEBUG_FILE_BYTES,
        }
    }
}

#[allow(dead_code)]
pub fn from_paths(paths: &[impl AsRef<Path>]) -> Result<DwarfInfo> {
    from_paths_with_options(paths, &NativeOptions::default())
}

pub fn from_paths_with_options(
    paths: &[impl AsRef<Path>],
    options: &NativeOptions,
) -> Result<DwarfInfo> {
    let mut modules = BTreeMap::new();
    let mut arch = None;
    let mut embedded_version = None;

    for path in paths {
        let path = path.as_ref();
        let module_name = basename(path)
            .with_context(|| format!("native DWARF target {} has no file name", path.display()))?
            .to_string();
        let parsed = parse_module(path, &module_name, &mut arch, options)
            .with_context(|| format!("failed to parse native DWARF from {}", path.display()))?;
        // First target (in path order) that embeds a version string wins -- the
        // order the old per-path re-read scanned them in.
        if embedded_version.is_none() {
            embedded_version = parsed.embedded_version;
        }
        modules.insert(module_name, parsed.module);
    }

    let version = options
        .ceph_version
        .as_deref()
        .and_then(clean_version)
        .or(embedded_version);
    let version = match version {
        Some(version) => Some(version),
        None => resolve_ceph_version(paths)?,
    };

    Ok(DwarfInfo {
        version,
        arch,
        modules,
    })
}

/// Version sources beyond the targets' own bytes (which [`parse_module`]
/// already scanned).
///
/// The HOST package database is consulted only when every target lives under
/// the host's own root. A target reached through `/proc/<pid>/root` of a
/// container belongs to whatever Ceph the container image ships; the host's
/// `radosgw` package (if any) says nothing about it, and the version selects the
/// `ceph_osd_op` ABI layout the BPF side reads -- a wrong guess there is wrong
/// reads, not a missing feature. So that case is an error asking for the
/// version, never a guess.
fn resolve_ceph_version(paths: &[impl AsRef<Path>]) -> Result<Option<String>> {
    if let Some(version) = microceph_ceph_version(paths) {
        return Ok(Some(version));
    }
    let foreign: Vec<String> = paths
        .iter()
        .map(AsRef::as_ref)
        .filter(|path| !shares_host_root(path))
        .map(|path| path.display().to_string())
        .collect();
    if !foreign.is_empty() {
        bail!(
            "no embedded \"ceph version\" string found in the targets, and the host package \
             database cannot describe {} (another mount namespace's root); pass \
             --ceph-version with the version the target process runs",
            foreign.join(", ")
        );
    }
    Ok(package_manager_ceph_version())
}

/// `/proc/<pid>/root` when `path` is reached through a numeric pid's root link.
fn proc_pid_root(path: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut components = path.components();
    let (
        Some(Component::RootDir),
        Some(Component::Normal(proc)),
        Some(Component::Normal(pid)),
        Some(Component::Normal(root)),
    ) = (
        components.next(),
        components.next(),
        components.next(),
        components.next(),
    )
    else {
        return None;
    };
    let pid = pid.to_str()?;
    (proc == "proc" && root == "root" && !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
        .then(|| Path::new("/proc").join(pid).join("root"))
}

/// Whether host-side metadata (the package database) describes `path`: true
/// unless `path` is under a `/proc/<pid>/root` that is NOT the host's own `/`.
/// A process that merely runs on the host (not in a container) shares the host
/// root -- same device and inode -- and keeps the package lookup.
fn shares_host_root(path: &Path) -> bool {
    let Some(root) = proc_pid_root(path) else {
        return true;
    };
    same_file(&root, Path::new("/"))
}

fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        // Cannot prove it is the host root: treat it as foreign.
        _ => false,
    }
}

/// Offset of the first `needle` in `haystack`. Jumps between occurrences of the
/// needle's first byte (a tight single-byte scan) instead of comparing a whole
/// window at every offset; no extra dependency.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let (&first, rest) = needle.split_first()?;
    let last_start = haystack.len().checked_sub(needle.len())?;
    let mut from = 0;
    while from <= last_start {
        let candidate = from
            + haystack[from..=last_start]
                .iter()
                .position(|&byte| byte == first)?;
        if haystack[candidate + 1..candidate + needle.len()] == *rest {
            return Some(candidate);
        }
        from = candidate + 1;
    }
    None
}

fn ceph_version_from_bytes(bytes: &[u8]) -> Option<String> {
    let needle = b"ceph version ";
    let start = find_bytes(bytes, needle)? + needle.len();
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
        if let Some(version) = command_output_version(
            crate::host_tools::DPKG_QUERY,
            &["-W", "-f=${Version}", package],
        ) {
            return Some(version);
        }
    }
    for package in ["ceph-radosgw", "librados2", "ceph-common"] {
        if let Some(version) = command_output_version(
            crate::host_tools::RPM,
            &["-q", "--qf", "%{VERSION}-%{RELEASE}", package],
        ) {
            return Some(version);
        }
    }
    None
}

fn command_output_version(candidates: &[&str], args: &[&str]) -> Option<String> {
    let output = crate::host_tools::system_command(candidates)?
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
        .and_then(|stdout| first_version_token(&stdout))
}

/// Read all of `path`, refusing a file larger than `limit` bytes. `what` names
/// the file's role in the error ("target", "debuglink file", ...).
///
/// The size is checked BEFORE reading (a sparse multi-GB file costs nothing to
/// stat), and the read itself is capped too, so a file that grows between the
/// two -- or one whose `stat` size understates it -- cannot exceed the limit.
pub(crate) fn read_file_bounded(path: &Path, limit: u64, what: &str) -> Result<Vec<u8>> {
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open {what} {}", path.display()))?;
    let size = file
        .metadata()
        .with_context(|| format!("failed to stat {what} {}", path.display()))?
        .len();
    if size > limit {
        bail!(
            "{what} {} is {size} bytes, over the {limit}-byte limit \
             (raise it with --max-debug-file-bytes)",
            path.display()
        );
    }
    let mut data = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    file.take(limit.saturating_add(1))
        .read_to_end(&mut data)
        .with_context(|| format!("failed to read {what} {}", path.display()))?;
    if data.len() as u64 > limit {
        bail!(
            "{what} {} grew past the {limit}-byte limit while being read \
             (raise it with --max-debug-file-bytes)",
            path.display()
        );
    }
    Ok(data)
}

/// Remaining decompression allowance for ONE object file's DWARF sections.
///
/// A compressed section's header declares its uncompressed size, and that
/// declaration is attacker-controlled: inflating it on trust lets a few KiB on
/// disk demand tens of GB. Every compressed section is charged against what is
/// left of its file's budget BEFORE it is inflated.
struct SectionBudget<'a> {
    file: &'a Path,
    limit: u64,
    used: u64,
}

impl<'a> SectionBudget<'a> {
    fn new(file: &'a Path, limit: u64) -> Self {
        Self {
            file,
            limit,
            used: 0,
        }
    }

    fn reserve(&mut self, section: &str, size: u64) -> Result<()> {
        let total = self.used.saturating_add(size);
        if total > self.limit {
            bail!(
                "compressed DWARF section {section} of {} declares {size} uncompressed \
                 bytes; with the {} bytes already decompressed from this file that exceeds \
                 the {}-byte limit (raise it with --max-debug-file-bytes)",
                self.file.display(),
                self.used,
                self.limit
            );
        }
        self.used = total;
        Ok(())
    }
}

/// What [`parse_module`] learns from one target.
struct ParsedModule {
    module: DwarfModule,
    /// Version from an embedded `ceph version X` string, scanned from the buffer
    /// the module was parsed from (the target is read once, not once per use).
    embedded_version: Option<String>,
}

fn parse_module(
    path: &Path,
    module_name: &str,
    arch: &mut Option<String>,
    options: &NativeOptions,
) -> Result<ParsedModule> {
    let limit = options.max_debug_file_bytes;
    let data = read_file_bounded(path, limit, "target")?;
    let embedded_version = ceph_version_from_bytes(&data);
    let file = object::File::parse(data.as_slice())
        .with_context(|| format!("{} is not a supported object file", path.display()))?;

    if arch.is_none() {
        *arch = arch_name(file.architecture());
    }

    let build_id = file.build_id()?.map(hex_string);
    let (debug_data, debug_file_path) = debug_data(path, &file, data.as_slice(), limit)?;
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

    // el9/Fedora/RHEL debuginfo is DWZ-compressed: the debug file's
    // `.gnu_debugaltlink` points at a shared supplementary object, and DIEs and
    // strings reference it via `DW_FORM_GNU_ref_alt`/`DW_FORM_GNU_strp_alt`.
    // Read the supplementary object's bytes up front so they outlive the `Dwarf`
    // built below; missing/mismatched sup degrades to what resolves locally.
    let sup_data = load_sup_object_bytes(&debug_file, &debug_file_path, limit);
    let sup_file = match &sup_data {
        Some(bytes) => Some(object::File::parse(bytes.as_slice()).with_context(|| {
            format!(
                "DWZ supplementary file for {} is not a supported object file",
                debug_file_path.display()
            )
        })?),
        None => None,
    };

    // Sections stay BORROWED from the file buffers when stored uncompressed
    // (`Cow::Borrowed`): copying them, as this used to, doubled peak memory for
    // nothing. Only a compressed section allocates, against its file's
    // decompression budget. The main and supplementary buffers both outlive
    // `dwarf_sections`, so the two `Cow` lifetimes unify without any
    // self-referential borrow.
    let mut budget = SectionBudget::new(&debug_file_path, limit);
    let mut dwarf_sections =
        Dwarf::load(|section| load_section(&debug_file, section, &mut budget))?;
    if let Some(sup_file) = &sup_file {
        let sup_label = debug_file_path.with_extension("dwz-supplementary");
        let mut sup_budget = SectionBudget::new(&sup_label, limit);
        dwarf_sections.load_sup(|section| load_section(sup_file, section, &mut sup_budget))?;
    }
    #[allow(deprecated)]
    let dwarf = dwarf_sections.borrow(|section| EndianSlice::new(section, endian));
    let wanted = probe_functions_for_module(module_name);
    // The probed binary's own symbols first: they describe the very file the
    // uprobe attaches to. A separate debug file's `.symtab` only fills the gaps a
    // stripped binary leaves (and it was proven to belong to this binary above).
    let mut resolved = symbol_function_pcs(&file, wanted);
    for (function, ranked) in symbol_function_pcs(&debug_file, wanted) {
        resolved.entry(function).or_insert(ranked);
    }
    // Load every compilation unit once and share it across both extraction
    // passes; cross-CU reference resolution needs all units resident anyway.
    let index = DwarfUnitIndex::load(&dwarf)?;
    if !has_all_functions(&resolved, wanted) {
        for (function, ranked) in function_pcs(&dwarf, &index, wanted)? {
            resolved.entry(function).or_insert(ranked);
        }
    }
    // Extraction of the descriptors comes AFTER address resolution, and is fed the
    // resolved addresses: each descriptor must be decoded at the PC its uprobe will
    // fire at, and must come from the definition that owns that PC.
    let (mut func2vf, dpp) = function_var_fields(&dwarf, &index, wanted, &resolved)?;
    // Refuse any function whose name resolved to two equally valid definitions at
    // different addresses -- there is nothing left to choose between them, so we
    // must not pick. Drop the descriptors with the address: an hprobe slot filled
    // for a probe that cannot attach is only a trap for the next reader.
    for function in drop_ambiguous_definitions(&mut resolved) {
        func2vf.remove(&function);
    }
    apply_dpp_identity_gates(module_name, &dpp, &mut resolved, &mut func2vf);
    // Split the resolved definitions into the address map and the PROVENANCE map.
    // The latter records the mangled linkage name the address came from, which is
    // the only evidence an importer of this artifact has that a
    // `req_state::~req_state` address is the complete/base destructor (D1/D2) and
    // not the deleting one (D0), and that an `rgw_rados_operate` address is the
    // overload it is filed under rather than the other one. Written for every
    // function whose demangled name is ambiguous; see
    // `VARIANT_PROVENANCE_FUNCTIONS`.
    let func2linkage = provenance_linkage_names(&resolved);
    let func2pc = ranked_pcs_into_pcs(resolved);

    Ok(ParsedModule {
        module: DwarfModule {
            build_id,
            func2pc,
            func2vf,
            func2linkage,
        },
        embedded_version,
    })
}

/// Drop every probe whose soundness depends on a `DoutPrefixProvider` identity
/// this build's DWARF did NOT prove, and say so.
///
/// The per-submit re-seed reads `rgw_rados_operate`'s `dpp` and looks its VALUE up
/// in the (pointer, tgid) bridge. That is only meaningful if a request's dpp is
/// numerically its `req_state*` -- i.e. if `req_state`'s `DoutPrefixProvider` base
/// is at offset 0. If we cannot prove that from this binary's DWARF, the probes
/// are not attached at all: a bridge keyed on the wrong pointer would not merely
/// miss, it could (astronomically unlikely, but the whole tool's value is that it
/// does not gamble) collide with another live request's key. Refuse instead.
///
/// The alternate `RGWOp*` key is gated the same way, but independently: losing it
/// only costs coverage (ops submitted under an RGWOp dpp go uncorrelated), so the
/// re-seed itself stays attached.
fn apply_dpp_identity_gates(
    module_name: &str,
    dpp: &DppFacts,
    resolved: &mut BTreeMap<String, RankedPc>,
    func2vf: &mut BTreeMap<String, FunctionVarFields>,
) {
    if !dpp.req_state_dpp_identity_holds() {
        let had_operate = RGW_RADOS_OPERATE_OVERLOADS
            .iter()
            .any(|function| resolved.contains_key(*function) || func2vf.contains_key(*function));
        for function in RGW_RADOS_OPERATE_OVERLOADS {
            resolved.remove(*function);
            func2vf.remove(*function);
        }
        if had_operate {
            warn!(
                module = module_name,
                req_state_dpp_base = ?dpp.req_state_base,
                "could not prove that {REQ_STATE_TYPE} inherits {DOUT_PREFIX_PROVIDER_TYPE} at \
                 offset 0 in this build's DWARF, so a request's `dpp` cannot be assumed to be its \
                 req_state*. The per-submit cross-thread re-seed ({RGW_RADOS_OPERATE}) is DISABLED \
                 for this artifact: RADOS ops submitted after a coroutine migration will not be \
                 correlated"
            );
        }
    }

    // The `op` descriptor is emitted only when the RGWOp identity is proven, so a
    // single var_field here means the proof failed (or the parameter was not
    // register-resident). Either way the operator must hear about it: it is the
    // difference between correlating the op data path and not.
    if func2vf
        .get(RGW_PROCESS_AUTHENTICATED)
        .is_some_and(|vars| vars.var_fields.len() < RGW_PROCESS_AUTHENTICATED_FIELDS.len())
    {
        warn!(
            module = module_name,
            rgw_op_dpp_base = ?dpp.rgw_op_base,
            "no usable `{RGW_OP_TYPE}*&` descriptor for {RGW_PROCESS_AUTHENTICATED} (parameter not \
             register-resident at entry, or {RGW_OP_TYPE}'s {DOUT_PREFIX_PROVIDER_TYPE} base not \
             provably at offset 0). The cross-thread bridge will key requests by their req_state* \
             ONLY, so RADOS ops submitted under an RGWOp dpp -- most of an op's data path -- stay \
             uncorrelated"
        );
    }
}

/// The mangled linkage names to export alongside `func2pc`, for the functions
/// whose demangled name cannot identify a single definition.
fn provenance_linkage_names(resolved: &BTreeMap<String, RankedPc>) -> BTreeMap<String, String> {
    resolved
        .iter()
        .filter(|(function, _)| VARIANT_PROVENANCE_FUNCTIONS.contains(&function.as_str()))
        .filter_map(|(function, ranked)| {
            ranked
                .linkage
                .as_ref()
                .map(|linkage| (function.clone(), linkage.clone()))
        })
        .collect()
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
#[derive(Clone, Copy, PartialEq, Eq)]
struct DieRef<Offset> {
    unit: usize,
    offset: UnitOffset<Offset>,
}

/// Hard cap on how many DIEs an attribute may be inherited through. Real chains
/// are two or three links; the cap only bounds work on adversarial/looping DWARF
/// (the visited check already breaks cycles).
const ORIGIN_CHAIN_LIMIT: usize = 8;

/// Hard cap on how many type DIEs one type walk may follow (typedef/cv
/// qualifiers, and pointer/reference indirections within one field-path step).
/// Real chains are a handful of links; only a reference cycle in malformed DWARF
/// reaches the cap, and the walk then fails instead of spinning forever.
const TYPE_CHAIN_LIMIT: usize = 64;

/// Hard cap on how many classes one member lookup may search through the
/// inheritance graph. The graph is already de-duplicated (a visited set breaks
/// cycles and diamonds); this only bounds the work an adversarial file can force.
const INHERITANCE_SEARCH_LIMIT: usize = 4096;

/// Hard cap on namespace/class nesting for the RECURSIVE function walkers
/// ([`collect_function_pcs`], [`collect_function_var_fields`]). They stop at every
/// subprogram, so they only ever descend through scopes -- a few dozen levels in
/// the deepest real C++. They stay recursive because the `EntriesTree` they walk
/// skips a subprogram's body via `DW_AT_sibling` without parsing it; the cap keeps
/// a hostile file from turning that recursion into a stack overflow (which aborts
/// the process rather than returning an error).
const SCOPE_NESTING_LIMIT: usize = 256;

/// Human-readable location of a DIE for error messages: its `.debug_info`
/// section offset (what `readelf --debug-dump=info` / `llvm-dwarfdump` print), and
/// which file it lives in.
fn die_location<R: Reader>(index: &DwarfUnitIndex<R>, die: DieRef<R::Offset>) -> String {
    let section = if index.is_sup(die.unit) {
        "supplementary (DWZ) .debug_info"
    } else {
        ".debug_info"
    };
    let unit = index.unit(die.unit);
    match die.offset.to_debug_info_offset(&unit.header) {
        Some(offset) => format!("DIE at {section} offset {:#x}", offset.0.into_u64()),
        None => format!(
            "DIE at unit offset {:#x} in {section} unit {}",
            die.offset.0.into_u64(),
            die.unit
        ),
    }
}

/// The DIEs an attribute of `die` may be inherited from, NEAREST FIRST: `die`
/// itself, then the transitive closure of its `DW_AT_abstract_origin` and
/// `DW_AT_specification` references.
///
/// TRANSITIVE is the point. DWARF 5 §3.3.8.1 says a concrete instance DIE
/// inherits every attribute it does not carry itself from the DIE its
/// `DW_AT_abstract_origin` names -- and that DIE may in turn inherit from
/// another. GCC's constructor/destructor CLONES make that stacking routine, and
/// on an LTO build (which is how Ceph is built) it is exactly two hops:
///
/// ```text
///   subprogram (concrete, low_pc)          formal_parameter (loclist, no name)
///     -> abstract_origin: D2 clone           -> abstract_origin: clone's param
///          (linkage _ZN9req_stateD2Ev)            (no DW_AT_name, no DW_AT_type)
///     -> abstract_origin: D4 unified         -> abstract_origin: unified param
///          (DW_AT_inline)                         (DW_AT_name "this", DW_AT_type)
/// ```
///
/// Walking only ONE hop -- which every caller here used to do -- finds a DIE that
/// carries neither the name nor the type, and so fails to recognise the implicit
/// `this` of a destructor as `this` at all. That is the whole reason the
/// request-END probe's descriptor went missing on real Ceph builds while every
/// non-cdtor probe (whose parameter is one hop from its name) extracted fine.
fn attribute_origin_chain<R: Reader>(
    index: &DwarfUnitIndex<R>,
    die: DieRef<R::Offset>,
) -> Result<Vec<DieRef<R::Offset>>> {
    let mut chain = vec![die];
    let mut next = 0;
    while next < chain.len() && chain.len() < ORIGIN_CHAIN_LIMIT {
        let current = chain[next];
        next += 1;
        let unit = index.unit(current.unit);
        let entry = unit.entry(current.offset)?;
        for attr in [gimli::DW_AT_abstract_origin, gimli::DW_AT_specification] {
            let Some(origin) = index.referenced_die(current.unit, &entry, attr)? else {
                continue;
            };
            // Cycle guard: malformed DWARF may point an origin back at itself.
            if !chain.contains(&origin) {
                chain.push(origin);
            }
        }
    }
    Ok(chain)
}

/// Eagerly parsed set of compilation units, kept alive together so that DIEs
/// resolved in one unit can be borrowed while walking another. Cross-CU
/// reference resolution needs stable ownership of every unit; parsing units
/// on demand (as the previous single-unit code did) cannot return a DIE that
/// outlives the temporary unit it came from.
struct DwarfUnitIndex<R: Reader> {
    /// Main-file compilation units first, then (if a DWZ supplementary file was
    /// loaded) the supplementary file's units. A single vec keeps `DieRef.unit`
    /// a plain index across both files.
    units: Vec<gimli::Unit<R>>,
    /// Number of main-file units; also the index where supplementary units
    /// begin. Equal to `units.len()` when no supplementary file is loaded.
    sup_start: usize,
    /// `(.debug_info start offset, index into `units`)` for every main-file
    /// unit, sorted ascending by start offset. Lets `debug_info_ref`
    /// binary-search the owning unit instead of scanning every unit per
    /// reference. The stored index maps back to the surviving unit, so gaps left
    /// by skipped (malformed) units resolve correctly.
    unit_offsets: Vec<(R::Offset, usize)>,
    /// Same as `unit_offsets` but for the supplementary file's `.debug_info`,
    /// resolving `DW_FORM_GNU_ref_alt` (`DebugInfoRefSup`) references and
    /// intra-supplementary `DebugInfoRef`s.
    sup_unit_offsets: Vec<(R::Offset, usize)>,
}

impl<R: Reader> DwarfUnitIndex<R> {
    fn load(dwarf: &Dwarf<R>) -> Result<Self> {
        let mut units = Vec::new();
        Self::load_units_into(dwarf, &mut units);
        let sup_start = units.len();
        if let Some(sup) = dwarf.sup() {
            Self::load_units_into(sup, &mut units);
        }

        let unit_offsets = Self::offset_table(&units[..sup_start], 0);
        let sup_unit_offsets = Self::offset_table(&units[sup_start..], sup_start);

        Ok(Self {
            units,
            sup_start,
            unit_offsets,
            sup_unit_offsets,
        })
    }

    fn load_units_into(dwarf: &Dwarf<R>, units: &mut Vec<gimli::Unit<R>>) {
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
    }

    /// Builds the `(start offset, absolute index)` table for `units`, whose
    /// first element sits at absolute index `base` in the combined vec. Sorted
    /// ascending so the binary search never depends on section order.
    fn offset_table(units: &[gimli::Unit<R>], base: usize) -> Vec<(R::Offset, usize)> {
        let mut offsets: Vec<(R::Offset, usize)> = units
            .iter()
            .enumerate()
            .filter_map(|(index, unit)| {
                unit.header
                    .offset()
                    .as_debug_info_offset()
                    .map(|offset| (offset.0, base + index))
            })
            .collect();
        offsets.sort_by_key(|(offset, _)| *offset);
        offsets
    }

    fn len(&self) -> usize {
        self.units.len()
    }

    /// Number of main-file units (the supplementary units follow them). Callers
    /// that walk compilation units for subprograms (which are only defined in
    /// the main file) iterate `0..main_len()`.
    fn main_len(&self) -> usize {
        self.sup_start
    }

    /// Whether `unit_index` names a supplementary-file unit.
    fn is_sup(&self, unit_index: usize) -> bool {
        unit_index >= self.sup_start
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
    /// owning unit (in the same file as `unit_index`); `DebugInfoRefSup`
    /// references (`DW_FORM_GNU_ref_alt`, emitted by DWZ) are resolved against
    /// the supplementary file's units.
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
            AttributeValue::DebugInfoRef(offset) => Ok(self.debug_info_ref(unit_index, offset)),
            AttributeValue::DebugInfoRefSup(offset) => Ok(self.sup_debug_info_ref(offset)),
            _ => Ok(None),
        }
    }

    /// Resolves a `.debug_info` offset within the same file as `from_unit` (main
    /// for main units, supplementary for supplementary units).
    fn debug_info_ref(
        &self,
        from_unit: usize,
        offset: DebugInfoOffset<R::Offset>,
    ) -> Option<DieRef<R::Offset>> {
        let offsets = if self.is_sup(from_unit) {
            &self.sup_unit_offsets
        } else {
            &self.unit_offsets
        };
        self.resolve_in(offsets, offset)
    }

    /// Resolves a `DW_FORM_GNU_ref_alt` offset against the supplementary file's
    /// `.debug_info`. Resolves to `None` when no supplementary file is loaded.
    fn sup_debug_info_ref(&self, offset: DebugInfoOffset<R::Offset>) -> Option<DieRef<R::Offset>> {
        self.resolve_in(&self.sup_unit_offsets, offset)
    }

    fn resolve_in(
        &self,
        offsets: &[(R::Offset, usize)],
        offset: DebugInfoOffset<R::Offset>,
    ) -> Option<DieRef<R::Offset>> {
        // Find the unit whose start offset is the greatest that is <= the target,
        // then confirm the target actually lands inside that unit's range. A
        // target in a gap (e.g. a skipped unit) or past the last unit fails the
        // confirmation and resolves to None, matching the prior silent-miss.
        let unit_index = owning_unit_index(offsets, offset.0)?;
        let unit = &self.units[unit_index];
        offset.to_unit_offset(&unit.header).map(|offset| DieRef {
            unit: unit_index,
            offset,
        })
    }
}

/// Selects the `Dwarf` that owns `unit_index`'s strings and section data: the
/// main file for main units, the supplementary (DWZ) file for supplementary
/// units. For modules with no supplementary file this always returns `dwarf`,
/// so same-file behavior is unchanged.
fn dwarf_for<'a, R: Reader>(
    dwarf: &'a Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
) -> &'a Dwarf<R> {
    if index.is_sup(unit_index) {
        dwarf.sup().unwrap_or(dwarf)
    } else {
        dwarf
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
) -> Result<BTreeMap<String, RankedPc>> {
    let mut result: BTreeMap<String, RankedPc> = BTreeMap::new();
    for unit_index in 0..index.main_len() {
        let unit = index.unit(unit_index);
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;
        collect_function_pcs(
            dwarf,
            index,
            unit_index,
            root,
            0,
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

/// Extract every probe's descriptors, decoding each variable's location AT THE
/// ADDRESS THE PROBE WILL ATTACH AT.
///
/// `probe_pcs` is the already-resolved address per probe key (`resolved` in
/// [`parse_module`], i.e. the definition the mangled-linkage-name gate picked).
/// Feeding it in is what ties the descriptor to the probed definition: a variable
/// whose `DW_AT_location` is a location LIST has a different location at different
/// PCs -- `this` is in RDI only at function entry and migrates to a callee-saved
/// register a few instructions in -- so a descriptor is only meaningful when it is
/// decoded at the exact PC the uprobe fires at.
fn function_var_fields<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    wanted: &[&str],
    probe_pcs: &BTreeMap<String, RankedPc>,
) -> Result<(BTreeMap<String, FunctionVarFields>, DppFacts)> {
    let mut result = BTreeMap::new();
    let mut facts = DppFacts::default();
    for unit_index in 0..index.main_len() {
        let unit = index.unit(unit_index);
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;
        collect_function_var_fields(
            dwarf,
            index,
            unit_index,
            root,
            0,
            &mut Vec::new(),
            &mut result,
            wanted,
            &mut facts,
            probe_pcs,
        )?;
        if has_all_functions(&result, wanted) {
            break;
        }
    }
    Ok((result, facts))
}

#[allow(clippy::too_many_arguments)]
fn collect_function_var_fields<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    node: EntriesTreeNode<R>,
    depth: usize,
    scopes: &mut Vec<String>,
    result: &mut BTreeMap<String, FunctionVarFields>,
    wanted: &[&str],
    facts: &mut DppFacts,
    probe_pcs: &BTreeMap<String, RankedPc>,
) -> Result<()> {
    if has_all_functions(result, wanted) {
        return Ok(());
    }
    if depth > SCOPE_NESTING_LIMIT {
        anyhow::bail!(
            "DWARF scope nesting deeper than {SCOPE_NESTING_LIMIT} levels at {} \
             (malformed DWARF?)",
            die_location(
                index,
                DieRef {
                    unit: unit_index,
                    offset: node.entry().offset(),
                }
            )
        );
    }

    let unit = index.unit(unit_index);
    let entry = node.entry();
    let scope = scope_name(dwarf, unit, entry)?;
    if let Some(scope) = &scope {
        scopes.push(scope.clone());
    }

    if entry.tag() == gimli::DW_TAG_subprogram {
        for fullname in function_names(dwarf, index, unit_index, entry, scopes)? {
            // One DIE can be a candidate for several probe keys (the two
            // `rgw_rados_operate` overloads share a demangled name); the
            // linkage-name gate below accepts it for exactly one of them.
            for key in probe_keys(&fullname, wanted) {
                // Same acceptance gate as `collect_function_pcs`: a rejected
                // definition (the D0 destructor, or the OTHER rgw_rados_operate
                // overload) must not supply this key's var_fields either. Its
                // register would often happen to agree, but the descriptors and
                // the probed address must come from the same definition --
                // otherwise a descriptor would silently describe a different
                // function body.
                let linkage_names = entry_linkage_names(dwarf, index, unit_index, entry)?;
                if definition_rank(key, &linkage_names).is_none() {
                    continue;
                }
                if let Some(paths) = probe_field_paths(key) {
                    if let Some(fields) = probe_function_var_fields(
                        dwarf,
                        index,
                        unit_index,
                        entry,
                        key,
                        paths,
                        facts,
                        probe_pcs.get(key).map(|ranked| ranked.pc),
                    )? {
                        result.entry(key.to_string()).or_insert(fields);
                    }
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
        collect_function_var_fields(
            dwarf,
            index,
            unit_index,
            child,
            depth + 1,
            scopes,
            result,
            wanted,
            facts,
            probe_pcs,
        )?;
        if has_all_functions(result, wanted) {
            break;
        }
    }

    if scope.is_some() {
        scopes.pop();
    }
    Ok(())
}

/// Is var_field `idx` of `function` OPTIONAL, i.e. may extraction drop it and keep
/// the descriptors before it?
///
/// Exactly one descriptor is: `rgw_process_authenticated`'s `RGWOp*& op` (slot 41,
/// the ALTERNATE bridge key). Every other descriptor is all-or-nothing, because a
/// missing one would shift no slot but would leave its BPF reader with a zeroed
/// VarField and no way to tell. The `op` slot is different by construction: its
/// BPF reader looks the slot up separately and treats an absent one as "this build
/// has no alternate key", which is a supported, counted, warned-about degradation
/// (`RGWTRACE_DIAG_RGWOP_KEY_UNRESOLVED`).
///
/// Optional descriptors must be TRAILING (an optional slot in the middle would
/// shift every later slot's key), which `debug_assert` below pins.
fn optional_trailing_var_field(function: &str, idx: usize) -> bool {
    function == RGW_PROCESS_AUTHENTICATED && idx == 1
}

/// The descriptors for one probe function, read from ONE subprogram DIE.
///
/// `probe_pc` is the address this probe will be attached at, when it is already
/// known (it always is for a probe that will actually attach: the address is
/// resolved before this pass runs). It does two jobs:
///
/// 1. It is the PC the locations are decoded at, so a location LIST resolves to
///    the range that covers the uprobe site rather than to some arbitrary range.
/// 2. It selects the DIE. Only the subprogram whose code CONTAINS that address is
///    allowed to describe it -- so a declaration DIE (no code), an abstract
///    instance, or a DIFFERENT definition that happens to share the demangled name
///    (the deleting destructor; a `req_state`-with-virtual-bases build where D1 and
///    D2 are distinct functions) cannot supply the descriptors for an address that
///    is not theirs.
#[allow(clippy::too_many_arguments)]
fn probe_function_var_fields<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    function: &DebuggingInformationEntry<R>,
    function_name: &str,
    paths: &[&[&str]],
    facts: &mut DppFacts,
    probe_pc: Option<u64>,
) -> Result<Option<FunctionVarFields>> {
    let unit = index.unit(unit_index);
    let pc = match probe_pc {
        Some(probe_pc) => {
            if !die_contains_pc(dwarf, unit, function, probe_pc)? {
                debug!(
                    function = function_name,
                    probe_pc,
                    "native DWARF probe rejected: this definition does not cover the probed address"
                );
                return Ok(None);
            }
            probe_pc
        }
        // No address resolved for this probe (it cannot attach, but a descriptor
        // is still extracted for the artifact): fall back to this definition's own
        // entry address, which is where a uprobe on it would fire.
        None => {
            let Some(pc) = entry_pc(dwarf, unit, function)? else {
                debug!(
                    function = function_name,
                    "native DWARF probe rejected: missing function PC"
                );
                return Ok(None);
            };
            pc
        }
    };
    let mut var_fields = Vec::new();

    for (idx, path) in paths.iter().enumerate() {
        debug_assert!(
            !optional_trailing_var_field(function_name, idx) || idx + 1 == paths.len(),
            "an optional var_field must be trailing, or it would shift later hprobe slot keys"
        );
        // A descriptor that cannot be resolved (or, for `op`, cannot be PROVEN)
        // either drops the whole function -- the all-or-nothing rule -- or, for an
        // optional trailing slot, drops just itself and everything after it.
        macro_rules! reject {
            ($($reason:tt)*) => {{
                debug!(function = function_name, idx, $($reason)*);
                if optional_trailing_var_field(function_name, idx) {
                    break;
                }
                return Ok(None);
            }};
        }

        let Some(variable_name) = path.first() else {
            reject!("native DWARF probe rejected: empty field path");
        };
        // The `rgw_rados_operate` overloads and the destructor resolve their single
        // pointer parameter by POSITION (first formal parameter): their
        // already-verified mangled name proves what parameter 0 is -- the
        // `const DoutPrefixProvider*` for the overloads, the implicit `req_state*`
        // `this` for the destructor. Every other probe resolves by name.
        let variable = if FIRST_PARAM_PROBE_FUNCTIONS.contains(&function_name) {
            find_first_formal_parameter(index, unit_index, function)?
        } else {
            find_function_variable(dwarf, index, unit_index, function, variable_name)?
        };
        let Some(variable) = variable else {
            reject!(
                variable = *variable_name,
                "native DWARF probe rejected: missing variable"
            );
        };

        // Record the DoutPrefixProvider base offsets the cross-thread bridge's key
        // identity depends on, from the parameter we just resolved. Done here
        // because every type we need is reachable from a parameter we already have
        // to walk -- no separate scan of the type tree.
        record_dpp_facts(dwarf, index, function_name, variable_name, variable, facts)?;

        let variable_unit = index.unit(variable.unit);
        let variable_entry = variable_unit.entry(variable.offset)?;
        let Some(location) = variable_location(
            dwarf_for(dwarf, index, variable.unit),
            variable_unit,
            function,
            &variable_entry,
            pc,
        )?
        else {
            reject!(
                variable = *variable_name,
                "native DWARF probe rejected: missing variable location"
            );
        };
        // Single-element path => a POINTER-VALUED descriptor, not a member-deref
        // chain: the parameter's own value (raw pointer), or -- for the `RGWOp*& op`
        // reference -- the value it refers to. Both are read from the ABI register at
        // entry, so a stack-located descriptor cannot encode either.
        if path.len() == 1 {
            if location.stack {
                reject!(
                    variable = *variable_name,
                    "native DWARF probe rejected: pointer parameter is stack-located at entry"
                );
            }
            // The `RGWOp*& op` reference: emitted only once DWARF proves the type
            // chain (reference -> pointer -> RGWOp) AND that RGWOp's
            // DoutPrefixProvider base is at offset 0, i.e. that the pointer we are
            // about to key the bridge on is the very pointer RGW passes as the dpp.
            // Anything else and we key nothing rather than key a guess.
            let pointer_ref = function_name == RGW_PROCESS_AUTHENTICATED && *variable_name == "op";
            if pointer_ref && facts.rgw_op_base != Some(0) {
                reject!(
                    variable = *variable_name,
                    rgw_op_dpp_base = ?facts.rgw_op_base,
                    "native DWARF probe rejected: cannot prove the parameter is an RGWOp*& whose \
                     DoutPrefixProvider base is at offset 0"
                );
            }
            var_fields.push(VarFieldJson {
                location,
                fields: vec![FieldJson {
                    offset: 0,
                    pointer: pointer_ref,
                }],
            });
            continue;
        }
        let Some(fields) = translate_field_path(dwarf, index, variable, path)? else {
            reject!(
                path = path.join("."),
                "native DWARF probe rejected: field path translation failed"
            );
        };
        var_fields.push(VarFieldJson { location, fields });
    }

    Ok(Some(FunctionVarFields { var_fields }))
}

/// Record whichever `DoutPrefixProvider` base offset this probe parameter can
/// prove. Each fact is recorded once, from the first parameter that reaches its
/// type; every path here is a parameter the extractor already resolves for its own
/// descriptor, so nothing extra is walked.
fn record_dpp_facts<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    function_name: &str,
    variable_name: &str,
    variable: DieRef<R::Offset>,
    facts: &mut DppFacts,
) -> Result<()> {
    match (function_name, variable_name) {
        // `req_state* s` (get_handler, rgw_process_authenticated) and the
        // destructor's implicit `this` are all `req_state*`.
        (RGWREST_GET_HANDLER, "s")
        | (RGW_PROCESS_AUTHENTICATED, "s")
        | (REQ_STATE_DTOR, "this")
            if facts.req_state_base.is_none() =>
        {
            facts.req_state_base = pointee_dpp_base_offset(dwarf, index, variable, REQ_STATE_TYPE)?;
        }
        (RGW_PROCESS_AUTHENTICATED, "op") if facts.rgw_op_base.is_none() => {
            facts.rgw_op_base = rgw_op_reference_dpp_base_offset(dwarf, index, variable)?;
        }
        _ => {}
    }
    Ok(())
}

/// The `DoutPrefixProvider` base offset of the class a `T*` parameter points at,
/// requiring that class to be named `expected`. `None` if any link of the chain is
/// not what we require -- fail closed, never assume.
fn pointee_dpp_base_offset<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    variable: DieRef<R::Offset>,
    expected: &str,
) -> Result<Option<i64>> {
    let Some(pointer) = die_type(index, variable)? else {
        return Ok(None);
    };
    let pointer = peel_type_qualifiers(index, pointer)?;
    if index.entry(pointer)?.tag() != gimli::DW_TAG_pointer_type {
        return Ok(None);
    }
    let Some(class) = die_type(index, pointer)? else {
        return Ok(None);
    };
    named_class_dpp_base_offset(dwarf, index, class, expected)
}

/// The `DoutPrefixProvider` base offset of `RGWOp`, reached through the
/// `RGWOp*& op` parameter -- i.e. a REFERENCE to a POINTER to `RGWOp`.
///
/// Proving this chain is what makes the single `bpf_probe_read_user` the BPF
/// handler performs on that register safe and meaningful: the register holds an
/// `RGWOp**`, so exactly one read yields the `RGWOp*`, and offset 0 means that
/// pointer is numerically the `dpp` RGW passes for this op.
fn rgw_op_reference_dpp_base_offset<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    variable: DieRef<R::Offset>,
) -> Result<Option<i64>> {
    let Some(reference) = die_type(index, variable)? else {
        return Ok(None);
    };
    let reference = peel_type_qualifiers(index, reference)?;
    if index.entry(reference)?.tag() != gimli::DW_TAG_reference_type {
        return Ok(None);
    }
    let Some(pointer) = die_type(index, reference)? else {
        return Ok(None);
    };
    let pointer = peel_type_qualifiers(index, pointer)?;
    if index.entry(pointer)?.tag() != gimli::DW_TAG_pointer_type {
        return Ok(None);
    }
    let Some(class) = die_type(index, pointer)? else {
        return Ok(None);
    };
    named_class_dpp_base_offset(dwarf, index, class, RGW_OP_TYPE)
}

/// The offset of `class`'s DIRECT `DoutPrefixProvider` base, if `class` IS the
/// type `expected` -- where "is" means its FULLY-QUALIFIED DWARF path matches, not
/// merely its unqualified name.
///
/// WHY QUALIFIED, NOT UNQUALIFIED. This function produces the PROOF that a
/// `req_state*`/`RGWOp*` and the `DoutPrefixProvider*` RGW passes for it are the
/// same pointer value -- the proof the entire cross-thread bridge key rests on.
/// Matching on an unqualified name would let `namespace x { struct RGWOp; }` --
/// an unrelated type that merely shares a name -- supply that proof, and a proof
/// that can be satisfied by the wrong type is not a proof. The probe targets are
/// global-scope Ceph types (`::req_state`, `::RGWOp`, `::DoutPrefixProvider`), so
/// `expected` is a global-scope path and anything nested in a namespace or another
/// class is REJECTED.
///
/// Only a DIRECT base counts. An indirect one would need its offsets summed
/// through the whole inheritance chain, and a virtual base is not a compile-time
/// constant offset at all -- so anything other than "names DoutPrefixProvider as
/// its own base" returns `None` and the dependent feature is disabled rather than
/// keyed on an offset we inferred.
fn named_class_dpp_base_offset<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    class: DieRef<R::Offset>,
    expected: &str,
) -> Result<Option<i64>> {
    let class = peel_type_qualifiers(index, class)?;
    if !is_global_type_named(dwarf, index, class, expected)? {
        return Ok(None);
    }
    // The DIE we reached may be a DECLARATION (`DW_AT_declaration`, no children) in
    // this CU; the base list lives on the DEFINITION, which may be in another unit.
    let Some(definition) = type_definition_die(dwarf, index, class)? else {
        return Ok(None);
    };
    dpp_base_offset(dwarf, index, definition)
}

/// Offset of the `DoutPrefixProvider` base of the (fully defined) class `typedie`,
/// or `None` when it does not inherit it directly.
///
/// The base's identity is checked the same way as the derived class's: by
/// FULLY-QUALIFIED path. A `namespace x { class DoutPrefixProvider {...}; }` base
/// would otherwise be accepted as the real one and hand us an offset for the wrong
/// inheritance edge.
fn dpp_base_offset<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    typedie: DieRef<R::Offset>,
) -> Result<Option<i64>> {
    let unit = index.unit(typedie.unit);
    let mut tree = unit.entries_tree(Some(typedie.offset))?;
    let root = tree.root()?;
    let mut children = root.children();
    while let Some(child) = children.next()? {
        let entry = child.entry();
        if entry.tag() != gimli::DW_TAG_inheritance {
            continue;
        }
        let base_ref = DieRef {
            unit: typedie.unit,
            offset: entry.offset(),
        };
        let Some(base) = die_type(index, base_ref)? else {
            continue;
        };
        let base = peel_type_qualifiers(index, base)?;
        if !is_global_type_named(dwarf, index, base, DOUT_PREFIX_PROVIDER_TYPE)? {
            continue;
        }
        // DWARF 5 5.7.3: a member (here, a base class) whose location coincides with
        // the start of the containing entity may omit DW_AT_data_member_location, so
        // an absent attribute means offset 0. A virtual base encodes its location as
        // a runtime expression that cannot be evaluated here; that is "unproven"
        // (None), never "0", and costs only the key this offset would have proven.
        return Ok(match inheritance_offset(unit, entry) {
            Ok(offset) => Some(offset),
            Err(err) => {
                warn!(
                    error = %format_args!("{err:#}"),
                    "cannot evaluate the DoutPrefixProvider base location; its offset is unproven"
                );
                None
            }
        });
    }
    Ok(None)
}

/// Is `typedie` the GLOBAL-SCOPE class/struct named `name` -- i.e. is its
/// fully-qualified DWARF path exactly `[name]`?
///
/// Fails closed on everything else: a different tag, an unnamed DIE, or a type
/// nested in any namespace or class (`x::RGWOp` is NOT `::RGWOp`).
fn is_global_type_named<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    typedie: DieRef<R::Offset>,
    name: &str,
) -> Result<bool> {
    let entry = index.entry(typedie)?;
    if !matches!(
        entry.tag(),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type
    ) {
        return Ok(false);
    }
    drop(entry);
    Ok(qualified_type_path(dwarf, index, typedie)?.as_deref() == Some(&[name.to_string()]))
}

/// The FULLY-QUALIFIED DWARF path of a type DIE: the names of every enclosing
/// namespace/class scope, outermost first, then its own name.
///
/// `None` when the DIE has no `DW_AT_name`, or when it cannot be located in its own
/// unit. An identity that cannot be stated is one we refuse to claim.
///
/// The scope stack is built exactly the way the function-name walker builds one
/// (`scope_name` -- namespaces and classes only), so `::RGWOp` and
/// `namespace x { struct RGWOp; }` produce DIFFERENT paths and can never be
/// confused for one another.
fn qualified_type_path<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    typedie: DieRef<R::Offset>,
) -> Result<Option<Vec<String>>> {
    let unit = index.unit(typedie.unit);
    let dwarf = dwarf_for(dwarf, index, typedie.unit);

    // DFS with a depth-tracked scope stack: a scope pushed at depth d encloses
    // every DIE deeper than d, and is popped as soon as the walk returns to d.
    let mut scopes: Vec<(isize, String)> = Vec::new();
    let mut depth = 0isize;
    let mut entries = unit.entries();
    while let Some((delta, entry)) = entries.next_dfs()? {
        depth += delta;
        scopes.retain(|(scope_depth, _)| *scope_depth < depth);

        if entry.offset() == typedie.offset {
            let Some(name) = die_name(dwarf, unit, entry)? else {
                return Ok(None);
            };
            let mut path: Vec<String> = scopes.into_iter().map(|(_, name)| name).collect();
            path.push(name);
            return Ok(Some(path));
        }

        if let Some(scope) = scope_name(dwarf, unit, entry)? {
            scopes.push((depth, scope));
        }
    }
    Ok(None)
}

/// The DEFINITION DIE of `typedie`: itself when it is not a mere declaration, or
/// the non-declaration DIE in any unit whose FULLY-QUALIFIED PATH is identical.
///
/// THE WHOLE POINT IS THE QUALIFIED PATH. This used to accept the first
/// non-declaration class/struct with a matching UNQUALIFIED name in any unit, which
/// meant a `namespace x { struct RGWOp { ... }; }` anywhere in the binary could
/// supply the `DoutPrefixProvider`-at-offset-0 "proof" for the real `::RGWOp` --
/// binding the bridge key to a type identity that was never actually established.
/// Matching the full path makes the definition the SAME TYPE as the declaration
/// (the one-definition rule then guarantees there is only one such definition), and
/// a declaration whose definition is nowhere to be found yields `None`, which
/// disables the dependent probe rather than probing on an unproven identity.
///
/// A definition that lives only in a `.debug_types` type unit (a `DW_AT_signature`
/// declaration) is not in the CU index and therefore is not found: that too fails
/// closed.
fn type_definition_die<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    typedie: DieRef<R::Offset>,
) -> Result<Option<DieRef<R::Offset>>> {
    let unit = index.unit(typedie.unit);
    let entry = unit.entry(typedie.offset)?;
    if !entry_flag(&entry, gimli::DW_AT_declaration)? {
        return Ok(Some(typedie));
    }
    drop(entry);

    let Some(path) = qualified_type_path(dwarf, index, typedie)? else {
        return Ok(None);
    };
    for unit_index in 0..index.len() {
        if let Some(found) = find_type_definition(dwarf, index, unit_index, &path)? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

/// Enclosing-scope stack for an iterative `next_dfs` walk: a scope pushed at
/// depth `d` encloses every DIE deeper than `d`, and is popped as soon as the walk
/// returns to depth `d` or shallower.
///
/// The type/scope searches below walk a WHOLE unit, subprogram bodies included,
/// so their depth is whatever lexical-block / inlined-subroutine nesting the file
/// has. Doing that with `next_dfs` instead of recursion keeps stack use constant,
/// however deep the tree -- a recursive walker overflows (and aborts the process)
/// on a hostile file's deep nesting.
struct DfsScopes {
    depth: isize,
    scopes: Vec<(isize, String)>,
}

impl DfsScopes {
    fn new() -> Self {
        Self {
            depth: 0,
            scopes: Vec::new(),
        }
    }

    /// Account for the `delta` `next_dfs` returned with the current entry and
    /// drop every scope the walk has left.
    fn step(&mut self, delta: isize) {
        self.depth += delta;
        while self
            .scopes
            .last()
            .is_some_and(|(scope_depth, _)| *scope_depth >= self.depth)
        {
            self.scopes.pop();
        }
    }

    /// The scopes enclosing the current entry, outermost first.
    fn enclosing(&self) -> impl Iterator<Item = &str> {
        self.scopes.iter().map(|(_, name)| name.as_str())
    }

    fn len(&self) -> usize {
        self.scopes.len()
    }

    /// Open `scope` (the current entry's own scope name) for its descendants.
    fn push(&mut self, scope: String) {
        self.scopes.push((self.depth, scope));
    }
}

/// Find the non-declaration class/struct DIE in unit `unit_index` whose
/// enclosing scopes plus own name equal `path`.
fn find_type_definition<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    path: &[String],
) -> Result<Option<DieRef<R::Offset>>> {
    let unit = index.unit(unit_index);
    let dwarf = dwarf_for(dwarf, index, unit_index);
    let mut scopes = DfsScopes::new();
    let mut entries = unit.entries();
    while let Some((delta, entry)) = entries.next_dfs()? {
        scopes.step(delta);
        let is_definition = matches!(
            entry.tag(),
            gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type
        ) && !entry_flag(entry, gimli::DW_AT_declaration)?;
        let name = die_name(dwarf, unit, entry)?;

        if is_definition {
            if let Some(name) = &name {
                // The candidate's identity is its scope stack plus its own name. Only
                // an exact match on the WHOLE path is the same type.
                if path.len() == scopes.len() + 1
                    && scopes
                        .enclosing()
                        .eq(path[..scopes.len()].iter().map(String::as_str))
                    && path[scopes.len()] == *name
                {
                    return Ok(Some(DieRef {
                        unit: unit_index,
                        offset: entry.offset(),
                    }));
                }
            }
        }

        if let Some(scope) = scope_name(dwarf, unit, entry)? {
            scopes.push(scope);
        }
    }
    Ok(None)
}

fn probe_field_paths(function: &str) -> Option<&'static [&'static [&'static str]]> {
    match function {
        "Objecter::_send_op" => Some(OBJECTER_SEND_OP_FIELDS),
        "Objecter::_finish_op" => Some(OBJECTER_FINISH_OP_FIELDS),
        RGWREST_GET_HANDLER => Some(RGWREST_GET_HANDLER_FIELDS),
        RGW_PROCESS_AUTHENTICATED => Some(RGW_PROCESS_AUTHENTICATED_FIELDS),
        REQ_STATE_DTOR => Some(REQ_STATE_DTOR_FIELDS),
        RGW_RADOS_OPERATE_READ | RGW_RADOS_OPERATE_WRITE => Some(RGW_RADOS_OPERATE_FIELDS),
        _ => None,
    }
}

/// Rank of a candidate definition (an ELF symbol or a DWARF subprogram DIE) as
/// THE definition to probe for `function`, given every mangled linkage name
/// reachable from it. Lower ranks win; `None` rejects the candidate outright.
///
/// This exists because two of our probe targets have a demangled name that does
/// NOT identify a single function:
///
/// * C++ destructors. The Itanium ABI emits up to three and ALL THREE DEMANGLE TO
///   THE SAME NAME (`req_state::~req_state`), so a plain demangled-name match
///   binds the probe to whichever variant the symbol table or DWARF lists first --
///   which, on the g++ output we checked, is the WRONG one (D0 precedes D1/D2 both
///   in `.symtab` order and in DIE order).
/// * The two `rgw_rados_operate` overloads (Phase B). `demangle_function_name`
///   strips the argument list, i.e. exactly the thing that distinguishes them, so
///   both definitions present themselves as `rgw_rados_operate` and a first-match
///   bind would attach one probe to an arbitrary one of them and never see the
///   other -- silently losing either every RADOS read or every RADOS write.
///
/// Both are resolved the same way: by the MANGLED linkage name, via
/// [`provenance_rank`]. Every other probe function has a single definition, so it
/// ranks 0 and the existing first-one-wins behavior is preserved exactly.
fn definition_rank(function: &str, linkage_names: &[String]) -> Option<u8> {
    definition_ranking(function, linkage_names).map(|(rank, _)| rank)
}

/// The accepted rank of this candidate definition together with the MANGLED
/// linkage name that earned it, for functions whose provenance must be exported
/// ([`VARIANT_PROVENANCE_FUNCTIONS`]). The name is `None` for every other
/// function: their demangled name identifies a single definition, so there is
/// nothing to prove and nothing to record.
fn definition_ranking(function: &str, linkage_names: &[String]) -> Option<(u8, Option<String>)> {
    if !VARIANT_PROVENANCE_FUNCTIONS.contains(&function) {
        return Some((0, None));
    }
    linkage_names
        .iter()
        .filter_map(|name| provenance_rank(function, name).map(|rank| (rank, name)))
        .min_by_key(|(rank, _)| *rank)
        .map(|(rank, name)| (rank, Some(name.clone())))
}

/// Insert `pc` for `function` keeping the best-ranked candidate seen so far.
/// Equal ranks keep the FIRST candidate, which preserves the previous
/// `or_insert` behavior for every single-definition probe function.
///
/// The rank is a tie-break between ACCEPTED destructor variants, never a
/// correctness gate (rejection is): D1 and D2 differ only for classes with
/// virtual bases, and `req_state`'s only base (`DoutPrefixProvider`) is
/// non-virtual at offset 0, so the two are emitted as aliases of one address on
/// both verified Ceph builds. Settling on D2 (e.g. when the DWARF scan short
/// circuits before an aliased D1 DIE) therefore probes the same instruction.
///
/// AMBIGUITY. For the provenance functions (and only for them -- every other probe
/// has one definition by construction) an equal-rank candidate at a DIFFERENT
/// address is a genuine ambiguity: two definitions the mangled-name rule considers
/// equally valid, at two addresses, so nothing distinguishes them and any pick
/// would be a coin flip. That is precisely the "silently grabbed the wrong
/// overload" failure this whole mechanism exists to prevent, so instead of
/// preferring one we MARK the entry and drop it entirely (loudly) at the end of
/// extraction. Fail closed: no address, no probe, an explicit warning.
fn insert_ranked_pc(
    result: &mut BTreeMap<String, RankedPc>,
    function: String,
    rank: u8,
    pc: u64,
    linkage: Option<String>,
) {
    match result.get_mut(&function) {
        Some(existing) if existing.rank < rank => {}
        Some(existing) if existing.rank == rank => {
            if existing.pc != pc && VARIANT_PROVENANCE_FUNCTIONS.contains(&function.as_str()) {
                existing.ambiguous = true;
            }
        }
        _ => {
            result.insert(
                function,
                RankedPc {
                    rank,
                    pc,
                    linkage,
                    ambiguous: false,
                },
            );
        }
    }
}

/// A resolved function PC, the rank of the definition it came from (see
/// [`definition_rank`]), and -- for the functions whose demangled name is
/// ambiguous -- the MANGLED linkage name that proves which definition it is.
/// Ranks are dropped once resolution finishes; the linkage name is exported as
/// `func2linkage` so an importer can re-verify the definition.
#[derive(Clone)]
struct RankedPc {
    rank: u8,
    pc: u64,
    linkage: Option<String>,
    /// Two equally-ranked definitions at different addresses were seen for this
    /// function. Nothing can choose between them, so the entry is DISCARDED rather
    /// than resolved to an arbitrary one. See [`insert_ranked_pc`].
    ambiguous: bool,
}

/// Drop every function whose definition could not be resolved unambiguously, and
/// say so. Returns the discarded keys so the caller can drop their var_fields too:
/// a descriptor without a proven address is dead weight at best, and at worst
/// would populate an hprobe slot for a probe that must not attach.
fn drop_ambiguous_definitions(resolved: &mut BTreeMap<String, RankedPc>) -> Vec<String> {
    let ambiguous: Vec<String> = resolved
        .iter()
        .filter(|(_, ranked)| ranked.ambiguous)
        .map(|(function, _)| function.clone())
        .collect();
    for function in &ambiguous {
        resolved.remove(function);
        warn!(
            function = %function,
            "refusing to resolve an address: two equally valid definitions with different \
             addresses share this name, and nothing can prove which one to probe; the probe will \
             not attach (fail closed)"
        );
    }
    ambiguous
}

fn ranked_pcs_into_pcs(ranked: BTreeMap<String, RankedPc>) -> BTreeMap<String, u64> {
    ranked
        .into_iter()
        .map(|(function, ranked)| (function, ranked.pc))
        .collect()
}

fn symbol_function_pcs(file: &object::File<'_>, wanted: &[&str]) -> BTreeMap<String, RankedPc> {
    let mut result: BTreeMap<String, RankedPc> = BTreeMap::new();
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
        if !may_name_probe(name, wanted) {
            continue;
        }
        let Some(function) = demangle_function_name(name) else {
            continue;
        };
        for key in probe_keys(&function, wanted) {
            // The symbol's own MANGLED name is the only evidence of WHICH
            // definition this address belongs to -- the demangled name is identical
            // for every destructor variant, and for both `rgw_rados_operate`
            // overloads. A rejected definition contributes NO address, so it can
            // never be probed by accident, and the accepted one's mangled name is
            // carried along as the address's provenance.
            let Some((rank, linkage)) = definition_ranking(key, &[name.to_string()]) else {
                continue;
            };
            insert_ranked_pc(
                &mut result,
                key.to_string(),
                rank,
                symbol.address(),
                linkage,
            );
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn collect_function_pcs<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    node: EntriesTreeNode<R>,
    depth: usize,
    scopes: &mut Vec<String>,
    result: &mut BTreeMap<String, RankedPc>,
    wanted: &[&str],
) -> Result<()> {
    if has_all_functions(result, wanted) {
        return Ok(());
    }
    if depth > SCOPE_NESTING_LIMIT {
        anyhow::bail!(
            "DWARF scope nesting deeper than {SCOPE_NESTING_LIMIT} levels at {} \
             (malformed DWARF?)",
            die_location(
                index,
                DieRef {
                    unit: unit_index,
                    offset: node.entry().offset(),
                }
            )
        );
    }

    let unit = index.unit(unit_index);
    let entry = node.entry();
    let scope = scope_name(dwarf, unit, entry)?;
    if let Some(scope) = &scope {
        scopes.push(scope.clone());
    }

    if entry.tag() == gimli::DW_TAG_subprogram {
        for fullname in function_names(dwarf, index, unit_index, entry, scopes)? {
            for key in probe_keys(&fullname, wanted) {
                // Rank this DIE as a definition of `key`. For a destructor and for
                // the two `rgw_rados_operate` overloads the rank comes from the
                // MANGLED linkage names reachable from the DIE, so neither the
                // deleting dtor (D0, which g++ emits BEFORE D1/D2 in both DIE and
                // symbol order) nor the wrong overload can win by position. The
                // winning mangled name travels with the address as its provenance.
                let linkage_names = entry_linkage_names(dwarf, index, unit_index, entry)?;
                let Some((rank, linkage)) = definition_ranking(key, &linkage_names) else {
                    continue;
                };
                if let Some(pc) = entry_pc(dwarf, unit, entry)? {
                    insert_ranked_pc(result, key.to_string(), rank, pc, linkage);
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
        collect_function_pcs(
            dwarf,
            index,
            unit_index,
            child,
            depth + 1,
            scopes,
            result,
            wanted,
        )?;
        if has_all_functions(result, wanted) {
            break;
        }
    }

    if scope.is_some() {
        scopes.pop();
    }
    Ok(())
}

/// Every mangled `DW_AT_linkage_name` reachable from `entry`: its own, plus the
/// ones anywhere up its `DW_AT_abstract_origin` / `DW_AT_specification` chain (an
/// optimized concrete subprogram carries its own linkage name and inherits the
/// declaration's through the origin chain).
///
/// The chain is walked TRANSITIVELY ([`attribute_origin_chain`]) so that a cdtor
/// clone -- concrete -> D1/D2 clone -> D4 unified -> class declaration -- yields
/// every name in it. Collecting MORE names cannot make an unacceptable definition
/// acceptable: [`definition_ranking`] accepts a name only if the mangled grammar
/// says it is the right variant/overload, so the deleting destructor's chain
/// (D0 -> D4) still ranks nowhere and is still rejected.
fn entry_linkage_names<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    entry: &DebuggingInformationEntry<R>,
) -> Result<Vec<String>> {
    let die = DieRef {
        unit: unit_index,
        offset: entry.offset(),
    };
    let mut names = Vec::new();
    for candidate in attribute_origin_chain(index, die)? {
        let candidate_unit = index.unit(candidate.unit);
        let candidate_entry = candidate_unit.entry(candidate.offset)?;
        if let Some(name) = linkage_name(
            dwarf_for(dwarf, index, candidate.unit),
            candidate_unit,
            &candidate_entry,
        )? {
            names.push(name);
        }
    }
    Ok(names)
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
    // A DWZ `DW_FORM_GNU_ref_alt` origin/specification lands in the
    // supplementary file, whose strings live in its own `.debug_str`.
    let referenced_dwarf = dwarf_for(dwarf, index, referenced.unit);
    let before = names.len();
    add_entry_function_names(
        referenced_dwarf,
        referenced_unit,
        &referenced_entry,
        &[],
        names,
    )?;

    let already_qualified = names[before..]
        .iter()
        .any(|name| is_probe_demangled_name(name));
    if !already_qualified {
        if let Some(name) = die_name(referenced_dwarf, referenced_unit, &referenced_entry)? {
            if PROBE_FUNCTION_LEAF_NAMES.contains(&name.as_str()) {
                let referenced_scopes = entry_scopes(dwarf, index, referenced)?.unwrap_or_default();
                add_entry_function_names(
                    referenced_dwarf,
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
        // Every caller only matches these names against probe keys, so a name
        // that cannot spell any probe's identifier is not worth demangling.
        if may_name_probe(&linkage_name, PROBE_FUNCTIONS) {
            if let Some(demangled) = demangle_function_name(&linkage_name) {
                names.push(demangled);
            }
        }
    }
    Ok(())
}

fn entry_scopes<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    die: DieRef<R::Offset>,
) -> Result<Option<Vec<String>>> {
    let dwarf = dwarf_for(dwarf, index, die.unit);
    let unit = index.unit(die.unit);
    let mut scopes = DfsScopes::new();
    let mut entries = unit.entries();
    while let Some((delta, entry)) = entries.next_dfs()? {
        scopes.step(delta);
        if entry.offset() == die.offset {
            return Ok(Some(scopes.enclosing().map(str::to_string).collect()));
        }
        if let Some(scope) = scope_name(dwarf, unit, entry)? {
            scopes.push(scope);
        }
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
    // Pointer/reference hops do not advance `field_index`, so a pointer type that
    // (directly or through qualifiers) points at itself would loop here forever.
    let mut indirections = 0;
    while field_index < path.len() {
        typedie = peel_type_qualifiers(index, typedie)?;
        let typedie_unit = index.unit(typedie.unit);
        let typedie_entry = typedie_unit.entry(typedie.offset)?;
        match typedie_entry.tag() {
            gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type
            | gimli::DW_TAG_pointer_type => {
                fields[field_index].pointer = true;
                indirections += 1;
                if indirections > TYPE_CHAIN_LIMIT {
                    anyhow::bail!(
                        "type chain at {} exceeds {TYPE_CHAIN_LIMIT} pointer/reference \
                         indirections while resolving field {:?} (malformed DWARF: \
                         reference cycle?)",
                        die_location(index, typedie),
                        path[field_index]
                    );
                }
                let Some(next_type) = die_type(index, typedie)? else {
                    return Ok(None);
                };
                typedie = next_type;
            }
            gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type | gimli::DW_TAG_class_type => {
                let Some(found) = find_member_entry(dwarf, index, typedie, path[field_index])?
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
                let member = found.member;
                let member_name = path[field_index];
                let member_unit = index.unit(member.unit);
                let member_entry = member_unit.entry(member.offset)?;
                let offset = member_offset(member_unit, &member_entry, member_name)?;
                // The member's location is relative to the class that declares it;
                // when it was found through a base class, that base's own location
                // inside `typedie` must be added, not assumed to be zero.
                let base_offset = found.base_offset.with_context(|| {
                    format!(
                        "member `{member_name}` is inherited through a base class whose \
                         location cannot be evaluated"
                    )
                })?;
                fields[field_index].offset = base_offset
                    .checked_add(i64::from(offset))
                    .and_then(|offset| i32::try_from(offset).ok())
                    .with_context(|| {
                        format!("offset of member `{member_name}` does not fit an i32")
                    })?;
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
    let Some(type_name) = die_name(dwarf_for(dwarf, index, typedie.unit), unit, &entry)? else {
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
        if let Some(fields) =
            find_named_type_field_path(dwarf, index, unit_index, &search, resolving)?
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

/// Try every definition of `search.type_name` in unit `unit_index`, in DIE
/// order, and return the first one the remaining field path resolves through.
/// Iterative (`next_dfs`) for the same reason as [`find_type_definition`].
fn find_named_type_field_path<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    search: &NamedTypeFieldSearch<'_>,
    resolving: &mut Vec<String>,
) -> Result<Option<Vec<FieldJson>>> {
    let unit = index.unit(unit_index);
    let unit_dwarf = dwarf_for(dwarf, index, unit_index);
    let mut entries = unit.entries();
    while let Some((_, entry)) = entries.next_dfs()? {
        if !matches!(
            entry.tag(),
            gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type | gimli::DW_TAG_class_type
        ) || die_name(unit_dwarf, unit, entry)?.as_deref() != Some(search.type_name)
            || entry_flag(entry, gimli::DW_AT_declaration)?
        {
            continue;
        }
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
        return decode_location_expression(unit.encoding(), frame_base, expression);
    }

    let Some(mut locations) = dwarf.attr_locations(unit, attr.value())? else {
        return Ok(None);
    };
    while let Some(location) = locations.next()? {
        if pc >= location.range.begin && pc < location.range.end {
            return decode_location_expression(unit.encoding(), frame_base, location.data);
        }
    }

    Ok(None)
}

/// Decode a variable location into the `reg + offset (+ stack)` shape the BPF
/// side reads. An operation outside that shape yields NO location (the probe's
/// descriptor is then rejected) -- skipping it would describe a different place
/// than the one DWARF names.
fn decode_location_expression<R: Reader>(
    encoding: gimli::Encoding,
    frame_base: Option<gimli::Expression<R>>,
    expression: gimli::Expression<R>,
) -> Result<Option<VarLocationJson>> {
    let mut location = VarLocationJson {
        reg: -1,
        offset: 0,
        stack: false,
    };
    let mut seen_location = false;
    let mut operations = expression.clone().operations(encoding);

    loop {
        let op_offset = operations.offset_from(&expression);
        let Some(operation) = operations.next()? else {
            break;
        };
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
                let Some(frame_base) = frame_base.as_ref() else {
                    return Ok(None);
                };
                let Some(mut frame_location) =
                    decode_location_expression(encoding, None, frame_base.clone())?
                else {
                    return Ok(None);
                };
                add_location_offset(&mut frame_location, offset)?;
                frame_location.stack = true;
                location = frame_location;
                seen_location = true;
            }
            Operation::PlusConstant { value } | Operation::UnsignedConstant { value } => {
                add_location_offset(&mut location, value as i64)?;
            }
            Operation::SignedConstant { value } => {
                add_location_offset(&mut location, value)?;
            }
            Operation::Nop => {}
            Operation::CallFrameCFA => return Ok(None),
            _ => {
                debug!(
                    op = %operation_name(&expression, op_offset),
                    "unsupported DWARF operation in a variable location; no location decoded"
                );
                return Ok(None);
            }
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
    start: DieRef<R::Offset>,
) -> Result<DieRef<R::Offset>> {
    let mut typedie = start;
    let mut hops = 0;
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
        hops += 1;
        if hops > TYPE_CHAIN_LIMIT {
            anyhow::bail!(
                "type qualifier chain starting at {} exceeds {TYPE_CHAIN_LIMIT} typedef/cv links \
                 (malformed DWARF: reference cycle?)",
                die_location(index, start)
            );
        }
        typedie = next_type;
    }
    Ok(typedie)
}

/// A `DW_TAG_member` found by [`find_member_entry`], plus the offset of the
/// (possibly inherited) class that declares it inside the searched type.
struct MemberMatch<O> {
    member: DieRef<O>,
    /// `Err` when the member was reached through a base class whose location
    /// cannot be evaluated (a virtual base's location is a runtime expression).
    /// Kept lazy so an unrelated virtual base elsewhere in the hierarchy does not
    /// fail a lookup that never goes through it.
    base_offset: Result<i64>,
}

fn find_member_entry<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    typedie: DieRef<R::Offset>,
    member_name: &str,
) -> Result<Option<MemberMatch<R::Offset>>> {
    let mut queue: Vec<(DieRef<R::Offset>, Result<i64>)> = vec![(typedie, Ok(0))];
    let mut visited: Vec<DieRef<R::Offset>> = Vec::new();
    while let Some((parent, parent_offset)) = queue.pop() {
        if visited.contains(&parent) {
            continue;
        }
        if visited.len() >= INHERITANCE_SEARCH_LIMIT {
            anyhow::bail!(
                "member lookup for {member_name:?} from {} searched more than \
                 {INHERITANCE_SEARCH_LIMIT} base classes (malformed DWARF?)",
                die_location(index, typedie)
            );
        }
        visited.push(parent);
        let unit = index.unit(parent.unit);
        // A member's owning struct may live in the DWZ supplementary file
        // (reached via `DW_FORM_GNU_ref_alt` on `DW_AT_type`); its member names
        // then resolve against the supplementary `.debug_str`.
        let parent_dwarf = dwarf_for(dwarf, index, parent.unit);
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
                    if die_name(parent_dwarf, unit, entry)?.as_deref() == Some(member_name) {
                        return Ok(Some(MemberMatch {
                            member: child_ref,
                            base_offset: parent_offset,
                        }));
                    }
                }
                gimli::DW_TAG_inheritance => {
                    if let Some(parent_type) = die_type(index, child_ref)? {
                        let base_offset = match &parent_offset {
                            Ok(outer) => inheritance_offset(unit, entry)
                                .map(|inner| outer + inner)
                                .with_context(|| {
                                    format!("cannot locate a base class while searching for `{member_name}`")
                                }),
                            Err(err) => Err(anyhow::anyhow!("{err:#}")),
                        };
                        queue.push((parent_type, base_offset));
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

/// The subprogram's FIRST `DW_TAG_formal_parameter`, in DIE order (which is
/// declaration order, per DWARF 5 §3.3.4). Used only by
/// [`FIRST_PARAM_PROBE_FUNCTIONS`], where the mangled signature has already proven
/// what parameter 0 is, so the position -- not the name -- is the identity.
///
/// Searches the subprogram's OWN children first and only then its abstract /
/// declaration instances ([`attribute_origin_chain`], nearest first). That order
/// is what makes this usable for a probe descriptor: the concrete instance is the
/// only DIE that carries `DW_AT_location`, and an abstract instance's parameter
/// (which has the name and the type but no location) must never displace it.
/// Deliberately ignores `DW_TAG_variable` (a local, never a parameter) and
/// `DW_TAG_unspecified_parameters` (the `...` of a variadic).
fn find_first_formal_parameter<R: Reader>(
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    function: &DebuggingInformationEntry<R>,
) -> Result<Option<DieRef<R::Offset>>> {
    let candidates = attribute_origin_chain(
        index,
        DieRef {
            unit: unit_index,
            offset: function.offset(),
        },
    )?;

    for parent in candidates {
        let unit = index.unit(parent.unit);
        let mut tree = unit.entries_tree(Some(parent.offset))?;
        let root = tree.root()?;
        let mut children = root.children();
        while let Some(child) = children.next()? {
            let entry = child.entry();
            if entry.tag() == gimli::DW_TAG_formal_parameter {
                return Ok(Some(DieRef {
                    unit: parent.unit,
                    offset: entry.offset(),
                }));
            }
        }
    }

    Ok(None)
}

/// The named parameter/local of `function`, preferring the CONCRETE instance's own
/// child (the only DIE that carries `DW_AT_location`) and falling back to the
/// abstract/declaration instances up the origin chain, nearest first.
fn find_function_variable<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    function: &DebuggingInformationEntry<R>,
    name: &str,
) -> Result<Option<DieRef<R::Offset>>> {
    let candidates = attribute_origin_chain(
        index,
        DieRef {
            unit: unit_index,
            offset: function.offset(),
        },
    )?;

    for parent in candidates {
        if let Some(variable) = find_function_child_variable(dwarf, index, parent, name)? {
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
        ) && child_variable_name_matches(dwarf, index, parent.unit, entry, name)?
        {
            // Return the concrete child DIE (the one that carries
            // `DW_AT_location`), never the name-bearing abstract origin.
            return Ok(Some(DieRef {
                unit: parent.unit,
                offset: entry.offset(),
            }));
        }
    }
    Ok(None)
}

/// True if `entry` names the variable `name`, either directly via `DW_AT_name`
/// or -- as on `-O2`/LTO builds where the concrete `DW_TAG_formal_parameter`
/// carries only `DW_AT_location`+`DW_AT_abstract_origin` -- through the name of a
/// DIE anywhere up its abstract-origin/specification chain.
///
/// The chain is walked TRANSITIVELY ([`attribute_origin_chain`]). One hop is not
/// enough: a cdtor clone's implicit `this` is two hops from the DIE that carries
/// `DW_AT_name("this")`, and stopping at one hop lands on a DIE with no name at
/// all -- so the parameter would not be recognised, the location-bearing concrete
/// DIE would be passed over, and the descriptor lost.
fn child_variable_name_matches<R: Reader>(
    dwarf: &Dwarf<R>,
    index: &DwarfUnitIndex<R>,
    unit_index: usize,
    entry: &DebuggingInformationEntry<R>,
    name: &str,
) -> Result<bool> {
    let die = DieRef {
        unit: unit_index,
        offset: entry.offset(),
    };
    for candidate in attribute_origin_chain(index, die)? {
        let candidate_unit = index.unit(candidate.unit);
        let candidate_entry = candidate_unit.entry(candidate.offset)?;
        if die_name(
            dwarf_for(dwarf, index, candidate.unit),
            candidate_unit,
            &candidate_entry,
        )?
        .as_deref()
            == Some(name)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn die_type<R: Reader>(
    index: &DwarfUnitIndex<R>,
    die: DieRef<R::Offset>,
) -> Result<Option<DieRef<R::Offset>>> {
    // A direct `DW_AT_type` always wins. On `-O2`/LTO builds the concrete DIE
    // (e.g. a `DW_TAG_formal_parameter` carrying only location + origin) has no
    // `DW_AT_type` of its own; the type lives further up the abstract-origin
    // chain -- TWO hops up for a cdtor clone's `this`, which is why the chain is
    // walked transitively (see `attribute_origin_chain`). Uses
    // `index.referenced_die`, so cross-unit LTO origins encoded as
    // `DW_FORM_ref_addr` (`DebugInfoRef`) resolve too.
    for candidate in attribute_origin_chain(index, die)? {
        let unit = index.unit(candidate.unit);
        let entry = unit.entry(candidate.offset)?;
        if let Some(typedie) = index.referenced_die(candidate.unit, &entry, gimli::DW_AT_type)? {
            return Ok(Some(typedie));
        }
    }
    Ok(None)
}

/// The facts about a `DW_TAG_member` that decide whether an ABSENT location
/// attribute may be read as offset 0.
#[derive(Clone, Copy, Debug, Default)]
struct MemberShape {
    /// A static data member (`DW_AT_external`/`DW_AT_declaration`): it has no
    /// location inside the object at all.
    is_static: bool,
    /// A bit-field located by `DW_AT_data_bit_offset`: its start is a BIT offset.
    has_data_bit_offset: bool,
}

/// Byte offset of `member` inside the class that declares it.
///
/// Every shape this cannot evaluate is an ERROR naming the member, never a
/// default: an offset of 0 that is not really 0 makes the BPF side read the wrong
/// bytes of every request, silently.
fn member_offset<R: Reader>(
    unit: &gimli::Unit<R>,
    member: &DebuggingInformationEntry<R>,
    member_name: &str,
) -> Result<i32> {
    let shape = MemberShape {
        is_static: entry_flag(member, gimli::DW_AT_external)?
            || entry_flag(member, gimli::DW_AT_declaration)?,
        has_data_bit_offset: member.attr(gimli::DW_AT_data_bit_offset)?.is_some(),
    };
    let location = member
        .attr(gimli::DW_AT_data_member_location)?
        .map(|attr| attr.value());
    resolve_member_offset(unit.encoding(), member_name, location, shape)
}

fn resolve_member_offset<R: Reader>(
    encoding: gimli::Encoding,
    member_name: &str,
    location: Option<AttributeValue<R>>,
    shape: MemberShape,
) -> Result<i32> {
    let Some(location) = location else {
        // DWARF 5 5.7.6: a data member that starts at the beginning of its
        // containing entity may omit both location attributes. That reading is only
        // valid for an ordinary, non-static, byte-addressed member.
        if shape.is_static {
            anyhow::bail!("member `{member_name}` is a static data member and has no offset");
        }
        if shape.has_data_bit_offset {
            anyhow::bail!(
                "member `{member_name}` is located by DW_AT_data_bit_offset, which is not supported"
            );
        }
        return Ok(0);
    };
    let offset = attr_offset(encoding, location)
        .with_context(|| format!("cannot evaluate the location of member `{member_name}`"))?;
    i32::try_from(offset)
        .with_context(|| format!("offset {offset} of member `{member_name}` does not fit an i32"))
}

/// Offset of a base class (`DW_TAG_inheritance`) inside the derived class.
fn inheritance_offset<R: Reader>(
    unit: &gimli::Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Result<i64> {
    // Same DWARF 5 rule as for members: a base at the start of the derived class
    // may omit its location.
    let Some(attr) = entry.attr(gimli::DW_AT_data_member_location)? else {
        return Ok(0);
    };
    attr_offset(unit.encoding(), attr.value())
}

/// Evaluate a constant-class or simple-expression `DW_AT_data_member_location`.
/// Any other form is an error: callers must never mistake "unsupported" for 0.
fn attr_offset<R: Reader>(encoding: gimli::Encoding, value: AttributeValue<R>) -> Result<i64> {
    Ok(match value {
        AttributeValue::Data1(value) => value as i64,
        AttributeValue::Data2(value) => value as i64,
        AttributeValue::Data4(value) => value as i64,
        AttributeValue::Data8(value) => value as i64,
        AttributeValue::Sdata(value) => value,
        AttributeValue::Udata(value) => {
            i64::try_from(value).context("DW_AT_data_member_location does not fit an i64")?
        }
        AttributeValue::Exprloc(expression) => expression_offset(encoding, expression)?,
        other => anyhow::bail!("unsupported DW_AT_data_member_location form {other:?}"),
    })
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
    encoding: gimli::Encoding,
    expression: gimli::Expression<R>,
) -> Result<i64> {
    let mut offset: i64 = 0;
    let mut operations = expression.clone().operations(encoding);
    loop {
        let op_offset = operations.offset_from(&expression);
        let Some(operation) = operations.next()? else {
            break;
        };
        let value = match operation {
            Operation::PlusConstant { value } | Operation::UnsignedConstant { value } => {
                i64::try_from(value).context("DWARF member location constant does not fit i64")?
            }
            Operation::SignedConstant { value } | Operation::FrameOffset { offset: value } => value,
            Operation::Nop => continue,
            _ => anyhow::bail!(
                "unsupported DWARF operation {} in a member location expression",
                operation_name(&expression, op_offset)
            ),
        };
        offset = offset
            .checked_add(value)
            .context("DWARF member location offset overflow")?;
    }
    Ok(offset)
}

/// The `DW_OP_*` name of the operation at `op_offset` in `expression`, for error
/// messages an operator can act on.
fn operation_name<R: Reader>(expression: &gimli::Expression<R>, op_offset: R::Offset) -> String {
    let mut reader = expression.0.clone();
    reader
        .skip(op_offset)
        .and_then(|()| reader.read_u8())
        .map(|opcode| gimli::DwOp(opcode).to_string())
        .unwrap_or_else(|_| "<unreadable DW_OP>".to_string())
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

/// Does the code of the subprogram `entry` cover `pc`?
///
/// Uses the DIE's full range set (`DW_AT_low_pc`/`DW_AT_high_pc`, or
/// `DW_AT_ranges` -- an optimized Ceph function is routinely split into a hot and
/// a cold range). A DIE with no code at all -- a declaration, or an abstract
/// instance -- covers nothing, which is exactly the answer wanted for it.
fn die_contains_pc<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    pc: u64,
) -> Result<bool> {
    let mut ranges = dwarf.die_ranges(unit, entry)?;
    while let Some(range) = ranges.next()? {
        if pc >= range.begin && pc < range.end {
            return Ok(true);
        }
    }
    Ok(false)
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
    budget: &mut SectionBudget<'_>,
) -> Result<Cow<'data, [u8]>> {
    let Some(section) = file
        .section_by_name(section.name())
        .or_else(|| file.section_by_name(&macho_section_name(section.name())))
    else {
        return Ok(Cow::Borrowed(&[]));
    };
    let name = section.name().unwrap_or("<unknown>");
    let compressed = section
        .compressed_data()
        .with_context(|| format!("failed to read {name}"))?;
    if compressed.format != CompressionFormat::None {
        // Charge the DECLARED size before `decompress` reserves and fills it.
        budget.reserve(name, compressed.uncompressed_size)?;
    }
    compressed
        .decompress()
        .with_context(|| format!("failed to decompress {name}"))
}

fn load_dwarf_sections<'data>(
    file: &object::File<'data>,
    path: &Path,
    limit: u64,
) -> Result<Dwarf<Cow<'data, [u8]>>> {
    let mut budget = SectionBudget::new(path, limit);
    Dwarf::load(|section| load_section(file, section, &mut budget))
}

#[cfg(test)]
fn load_section_unbounded<'data>(
    file: &object::File<'data>,
    section: gimli::SectionId,
) -> Result<Cow<'data, [u8]>> {
    load_section(
        file,
        section,
        &mut SectionBudget::new(Path::new("<test>"), u64::MAX),
    )
}

/// Returns the DWARF-bearing object bytes and the on-disk path they came from.
/// The path is the debug file itself (the main binary when debug info is
/// embedded, otherwise the separate `.debug`/build-id file); DWZ supplementary
/// lookup keys off that file's directory.
fn debug_data<'data>(
    path: &Path,
    file: &object::File<'data>,
    data: &'data [u8],
    limit: u64,
) -> Result<(Cow<'data, [u8]>, PathBuf)> {
    if file.has_debug_symbols() {
        return Ok((Cow::Borrowed(data), path.to_path_buf()));
    }

    if let Some((bytes, debug_path)) = separate_debug_file_with_limit(path, file, limit)? {
        return Ok((Cow::Owned(bytes), debug_path));
    }

    Ok((Cow::Borrowed(data), path.to_path_buf()))
}

/// Locate `path`'s separate debug file (`.gnu_debuglink`, then the
/// `.build-id/xx/yyyy.debug` tree) and PROVE it belongs to this binary before
/// any of its DWARF or symbols are trusted. Returns `Ok(None)` when no candidate
/// exists, and an error when candidates exist but none of them matches: a debug
/// file from another build yields wrong field offsets and wrong addresses with no
/// other symptom, and the build-ID preflight check cannot see it (it compares
/// the binary with itself).
///
/// The proof is the NT_GNU_BUILD_ID when both files carry one (equality
/// required), otherwise the `.gnu_debuglink` CRC-32 over the whole debug file.
/// The build ID wins when both are available because post-processing such as
/// dwz can rewrite a debug file after its CRC was recorded.
#[allow(dead_code)] // The test helper preserves a convenient default-limit API.
pub(crate) fn separate_debug_file(
    path: &Path,
    file: &object::File<'_>,
) -> Result<Option<(Vec<u8>, PathBuf)>> {
    separate_debug_file_with_limit(path, file, DEFAULT_MAX_DEBUG_FILE_BYTES)
}

pub(crate) fn separate_debug_file_with_limit(
    path: &Path,
    file: &object::File<'_>,
    limit: u64,
) -> Result<Option<(Vec<u8>, PathBuf)>> {
    let binary_build_id = file.build_id()?;
    let mut rejected = Vec::new();

    if let Some((filename, crc)) = file.gnu_debuglink()? {
        let filename =
            std::str::from_utf8(filename).context(".gnu_debuglink filename is not UTF-8")?;
        let candidates = debuglink_candidates(path, filename);
        if let Some(found) =
            first_matching_debug_file(candidates, binary_build_id, Some(crc), limit, &mut rejected)?
        {
            return Ok(Some(found));
        }
    }

    if let Some(build_id) = binary_build_id {
        let candidates = build_id_debug_candidates(path, &hex_string(build_id));
        if let Some(found) =
            first_matching_debug_file(candidates, binary_build_id, None, limit, &mut rejected)?
        {
            return Ok(Some(found));
        }
    }

    if !rejected.is_empty() {
        anyhow::bail!(
            "refusing separate debug info for {}: {}. Install the debuginfo that matches the \
             probed binary (or point --dwarf-source at a binary with embedded DWARF)",
            path.display(),
            rejected.join("; ")
        );
    }
    Ok(None)
}

/// The subset of `wanted` that are `DW_AT_low_pc` of a `DW_TAG_subprogram` in
/// `file`'s DWARF: a concrete, out-of-line function starts there. Only
/// `low_pc` counts -- the first `DW_AT_ranges` entry of a hot/cold-split
/// function is not guaranteed to be its entry.
pub(crate) fn subprogram_low_pcs(
    file: &object::File<'_>,
    wanted: &std::collections::BTreeSet<u64>,
    path: &Path,
    limit: u64,
) -> Result<std::collections::BTreeSet<u64>> {
    let endian = if file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let dwarf_cow = load_dwarf_sections(file, path, limit)?;
    #[allow(deprecated)]
    let dwarf = dwarf_cow.borrow(|section| EndianSlice::new(section, endian));
    let mut found = std::collections::BTreeSet::new();
    let mut headers = dwarf.units();
    while let Some(header) = headers.next()? {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();
        while let Some((_, entry)) = entries.next_dfs()? {
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }
            let Some(attr) = entry.attr(gimli::DW_AT_low_pc)? else {
                continue;
            };
            if let Some(pc) = dwarf.attr_address(&unit, attr.value())? {
                if wanted.contains(&pc) {
                    found.insert(pc);
                }
            }
        }
        if found.len() == wanted.len() {
            break;
        }
    }
    Ok(found)
}

fn first_matching_debug_file(
    candidates: Vec<PathBuf>,
    binary_build_id: Option<&[u8]>,
    debuglink_crc: Option<u32>,
    limit: u64,
    rejected: &mut Vec<String>,
) -> Result<Option<(Vec<u8>, PathBuf)>> {
    for candidate in candidates.into_iter().filter(|path| path.is_file()) {
        let bytes = read_file_bounded(&candidate, limit, "separate debug file")?;
        match debug_file_mismatch(binary_build_id, debuglink_crc, &bytes) {
            None => return Ok(Some((bytes, candidate))),
            Some(reason) => {
                warn!(
                    path = %candidate.display(),
                    reason = %reason,
                    "ignoring a separate debug file that does not belong to the probed binary"
                );
                rejected.push(format!("{} ({reason})", candidate.display()));
            }
        }
    }
    Ok(None)
}

/// Why `debug_bytes` cannot be proven to be this binary's debug file, or `None`
/// when it is proven.
fn debug_file_mismatch(
    binary_build_id: Option<&[u8]>,
    debuglink_crc: Option<u32>,
    debug_bytes: &[u8],
) -> Option<String> {
    let debug_build_id = match object::File::parse(debug_bytes) {
        Ok(debug_file) => match debug_file.build_id() {
            Ok(build_id) => build_id,
            Err(err) => return Some(format!("unreadable build ID: {err}")),
        },
        Err(err) => return Some(format!("not a supported object file: {err}")),
    };
    if let (Some(expected), Some(actual)) = (binary_build_id, debug_build_id) {
        return (expected != actual).then(|| {
            format!(
                "build ID {} does not match the binary's {}",
                hex_string(actual),
                hex_string(expected)
            )
        });
    }
    let Some(expected_crc) = debuglink_crc else {
        return Some(
            "the debug file carries no build ID, so nothing proves it belongs to the binary"
                .to_string(),
        );
    };
    let mut crc = flate2::Crc::new();
    crc.update(debug_bytes);
    let actual_crc = crc.sum();
    (actual_crc != expected_crc).then(|| {
        format!(
            ".gnu_debuglink CRC {expected_crc:#010x} does not match the file's {actual_crc:#010x}"
        )
    })
}

/// Best-effort location and validation of the DWZ supplementary object named by
/// the debug file's `.gnu_debugaltlink`. Returns the supplementary object's raw
/// bytes when the file is found and its build-id matches the link; otherwise
/// warns and returns `None` so extraction continues with whatever resolves
/// without it (consistent with tolerating missing supplementary string refs).
fn load_sup_object_bytes(
    debug_file: &object::File<'_>,
    debug_file_path: &Path,
    limit: u64,
) -> Option<Vec<u8>> {
    let section = debug_file.section_by_name(".gnu_debugaltlink")?;
    let data = match section.data() {
        Ok(data) => data,
        Err(err) => {
            warn!(error = %err, "failed to read .gnu_debugaltlink section; ignoring supplementary DWARF");
            return None;
        }
    };
    let Some((alt_path, alt_build_id)) = parse_debugaltlink(data) else {
        warn!("malformed .gnu_debugaltlink section; ignoring supplementary DWARF");
        return None;
    };
    let Some(sup_path) = first_existing(debugaltlink_candidates(debug_file_path, alt_path)) else {
        warn!(
            alt_path = %alt_path.display(),
            "DWZ supplementary file from .gnu_debugaltlink not found; \
             names and types resolved through it will be unavailable"
        );
        return None;
    };
    let bytes = match read_file_bounded(&sup_path, limit, "DWZ supplementary file") {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(path = %sup_path.display(), error = format!("{err:#}"), "failed to read DWZ supplementary file; ignoring it");
            return None;
        }
    };
    let sup = match object::File::parse(bytes.as_slice()) {
        Ok(sup) => sup,
        Err(err) => {
            warn!(path = %sup_path.display(), error = %err, "DWZ supplementary file is not a supported object; ignoring it");
            return None;
        }
    };
    let actual_build_id = sup.build_id().ok().flatten();
    if sup_build_id_matches(alt_build_id, actual_build_id) {
        Some(bytes)
    } else {
        warn!(
            path = %sup_path.display(),
            "DWZ supplementary build-id does not match .gnu_debugaltlink; ignoring it"
        );
        None
    }
}

/// Parse a `.gnu_debugaltlink` section body: a NUL-terminated path to the DWZ
/// supplementary file, followed by that file's build-id bytes.
fn parse_debugaltlink(data: &[u8]) -> Option<(&Path, &[u8])> {
    let nul = data.iter().position(|&byte| byte == 0)?;
    let path_bytes = &data[..nul];
    let build_id = &data[nul + 1..];
    if path_bytes.is_empty() || build_id.is_empty() {
        return None;
    }
    let path = std::str::from_utf8(path_bytes).ok()?;
    Some((Path::new(path), build_id))
}

/// True when the supplementary object's build-id equals the id embedded in
/// `.gnu_debugaltlink`. A missing build-id never matches.
fn sup_build_id_matches(expected: &[u8], actual: Option<&[u8]>) -> bool {
    actual == Some(expected)
}

/// Candidate on-disk locations for the DWZ supplementary file. The
/// `.gnu_debugaltlink` path is encoded relative to the debug file's directory;
/// also try the conventional `/usr/lib/debug/.dwz/` tree, rooted under the debug
/// file's ancestors so a `/proc/<pid>/root/...` debug file finds the
/// namespace-local copy.
fn debugaltlink_candidates(debug_file: &Path, alt_path: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if alt_path.is_absolute() {
        push_unique(&mut candidates, alt_path.to_path_buf());
    }
    if let Some(parent) = debug_file.parent() {
        push_unique(&mut candidates, parent.join(alt_path));
    }
    if let Some(basename) = alt_path.file_name() {
        if let Some(parent) = debug_file.parent() {
            for ancestor in parent.ancestors() {
                push_unique(
                    &mut candidates,
                    ancestor.join("usr/lib/debug/.dwz").join(basename),
                );
            }
        }
        push_unique(
            &mut candidates,
            Path::new("/usr/lib/debug/.dwz").join(basename),
        );
    }
    candidates
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

    fn test_encoding() -> gimli::Encoding {
        gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 4,
            address_size: 8,
        }
    }

    fn expression(bytes: &[u8]) -> gimli::Expression<EndianSlice<'_, gimli::LittleEndian>> {
        gimli::Expression(EndianSlice::new(bytes, gimli::LittleEndian))
    }

    #[test]
    fn member_location_expression_evaluates_supported_constant_ops() {
        let bytes = [gimli::DW_OP_plus_uconst.0, 0x18];
        let offset = expression_offset(test_encoding(), expression(&bytes)).unwrap();
        assert_eq!(offset, 0x18);
    }

    #[test]
    fn member_location_expression_with_an_unsupported_op_is_an_error_not_offset_zero() {
        // A virtual base's location: `DW_OP_dup; DW_OP_deref; ...`. It used to
        // evaluate to offset 0, so the BPF side read the wrong bytes silently.
        let bytes = [gimli::DW_OP_dup.0, gimli::DW_OP_deref.0];
        let err = expression_offset(test_encoding(), expression(&bytes)).unwrap_err();
        assert!(format!("{err:#}").contains("DW_OP_dup"), "message: {err:#}");
    }

    #[test]
    fn member_offset_names_the_member_and_the_unsupported_op() {
        let bytes = [gimli::DW_OP_dup.0, gimli::DW_OP_deref.0];
        let err = resolve_member_offset(
            test_encoding(),
            "target",
            Some(AttributeValue::Exprloc(expression(&bytes))),
            MemberShape::default(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("`target`"), "message: {msg}");
        assert!(msg.contains("DW_OP_dup"), "message: {msg}");
    }

    #[test]
    fn member_offset_refuses_unsupported_forms_and_out_of_range_values() {
        let loclist = resolve_member_offset::<EndianSlice<'_, gimli::LittleEndian>>(
            test_encoding(),
            "target",
            Some(AttributeValue::LocationListsRef(
                gimli::LocationListsOffset(0),
            )),
            MemberShape::default(),
        );
        assert!(loclist.is_err());

        // Used to be `i32::try_from(..).ok()` -> None -> `unwrap_or_default()` = 0.
        let huge = resolve_member_offset::<EndianSlice<'_, gimli::LittleEndian>>(
            test_encoding(),
            "target",
            Some(AttributeValue::Udata(1 << 40)),
            MemberShape::default(),
        );
        let msg = format!("{:#}", huge.unwrap_err());
        assert!(msg.contains("`target`"), "message: {msg}");
    }

    #[test]
    fn absent_member_location_is_offset_zero_only_for_a_plain_data_member() {
        // DWARF 5 5.7.6: a member that starts at the beginning of its container may
        // omit both location attributes.
        let plain = resolve_member_offset::<EndianSlice<'_, gimli::LittleEndian>>(
            test_encoding(),
            "first",
            None,
            MemberShape::default(),
        )
        .unwrap();
        assert_eq!(plain, 0);

        // A static data member has no in-object location at all, and a bit-field
        // located by DW_AT_data_bit_offset is not at "offset 0" either.
        for shape in [
            MemberShape {
                is_static: true,
                has_data_bit_offset: false,
            },
            MemberShape {
                is_static: false,
                has_data_bit_offset: true,
            },
        ] {
            let err = resolve_member_offset::<EndianSlice<'_, gimli::LittleEndian>>(
                test_encoding(),
                "counter",
                None,
                shape,
            )
            .unwrap_err();
            assert!(format!("{err:#}").contains("`counter`"), "message: {err:#}");
        }
    }

    #[test]
    fn a_location_expression_with_an_unsupported_op_yields_no_location() {
        // `DW_OP_reg5; DW_OP_deref`: ignoring the deref would hand the BPF side the
        // register itself -- a wrong location, not a missing one.
        let bytes = [gimli::DW_OP_reg5.0, gimli::DW_OP_deref.0];
        let location =
            decode_location_expression(test_encoding(), None, expression(&bytes)).unwrap();
        assert!(location.is_none());

        let bytes = [gimli::DW_OP_reg5.0];
        let location =
            decode_location_expression(test_encoding(), None, expression(&bytes)).unwrap();
        assert_eq!(location.map(|location| location.reg), Some(5));

        // The frame-relative address is only valid if all following operations
        // are also understood. In particular, dropping a dereference changes
        // the variable's location and must fail closed.
        let frame_base = expression(&[gimli::DW_OP_reg5.0]);
        let frame_location = [gimli::DW_OP_fbreg.0, 0x78, gimli::DW_OP_deref.0];
        assert!(decode_location_expression(
            test_encoding(),
            Some(frame_base),
            expression(&frame_location),
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn inherited_member_offsets_include_the_base_class_offset() {
        // `struct Derived : A, B` and the probed member lives in `B`, which sits at
        // offset 16 inside `Derived`. The member's own location (8) is relative to
        // `B`, so the real offset is 24 -- not 8, which is what dropping the
        // inheritance edge's location produced.
        let Some(binary) = compile_cpp_source(
            "inherited-member-fixture",
            r#"
            struct A { long a0; long a1; };
            struct B { long b0; long target; };
            struct Derived : A, B { long own; };
            long inspect(Derived* outer) { return outer->target; }
            int main() { Derived d{}; return (int)inspect(&d); }
            "#,
        ) else {
            return;
        };
        let Some(fields) =
            fixture_field_path(&binary, "inspect", "outer", &["outer", "target"]).unwrap()
        else {
            // No DWARF in the linked binary (macOS keeps it in a .dSYM); the Linux
            // CI build runs this for real.
            return;
        };
        assert!(fields[1].pointer || fields[0].pointer);
        assert_eq!(fields[1].offset, 24);
    }

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

    /// Split `binary` into a stripped copy carrying a `.gnu_debuglink` and its
    /// `--only-keep-debug` file. `None` when objcopy is unavailable (macOS).
    fn objcopy_debuglink_pair(binary: &Path) -> Option<(PathBuf, PathBuf)> {
        let objcopy = std::env::var_os("OBJCOPY").unwrap_or_else(|| "objcopy".into());
        let debug_file = binary.with_extension("debug");
        let stripped = binary.with_file_name("fixture-stripped");

        if !std::process::Command::new(&objcopy)
            .args(["--only-keep-debug"])
            .arg(binary)
            .arg(&debug_file)
            .status()
            .is_ok_and(|status| status.success())
        {
            return None;
        }
        std::fs::copy(binary, &stripped).ok()?;
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
            return None;
        }
        Some((stripped, debug_file))
    }

    #[test]
    fn parses_probe_function_pcs_from_gnu_debuglink_when_objcopy_is_available() {
        let Some(binary) = compile_cpp_fixture() else {
            return;
        };
        let Some((stripped, _)) = objcopy_debuglink_pair(&binary) else {
            return;
        };

        let info = from_paths(&[stripped.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();

        assert!(module.function_addr("Objecter::_send_op").is_some());
        assert!(module.function_addr("Objecter::_finish_op").is_some());
        assert!(module.function_addr("RGWREST::get_handler").is_some());
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = flate2::Crc::new();
        crc.update(bytes);
        crc.sum()
    }

    /// Write `binary` (linking to `radosgw.debug`) and `debug` side by side and
    /// return the binary's path.
    fn write_debuglink_pair(name: &str, binary: &[u8], debug: &[u8]) -> PathBuf {
        let dir = crate::test_elf::temp_dir(name);
        std::fs::write(dir.join("radosgw.debug"), debug).unwrap();
        let path = dir.join("radosgw");
        std::fs::write(&path, binary).unwrap();
        path
    }

    fn lookup_debug_file(path: &Path) -> Result<Option<(Vec<u8>, PathBuf)>> {
        let data = std::fs::read(path).unwrap();
        let file = object::File::parse(data.as_slice()).unwrap();
        separate_debug_file(path, &file)
    }

    #[test]
    fn a_debuglink_file_with_a_different_build_id_is_refused() {
        use crate::test_elf::{build_id_note, debuglink, TestElf};
        let debug = TestElf::pie(0x1000, 0x100)
            .section(build_id_note(&[0xbb; 20]))
            .build();
        // The CRC even matches: a build-ID disagreement still wins.
        let binary = TestElf::pie(0x1000, 0x100)
            .section(build_id_note(&[0xaa; 20]))
            .section(debuglink("radosgw.debug", crc32(&debug)))
            .build();
        let path = write_debuglink_pair("debuglink-build-id-mismatch", &binary, &debug);

        let err = lookup_debug_file(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("build ID"), "message: {msg}");
        assert!(msg.contains(&"bb".repeat(20)), "message: {msg}");
    }

    #[test]
    fn a_debuglink_file_with_the_same_build_id_is_accepted_even_with_a_stale_crc() {
        // dwz rewrites the debug file after the debuglink CRC was computed; the
        // build ID is the stronger identity and is what gdb trusts first too.
        use crate::test_elf::{build_id_note, debuglink, TestElf};
        let debug = TestElf::pie(0x1000, 0x100)
            .section(build_id_note(&[0xaa; 20]))
            .build();
        let binary = TestElf::pie(0x1000, 0x100)
            .section(build_id_note(&[0xaa; 20]))
            .section(debuglink("radosgw.debug", crc32(&debug) ^ 1))
            .build();
        let path = write_debuglink_pair("debuglink-build-id-match", &binary, &debug);

        let (bytes, found) = lookup_debug_file(&path).unwrap().unwrap();
        assert_eq!(bytes, debug);
        assert_eq!(found, path.with_file_name("radosgw.debug"));
    }

    #[test]
    fn without_build_ids_the_debuglink_crc_must_match() {
        use crate::test_elf::{debuglink, TestElf};
        let debug = TestElf::pie(0x1000, 0x100).build();

        let corrupted = TestElf::pie(0x1000, 0x100)
            .section(debuglink("radosgw.debug", crc32(&debug) ^ 0xdead_beef))
            .build();
        let path = write_debuglink_pair("debuglink-crc-mismatch", &corrupted, &debug);
        let msg = format!("{:#}", lookup_debug_file(&path).unwrap_err());
        assert!(msg.contains("CRC"), "message: {msg}");

        let intact = TestElf::pie(0x1000, 0x100)
            .section(debuglink("radosgw.debug", crc32(&debug)))
            .build();
        let path = write_debuglink_pair("debuglink-crc-match", &intact, &debug);
        assert!(lookup_debug_file(&path).unwrap().is_some());
    }

    #[test]
    fn a_build_id_tree_debug_file_must_carry_the_same_build_id() {
        use crate::test_elf::{build_id_note, TestElf};
        let id = [0x0a; 20];
        let dir = crate::test_elf::temp_dir("build-id-tree");
        let debug_dir = dir.join("usr/lib/debug/.build-id/0a");
        std::fs::create_dir_all(&debug_dir).unwrap();
        let debug_path = debug_dir.join(format!("{}.debug", "0a".repeat(19)));
        let path = dir.join("radosgw");
        std::fs::write(
            &path,
            TestElf::pie(0x1000, 0x100)
                .section(build_id_note(&id))
                .build(),
        )
        .unwrap();

        // No build ID in the debug file: nothing proves it belongs to the binary.
        std::fs::write(&debug_path, TestElf::pie(0x1000, 0x100).build()).unwrap();
        assert!(lookup_debug_file(&path).is_err());

        std::fs::write(
            &debug_path,
            TestElf::pie(0x1000, 0x100)
                .section(build_id_note(&[0x0b; 20]))
                .build(),
        )
        .unwrap();
        assert!(lookup_debug_file(&path).is_err());

        std::fs::write(
            &debug_path,
            TestElf::pie(0x1000, 0x100)
                .section(build_id_note(&id))
                .build(),
        )
        .unwrap();
        let (_, found) = lookup_debug_file(&path).unwrap().unwrap();
        assert_eq!(found, debug_path);
    }

    #[test]
    fn the_probed_binarys_own_symbol_wins_over_the_debug_files() {
        use crate::test_elf::{build_id_note, debuglink, TestElf};
        const GET_HANDLER: &str = "_ZN7RGWREST11get_handlerEv";
        let debug = TestElf::pie(0x1000, 0x100)
            .section(build_id_note(&[0xcc; 20]))
            .function(GET_HANDLER, 0x1080)
            .build();
        let binary = TestElf::pie(0x1000, 0x100)
            .section(build_id_note(&[0xcc; 20]))
            .section(debuglink("radosgw.debug", crc32(&debug)))
            .function(GET_HANDLER, 0x1040)
            .build();
        let path = write_debuglink_pair("own-symbols-win", &binary, &debug);

        let module = parse_module(&path, "radosgw", &mut None, &NativeOptions::default())
            .unwrap()
            .module;
        assert_eq!(module.func2pc.get(RGWREST_GET_HANDLER), Some(&0x1040));
    }

    #[test]
    fn refuses_a_gnu_debuglink_file_from_another_build_when_objcopy_is_available() {
        let (Some(binary), Some(other)) = (compile_cpp_fixture(), compile_field_fixture()) else {
            return;
        };
        let Some((stripped, debug_file)) = objcopy_debuglink_pair(&binary) else {
            return;
        };
        // Replace the linked debug file with ANOTHER build's, under the same name:
        // the stale-debuginfo-package situation. Its DWARF describes other code.
        let Some((_, other_debug)) = objcopy_debuglink_pair(&other) else {
            return;
        };
        std::fs::copy(&other_debug, &debug_file).unwrap();

        let err = from_paths(&[stripped.as_path()]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("refusing separate debug info"),
            "message: {msg}"
        );
    }

    /// The artifact addresses native extraction produces for `binary`, as
    /// `validate_target` requests. `None` off ELF (macOS Mach-O fixtures).
    fn elf_probe_requests(binary: &Path) -> Option<Vec<(String, u64)>> {
        let data = std::fs::read(binary).ok()?;
        let file = object::File::parse(data.as_slice()).ok()?;
        if file.format() != object::BinaryFormat::Elf {
            return None;
        }
        let info = from_paths(&[binary]).unwrap();
        let module = info.modules.values().next().unwrap();
        let requests = module
            .func2pc
            .iter()
            .map(|(function, addr)| (function.clone(), *addr))
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 3, "fixture resolves all three probes");
        Some(requests)
    }

    fn as_requests(requests: &[(String, u64)]) -> Vec<(&str, u64)> {
        requests
            .iter()
            .map(|(function, addr)| (function.as_str(), *addr))
            .collect()
    }

    #[test]
    fn real_probe_addresses_validate_as_function_entries() {
        use crate::probe_sites::{validate_target, EntryEvidence};
        let Some(binary) = compile_cpp_fixture() else {
            return;
        };
        let Some(requests) = elf_probe_requests(&binary) else {
            return;
        };
        let sites = validate_target(&binary, "fixture", &as_requests(&requests)).unwrap();
        assert!(sites
            .iter()
            .all(|site| site.evidence == EntryEvidence::Symbol));

        // One byte in is inside the function, not its entry.
        let (function, addr) = &requests[0];
        assert!(validate_target(&binary, "fixture", &[(function.as_str(), addr + 1)]).is_err());

        // With no symbol table left, the DWARF subprogram low_pc still proves them.
        let objcopy = std::env::var_os("OBJCOPY").unwrap_or_else(|| "objcopy".into());
        let no_symtab = binary.with_file_name("fixture-no-symtab");
        if !std::process::Command::new(&objcopy)
            .args(["--strip-all", "--keep-section=.debug_*"])
            .arg(&binary)
            .arg(&no_symtab)
            .status()
            .is_ok_and(|status| status.success())
        {
            return;
        }
        let sites = validate_target(&no_symtab, "fixture", &as_requests(&requests)).unwrap();
        assert!(
            sites
                .iter()
                .all(|site| site.evidence == EntryEvidence::DwarfLowPc),
            "{sites:?}"
        );
    }

    #[test]
    fn real_non_pie_probe_addresses_translate_to_file_offsets() {
        let Some(binary) = compile_cpp_fixture_with_flags(&["-no-pie", "-fno-pie"]) else {
            return;
        };
        let Some(requests) = elf_probe_requests(&binary) else {
            return;
        };
        let sites =
            crate::probe_sites::validate_target(&binary, "fixture", &as_requests(&requests))
                .unwrap();
        for site in sites {
            // ET_EXEC text is linked at a base (0x400000 on x86_64/aarch64), so the
            // vaddr the artifact carries is NOT the offset the uprobe API needs.
            assert!(
                site.file_offset < site.vaddr,
                "{} vaddr {:#x} offset {:#x}",
                site.function,
                site.vaddr,
                site.file_offset
            );
        }
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
    fn parses_gnu_debugaltlink_path_and_build_id() {
        let mut data = Vec::new();
        data.extend_from_slice(b"../../.dwz/ceph-debugsource-18.2.8-0.el9.x86_64");
        data.push(0);
        let build_id = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
        data.extend_from_slice(&build_id);

        let (path, parsed_build_id) =
            parse_debugaltlink(&data).expect("well-formed .gnu_debugaltlink parses");
        assert_eq!(
            path,
            Path::new("../../.dwz/ceph-debugsource-18.2.8-0.el9.x86_64")
        );
        assert_eq!(parsed_build_id, build_id);
    }

    #[test]
    fn rejects_malformed_gnu_debugaltlink() {
        // No NUL terminator at all.
        assert!(parse_debugaltlink(b"no-nul-terminator").is_none());
        // Path present but no build-id bytes follow the NUL.
        assert!(parse_debugaltlink(b"path\0").is_none());
        // Empty section.
        assert!(parse_debugaltlink(b"").is_none());
        // Empty path (leading NUL) is not a usable link.
        assert!(parse_debugaltlink(b"\0\x01\x02").is_none());
    }

    #[test]
    fn supplementary_build_id_mismatch_is_rejected() {
        let expected = [0x01u8, 0x02, 0x03, 0x04];
        assert!(sup_build_id_matches(&expected, Some(&expected)));
        // A different id, a truncated id, and a missing id are all rejected so a
        // stale/wrong .dwz file is never silently trusted.
        assert!(!sup_build_id_matches(
            &expected,
            Some(&[0x01, 0x02, 0x03, 0x05])
        ));
        assert!(!sup_build_id_matches(&expected, Some(&[0x01, 0x02])));
        assert!(!sup_build_id_matches(&expected, None));
    }

    #[test]
    fn debugaltlink_candidates_cover_relative_and_dwz_trees() {
        let candidates = debugaltlink_candidates(
            Path::new("/proc/9/root/usr/lib/debug/usr/lib64/librados.so.2.0.0.debug"),
            Path::new("../../../.dwz/ceph-debugsource-18.2.8-0.el9.x86_64"),
        );

        // Resolved relative to the debug file's own directory (the encoding).
        assert!(candidates.contains(&PathBuf::from(
            "/proc/9/root/usr/lib/debug/usr/lib64/../../../.dwz/ceph-debugsource-18.2.8-0.el9.x86_64"
        )));
        // Conventional host /usr/lib/debug/.dwz tree.
        assert!(candidates.contains(&PathBuf::from(
            "/usr/lib/debug/.dwz/ceph-debugsource-18.2.8-0.el9.x86_64"
        )));
        // Same tree rooted under the debug file's mount-namespace root, so a
        // /proc/<pid>/root/... debug file finds the namespace-local copy.
        assert!(candidates.contains(&PathBuf::from(
            "/proc/9/root/usr/lib/debug/.dwz/ceph-debugsource-18.2.8-0.el9.x86_64"
        )));
    }

    #[test]
    fn missing_supplementary_file_degrades_gracefully() {
        // When no candidate exists on disk the lookup returns None rather than
        // erroring, so extraction continues with whatever resolves locally.
        let candidates = debugaltlink_candidates(
            Path::new("/nonexistent/dir/foo.debug"),
            Path::new("bar.dwz"),
        );
        assert!(first_existing(candidates).is_none());
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
    fn extracts_rgw_get_handler_var_fields_from_optimized_cpp_fixture() {
        let Some(binary) = compile_rgw_optimized_fixture() else {
            return;
        };

        let data = std::fs::read(&binary).unwrap();
        let file = object::File::parse(data.as_slice()).unwrap();
        let endian = if file.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let dwarf_cow = Dwarf::load(|section| load_section_unbounded(&file, section)).unwrap();
        #[allow(deprecated)]
        let dwarf = dwarf_cow.borrow(|section| EndianSlice::new(section, endian));
        let index = DwarfUnitIndex::load(&dwarf).unwrap();

        // Locate the concrete out-of-line `get_handler` (the PC-bearing instance
        // the collector probes).
        let Some(function) = find_concrete_get_handler(&dwarf, &index).unwrap() else {
            eprintln!(
                "SKIPPED extracts_rgw_get_handler_var_fields_from_optimized_cpp_fixture: \
                 no concrete RGWREST::get_handler instance found"
            );
            return;
        };

        // Shape guard: only meaningful if the toolchain emitted the optimized
        // abstract/concrete split -- a concrete `s` parameter with
        // `DW_AT_location`+`DW_AT_abstract_origin` but no `DW_AT_name` and no
        // `DW_AT_type`. Skip loudly otherwise so this cannot masquerade as a pass.
        if !concrete_param_has_target_shape(&dwarf, &index, function, "s").unwrap() {
            eprintln!(
                "SKIPPED extracts_rgw_get_handler_var_fields_from_optimized_cpp_fixture: \
                 toolchain did not emit the abstract_origin/no-name/no-type parameter shape"
            );
            return;
        }

        let function_unit = index.unit(function.unit);
        let function_entry = function_unit.entry(function.offset).unwrap();
        let pc = entry_pc(&dwarf, function_unit, &function_entry)
            .unwrap()
            .expect("concrete get_handler has a PC");

        // Fix 1: child-name matching follows abstract_origin and returns the
        // CONCRETE parameter DIE (the one carrying `DW_AT_location`). Reverting
        // fix 1 makes this resolve to the name-bearing abstract parameter, which
        // has no location, so `variable_location` below yields None and the
        // `.expect("fix 1 ...")` fails.
        let variable = find_function_variable(&dwarf, &index, function.unit, &function_entry, "s")
            .unwrap()
            .expect("fix 1: concrete `s` parameter must be found via abstract_origin");
        let variable_unit = index.unit(variable.unit);
        let variable_entry = variable_unit.entry(variable.offset).unwrap();
        let location =
            variable_location(&dwarf, variable_unit, &function_entry, &variable_entry, pc)
                .unwrap()
                .expect("fix 1: location must resolve on the concrete parameter DIE");
        assert!(location.reg >= 0);

        // Fix 2: `die_type` follows abstract_origin when the concrete DIE has no
        // `DW_AT_type`, so `translate_field_path` can walk the nested member path.
        // Reverting fix 2 makes `die_type(variable)` return None here, so the
        // `.expect("fix 2 ...")` fails even though fix 1 resolved the location.
        let fields = translate_field_path(
            &dwarf,
            &index,
            variable,
            &["s", "trans_id", "_M_string_length"],
        )
        .unwrap()
        .expect("fix 2: nested field path must translate via the abstract_origin type");
        assert_eq!(fields.len(), 3);
        assert!(fields[1].pointer);
        assert_eq!(fields[2].offset, 8);

        // End to end: the public entry point now surfaces both var_fields on the
        // optimized shape (this is what silently returned nothing before).
        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();
        let var_fields = module
            .func2vf
            .get("RGWREST::get_handler")
            .expect("optimized DWARF must yield RGWREST::get_handler var_fields");

        assert_eq!(var_fields.var_fields.len(), 2);
        for var_field in &var_fields.var_fields {
            assert!(var_field.location.reg >= 0);
            assert!(!var_field.fields.is_empty());
        }
        assert_eq!(var_fields.var_fields[0].fields.len(), 3);
        assert!(var_fields.var_fields[0].fields[1].pointer);
        assert_eq!(var_fields.var_fields[0].fields[2].offset, 8);
        assert_eq!(var_fields.var_fields[1].fields.len(), 4);
        assert!(var_fields.var_fields[1].fields[1].pointer);
    }

    /// Finds the concrete (PC-bearing) `RGWREST::get_handler` subprogram -- the
    /// out-of-line instance the collector probes -- returning its cross-unit DIE
    /// reference.
    fn find_concrete_get_handler<R: Reader>(
        dwarf: &Dwarf<R>,
        index: &DwarfUnitIndex<R>,
    ) -> Result<Option<DieRef<R::Offset>>> {
        for unit_index in 0..index.len() {
            let unit = index.unit(unit_index);
            let mut tree = unit.entries_tree(None)?;
            let root = tree.root()?;
            if let Some(found) =
                find_concrete_get_handler_node(dwarf, index, unit_index, root, &mut Vec::new())?
            {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    fn find_concrete_get_handler_node<R: Reader>(
        dwarf: &Dwarf<R>,
        index: &DwarfUnitIndex<R>,
        unit_index: usize,
        node: EntriesTreeNode<R>,
        scopes: &mut Vec<String>,
    ) -> Result<Option<DieRef<R::Offset>>> {
        let unit = index.unit(unit_index);
        let entry = node.entry();
        let scope = scope_name(dwarf, unit, entry)?;
        if let Some(scope) = &scope {
            scopes.push(scope.clone());
        }

        // Select the concrete out-of-line instance the same way the collector
        // does: a subprogram that both has a PC and resolves to the probe name.
        let mut found = None;
        if entry.tag() == gimli::DW_TAG_subprogram
            && entry_pc(dwarf, unit, entry)?.is_some()
            && function_names(dwarf, index, unit_index, entry, scopes)?
                .iter()
                .any(|name| name == "RGWREST::get_handler")
        {
            found = Some(DieRef {
                unit: unit_index,
                offset: entry.offset(),
            });
        }

        if found.is_none() {
            let mut children = node.children();
            while let Some(child) = children.next()? {
                if let Some(result) =
                    find_concrete_get_handler_node(dwarf, index, unit_index, child, scopes)?
                {
                    found = Some(result);
                    break;
                }
            }
        }

        if scope.is_some() {
            scopes.pop();
        }
        Ok(found)
    }

    fn concrete_param_has_target_shape<R: Reader>(
        dwarf: &Dwarf<R>,
        index: &DwarfUnitIndex<R>,
        function: DieRef<R::Offset>,
        name: &str,
    ) -> Result<bool> {
        let unit = index.unit(function.unit);
        let mut tree = unit.entries_tree(Some(function.offset))?;
        let root = tree.root()?;
        let mut children = root.children();
        while let Some(child) = children.next()? {
            let entry = child.entry();
            if entry.tag() != gimli::DW_TAG_formal_parameter {
                continue;
            }
            if die_name(dwarf, unit, entry)?.is_some() {
                continue;
            }
            if entry.attr(gimli::DW_AT_type)?.is_some() {
                continue;
            }
            if entry.attr(gimli::DW_AT_location)?.is_none() {
                continue;
            }
            let Some(origin) =
                index.referenced_die(function.unit, entry, gimli::DW_AT_abstract_origin)?
            else {
                continue;
            };
            let origin_unit = index.unit(origin.unit);
            let origin_entry = origin_unit.entry(origin.offset)?;
            if die_name(dwarf, origin_unit, &origin_entry)?.as_deref() == Some(name) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The Stage-3 re-seed site, with RGW's real parameter shapes: `req_state* s`
    /// (the CANONICAL bridge key) and `RGWOp*& op` -- a REFERENCE to a pointer,
    /// which is the ALTERNATE bridge key and the identity RGW actually passes as
    /// the `dpp` at most call sites in an op's data path.
    ///
    /// Both `req_state` and `RGWOp` derive from `DoutPrefixProvider` (first and
    /// only base, so the base subobject is at offset 0) exactly as they do in Ceph.
    /// That property is the whole premise of the bridge, and extraction verifies it
    /// here rather than assuming it.
    ///
    /// Built at `-O1 -fno-inline` (not `-O0`) so the parameters are
    /// register-resident at entry and `variable_location` can decode them; at `-O0`
    /// this toolchain emits `DW_OP_fbreg`/CFA locations the decoder rejects,
    /// matching the other optimized fixtures.
    fn compile_rgw_process_authenticated_fixture() -> Option<std::path::PathBuf> {
        compile_rgw_process_authenticated_source(
            "rgw-process-authenticated-fixture",
            "class RGWOp : public DoutPrefixProvider { public: int y; };",
        )
    }

    /// The same site, but with an `RGWOp` whose `DoutPrefixProvider` base is NOT at
    /// offset 0 (another non-empty base comes first). A build like this breaks the
    /// premise "the RGWOp* we read IS the dpp RGW passes", so the alternate key
    /// must be refused rather than keyed on a pointer that is off by a constant.
    fn compile_rgw_process_authenticated_offset_base_fixture() -> Option<std::path::PathBuf> {
        compile_rgw_process_authenticated_source(
            "rgw-process-authenticated-offset-base-fixture",
            "struct FirstBase { virtual ~FirstBase() {} long pad; };\n\
             class RGWOp : public FirstBase, public DoutPrefixProvider { public: int y; };",
        )
    }

    fn compile_rgw_process_authenticated_source(
        name: &str,
        rgw_op_decl: &str,
    ) -> Option<std::path::PathBuf> {
        let source = format!(
            r#"
                struct DoutPrefixProvider {{
                  virtual ~DoutPrefixProvider() {{}}
                  virtual int get_id() const {{ return 0; }}
                }};
                struct req_state : public DoutPrefixProvider {{
                  unsigned long id;
                  int get_id() const override {{ return (int)id; }}
                }};
                {rgw_op_decl}
                struct RGWHandler_REST {{ int x; }};
                struct RGWRequest {{ int z; }};
                static volatile unsigned long sink;
                __attribute__((noinline)) void rgw_process_authenticated(
                    RGWHandler_REST* handler, RGWOp*& op, RGWRequest* req,
                    req_state* s) {{
                  sink += handler->x;
                  sink += op->y;
                  sink += req->z;
                  sink += s->id;
                }}
                int main() {{
                  RGWHandler_REST h{{1}};
                  RGWOp o; o.y = 2;
                  RGWOp* op = &o;
                  RGWRequest r{{3}};
                  req_state s; s.id = 4;
                  rgw_process_authenticated(&h, op, &r, &s);
                  return 0;
                }}
                "#
        );
        compile_cpp_sources_flags_only(name, &[(name, &source)], &["-g", "-O1", "-fno-inline"])
    }

    #[test]
    fn extracts_rgw_process_authenticated_raw_pointer_descriptor_from_cpp_fixture() {
        let Some(binary) = compile_rgw_process_authenticated_fixture() else {
            return;
        };

        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();
        // Function PC must resolve (proves the free-function name is matched).
        assert!(module.func2pc.contains_key(RGW_PROCESS_AUTHENTICATED));

        let Some(fields) = module.func2vf.get(RGW_PROCESS_AUTHENTICATED) else {
            // Toolchain did not emit a decodable register location for `s` at
            // entry; the all-or-nothing raw-pointer path then drops the
            // var_fields. Announce loudly so this does not look like a pass.
            eprintln!(
                "SKIPPED extracts_rgw_process_authenticated_raw_pointer_descriptor_from_cpp_fixture: \
                 toolchain did not emit a decodable register location for the req_state* parameter"
            );
            return;
        };

        // Slot 40: the raw-pointer descriptor for `req_state* s`. Register-located
        // (never stack), one sentinel field {offset:0, pointer:false} -- the
        // parameter's own value, no member access, no read.
        let raw = &fields.var_fields[0];
        assert!(raw.location.reg >= 0, "descriptor must be register-located");
        assert!(!raw.location.stack, "descriptor must not be stack-located");
        assert_eq!(raw.fields.len(), 1);
        assert_eq!(raw.fields[0].offset, 0);
        assert!(!raw.fields[0].pointer);
    }

    #[test]
    fn extracts_the_rgw_op_reference_descriptor_that_carries_the_alternate_bridge_key() {
        // THE key that makes Phase B recover anything. RGW passes the executing
        // RGWOp -- not the req_state -- as the `dpp` at most call sites in an op's
        // data path, so the request must ALSO be keyed by its RGWOp*. That pointer
        // is only reachable through the `RGWOp*& op` parameter: a REFERENCE to a
        // pointer, so the register holds an RGWOp** and the BPF handler must read
        // the pointee exactly once.
        //
        // The descriptor therefore carries {offset:0, pointer:true} -- distinct from
        // the raw-pointer shape, because keying the bridge on the ADDRESS OF the
        // caller's pointer variable instead of the RGWOp would silently correlate
        // nothing.
        let Some(binary) = compile_rgw_process_authenticated_fixture() else {
            return;
        };
        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();
        let Some(fields) = module.func2vf.get(RGW_PROCESS_AUTHENTICATED) else {
            eprintln!(
                "SKIPPED extracts_the_rgw_op_reference_descriptor_that_carries_the_alternate_bridge_key: \
                 toolchain did not emit a decodable register location"
            );
            return;
        };

        assert_eq!(
            fields.var_fields.len(),
            2,
            "both bridge keys must be extractable: the req_state* and the RGWOp*&"
        );
        let op = &fields.var_fields[1];
        assert!(op.location.reg >= 0, "descriptor must be register-located");
        assert!(!op.location.stack);
        assert_eq!(op.fields.len(), 1);
        assert_eq!(op.fields[0].offset, 0);
        assert!(
            op.fields[0].pointer,
            "the reference must be marked as needing exactly one deref to reach the RGWOp*"
        );
        // The two descriptors name DIFFERENT parameters (different registers), so
        // the alternate key is not just the req_state* under another name.
        assert_ne!(fields.var_fields[0].location.reg, op.location.reg);
    }

    #[test]
    fn refuses_the_rgw_op_key_when_its_dpp_base_is_not_at_offset_zero() {
        // FAIL CLOSED ON AN UNPROVEN IDENTITY. The alternate key is only sound
        // because `(DoutPrefixProvider*)op == (void*)op`, i.e. because RGWOp's
        // DoutPrefixProvider base sits at offset 0. On a build where it does not,
        // the pointer we can read is NOT the dpp RGW passes -- so we must not key
        // the bridge on it. (A wrong key would mostly just miss; but "mostly" is not
        // a property this tool is allowed to rely on, and a pointer that is off by a
        // constant is exactly the kind of thing that collides with something real.)
        //
        // The req_state descriptor SURVIVES: losing the alternate key costs coverage
        // (ops submitted under an RGWOp dpp), not correctness.
        let Some(binary) = compile_rgw_process_authenticated_offset_base_fixture() else {
            return;
        };
        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();
        let Some(fields) = module.func2vf.get(RGW_PROCESS_AUTHENTICATED) else {
            eprintln!(
                "SKIPPED refuses_the_rgw_op_key_when_its_dpp_base_is_not_at_offset_zero: \
                 toolchain did not emit a decodable register location"
            );
            return;
        };

        assert_eq!(
            fields.var_fields.len(),
            1,
            "an RGWOp whose DoutPrefixProvider base is not at offset 0 must yield NO alternate-key \
             descriptor, and must not break the req_state one"
        );
        assert!(
            !fields.var_fields[0].fields[0].pointer,
            "slot 40 stays the raw pointer"
        );
    }

    /// A two-TU fixture that puts a DECOY type -- `namespace decoy { struct RGWOp; }`
    /// -- in the very CU that contains `rgw_process_authenticated`, while the REAL
    /// `::RGWOp` is only DECLARED there and DEFINED in the other TU.
    ///
    /// This is the shape that makes the offset-0 proof falsifiable. A parameter whose
    /// type is an incomplete `::RGWOp` reaches a DECLARATION DIE, so the extractor has
    /// to go looking for the definition in another unit -- and that search is where
    /// binding by UNQUALIFIED name goes wrong: `decoy::RGWOp` is a definition, it is
    /// named `RGWOp`, and it appears FIRST (it is in the same CU as the function).
    ///
    /// `real_rgw_op_bases` decides what the REAL `::RGWOp` inherits, which is the only
    /// difference between the two tests below.
    ///
    /// The binary is named `radosgw` because the module key (and hence the RGW probe
    /// function set) is derived from the binary's basename.
    fn compile_namespaced_decoy_rgw_op_fixture(
        real_rgw_op_bases: &str,
    ) -> Option<std::path::PathBuf> {
        let dpp = "struct DoutPrefixProvider {\n\
                     virtual ~DoutPrefixProvider() {}\n\
                     virtual int get_id() const { return 0; }\n\
                   };";
        // The CU with the probe function: the decoy is DEFINED here (with its
        // DoutPrefixProvider base at offset 0 -- i.e. it would satisfy the proof),
        // and the real ::RGWOp is only declared.
        let radosgw = format!(
            r#"
                {dpp}
                struct req_state : public DoutPrefixProvider {{
                  unsigned long id;
                  int get_id() const override {{ return (int)id; }}
                }};
                namespace decoy {{
                  struct RGWOp : public DoutPrefixProvider {{ int y; }};
                }}
                struct RGWOp;
                struct RGWHandler_REST {{ int x; }};
                struct RGWRequest {{ int z; }};
                static volatile unsigned long sink;
                __attribute__((noinline)) void rgw_process_authenticated(
                    RGWHandler_REST* handler, RGWOp*& op, RGWRequest* req,
                    req_state* s) {{
                  sink += handler->x;
                  sink += (unsigned long)(void*)op;
                  sink += req->z;
                  sink += s->id;
                }}
                int touch_real_rgw_op();
                int main() {{
                  RGWHandler_REST h{{1}};
                  RGWRequest r{{3}};
                  req_state s; s.id = 4;
                  RGWOp* op = 0;
                  decoy::RGWOp d; d.y = 7;
                  sink += d.get_id();
                  rgw_process_authenticated(&h, op, &r, &s);
                  return touch_real_rgw_op();
                }}
                "#
        );
        // The other CU: the real ::RGWOp's DEFINITION.
        let other = format!(
            r#"
                {dpp}
                struct FirstBase {{ virtual ~FirstBase() {{}} long pad; }};
                struct RGWOp {real_rgw_op_bases} {{ int y; }};
                static volatile int real_sink;
                int touch_real_rgw_op() {{
                  RGWOp o; o.y = 1;
                  real_sink += o.y;
                  return o.get_id();
                }}
                "#
        );
        compile_cpp_sources_flags_only(
            "radosgw",
            &[("probe_unit", &radosgw), ("other_unit", &other)],
            &["-g", "-O1", "-fno-inline"],
        )
    }

    #[test]
    fn a_namespaced_same_named_type_cannot_supply_the_offset_zero_proof() {
        // THE UNSOUND PROOF. The `RGWOp*` bridge key is only legitimate because
        // `(DoutPrefixProvider*)op == (void*)op` -- i.e. because ::RGWOp inherits
        // DoutPrefixProvider at offset 0. That proof used to be obtained by resolving
        // the declaration DIE to "the first non-declaration class/struct with a
        // matching UNQUALIFIED name in any unit", which means a completely unrelated
        // `namespace decoy { struct RGWOp : DoutPrefixProvider {}; }` could supply it.
        // A proof that the wrong type can satisfy is not a proof.
        //
        // Here the REAL ::RGWOp puts DoutPrefixProvider at a NON-ZERO offset, while
        // the decoy puts it at 0. Binding by unqualified name reads the decoy's 0 and
        // EMITS the key -- keying the bridge on a pointer that is not the dpp. Binding
        // by fully-qualified DIE path reads the real type's nonzero offset and
        // REFUSES the key.
        let Some(binary) = compile_namespaced_decoy_rgw_op_fixture(
            ": public FirstBase, public DoutPrefixProvider",
        ) else {
            return;
        };
        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.get("radosgw").expect("radosgw module");
        let Some(fields) = module.func2vf.get(RGW_PROCESS_AUTHENTICATED) else {
            eprintln!(
                "SKIPPED a_namespaced_same_named_type_cannot_supply_the_offset_zero_proof: \
                 toolchain did not emit a decodable register location"
            );
            return;
        };

        assert_eq!(
            fields.var_fields.len(),
            1,
            "a namespaced type that merely SHARES the name `RGWOp` must not satisfy the \
             DoutPrefixProvider-at-offset-0 proof for ::RGWOp -- the alternate bridge key must be \
             refused, leaving only the req_state* descriptor"
        );
        assert!(!fields.var_fields[0].fields[0].pointer);
    }

    #[test]
    fn the_real_global_type_is_still_found_through_a_cross_unit_declaration() {
        // The CONTROL for the test above, and the reason it proves something. Same
        // decoy, same cross-TU declaration, same everything -- except the REAL ::RGWOp
        // does inherit DoutPrefixProvider at offset 0. The key must now be EMITTED.
        //
        // Without this, the test above could pass for a boring reason (extraction
        // failing to resolve any definition through a cross-unit declaration, so the
        // key is refused no matter what the types say). Together, the pair shows the
        // resolver finds the RIGHT type: it follows the declaration across units, and
        // it refuses to be satisfied by a same-named type in a namespace.
        let Some(binary) = compile_namespaced_decoy_rgw_op_fixture(": public DoutPrefixProvider")
        else {
            return;
        };
        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.get("radosgw").expect("radosgw module");
        let Some(fields) = module.func2vf.get(RGW_PROCESS_AUTHENTICATED) else {
            eprintln!(
                "SKIPPED the_real_global_type_is_still_found_through_a_cross_unit_declaration: \
                 toolchain did not emit a decodable register location"
            );
            return;
        };

        assert_eq!(
            fields.var_fields.len(),
            2,
            "the real ::RGWOp's definition must be resolvable through its cross-unit DECLARATION, \
             or the qualified-path binding would just be a way of never proving anything"
        );
        assert!(
            fields.var_fields[1].fields[0].pointer,
            "the alternate key is the RGWOp*& reference descriptor"
        );
    }

    /// A `req_state` shaped like RGW's: a polymorphic `DoutPrefixProvider` base
    /// and an out-of-line destructor, destroyed BOTH as a stack-allocated
    /// complete object (like `process_request` does) and through a base pointer
    /// via `delete` (which is what forces g++ to emit the deleting dtor, D0).
    /// The result is the exact hazard this probe has to survive: three symbols
    /// (`D0`, `D1`, `D2`) that all demangle to `req_state::~req_state`, with D0
    /// listed FIRST in both the symbol table and the DWARF DIE order.
    ///
    /// Built at `-O1 -fno-inline` for the same reason as the other raw-pointer
    /// fixture: at `-O0` this toolchain emits `DW_OP_fbreg`/CFA locations the
    /// decoder rejects, so `this` would not be register-resident at entry.
    fn compile_req_state_dtor_fixture() -> Option<std::path::PathBuf> {
        compile_cpp_sources_flags_only(
            "req-state-dtor-fixture",
            &[(
                "req-state-dtor-fixture",
                r#"
                struct DoutPrefixProvider {
                  virtual ~DoutPrefixProvider() {}
                  virtual int get_id() const { return 0; }
                };
                struct req_state : public DoutPrefixProvider {
                  unsigned long id;
                  char* buf;
                  req_state(unsigned long i);
                  ~req_state();
                  int get_id() const override { return (int)id; }
                };
                static volatile unsigned long sink;
                req_state::req_state(unsigned long i) : id(i), buf(new char[16]) {}
                __attribute__((noinline)) req_state::~req_state() {
                  sink += id;
                  delete[] buf;
                }
                __attribute__((noinline)) void process_request(unsigned long i) {
                  req_state s(i);
                  sink += s.get_id();
                }
                __attribute__((noinline)) void destroy(DoutPrefixProvider* p) { delete p; }
                int main() {
                  process_request(3);
                  destroy(new req_state(4));
                  return 0;
                }
                "#,
            )],
            &["-g", "-O1", "-fno-inline"],
        )
    }

    /// Addresses of the mangled destructor symbols in `binary`, by variant.
    fn dtor_symbol_addresses(binary: &Path) -> BTreeMap<String, u64> {
        let data = std::fs::read(binary).unwrap();
        let file = object::File::parse(data.as_slice()).unwrap();
        let mut result = BTreeMap::new();
        for symbol in file.symbols() {
            let Ok(name) = symbol.name() else { continue };
            if name.starts_with("_ZN9req_stateD") {
                result.insert(name.to_string(), symbol.address());
            }
        }
        result
    }

    #[test]
    fn binds_req_state_dtor_to_the_complete_object_destructor_not_the_deleting_one() {
        let Some(binary) = compile_req_state_dtor_fixture() else {
            return;
        };
        let symbols = dtor_symbol_addresses(&binary);
        let (Some(&deleting), Some(&complete)) = (
            symbols.get("_ZN9req_stateD0Ev"),
            symbols
                .get("_ZN9req_stateD1Ev")
                .or_else(|| symbols.get("_ZN9req_stateD2Ev")),
        ) else {
            eprintln!(
                "SKIPPED binds_req_state_dtor_to_the_complete_object_destructor_not_the_deleting_one: \
                 toolchain did not emit both destructor variants ({symbols:?})"
            );
            return;
        };
        assert_ne!(
            deleting, complete,
            "fixture must actually distinguish D0 from D1/D2"
        );

        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();
        let addr = module
            .func2pc
            .get(REQ_STATE_DTOR)
            .copied()
            .expect("req_state::~req_state must resolve");

        // THE invariant: the probe binds to the complete/base object destructor
        // that `process_request` calls, never to the deleting destructor (which
        // only runs for heap `delete` and would fire on the wrong path). All
        // three variants demangle identically, so a name-only match would have
        // taken D0 here -- it is listed first.
        assert_eq!(addr, complete);
        assert_ne!(addr, deleting);
    }

    #[test]
    fn binds_req_state_dtor_from_dwarf_dies_when_the_symbol_table_is_gone() {
        // The symbol table is the FIRST resolution source, so the test above only
        // exercises symbol ranking. Strip the destructor SYMBOLS (keeping the
        // DWARF, and every section address, untouched) to force resolution
        // through the DIE walk -- where g++ also emits the deleting destructor's
        // subprogram DIE BEFORE the complete/base one, so a first-DIE-wins match
        // would again take D0.
        let Some(binary) = compile_req_state_dtor_fixture() else {
            return;
        };
        let symbols = dtor_symbol_addresses(&binary);
        let (Some(&deleting), Some(&complete)) = (
            symbols.get("_ZN9req_stateD0Ev"),
            symbols
                .get("_ZN9req_stateD1Ev")
                .or_else(|| symbols.get("_ZN9req_stateD2Ev")),
        ) else {
            return;
        };

        let objcopy = std::env::var_os("OBJCOPY").unwrap_or_else(|| "objcopy".into());
        let stripped = binary.with_file_name("req-state-dtor-fixture-nodtorsyms");
        if !std::process::Command::new(&objcopy)
            .args([
                "--strip-symbol=_ZN9req_stateD0Ev",
                "--strip-symbol=_ZN9req_stateD1Ev",
                "--strip-symbol=_ZN9req_stateD2Ev",
            ])
            .arg(&binary)
            .arg(&stripped)
            .status()
            .is_ok_and(|status| status.success())
        {
            eprintln!(
                "SKIPPED binds_req_state_dtor_from_dwarf_dies_when_the_symbol_table_is_gone: \
                 objcopy unavailable"
            );
            return;
        }
        assert!(
            dtor_symbol_addresses(&stripped).is_empty(),
            "the stripped fixture must have no destructor symbols left"
        );

        let info = from_paths(&[stripped.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();
        let addr = module
            .func2pc
            .get(REQ_STATE_DTOR)
            .copied()
            .expect("req_state::~req_state must resolve from DWARF alone");

        assert_eq!(addr, complete);
        assert_ne!(addr, deleting);
    }

    #[test]
    fn extracts_req_state_dtor_this_raw_pointer_descriptor_from_cpp_fixture() {
        let Some(binary) = compile_req_state_dtor_fixture() else {
            return;
        };

        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();
        let Some(fields) = module.func2vf.get(REQ_STATE_DTOR) else {
            eprintln!(
                "SKIPPED extracts_req_state_dtor_this_raw_pointer_descriptor_from_cpp_fixture: \
                 toolchain did not emit a decodable register location for `this`"
            );
            return;
        };

        // Exactly one var_field: the register-only raw-pointer descriptor for
        // `this`, with the sentinel field (no member access, no deref). The BPF
        // end handler reads `location.reg` and nothing else.
        assert_eq!(fields.var_fields.len(), 1);
        let raw = &fields.var_fields[0];
        assert!(raw.location.reg >= 0, "descriptor must be register-located");
        assert!(!raw.location.stack, "descriptor must not be stack-located");
        assert_eq!(raw.fields.len(), 1);
        assert_eq!(raw.fields[0].offset, 0);
        assert!(!raw.fields[0].pointer);
    }

    // --- The LTO cdtor-clone destructor: what real Ceph actually looks like ---
    //
    // The `-O1 -fno-inline` destructor fixture above proves nothing about a real
    // build, and that is exactly how the request-END probe shipped inert. At `-O1`
    // GCC gives the concrete destructor's `this` a one-hop `DW_AT_abstract_origin`
    // to a DIE that carries `DW_AT_name("this")`, and a location it can express as
    // a single expression. Ceph is built `-O2 -flto`, where BOTH of those change:
    //
    //   * GCC's cdtor CLONING inserts an extra abstract instance (the D1/D2 clone)
    //     between the concrete instance and the "unified" D4 abstract instance, so
    //     the parameter's NAME and TYPE sit TWO `DW_AT_abstract_origin` hops away
    //     and the concrete parameter DIE carries neither.
    //   * `~req_state` is a big function, so `this` does not stay in RDI and its
    //     `DW_AT_location` is a location LIST: RDI at entry, a callee-saved
    //     register for the body, `DW_OP_entry_value` at the tail.
    //
    // This fixture reproduces both, and it is compiled from TWO translation units
    // so that `-flto` is real. It is the same `radosgw`-shaped module as the Phase
    // B overload fixture (both `rgw_rados_operate` overloads, `req_state` deriving
    // `DoutPrefixProvider`) for a second reason: with no `RGWREST::get_handler` and
    // no `rgw_process_authenticated` in the module, the DESTRUCTOR'S `this` is the
    // ONLY parameter that can prove `req_state`'s `DoutPrefixProvider` base sits at
    // offset 0 -- and that proof requires reading its `DW_AT_type` through the same
    // two-hop chain. So if the chain walk regresses, the overload descriptors
    // disappear too, and this test says so.
    const RGW_LTO_DTOR_FIXTURE_SOURCE: &str = r#"
            class DoutPrefixProvider {
              public:
                virtual ~DoutPrefixProvider() {}
                virtual int get_id() const { return 0; }
            };
            struct Chunk { char* p; unsigned long n; };
            struct req_state : public DoutPrefixProvider {
              unsigned long id;
              Chunk chunks[16];
              req_state(unsigned long i);
              ~req_state();
              int get_id() const override { return (int)id; }
            };
            static volatile unsigned long sink;
            extern void observe(unsigned long v);
            extern unsigned long churn(unsigned long v);
            req_state::req_state(unsigned long i) : id(i) {
              for (int k = 0; k < 16; k++) { chunks[k].p = new char[8]; chunks[k].n = i + k; }
            }
            // Big enough that `this` cannot stay in the argument register: the loop
            // makes calls, so `this` is forced into a callee-saved register for the
            // body and DWARF describes it with a location LIST.
            __attribute__((noinline, used)) req_state::~req_state() {
              sink += id;
              for (int k = 0; k < 16; k++) {
                observe(chunks[k].n + id);
                delete[] chunks[k].p;
                sink += churn(chunks[k].n);
                if (chunks[k].n & 1) { observe(id); sink ^= churn(chunks[k].n + 1); }
                else { sink += get_id(); observe(sink); }
              }
              observe(sink + id);
            }

            namespace librados { inline namespace v14_2_0 {
              class IoCtx { public: int fd; };
              class ObjectReadOperation { public: int r; };
              class ObjectWriteOperation { public: int w; };
            }}
            namespace ceph { namespace buffer { inline namespace v15_2_0 {
              class list { public: int len; };
            }}}
            class optional_yield { public: int y; };
            class CephString { public: const char* p; };

            __attribute__((noinline, used))
            int rgw_rados_operate(const DoutPrefixProvider *dpp, librados::IoCtx& ioctx,
                                  const CephString& oid, librados::ObjectWriteOperation *op,
                                  optional_yield y, int flags) {
              observe((unsigned long)dpp);
              return dpp != 0 ? ioctx.fd + op->w + y.y + flags : (int)(unsigned long)oid.p;
            }

            __attribute__((noinline, used))
            int rgw_rados_operate(const DoutPrefixProvider *dpp, librados::IoCtx& ioctx,
                                  const CephString& oid, librados::ObjectReadOperation *op,
                                  ceph::buffer::list* pbl, optional_yield y, int flags) {
              observe((unsigned long)dpp);
              return dpp != 0 ? ioctx.fd + op->r + pbl->len + y.y + flags : (int)(unsigned long)oid.p;
            }

            // Forces g++ to emit the DELETING destructor (D0) as well, so the
            // D0-vs-D1/D2 hazard is present here too.
            __attribute__((noinline, used)) void destroy(DoutPrefixProvider* p) { delete p; }

            int main(int argc, char**) {
              librados::IoCtx ioctx; CephString oid; optional_yield y;
              librados::ObjectReadOperation rop; librados::ObjectWriteOperation wop;
              ceph::buffer::list bl;
              req_state s((unsigned long)argc);
              const DoutPrefixProvider* dpp = &s;
              int rc = rgw_rados_operate(dpp, ioctx, oid, &rop, &bl, y, argc)
                     + rgw_rados_operate(dpp, ioctx, oid, &wop, y, argc);
              destroy(new req_state((unsigned long)argc + 1));
              return rc & 1;
            }
        "#;

    const RGW_LTO_DTOR_FIXTURE_HELPER_SOURCE: &str = r#"
            static volatile unsigned long g;
            void observe(unsigned long v) { g += v; }
            unsigned long churn(unsigned long v) { g ^= v * 2654435761u; return g; }
        "#;

    fn compile_lto_req_state_dtor_fixture() -> Option<std::path::PathBuf> {
        compile_cpp_sources_flags_only(
            "radosgw",
            &[
                ("radosgw", RGW_LTO_DTOR_FIXTURE_SOURCE),
                ("radosgw-helper", RGW_LTO_DTOR_FIXTURE_HELPER_SOURCE),
            ],
            &["-g", "-O2", "-flto"],
        )
    }

    /// What the DWARF of the fixture's concrete `req_state::~req_state` ACTUALLY
    /// says about its implicit `this`, read independently of the extractor's
    /// parameter lookup. The test uses it twice: to refuse to pass unless the
    /// fixture really does reproduce the hazard, and as the ground truth for which
    /// register `this` is in AT THE PROBE PC.
    #[derive(Debug)]
    struct DtorThisShape {
        /// The concrete instance's own `this` DIE has a `DW_AT_name`. On the builds
        /// that matter it does NOT -- the name is inherited.
        param_has_own_name: bool,
        /// `DW_AT_abstract_origin`/`DW_AT_specification` hops from the concrete
        /// `this` DIE to the DIE that carries `DW_AT_name("this")`. Two on an LTO
        /// cdtor clone; one on a plain `-O1` build.
        hops_to_name: Option<usize>,
        /// Entries in the parameter's location LIST. Zero means the location is a
        /// single expression -- the case that proves nothing.
        loclist_entries: usize,
        /// The register `this` lives in at the destructor's ENTRY pc...
        entry_reg: Option<i32>,
        /// ...and the ones it migrates to afterwards, which a descriptor decoded at
        /// the wrong PC would pick up instead.
        later_regs: Vec<i32>,
    }

    fn req_state_dtor_this_shape(binary: &Path) -> Option<DtorThisShape> {
        let data = fs::read(binary).ok()?;
        let file = object::File::parse(data.as_slice()).ok()?;
        let endian = if file.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let dwarf_owned = Dwarf::load(|section| {
            load_section_unbounded(&file, section).map(|data| data.into_owned())
        })
        .ok()?;
        #[allow(deprecated)]
        let dwarf = dwarf_owned.borrow(|section| EndianSlice::new(section, endian));
        let index = DwarfUnitIndex::load(&dwarf).ok()?;

        // The CONCRETE destructor definition: a subprogram with code whose reachable
        // mangled names make it an accepted (D1/D2) destructor.
        let mut concrete = None;
        'units: for unit_index in 0..index.main_len() {
            let unit = index.unit(unit_index);
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs().ok()? {
                if entry.tag() != gimli::DW_TAG_subprogram {
                    continue;
                }
                let Some(low_pc) = entry_pc(&dwarf, unit, entry).ok()? else {
                    continue;
                };
                let names = entry_linkage_names(&dwarf, &index, unit_index, entry).ok()?;
                if definition_rank(REQ_STATE_DTOR, &names).is_some() {
                    concrete = Some((unit_index, entry.offset(), low_pc));
                    break 'units;
                }
            }
        }
        let (unit_index, offset, low_pc) = concrete?;

        // Its OWN first formal parameter -- the implicit `this`.
        let unit = index.unit(unit_index);
        let mut tree = unit.entries_tree(Some(offset)).ok()?;
        let root = tree.root().ok()?;
        let mut children = root.children();
        let mut param = None;
        while let Some(child) = children.next().ok()? {
            if child.entry().tag() == gimli::DW_TAG_formal_parameter {
                param = Some(child.entry().offset());
                break;
            }
        }
        let param = param?;
        let param_entry = unit.entry(param).ok()?;

        let param_has_own_name = die_name(&dwarf, unit, &param_entry).ok()?.is_some();

        // Hops to the DIE that actually names it, following the inheritance chain
        // link by link (this is the count the fix is about).
        let mut hops_to_name = None;
        let mut current = DieRef {
            unit: unit_index,
            offset: param,
        };
        for hop in 0..=ORIGIN_CHAIN_LIMIT {
            let current_unit = index.unit(current.unit);
            let current_entry = current_unit.entry(current.offset).ok()?;
            if die_name(
                dwarf_for(&dwarf, &index, current.unit),
                current_unit,
                &current_entry,
            )
            .ok()?
            .as_deref()
                == Some("this")
            {
                hops_to_name = Some(hop);
                break;
            }
            let next = [gimli::DW_AT_abstract_origin, gimli::DW_AT_specification]
                .into_iter()
                .find_map(|attr| {
                    index
                        .referenced_die(current.unit, &current_entry, attr)
                        .ok()
                        .flatten()
                });
            match next {
                Some(next) => current = next,
                None => break,
            }
        }

        // The location list, and the registers it names at entry and afterwards.
        let mut loclist_entries = 0;
        let mut entry_reg = None;
        let mut later_regs = Vec::new();
        if let Some(attr) = param_entry.attr(gimli::DW_AT_location).ok()? {
            if let Some(mut locations) = dwarf.attr_locations(unit, attr.value()).ok()? {
                while let Some(location) = locations.next().ok()? {
                    loclist_entries += 1;
                    let decoded =
                        decode_location_expression(unit.encoding(), None, location.data).ok()?;
                    let Some(decoded) = decoded.filter(|decoded| !decoded.stack) else {
                        continue;
                    };
                    if low_pc >= location.range.begin && low_pc < location.range.end {
                        entry_reg = Some(decoded.reg);
                    } else {
                        later_regs.push(decoded.reg);
                    }
                }
            }
        }

        Some(DtorThisShape {
            param_has_own_name,
            hops_to_name,
            loclist_entries,
            entry_reg,
            later_regs,
        })
    }

    #[test]
    fn extracts_req_state_dtor_this_descriptor_from_an_lto_cdtor_clone_with_a_loclist_this() {
        let Some(binary) = compile_lto_req_state_dtor_fixture() else {
            eprintln!(
                "SKIPPED extracts_req_state_dtor_this_descriptor_from_an_lto_cdtor_clone_with_a_loclist_this: \
                 no working C++ compiler with -flto"
            );
            return;
        };
        let Some(shape) = req_state_dtor_this_shape(&binary) else {
            eprintln!(
                "SKIPPED ...lto_cdtor_clone...: no concrete D1/D2 destructor DIE in the fixture"
            );
            return;
        };

        // The fixture must reproduce the REAL hazard, or it proves nothing and must
        // not be allowed to pass quietly -- which is precisely how the shipped bug
        // slipped through a green test suite.
        let reproduces_hazard = !shape.param_has_own_name
            && shape.hops_to_name.is_some_and(|hops| hops >= 2)
            && shape.loclist_entries >= 2
            && shape.entry_reg.is_some()
            && !shape.later_regs.is_empty();
        if !reproduces_hazard {
            eprintln!(
                "SKIPPED extracts_req_state_dtor_this_descriptor_from_an_lto_cdtor_clone_with_a_loclist_this: \
                 this toolchain did not emit the LTO cdtor-clone shape (artificial `this`, named \
                 through >=2 abstract_origin hops, loclist-located and migrating out of the entry \
                 register): {shape:?}"
            );
            return;
        }
        let entry_reg = shape.entry_reg.expect("checked above");

        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.get("radosgw").expect("radosgw module");

        // THE regression. Before the origin-chain fix this key was simply absent:
        // the concrete `this` DIE (the only one with a location) was not recognised
        // as `this`, so extraction fell through to the abstract instance's parameter,
        // which has no `DW_AT_location` at all -- and the request-END probe shipped
        // with no descriptor, disabling itself and the cross-thread re-seed with it.
        let fields = module.func2vf.get(REQ_STATE_DTOR).unwrap_or_else(|| {
            panic!(
                "no `this` descriptor for {REQ_STATE_DTOR}: DWARF puts it in DWARF register \
                 {entry_reg} at the probed entry pc, so one MUST be extracted"
            )
        });

        assert_eq!(fields.var_fields.len(), 1);
        let raw = &fields.var_fields[0];
        assert!(!raw.location.stack, "descriptor must not be stack-located");
        assert_eq!(raw.location.offset, 0, "a raw pointer has no offset");
        // The register-only raw-pointer shape the importer validates: one sentinel
        // field, offset 0, no dereference.
        assert_eq!(raw.fields.len(), 1);
        assert_eq!(raw.fields[0].offset, 0);
        assert!(!raw.fields[0].pointer);

        // The register must be the one `this` is in AT THE PROBE PC (function entry:
        // RDI / DWARF reg 5 on x86-64), never one of the registers it migrates to
        // later in the body -- which is what a descriptor decoded at the wrong PC,
        // or at no PC, would hand the BPF handler.
        assert_eq!(
            raw.location.reg, entry_reg,
            "`this` must be read from the register DWARF gives it at the ENTRY pc"
        );
        assert!(
            !shape.later_regs.contains(&raw.location.reg),
            "descriptor picked a register from a LATER loclist range ({:?}); the uprobe fires at \
             entry, where `this` is in DWARF register {entry_reg}",
            shape.later_regs
        );

        // Still bound to the complete/base destructor, never the deleting one.
        let symbols = dtor_symbol_addresses(&binary);
        let addr = module
            .func2pc
            .get(REQ_STATE_DTOR)
            .copied()
            .expect("the destructor address must resolve");
        let linkage = module
            .func2linkage
            .get(REQ_STATE_DTOR)
            .expect("the destructor address must carry its variant provenance");
        assert!(
            dtor_variant_rank(linkage).is_some(),
            "provenance {linkage} must be an ACCEPTED (D1/D2) destructor variant"
        );
        assert_eq!(symbols.get(linkage.as_str()), Some(&addr));
        if let Some(deleting) = symbols.get("_ZN9req_stateD0Ev") {
            assert_ne!(addr, *deleting, "must never bind the DELETING destructor");
        }

        // And the descriptors that depend on the SAME two-hop chain for their TYPE:
        // this module has no `get_handler` and no `rgw_process_authenticated`, so the
        // destructor's `this` is the only parameter that can prove `req_state`'s
        // DoutPrefixProvider base is at offset 0 -- and without that proof the
        // per-submit re-seed probes are (correctly) dropped. Their presence is the
        // proof that the chain walk resolved the parameter's TYPE, not just its
        // location.
        for overload in RGW_RADOS_OPERATE_OVERLOADS {
            assert!(
                module.func2vf.contains_key(*overload),
                "{overload} descriptor must survive: the dpp identity is proven from the \
                 destructor's `this` type, through the same abstract-origin chain"
            );
        }
    }

    #[test]
    fn refuses_the_req_state_dtor_descriptor_when_this_is_not_register_resident_at_entry() {
        // The other half of the contract: extraction must still FAIL CLOSED. Built
        // at `-O0`, this toolchain gives `this` a `DW_OP_fbreg` location -- it is on
        // the stack at entry, so there is no register for the BPF handler to read
        // and NO descriptor may be emitted. Nothing about resolving the parameter
        // positionally, or through a longer origin chain, is allowed to turn a
        // stack location into a register one.
        let Some(binary) = compile_cpp_sources_flags_only(
            "radosgw",
            &[
                ("radosgw", RGW_LTO_DTOR_FIXTURE_SOURCE),
                ("radosgw-helper", RGW_LTO_DTOR_FIXTURE_HELPER_SOURCE),
            ],
            &["-g", "-O0"],
        ) else {
            return;
        };
        let Some(shape) = req_state_dtor_this_shape(&binary) else {
            return;
        };
        if shape.entry_reg.is_some() {
            eprintln!(
                "SKIPPED refuses_the_req_state_dtor_descriptor_when_this_is_not_register_resident_at_entry: \
                 this toolchain DOES keep `this` in a register at -O0 ({shape:?})"
            );
            return;
        }

        let info = from_paths(&[binary.as_path()]).unwrap();
        let (module_key, module) = info
            .modules
            .iter()
            .next()
            .expect("the fixture module must parse");

        // The destructor itself IS found -- so the absence below is a REFUSAL, not a
        // failure to locate the function.
        let addr = module
            .func2pc
            .get(REQ_STATE_DTOR)
            .copied()
            .expect("the destructor address must still resolve");
        assert!(
            !module.func2vf.contains_key(REQ_STATE_DTOR),
            "a stack-located `this` must yield NO descriptor: there is no register to read it from"
        );

        // And the artifact says so in the importer's own words, rather than shipping
        // an address whose descriptor is missing.
        assert_eq!(
            info.request_end_probe(module_key),
            crate::dwarf_json::RequestEndProbe::Unavailable(
                crate::dwarf_json::RequestEndProbeGap::NoDescriptor
            ),
            "the request-END probe must report itself unavailable (addr {addr:#x} resolved, but no \
             register-only raw-pointer descriptor)"
        );
    }

    #[test]
    fn exports_the_variant_provenance_of_the_req_state_dtor_address() {
        // The address alone cannot prove which destructor variant it is, so an
        // artifact that carries only `func2pc` leaves an importer no way to tell
        // a D1/D2 address from a D0 one. Native extraction therefore exports the
        // MANGLED name of the definition it chose, and that name must (a) be one
        // of the accepted variants and (b) actually correspond to the exported
        // address -- i.e. it is the address's provenance, not decoration.
        let Some(binary) = compile_req_state_dtor_fixture() else {
            return;
        };
        let symbols = dtor_symbol_addresses(&binary);
        if symbols.is_empty() {
            eprintln!(
                "SKIPPED exports_the_variant_provenance_of_the_req_state_dtor_address: \
                 toolchain emitted no destructor symbols"
            );
            return;
        }

        let info = from_paths(&[binary.as_path()]).unwrap();
        let (module_key, module) = info.modules.iter().next().unwrap();
        let addr = module
            .func2pc
            .get(REQ_STATE_DTOR)
            .copied()
            .expect("req_state::~req_state must resolve");
        let linkage = module
            .func2linkage
            .get(REQ_STATE_DTOR)
            .expect("the destructor address must carry its variant provenance");

        assert!(
            dtor_variant_rank(linkage).is_some(),
            "exported provenance {linkage} must be an ACCEPTED destructor variant (D1/D2)"
        );
        assert_eq!(
            symbols.get(linkage.as_str()),
            Some(&addr),
            "the exported linkage name must be the name of the exported address"
        );

        // And the import-side gate accepts what native extraction produced: the
        // native path must never emit an artifact its own importer refuses.
        if module.func2vf.contains_key(REQ_STATE_DTOR) {
            assert_eq!(
                info.request_end_probe(module_key),
                crate::dwarf_json::RequestEndProbe::Available {
                    addr,
                    linkage: linkage.clone(),
                }
            );
        }
    }

    #[test]
    fn dtor_variant_rank_accepts_complete_and_base_but_never_deleting() {
        // D1 (complete object) is preferred over D2 (base object); the deleting
        // destructor D0 and GCC's DWARF-only D4 placeholder are rejected
        // outright, so they can never supply an address.
        assert_eq!(dtor_variant_rank("_ZN9req_stateD1Ev"), Some(0));
        assert_eq!(dtor_variant_rank("_ZN9req_stateD2Ev"), Some(1));
        assert_eq!(dtor_variant_rank("_ZN9req_stateD0Ev"), None);
        assert_eq!(dtor_variant_rank("_ZN9req_stateD4Ev"), None);
        assert_eq!(dtor_variant_rank("_ZN9req_stateD5Ev"), None);
        // Not a destructor mangling at all.
        assert_eq!(dtor_variant_rank("_ZN9req_state6get_idEv"), None);
        assert_eq!(dtor_variant_rank(""), None);
        assert_eq!(dtor_variant_rank("Ev"), None);
    }

    #[test]
    fn definition_rank_rejects_the_deleting_dtor_and_passes_other_functions_through() {
        // Only the destructor is ranked; every other probe function keeps the
        // previous first-definition-wins behavior (rank 0, never rejected).
        assert_eq!(
            definition_rank(REQ_STATE_DTOR, &["_ZN9req_stateD1Ev".to_string()]),
            Some(0)
        );
        assert_eq!(
            definition_rank(REQ_STATE_DTOR, &["_ZN9req_stateD2Ev".to_string()]),
            Some(1)
        );
        // The deleting dtor's DIE also reaches the declaration's D4 placeholder
        // through its abstract origin; neither is acceptable, so it is rejected.
        assert_eq!(
            definition_rank(
                REQ_STATE_DTOR,
                &[
                    "_ZN9req_stateD0Ev".to_string(),
                    "_ZN9req_stateD4Ev".to_string()
                ]
            ),
            None
        );
        // A destructor definition with no reachable linkage name cannot be
        // proven to be the right variant -- reject rather than coin-flip.
        assert_eq!(definition_rank(REQ_STATE_DTOR, &[]), None);
        // Non-destructor probe functions are unaffected.
        assert_eq!(definition_rank("RGWREST::get_handler", &[]), Some(0));
        assert_eq!(
            definition_rank(
                "Objecter::_send_op",
                &["_ZN8Objecter8_send_opEv".to_string()]
            ),
            Some(0)
        );
    }

    // --- PHASE B: rgw_rados_operate overload extraction ---------------------

    /// A radosgw-shaped fixture carrying BOTH `rgw_rados_operate` overloads with
    /// the real Ceph namespaces, so the mangled names it produces are the ones a
    /// real radosgw exports. The write overload is DECLARED AND DEFINED FIRST on
    /// purpose: a first-match binder would hand its address to whichever key it
    /// looked up first, and this fixture is what catches that.
    ///
    /// It also carries `req_state : DoutPrefixProvider` (with the out-of-line
    /// destructor) because the per-submit re-seed is only extracted once DWARF
    /// PROVES that a `req_state*` and the `dpp` RGW passes for it are the same
    /// pointer -- i.e. that the DoutPrefixProvider base sits at offset 0. A fixture
    /// without that type models a build we would (correctly) refuse to probe.
    const RGW_RADOS_OPERATE_FIXTURE_SOURCE: &str = r#"
            class DoutPrefixProvider {
              public:
                virtual ~DoutPrefixProvider() {}
                virtual int get_id() const { return 0; }
            };
            struct req_state : public DoutPrefixProvider {
              unsigned long id;
              req_state(unsigned long i);
              ~req_state();
              int get_id() const override { return (int)id; }
            };
            static volatile unsigned long sink;
            req_state::req_state(unsigned long i) : id(i) {}
            __attribute__((noinline)) req_state::~req_state() { sink += id; }

            namespace librados { inline namespace v14_2_0 {
              class IoCtx { public: int fd; };
              class ObjectReadOperation { public: int r; };
              class ObjectWriteOperation { public: int w; };
            }}
            namespace ceph { namespace buffer { inline namespace v15_2_0 {
              class list { public: int len; };
            }}}
            class optional_yield { public: int y; };
            class CephString { public: const char* p; };

            int rgw_rados_operate(const DoutPrefixProvider *dpp, librados::IoCtx& ioctx,
                                  const CephString& oid, librados::ObjectWriteOperation *op,
                                  optional_yield y, int flags) {
              return dpp != 0 ? ioctx.fd + op->w + y.y + flags : (int)(unsigned long)oid.p;
            }

            int rgw_rados_operate(const DoutPrefixProvider *dpp, librados::IoCtx& ioctx,
                                  const CephString& oid, librados::ObjectReadOperation *op,
                                  ceph::buffer::list* pbl, optional_yield y, int flags) {
              return dpp != 0 ? ioctx.fd + op->r + pbl->len + y.y + flags : (int)(unsigned long)oid.p;
            }

            int main(int argc, char**) {
              librados::IoCtx ioctx; CephString oid; optional_yield y;
              librados::ObjectReadOperation rop; librados::ObjectWriteOperation wop;
              ceph::buffer::list bl;
              req_state s((unsigned long)argc);
              const DoutPrefixProvider* dpp = &s;
              return rgw_rados_operate(dpp, ioctx, oid, &rop, &bl, y, argc)
                   + rgw_rados_operate(dpp, ioctx, oid, &wop, y, argc);
            }
        "#;

    /// Builds the fixture as a module named `radosgw` (which is what routes it
    /// through `RGW_PROBE_FUNCTIONS`). `-O1` because at `-O0` this toolchain gives
    /// parameters `DW_OP_fbreg`+`DW_OP_call_frame_cfa` locations that
    /// `variable_location` deliberately rejects -- the same reason the DWZ fixture
    /// uses `-O1`.
    fn compile_rgw_rados_operate_fixture() -> Option<std::path::PathBuf> {
        compile_cpp_sources_flags_only(
            "radosgw",
            &[("radosgw", RGW_RADOS_OPERATE_FIXTURE_SOURCE)],
            &["-g", "-O1", "-fno-inline"],
        )
    }

    /// The ELF address of the symbol in `binary` whose MANGLED name classifies as
    /// `overload`. This is the ground truth the extractor's binding is checked
    /// against: it is read straight from the symbol table, independently of any of
    /// the code under test except the classifier itself.
    fn symbol_address_of_overload(
        binary: &std::path::Path,
        overload: crate::dwarf_json::RadosOperateOverload,
    ) -> Option<u64> {
        let data = fs::read(binary).ok()?;
        let file = object::File::parse(data.as_slice()).ok()?;
        file.symbols().find_map(|symbol| {
            let name = symbol.name().ok()?;
            (crate::dwarf_json::rados_operate_overload(name) == Some(overload))
                .then(|| symbol.address())
        })
    }

    #[test]
    fn binds_each_rados_operate_overload_to_its_own_address() {
        // THE end-to-end overload-binding proof, on a real compiled binary with real
        // mangled names. Both overloads exist, at different addresses, under ONE
        // demangled name -- and the fixture defines the WRITE one first, so a
        // first-match binder would give the read key the write overload's address.
        let Some(binary) = compile_rgw_rados_operate_fixture() else {
            return;
        };
        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.get("radosgw").expect("radosgw module");

        let (Some(read_addr), Some(write_addr)) = (
            module.func2pc.get(RGW_RADOS_OPERATE_READ).copied(),
            module.func2pc.get(RGW_RADOS_OPERATE_WRITE).copied(),
        ) else {
            panic!(
                "both overloads must resolve an address; got {:?}",
                module.func2pc.keys().collect::<Vec<_>>()
            );
        };
        assert_ne!(
            read_addr, write_addr,
            "the two overloads are distinct functions and must not share an address"
        );

        // Ground truth from the symbol table: each key must hold the address of the
        // symbol whose own mangled signature says it is that overload.
        assert_eq!(
            Some(read_addr),
            symbol_address_of_overload(&binary, crate::dwarf_json::RadosOperateOverload::Read),
            "the read key must hold the READ overload's address"
        );
        assert_eq!(
            Some(write_addr),
            symbol_address_of_overload(&binary, crate::dwarf_json::RadosOperateOverload::Write),
            "the write key must hold the WRITE overload's address"
        );

        // The exported provenance must name the mangled symbol each address came
        // from, and it must classify back to the key it is filed under -- this is
        // what an importer re-verifies (`DwarfInfo::rados_operate_probe`).
        for (function, overload) in [
            (
                RGW_RADOS_OPERATE_READ,
                crate::dwarf_json::RadosOperateOverload::Read,
            ),
            (
                RGW_RADOS_OPERATE_WRITE,
                crate::dwarf_json::RadosOperateOverload::Write,
            ),
        ] {
            let linkage = module
                .func2linkage
                .get(function)
                .unwrap_or_else(|| panic!("{function} must export its mangled linkage name"));
            assert_eq!(
                crate::dwarf_json::rados_operate_overload(linkage),
                Some(overload),
                "{function}: exported provenance {linkage} does not classify back to its own key"
            );
        }
    }

    #[test]
    fn extracts_a_register_only_dpp_descriptor_for_both_overloads() {
        // The `dpp` descriptor must be the raw-pointer sentinel: register-located,
        // exactly one {offset: 0, pointer: false} field. The BPF handler reads
        // `location.reg` and NOTHING else -- it never dereferences the dpp -- so any
        // other shape is refused at import (`is_raw_pointer_descriptor`).
        let Some(binary) = compile_rgw_rados_operate_fixture() else {
            return;
        };
        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.get("radosgw").expect("radosgw module");

        for function in [RGW_RADOS_OPERATE_READ, RGW_RADOS_OPERATE_WRITE] {
            let fields = module
                .func2vf
                .get(function)
                .unwrap_or_else(|| panic!("{function} must resolve a dpp descriptor"));
            assert_eq!(fields.var_fields.len(), 1, "{function}");

            let dpp = &fields.var_fields[0];
            assert!(
                crate::dwarf_json::is_raw_pointer_descriptor(dpp),
                "{function}: dpp descriptor must be the register-only raw-pointer sentinel: {dpp:?}"
            );
            assert!(!dpp.location.stack, "{function}");
            assert_eq!(dpp.fields.len(), 1, "{function}");
            assert_eq!(dpp.fields[0].offset, 0, "{function}");
            assert!(!dpp.fields[0].pointer, "{function}");

            // The register is DERIVED FROM DWARF, never hardcoded -- but on x86-64
            // arg0 is rdi, which is DWARF register 5, so that is what a correct
            // derivation must produce here. (Cross-check of the same rule the
            // existing probes obey: get_handler's req_state* is arg2 => rdx => 1,
            // rgw_process_authenticated's is arg3 => rcx => 2.)
            if cfg!(target_arch = "x86_64") {
                assert_eq!(
                    dpp.location.reg, 5,
                    "{function}: dpp is arg0 => rdi => DWARF reg 5 on x86-64"
                );
            }
        }
    }

    #[test]
    fn refuses_an_ambiguous_definition_rather_than_picking_one() {
        // Two equally-valid definitions of the SAME key at DIFFERENT addresses (a
        // third overload added upstream that also takes an ObjectWriteOperation, an
        // ICF'd alias, a duplicated symbol). Nothing can choose between them, so the
        // address is DROPPED, not guessed -- the probe simply does not attach.
        let mut resolved = BTreeMap::new();
        insert_ranked_pc(
            &mut resolved,
            RGW_RADOS_OPERATE_WRITE.to_string(),
            0,
            0x1000,
            Some("_ZN4mangledA".to_string()),
        );
        insert_ranked_pc(
            &mut resolved,
            RGW_RADOS_OPERATE_WRITE.to_string(),
            0,
            0x2000, // a DIFFERENT address, equally ranked
            Some("_ZN4mangledB".to_string()),
        );

        assert!(resolved[RGW_RADOS_OPERATE_WRITE].ambiguous);
        let dropped = drop_ambiguous_definitions(&mut resolved);
        assert_eq!(dropped, vec![RGW_RADOS_OPERATE_WRITE.to_string()]);
        assert!(
            !resolved.contains_key(RGW_RADOS_OPERATE_WRITE),
            "an ambiguous definition must not be resolved to an arbitrary address"
        );
    }

    #[test]
    fn the_same_definition_seen_twice_is_not_ambiguous() {
        // The symbol table and the dynamic symbol table both list the same symbol,
        // and the DWARF scan may re-find it. Same address => same definition => not
        // an ambiguity, or every binary would lose its probes.
        let mut resolved = BTreeMap::new();
        for _ in 0..3 {
            insert_ranked_pc(
                &mut resolved,
                RGW_RADOS_OPERATE_READ.to_string(),
                0,
                0x1000,
                Some("_ZN4same".to_string()),
            );
        }

        assert!(!resolved[RGW_RADOS_OPERATE_READ].ambiguous);
        assert!(drop_ambiguous_definitions(&mut resolved).is_empty());
        assert_eq!(resolved[RGW_RADOS_OPERATE_READ].pc, 0x1000);
    }

    #[test]
    fn probe_keys_expands_only_the_overload_set() {
        // A definition demangling to `rgw_rados_operate` is a candidate for BOTH
        // overload keys (the linkage-name gate then picks exactly one); every other
        // demangled name maps to itself, preserving the previous behavior.
        assert_eq!(
            probe_keys(RGW_RADOS_OPERATE, RGW_PROBE_FUNCTIONS),
            vec![RGW_RADOS_OPERATE_READ, RGW_RADOS_OPERATE_WRITE]
        );
        assert_eq!(
            probe_keys("RGWREST::get_handler", RGW_PROBE_FUNCTIONS),
            vec!["RGWREST::get_handler"]
        );
        // The synthetic keys are not demangled names and must never match a symbol.
        assert!(probe_keys(RGW_RADOS_OPERATE_READ, RGW_PROBE_FUNCTIONS).is_empty());
        assert!(probe_keys("Objecter::_send_op", RGW_PROBE_FUNCTIONS).is_empty());
        // Restricted to `wanted`: a librados module never asks for the RGW probes.
        assert!(probe_keys(RGW_RADOS_OPERATE, OBJECTER_PROBE_FUNCTIONS).is_empty());
    }

    #[test]
    fn definition_rank_binds_each_overload_only_to_its_own_signature() {
        // Symbol-table order cannot swap the overloads: each key ACCEPTS only its
        // own mangled signature and REJECTS the other's, so whichever is seen first
        // can still only claim its own slot.
        let read = "_Z17rgw_rados_operatePK18DoutPrefixProviderRN8librados7v14_2_05IoCtxERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPNS3_19ObjectReadOperationEPN4ceph6buffer7v15_2_04listE14optional_yieldi";
        let write = "_Z17rgw_rados_operatePK18DoutPrefixProviderRN8librados7v14_2_05IoCtxERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPNS3_20ObjectWriteOperationE14optional_yieldi";

        assert_eq!(
            definition_rank(RGW_RADOS_OPERATE_READ, &[read.to_string()]),
            Some(0)
        );
        assert_eq!(
            definition_rank(RGW_RADOS_OPERATE_READ, &[write.to_string()]),
            None
        );
        assert_eq!(
            definition_rank(RGW_RADOS_OPERATE_WRITE, &[write.to_string()]),
            Some(0)
        );
        assert_eq!(
            definition_rank(RGW_RADOS_OPERATE_WRITE, &[read.to_string()]),
            None
        );
        // A definition with no reachable linkage name cannot be proven to be either
        // overload -- reject rather than coin-flip.
        assert_eq!(definition_rank(RGW_RADOS_OPERATE_READ, &[]), None);
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
            func2linkage: BTreeMap::new(),
        };
        module.func2pc.insert(function.to_string(), pc);
        module
    }

    fn compile_cpp_fixture() -> Option<std::path::PathBuf> {
        compile_cpp_fixture_with_flags(&[])
    }

    fn compile_cpp_fixture_with_flags(flags: &[&str]) -> Option<std::path::PathBuf> {
        compile_cpp_sources_with_flags("fixture", &[("fixture", CPP_FIXTURE_SOURCE)], flags)
    }

    const CPP_FIXTURE_SOURCE: &str = r#"
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
            "#;

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

    /// Compiled at `-g -O2` (no `-O0`/`-fno-inline` defaults) so GCC emits
    /// `get_handler` as an abstract instance -- whose parameters carry
    /// `DW_AT_name` and `DW_AT_type` -- plus a concrete out-of-line instance
    /// whose parameters carry `DW_AT_location`+`DW_AT_abstract_origin` but no
    /// `DW_AT_name` and no `DW_AT_type`. The member-function-pointer indirection
    /// keeps the out-of-line copy alive while the direct call is inlined, which
    /// is what triggers the abstract/concrete split this fixture exercises.
    fn compile_rgw_optimized_fixture() -> Option<std::path::PathBuf> {
        compile_cpp_sources_flags_only(
            "rgw-optimized-fixture",
            &[(
                "rgw-optimized-fixture",
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
                  void get_handler(ReqState* s);
                  volatile unsigned long sink = 0;
                };
                void RGWREST::get_handler(ReqState* s) {
                  sink += s->trans_id._M_string_length;
                  sink += (unsigned long)s->trans_id._M_dataplus._M_p;
                }
                static RGWREST rest;
                void (RGWREST::*handler_ptr)(ReqState*) = &RGWREST::get_handler;
                int main() {
                  char value = 0;
                  ReqState state = {{{&value}, 12}};
                  rest.get_handler(&state);
                  (rest.*handler_ptr)(&state);
                  return 0;
                }
                "#,
            )],
            &["-g", "-O2"],
        )
    }

    const OBJECTER_FIXTURE_SOURCE: &str = r#"
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
            "#;

    fn compile_objecter_fixture() -> Option<std::path::PathBuf> {
        compile_cpp_source("objecter-fixture", OBJECTER_FIXTURE_SOURCE)
    }

    /// Whether the `dwz` DWZ-compression tool is available, gating the
    /// supplementary-file end-to-end test (skip-if-absent, like the objcopy and
    /// LTO fixtures).
    fn dwz_available() -> bool {
        std::process::Command::new("dwz")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Compiles the Objecter fixture into two identical binaries in a shared
    /// directory and runs `dwz -m` over them. DWZ moves the duplicated type DIEs
    /// into the supplementary multifile and rewrites each binary with a
    /// `.gnu_debugaltlink` pointing at it, so resolving the probe's field paths
    /// then genuinely requires following `DW_FORM_GNU_ref_alt`/`GNU_strp_alt`
    /// into the supplementary file. Returns the first binary's path.
    fn compile_dwz_pair() -> Option<std::path::PathBuf> {
        let compiler = std::env::var_os("CXX").unwrap_or_else(|| "c++".into());
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("rgwtrace-dwz-{}-{suffix}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;

        let source = dir.join("objecter.cc");
        std::fs::write(&source, OBJECTER_FIXTURE_SOURCE).ok()?;

        // Relative output names so the .gnu_debugaltlink dwz writes is relative
        // to (and resolvable from) the binary's own directory. `-O1` (not `-O0`)
        // so parameters get register-resident locations `variable_location` can
        // decode; at `-O0` this toolchain emits `DW_OP_fbreg`+`DW_OP_call_frame_cfa`,
        // which the decoder rejects (unrelated to DWZ -- the same-file objecter
        // fixture skips for the same reason at `-O0`).
        for name in ["objecter-a", "objecter-b"] {
            let ok = std::process::Command::new(&compiler)
                .current_dir(&dir)
                .args(["-g", "-O1", "-fno-inline", "objecter.cc", "-o", name])
                .status()
                .ok()?
                .success();
            if !ok {
                return None;
            }
        }

        let ok = std::process::Command::new("dwz")
            .current_dir(&dir)
            .args(["-m", "objecter.dwz", "objecter-a", "objecter-b"])
            .status()
            .ok()?
            .success();
        if !ok {
            return None;
        }

        Some(dir.join("objecter-a"))
    }

    /// Same fixture compiled at `-O1 -fno-inline` (the level the DWZ pair uses)
    /// but WITHOUT dwz. Serves as the oracle for the end-to-end test: resolving
    /// through the supplementary file must match same-file resolution exactly.
    fn compile_objecter_at_o1() -> Option<std::path::PathBuf> {
        compile_cpp_sources_flags_only(
            "objecter-o1",
            &[("objecter", OBJECTER_FIXTURE_SOURCE)],
            &["-g", "-O1", "-fno-inline"],
        )
    }

    /// Whether the DWZ'd binary's main `.debug_info` actually references the
    /// supplementary file via `DW_FORM_GNU_ref_alt` (`DebugInfoRefSup`). Shape
    /// guard so the end-to-end test never passes vacuously when dwz found
    /// nothing worth moving into the supplementary file.
    fn dwz_binary_uses_sup_refs(binary: &Path) -> bool {
        let data = std::fs::read(binary).unwrap();
        let file = object::File::parse(data.as_slice()).unwrap();
        let (debug_data, debug_file_path) =
            debug_data(binary, &file, data.as_slice(), u64::MAX).unwrap();
        let debug_file = object::File::parse(debug_data.as_ref()).unwrap();
        let endian = if debug_file.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let sup_data = load_sup_object_bytes(&debug_file, &debug_file_path, u64::MAX);
        let sup_file = sup_data
            .as_ref()
            .map(|bytes| object::File::parse(bytes.as_slice()).unwrap());
        let mut dwarf_owned = Dwarf::load(|section| {
            load_section_unbounded(&debug_file, section).map(|data| data.into_owned())
        })
        .unwrap();
        if let Some(sup_file) = &sup_file {
            dwarf_owned
                .load_sup(|section| {
                    load_section_unbounded(sup_file, section).map(|data| data.into_owned())
                })
                .unwrap();
        }
        #[allow(deprecated)]
        let dwarf = dwarf_owned.borrow(|section| EndianSlice::new(section, endian));
        if dwarf.sup().is_none() {
            return false;
        }
        let index = DwarfUnitIndex::load(&dwarf).unwrap();
        for unit_index in 0..index.main_len() {
            let unit = index.unit(unit_index);
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs().unwrap() {
                let mut attrs = entry.attrs();
                while let Some(attr) = attrs.next().unwrap() {
                    if matches!(attr.value(), AttributeValue::DebugInfoRefSup(_)) {
                        return true;
                    }
                }
            }
        }
        false
    }

    #[test]
    fn extracts_objecter_var_fields_through_dwz_supplementary_file() {
        if !dwz_available() {
            eprintln!(
                "SKIPPED extracts_objecter_var_fields_through_dwz_supplementary_file: \
                 dwz tool not installed"
            );
            return;
        }
        let Some(binary) = compile_dwz_pair() else {
            eprintln!(
                "SKIPPED extracts_objecter_var_fields_through_dwz_supplementary_file: \
                 could not build/dwz the fixture pair"
            );
            return;
        };

        // Shape guard 1: dwz actually emitted a supplementary link.
        let data = std::fs::read(&binary).unwrap();
        let file = object::File::parse(data.as_slice()).unwrap();
        if file.section_by_name(".gnu_debugaltlink").is_none() {
            eprintln!(
                "SKIPPED extracts_objecter_var_fields_through_dwz_supplementary_file: \
                 dwz did not emit a .gnu_debugaltlink"
            );
            return;
        }
        // Shape guard 2: the main file genuinely references DIEs in the
        // supplementary file via DW_FORM_GNU_ref_alt, so the extraction below
        // truly exercises DebugInfoRefSup/strp_alt rather than resolving
        // everything locally. Never a vacuous pass.
        if !dwz_binary_uses_sup_refs(&binary) {
            eprintln!(
                "SKIPPED extracts_objecter_var_fields_through_dwz_supplementary_file: \
                 dwz did not move DIEs into the supplementary file"
            );
            return;
        }

        // Oracle: a pristine (non-dwz) build at the same optimization level. If
        // this toolchain cannot decode the parameter locations even without dwz
        // (e.g. only fbreg/CFA locations), skip -- that gap is unrelated to DWZ.
        let Some(pristine) = compile_objecter_at_o1() else {
            eprintln!(
                "SKIPPED extracts_objecter_var_fields_through_dwz_supplementary_file: \
                 could not compile the -O1 oracle"
            );
            return;
        };
        let pinfo = from_paths(&[pristine.as_path()]).unwrap();
        let pmodule = pinfo.modules.values().next().unwrap();
        let Some(pfields) = pmodule.func2vf.get("Objecter::_send_op") else {
            eprintln!(
                "SKIPPED extracts_objecter_var_fields_through_dwz_supplementary_file: \
                 toolchain did not emit decodable var fields even without dwz"
            );
            return;
        };

        // Full public chain over the DWZ'd binary: function PC, variable
        // location, AND every nested field path (member offsets) -- all
        // resolving through the supplementary file -- must match same-file
        // resolution byte for byte. `func2vf` was empty here before the sup file
        // was loaded.
        let info = from_paths(&[binary.as_path()]).unwrap();
        let module = info.modules.values().next().unwrap();

        assert!(module.func2pc.contains_key("Objecter::_send_op"));
        let fields = module.func2vf.get("Objecter::_send_op").expect(
            "Objecter::_send_op var fields must resolve through the DWZ supplementary file",
        );
        assert_eq!(fields.var_fields.len(), 12);
        // Nested paths whose member/type DIEs live in the supplementary file
        // (e.g. op->target.base_oid.name._M_dataplus._M_p, this->monc.global_id).
        assert_eq!(fields.var_fields[0].fields.len(), 2);
        assert_eq!(fields.var_fields[1].fields.len(), 3);
        assert_eq!(fields.var_fields[3].fields.len(), 5);
        assert_eq!(fields.var_fields[4].fields.len(), 6);
        assert!(fields
            .var_fields
            .iter()
            .all(|field| field.location.reg >= 0));
        assert!(
            same_var_fields(pfields, fields),
            "DWZ sup-resolved var fields must equal same-file (non-dwz) resolution"
        );
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

    /// Like `compile_cpp_sources_with_flags` but passes `flags` verbatim without
    /// the default `-g -O0 -fno-inline`, so a fixture can be built optimized
    /// (`-O2`) to exercise the abstract/concrete DWARF split.
    fn compile_cpp_sources_flags_only(
        name: &str,
        sources: &[(&str, &str)],
        flags: &[&str],
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
        command.args(flags);
        for source in &sources {
            command.arg(source);
        }
        let status = command.arg("-o").arg(&binary).status().ok()?;
        status.success().then_some(binary)
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
                        if let Some(target) = index.debug_info_ref(unit_index, offset) {
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
        let dwarf_cow = Dwarf::load(|section| load_section_unbounded(&file, section)).unwrap();
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
        assert_ne!(pc.pc, 0);
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
        fixture_field_path(binary, "inspect", "outer", &["outer", "leaf", "value"])
    }

    fn fixture_field_path(
        binary: &Path,
        function_name: &str,
        param_name: &str,
        path: &[&str],
    ) -> Result<Option<Vec<FieldJson>>> {
        let data = std::fs::read(binary)?;
        let file = object::File::parse(data.as_slice())?;
        let endian = if file.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let dwarf_cow = Dwarf::load(|section| load_section_unbounded(&file, section))?;
        #[allow(deprecated)]
        let dwarf = dwarf_cow.borrow(|section| EndianSlice::new(section, endian));

        let index = DwarfUnitIndex::load(&dwarf)?;
        for unit_index in 0..index.len() {
            let unit = index.unit(unit_index);
            let Some(function) =
                find_subprogram_by_name(&dwarf, &index, unit_index, function_name)?
            else {
                continue;
            };
            let Some(param) = find_child_entry_by_name(
                &dwarf,
                unit,
                function.offset(),
                &[gimli::DW_TAG_formal_parameter],
                param_name,
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
                path,
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
        let dwarf_cow = Dwarf::load(|section| load_section_unbounded(&file, section))?;
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

#[cfg(test)]
#[path = "dwarf_native_robustness_tests.rs"]
mod robustness_tests;
