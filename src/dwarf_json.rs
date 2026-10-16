use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Serialize)]
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
    /// MANGLED linkage name of the definition each `func2pc` address was resolved
    /// from -- the variant PROVENANCE of the address. Only emitted for functions
    /// where the demangled name is ambiguous, which today means exactly the
    /// `req_state` destructor: the Itanium ABI's D0 (deleting), D1 (complete) and
    /// D2 (base) variants all demangle to `req_state::~req_state`, and D0 -- the
    /// one that must NEVER be probed -- is the one g++ lists first.
    ///
    /// A third-party or cephtrace-style producer that resolved "the first
    /// destructor with that demangled name" hands us D0, and nothing in the
    /// address or the descriptor can tell us so. Without this field we cannot
    /// prove which variant an imported address belongs to, so we refuse to probe
    /// it (see [`DwarfInfo::request_end_probe`]) rather than gamble on attaching
    /// an END uprobe to a deleting destructor. Older artifacts simply lack the
    /// field and lose the end probe, degrading to derived request durations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub func2linkage: BTreeMap<String, String>,
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct VarLocationKernel {
    pub reg: i32,
    pub offset: i32,
    pub stack: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FieldKernel {
    pub offset: i32,
    pub pointer: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct VarFieldKernel {
    pub varloc: VarLocationKernel,
    pub fields: [FieldKernel; 10],
    pub size: i32,
}

/// The request-START probe: the earliest site where the request's `trans_id` and
/// its `req_state*` (the bridge's canonical key) are both available.
pub const RGWREST_GET_HANDLER: &str = "RGWREST::get_handler";

const FUNCTION_BASE_IDS: &[(&str, i32)] = &[
    ("Objecter::_send_op", 0),
    ("Objecter::_finish_op", 20),
    (RGWREST_GET_HANDLER, 30),
    (RGW_PROCESS_AUTHENTICATED, 40),
    (REQ_STATE_DTOR, 50),
    (RGW_RADOS_OPERATE_READ, 60),
    (RGW_RADOS_OPERATE_WRITE, 70),
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

/// Cross-thread re-seed probe (`--correlate-cross-thread`). Its hprobe slot
/// carries a raw-pointer descriptor rather than a member-deref chain: the
/// var_field is read register-only by the BPF re-seed handler (`fetch_param_ptr`
/// in bpf/rgwtrace.bpf.c), which consumes `location.reg` and ignores `fields`.
/// Any other var_field shape here would make the handler read a wrong parameter,
/// so we pin the shape at import.
pub const RGW_PROCESS_AUTHENTICATED: &str = "rgw_process_authenticated";

/// Request-END probe: the `req_state` destructor, i.e. the true end of an RGW
/// request. Like [`RGW_PROCESS_AUTHENTICATED`] its hprobe slot carries the
/// raw-pointer descriptor (here the implicit `this` parameter), read
/// register-only by `uprobe_rgw_req_state_dtor`.
///
/// The name is the DEMANGLED destructor name, which is identical for all three
/// Itanium-ABI destructor variants (D0 deleting / D1 complete / D2 base). The
/// address bound to it is disambiguated at extraction time (`dtor_variant_rank`
/// in `src/dwarf_native.rs`): only the complete/base object destructor -- the one
/// `process_request` actually calls -- is ever accepted.
pub const REQ_STATE_DTOR: &str = "req_state::~req_state";

/// PHASE B. The demangled name of the per-submit re-seed site: the last common
/// frame before a RADOS submit, whose first parameter is the request's
/// `DoutPrefixProvider*` (`dpp`).
///
/// It is NOT a probe key on its own, because it names TWO distinct out-of-line
/// functions -- the `ObjectReadOperation` and `ObjectWriteOperation` overloads --
/// and `demangle_function_name` strips the argument list, so both collapse onto
/// this one string. Binding a probe to "the first symbol with this demangled
/// name" would attach to whichever overload the symbol table happens to list
/// first and silently drop the other half of the data path. The two synthetic
/// keys below carry the overloads separately, and
/// [`rados_operate_overload`] decides which is which from the MANGLED name.
pub const RGW_RADOS_OPERATE: &str = "rgw_rados_operate";

/// Synthetic probe key for the `ObjectReadOperation` overload of
/// [`RGW_RADOS_OPERATE`]. Not a demangled C++ name -- it never appears in a
/// binary -- it is the artifact key under which that overload's address, `dpp`
/// descriptor, and mangled-name provenance are stored.
pub const RGW_RADOS_OPERATE_READ: &str = "rgw_rados_operate(read)";

/// Synthetic probe key for the `ObjectWriteOperation` overload of
/// [`RGW_RADOS_OPERATE`]. See [`RGW_RADOS_OPERATE_READ`].
pub const RGW_RADOS_OPERATE_WRITE: &str = "rgw_rados_operate(write)";

/// Both `rgw_rados_operate` overload keys, in probe-attach order.
pub const RGW_RADOS_OPERATE_OVERLOADS: &[&str] = &[RGW_RADOS_OPERATE_READ, RGW_RADOS_OPERATE_WRITE];

/// Which overload of `rgw_rados_operate` a definition is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RadosOperateOverload {
    Read,
    Write,
}

impl RadosOperateOverload {
    /// The artifact/probe key this overload is stored under.
    pub fn function(self) -> &'static str {
        match self {
            Self::Read => RGW_RADOS_OPERATE_READ,
            Self::Write => RGW_RADOS_OPERATE_WRITE,
        }
    }
}

/// Classify a MANGLED `rgw_rados_operate` symbol into its overload, or `None` if
/// the name is not one of the two overloads we may probe.
///
/// This is the single source of truth for the overload binding, shared by native
/// extraction (which uses it to route each definition to the right key, so
/// neither overload can win the other's slot by appearing first) and by JSON
/// import (which uses it to re-verify an imported artifact's `func2linkage`
/// provenance -- a third-party producer keyed only by demangled name would hand
/// us one address for both overloads, and only the mangled name can reveal that).
///
/// It demangles WITH the argument list -- unlike `demangle_function_name`, which
/// strips it, which is precisely why the two overloads are indistinguishable
/// everywhere else -- and requires ALL of:
///
/// * the function is exactly `rgw_rados_operate` (not a member function, not a
///   lookalike);
/// * its FIRST parameter is `const DoutPrefixProvider*`. This is the load-bearing
///   check: the BPF handler reads arg0 as an opaque identity token and looks it
///   up in the `(req_state*, tgid)` bridge, which is only sound because
///   `req_state` inherits `DoutPrefixProvider` at offset 0. If upstream ever
///   reorders the parameters, arg0 stops being the dpp, this returns `None`, and
///   the probe is not attached -- rather than keying the bridge on an `IoCtx&`;
/// * exactly one of `ObjectReadOperation` / `ObjectWriteOperation` appears, which
///   is what distinguishes the two overloads.
///
/// Anything else -- a third overload added upstream, a renamed parameter type, a
/// `.cold`/`.constprop` clone -- is rejected, so an unrecognized definition is
/// never probed on a guess.
pub fn rados_operate_overload(mangled: &str) -> Option<RadosOperateOverload> {
    let symbol = cpp_demangle::Symbol::new(mangled)
        .or_else(|_| cpp_demangle::Symbol::new(mangled.strip_prefix('_').unwrap_or(mangled)))
        .ok()?;
    let demangled = symbol
        .demangle(&cpp_demangle::DemangleOptions::default())
        .ok()?;

    let prefix = format!("{RGW_RADOS_OPERATE}(");
    let args = demangled.strip_prefix(&prefix)?;

    // Compare whitespace-insensitively: demanglers disagree about the spacing (and
    // the side) of `const` on a pointer parameter, and we would rather not hinge
    // the whole feature on `DoutPrefixProvider const*` vs `const DoutPrefixProvider *`.
    let compact: String = args.chars().filter(|ch| !ch.is_whitespace()).collect();
    let dpp_is_first = compact.starts_with("DoutPrefixProviderconst*")
        || compact.starts_with("constDoutPrefixProvider*");
    if !dpp_is_first {
        return None;
    }

    match (
        compact.contains("ObjectReadOperation"),
        compact.contains("ObjectWriteOperation"),
    ) {
        (true, false) => Some(RadosOperateOverload::Read),
        (false, true) => Some(RadosOperateOverload::Write),
        _ => None,
    }
}

/// The exact descriptor shape a pinned hprobe slot must carry. These slots are
/// NOT read through the generic member-deref walker (`fetch_var_member_addr`);
/// each is read by a specific BPF accessor that assumes a specific shape, so the
/// shape is validated at import and a mismatched descriptor is refused rather
/// than fed to a handler that would silently read a wrong parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorShape {
    /// Register-located, exactly one `{offset: 0, pointer: false}` field: the
    /// parameter's own pointer VALUE, read by `fetch_param_ptr` (register-only,
    /// no memory access at all).
    RawPointer,
    /// Register-located, exactly one `{offset: 0, pointer: true}` field: the
    /// parameter is a C++ REFERENCE to a pointer (`RGWOp*& op`), so the register
    /// holds the ADDRESS of the pointer and `fetch_param_ptr_ref` performs exactly
    /// ONE read of the pointee to get the pointer's value. The `pointer: true`
    /// flag is what distinguishes it from [`Self::RawPointer`]: an artifact that
    /// carried a raw-pointer descriptor here would make the handler key the bridge
    /// on the ADDRESS OF a stack slot instead of the RGWOp, so the shapes must not
    /// be interchangeable.
    PointerRef,
}

impl DescriptorShape {
    fn matches(self, var_field: &VarFieldJson) -> bool {
        let single_field_at_zero = !var_field.location.stack
            && var_field.fields.len() == 1
            && var_field.fields[0].offset == 0;
        match self {
            Self::RawPointer => single_field_at_zero && !var_field.fields[0].pointer,
            Self::PointerRef => single_field_at_zero && var_field.fields[0].pointer,
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::RawPointer => {
                "the raw-pointer descriptor (register-located, exactly one \
                 {offset:0, pointer:false} field)"
            }
            Self::PointerRef => {
                "the reference-to-pointer descriptor (register-located, exactly one \
                 {offset:0, pointer:true} field)"
            }
        }
    }
}

/// The descriptor shapes a probe function's hprobe slots must carry, in slot
/// order, or `None` when its slots are generic member-deref chains.
///
/// A function may legitimately carry FEWER var_fields than shapes listed here --
/// `rgw_process_authenticated`'s `RGWOp*&` descriptor is dropped by extraction on
/// any build where the RGWOp dpp identity could not be PROVEN -- but never more,
/// and never a different shape at a given slot.
pub fn descriptor_shapes(function: &str) -> Option<&'static [DescriptorShape]> {
    match function {
        // slot 40: `req_state* s` (raw pointer).
        // slot 41: `RGWOp*& op`   (reference to pointer) -- the alternate bridge key.
        RGW_PROCESS_AUTHENTICATED => {
            Some(&[DescriptorShape::RawPointer, DescriptorShape::PointerRef])
        }
        // slot 50: the destructor's implicit `this` (raw pointer).
        REQ_STATE_DTOR => Some(&[DescriptorShape::RawPointer]),
        // slots 60/70: each overload's `dpp` (raw pointer, never dereferenced).
        RGW_RADOS_OPERATE_READ | RGW_RADOS_OPERATE_WRITE => Some(&[DescriptorShape::RawPointer]),
        _ => None,
    }
}

/// Probe functions whose `func2pc` address is meaningless without MANGLED-name
/// provenance, i.e. whose demangled name maps to more than one definition:
///
/// * `req_state::~req_state` -- the Itanium D0/D1/D2 variants all demangle
///   identically, and D0 (which must never be probed) is the one g++ lists first;
/// * the two `rgw_rados_operate` overloads -- distinct functions at distinct
///   addresses that collapse onto one demangled name once the argument list is
///   stripped.
///
/// Both are the same hazard: "resolve the first symbol with this demangled name"
/// silently binds the probe to the wrong definition. A resolved address for any of
/// these is refused unless `func2linkage` proves, from the mangled name, which
/// definition it came from ([`provenance_rank`]).
pub const VARIANT_PROVENANCE_FUNCTIONS: &[&str] = &[
    REQ_STATE_DTOR,
    RGW_RADOS_OPERATE_READ,
    RGW_RADOS_OPERATE_WRITE,
];

/// Rank of a candidate definition for `function`, given ONE mangled linkage name,
/// or `None` if that linkage name is not an acceptable definition of `function`.
/// Lower ranks win; `None` REJECTS.
///
/// This is the shared never-bind-the-wrong-definition rule for every function in
/// [`VARIANT_PROVENANCE_FUNCTIONS`]. Functions outside that set have exactly one
/// definition, so their demangled name is proof enough and they rank 0
/// unconditionally.
pub fn provenance_rank(function: &str, mangled: &str) -> Option<u8> {
    match function {
        REQ_STATE_DTOR => dtor_variant_rank(mangled),
        // Each overload accepts ONLY the mangled signature that classifies back to
        // its own key, so the read overload's address can never land in the write
        // overload's slot (or vice versa) no matter which the symbol table lists
        // first.
        RGW_RADOS_OPERATE_READ | RGW_RADOS_OPERATE_WRITE => rados_operate_overload(mangled)
            .filter(|overload| overload.function() == function)
            .map(|_| 0),
        _ => Some(0),
    }
}

/// Rank of an Itanium-ABI destructor variant encoded in a MANGLED name, or
/// `None` when the name is not a destructor variant we may probe.
///
/// This is the single source of truth for the never-D0 rule, shared by native
/// extraction (which ranks candidate DIEs/symbols by it) and by JSON import
/// (which uses it to validate an imported artifact's `func2linkage` provenance).
///
/// * `D1` (complete object destructor) -- ACCEPTED, rank 0. This is the one
///   `process_request` calls out-of-line for its stack-allocated `req_state`
///   (verified on Ceph 18.2.4 and 19.2.4: `call <_ZN9req_stateD1Ev>`), so it is
///   preferred whenever it exists.
/// * `D2` (base object destructor) -- ACCEPTED, rank 1. On both verified builds
///   it is ALIASED to D1 at the same address; it only diverges for classes with
///   virtual bases, and then D1 is present and wins on rank anyway.
/// * `D0` (deleting destructor) -- REJECTED. It runs only for `delete`-ed
///   objects (`operator delete` after the base dtor); `req_state` is
///   stack-allocated, so probing D0 would fire on the wrong path (or never).
/// * `D4`, `D5`, anything else -- REJECTED. `D4` is GCC's DWARF-only "unified"
///   placeholder that appears on the class-scope DECLARATION (never a
///   definition, so it has no PC anyway). Rejecting the unknown rest keeps the
///   choice deterministic instead of a coin flip: worst case the end probe does
///   not attach and the tracer degrades to derived durations.
pub fn dtor_variant_rank(mangled: &str) -> Option<u8> {
    // A destructor takes no arguments, so its mangled name ends in `D<n>Ev`.
    let head = mangled.strip_suffix("Ev")?;
    let bytes = head.as_bytes();
    let [.., b'D', variant] = bytes else {
        return None;
    };
    match variant {
        b'1' => Some(0),
        b'2' => Some(1),
        _ => None,
    }
}

/// Availability of the request-END probe (`req_state::~req_state`) for one
/// artifact module. Everything the probe needs must be provable from the
/// artifact alone, because attaching an END uprobe to the WRONG destructor
/// variant is not a degradation -- it is a probe on a function that never runs
/// for a stack-allocated `req_state` (D0), on a build we cannot inspect at
/// runtime. Hence: prove it, or do not attach it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestEndProbe {
    /// Address + a linkage name that PROVES it is the complete/base destructor.
    Available { addr: u64, linkage: String },
    /// Not attachable; carries the operator-facing reason.
    Unavailable(RequestEndProbeGap),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestEndProbeGap {
    /// The radosgw path resolved to no (or an ambiguous) artifact module.
    NoModule,
    /// The artifact has no `func2pc` address for the destructor (older/stripped
    /// build, or native extraction refused every variant it saw).
    NoAddress,
    /// No register-only raw-pointer descriptor for the `this` parameter, so the
    /// BPF handler could not read the `req_state*` even if it attached.
    NoDescriptor,
    /// An address, but NO `func2linkage` entry proving which destructor variant
    /// it came from. Pre-provenance artifacts land here: they are refused, not
    /// trusted, because a producer that picked the first demangled match picked
    /// D0. Re-export the artifact to regain the end probe.
    MissingVariantProvenance,
    /// An address whose linkage name proves it is a variant we must never probe
    /// (D0 deleting destructor, or an unrecognized mangling).
    RejectedVariant(String),
}

/// Why a probe whose demangled name is AMBIGUOUS could not be bound to a proven
/// definition. Shared by every function in [`VARIANT_PROVENANCE_FUNCTIONS`]; the
/// probe-specific wrappers ([`RequestEndProbeGap`], [`RadosOperateProbeGap`])
/// turn it into an operator-facing reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProvenanceGap {
    /// The target path resolved to no (or an ambiguous) artifact module.
    NoModule,
    /// The artifact has no `func2pc` address for the function.
    NoAddress,
    /// No register-only raw-pointer descriptor for the probed pointer parameter,
    /// so the BPF handler could not read it even if the probe attached.
    NoDescriptor,
    /// An address, but NO `func2linkage` entry proving WHICH of the several
    /// definitions sharing this demangled name it came from.
    MissingProvenance,
    /// An address whose mangled linkage name proves it is NOT an acceptable
    /// definition of this function (the D0 destructor; the other
    /// `rgw_rados_operate` overload; an unrecognized signature).
    RejectedLinkage(String),
}

impl From<ProvenanceGap> for RequestEndProbeGap {
    fn from(gap: ProvenanceGap) -> Self {
        match gap {
            ProvenanceGap::NoModule => Self::NoModule,
            ProvenanceGap::NoAddress => Self::NoAddress,
            ProvenanceGap::NoDescriptor => Self::NoDescriptor,
            ProvenanceGap::MissingProvenance => Self::MissingVariantProvenance,
            ProvenanceGap::RejectedLinkage(linkage) => Self::RejectedVariant(linkage),
        }
    }
}

/// PHASE B. Availability of ONE `rgw_rados_operate` overload's per-submit re-seed
/// probe. Same fail-closed contract as [`RequestEndProbe`]: an address is only
/// usable when the artifact also proves, from the MANGLED linkage name, that it
/// belongs to THIS overload -- otherwise the read overload's probe could be
/// attached to the write overload's address (and read its `dpp` with the other
/// definition's register descriptor).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RadosOperateProbe {
    /// Address + a linkage name that PROVES it is this overload.
    Available { addr: u64, linkage: String },
    /// Not attachable; carries the operator-facing reason.
    Unavailable(RadosOperateProbeGap),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RadosOperateProbeGap {
    pub function: &'static str,
    pub gap: ProvenanceGap,
}

impl RadosOperateProbeGap {
    /// Short, stable reason string for logs, preflight output, and tests.
    pub fn reason(&self) -> String {
        let function = self.function;
        match &self.gap {
            ProvenanceGap::NoModule => "radosgw resolved to no artifact module".to_string(),
            ProvenanceGap::NoAddress => format!(
                "artifact has no {function} address (older/stripped RGW, or extraction could not \
                 prove which overload a definition was)"
            ),
            ProvenanceGap::NoDescriptor => {
                format!("artifact has no register-only raw-pointer `dpp` descriptor for {function}")
            }
            ProvenanceGap::MissingProvenance => format!(
                "artifact has a {function} address but no func2linkage entry proving which \
                 overload it came from; {RGW_RADOS_OPERATE} has TWO overloads that demangle \
                 identically, so an unproven address could be the other one. Re-export the DWARF \
                 artifact with a current rgwtrace to regain the per-submit re-seed"
            ),
            ProvenanceGap::RejectedLinkage(linkage) => format!(
                "artifact's {function} address comes from linkage name {linkage}, which does not \
                 demangle to the expected overload signature (dpp as first parameter, and the \
                 matching Object{{Read,Write}}Operation); refusing to attach it"
            ),
        }
    }
}

impl RequestEndProbeGap {
    /// Short, stable reason string for logs, preflight output, and tests.
    pub fn reason(&self) -> String {
        match self {
            Self::NoModule => "radosgw resolved to no artifact module".to_string(),
            Self::NoAddress => format!("artifact has no {REQ_STATE_DTOR} address"),
            Self::NoDescriptor => format!(
                "artifact has no register-only raw-pointer `this` descriptor for {REQ_STATE_DTOR}"
            ),
            Self::MissingVariantProvenance => format!(
                "artifact has a {REQ_STATE_DTOR} address but no func2linkage entry proving it is \
                 the complete/base destructor (D1/D2); refusing to risk probing the deleting \
                 destructor (D0). Re-export the DWARF artifact with a current rgwtrace to regain \
                 the request-END probe"
            ),
            Self::RejectedVariant(linkage) => format!(
                "artifact's {REQ_STATE_DTOR} address comes from linkage name {linkage}, which is \
                 not the complete/base destructor (D1/D2) -- the deleting destructor (D0) never \
                 runs for a stack-allocated req_state, so this address is refused"
            ),
        }
    }
}

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
                    // F1: the pinned slots (rgw_process_authenticated's `req_state*`
                    // and `RGWOp*&`, req_state::~req_state's `this`, and each
                    // rgw_rados_operate overload's `dpp`) are NOT read through the
                    // generic member-deref walker. Each is read by a specific BPF
                    // accessor that assumes a specific shape: `fetch_param_ptr`
                    // (register-only, no memory access) or `fetch_param_ptr_ref`
                    // (register + exactly one read of the pointee). A stale or
                    // hand-edited JSON with any other shape -- a stack location, extra
                    // fields, a nonzero offset, or the wrong `pointer` flag -- would
                    // silently name a wrong parameter and, on a bridge match, re-seed
                    // request context from (or end) the wrong request. Fail closed at
                    // import: these slots only ever carry their pinned sentinel.
                    if let Some(shape) = descriptor_shapes(function).and_then(|shapes| {
                        // Fewer var_fields than shapes is legitimate (a descriptor
                        // extraction could not PROVE is dropped, never guessed); more
                        // is not, and is caught by the capacity check above plus this
                        // lookup returning None -- which we treat as a hard mismatch.
                        shapes.get(idx).copied()
                    }) {
                        if !shape.matches(var_field) {
                            bail!(
                                "module {module_name} function {function} var_field {idx}: expected \
                                 {}, but got location {:?} with {} field(s) {:?}; refusing a \
                                 descriptor that could read a wrong parameter",
                                shape.describe(),
                                var_field.location,
                                var_field.fields.len(),
                                var_field.fields
                            );
                        }
                    } else if descriptor_shapes(function).is_some() {
                        bail!(
                            "module {module_name} function {function} var_field {idx}: this function \
                             has only {} pinned descriptor slot(s); an extra var_field would be read \
                             by no BPF accessor and cannot be trusted",
                            descriptor_shapes(function).map(<[_]>::len).unwrap_or(0)
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

    /// The hprobe descriptors to install for a run that attaches to the modules
    /// named by `target_keys` (path-derived keys, resolved exactly like attach
    /// resolves them -- see [`Self::match_module`]).
    ///
    /// The hprobes map is keyed by a GLOBAL function id, not by module, so one
    /// slot serves every address the function is probed at. Two rules follow:
    ///
    /// * only modules that are actually attach targets may contribute. Any other
    ///   module in the artifact (a stale `radosgw.old`, an unrelated library) is
    ///   ignored -- otherwise it could overwrite the target's descriptors and the
    ///   probe would read another build's field offsets at this build's address;
    /// * two target modules that both describe the same slot must describe it
    ///   IDENTICALLY. If they differ there is no correct value for the shared
    ///   slot, so this refuses rather than letting the last writer win. A module
    ///   with NO descriptors for a function never conflicts, which keeps the
    ///   librados-addresses / libceph-common-descriptors split working.
    pub fn hprobe_entries_for_modules(&self, target_keys: &[String]) -> Result<Vec<HprobeEntry>> {
        let mut selected: Vec<&str> = Vec::new();
        for key in target_keys {
            let ModuleMatch::Unique(module) = self.match_module(key) else {
                continue;
            };
            let Some(name) = self
                .modules
                .iter()
                .find_map(|(name, candidate)| std::ptr::eq(candidate, module).then_some(name))
            else {
                continue;
            };
            if !selected.contains(&name.as_str()) {
                selected.push(name);
            }
        }

        let mut by_key: BTreeMap<i32, HprobeEntry> = BTreeMap::new();
        for entry in self.hprobe_entries() {
            if !selected.contains(&entry.module.as_str()) {
                continue;
            }
            match by_key.get(&entry.key) {
                Some(existing) if existing.field != entry.field => bail!(
                    "modules {} and {} both provide hprobe slot {} ({}) with DIFFERENT variable \
                     descriptors; the slot is shared by every probe address of that function, so \
                     one of them would read the other's field offsets. Re-export the DWARF \
                     artifact from the binaries the target process actually maps, or remove the \
                     extra module from it",
                    existing.module,
                    entry.module,
                    entry.key,
                    entry.function
                ),
                Some(_) => {}
                None => {
                    by_key.insert(entry.key, entry);
                }
            }
        }
        Ok(by_key.into_values().collect())
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

    /// Whether `function` in `module_basename` carries a valid raw-pointer
    /// descriptor in its FIRST slot (see [`is_raw_pointer_descriptor`]), and that
    /// every descriptor it does carry matches the shape pinned for that slot. The
    /// attach gate and the `cross_thread_reseed_probe` preflight check use this
    /// instead of a mere presence test so that only a descriptor the BPF handler
    /// can actually read (`fetch_param_ptr`) enables the bridge -- keeping the path
    /// fail-closed even if `validate` is ever bypassed.
    ///
    /// The first slot is checked rather than the only slot because
    /// `rgw_process_authenticated` now carries a SECOND descriptor (the `RGWOp*&`
    /// alternate bridge key). That second slot is independent: a build that could
    /// not prove it still gets the re-seed from slot 40.
    pub fn function_has_raw_pointer_descriptor(
        &self,
        module_basename: &str,
        function: &str,
    ) -> bool {
        self.resolve_module(module_basename)
            .and_then(|module| module.func2vf.get(function))
            .is_some_and(|vars| {
                let Some(shapes) = descriptor_shapes(function) else {
                    return false;
                };
                !vars.var_fields.is_empty()
                    && vars.var_fields.len() <= shapes.len()
                    && vars
                        .var_fields
                        .iter()
                        .zip(shapes)
                        .all(|(var_field, shape)| shape.matches(var_field))
                    && is_raw_pointer_descriptor(&vars.var_fields[0])
            })
    }

    /// Whether `rgw_process_authenticated` in `module_basename` carries the
    /// `RGWOp*&` reference-to-pointer descriptor (slot 41) that lets the BPF
    /// handler register a request's ALTERNATE bridge key.
    ///
    /// Native extraction emits it ONLY after proving, from DWARF, that the
    /// parameter is a reference to a pointer to `RGWOp` AND that `RGWOp` inherits
    /// `DoutPrefixProvider` at offset 0 -- i.e. that the RGWOp* RGW passes as a
    /// `dpp` is numerically the pointer we read here. Its absence is therefore a
    /// PROOF GAP, not a cosmetic one, and the operator is warned: without it, RADOS
    /// ops submitted under an RGWOp dpp (most of the op data path) cannot be
    /// correlated at all.
    pub fn function_has_rgw_op_descriptor(&self, module_basename: &str) -> bool {
        self.resolve_module(module_basename)
            .and_then(|module| module.func2vf.get(RGW_PROCESS_AUTHENTICATED))
            .and_then(|vars| vars.var_fields.get(1))
            .is_some_and(|var_field| DescriptorShape::PointerRef.matches(var_field))
    }

    /// Whether `RGWREST::get_handler` in `module_basename` resolves its
    /// `req_state*` from a REGISTER at entry (`location.stack == false` on the
    /// slot-30 descriptor, whose base register the BPF handler reuses as the
    /// bridge key).
    ///
    /// This is the whole cross-thread bridge's precondition. When it is false,
    /// `rgw_request_ctx::req_state_ptr` stays 0 for every request, nothing is ever
    /// bridged, no context can ever be revoked -- and with the END probe attached,
    /// `_send_op` therefore refuses to stamp ANY op (fail-closed, Finding 4). That
    /// is a total correlation blackout and must be warned about at attach, not
    /// discovered from an empty trace.
    #[cfg(target_os = "linux")]
    pub fn get_handler_req_state_is_register_resolvable(&self, module_basename: &str) -> bool {
        self.resolve_module(module_basename)
            .and_then(|module| module.func2vf.get(RGWREST_GET_HANDLER))
            .and_then(|vars| vars.var_fields.first())
            .is_some_and(|var_field| !var_field.location.stack)
    }

    /// Whether the request-END probe may be attached for `module_basename`, and
    /// if not, why. FAIL-CLOSED by construction: every gap returns
    /// [`RequestEndProbe::Unavailable`], so the only way to get an address back
    /// is for the artifact to carry (a) the address, (b) the register-only
    /// `this` descriptor, and (c) a `func2linkage` entry whose MANGLED name
    /// proves the address is the complete/base destructor.
    ///
    /// (c) is the JSON-import half of the never-D0 rule. Native extraction ranks
    /// candidate definitions by mangled name and never records a D0 address, but
    /// an IMPORTED artifact is just a map from a demangled name to a number: a
    /// third-party/cephtrace-style producer that resolved the first destructor
    /// with that demangled name would hand us D0, and the address and descriptor
    /// checks would both pass. Provenance is the only thing that can tell them
    /// apart, so an address without it is refused rather than probed.
    pub fn request_end_probe(&self, module_basename: &str) -> RequestEndProbe {
        match self.provenance_probe(module_basename, REQ_STATE_DTOR) {
            Ok((addr, linkage)) => RequestEndProbe::Available { addr, linkage },
            Err(gap) => RequestEndProbe::Unavailable(gap.into()),
        }
    }

    /// PHASE B. Whether ONE `rgw_rados_operate` overload's per-submit re-seed
    /// probe may be attached for `module_basename`, and if not, why.
    ///
    /// `function` must be [`RGW_RADOS_OPERATE_READ`] or
    /// [`RGW_RADOS_OPERATE_WRITE`]. Same fail-closed contract as
    /// [`Self::request_end_probe`], and for the same reason: the two overloads
    /// share one demangled name, so an address without MANGLED-name provenance
    /// could belong to either. The linkage name is re-verified here (not merely
    /// stored) so an IMPORTED artifact -- which is just a map from a name to a
    /// number, and could have been produced by a tool that keyed only on the
    /// demangled name and therefore recorded ONE address for BOTH overloads --
    /// cannot silently make us probe the write overload twice.
    pub fn rados_operate_probe(
        &self,
        module_basename: &str,
        function: &'static str,
    ) -> RadosOperateProbe {
        match self.provenance_probe(module_basename, function) {
            Ok((addr, linkage)) => RadosOperateProbe::Available { addr, linkage },
            Err(gap) => RadosOperateProbe::Unavailable(RadosOperateProbeGap { function, gap }),
        }
    }

    /// Resolve an ambiguous-demangled-name probe to a PROVEN (address, mangled
    /// linkage name) pair, or explain which half is missing.
    ///
    /// FAIL-CLOSED by construction: the only way to get an address back is for the
    /// artifact to carry (a) the address, (b) the register-only raw-pointer
    /// descriptor its BPF handler reads, and (c) a `func2linkage` entry whose
    /// MANGLED name [`provenance_rank`] accepts as a definition of exactly this
    /// function.
    ///
    /// (c) is the JSON-import half of the never-bind-the-wrong-definition rule.
    /// Native extraction routes each definition to its key by mangled name and
    /// never records a rejected one, but an IMPORTED artifact is just a map from a
    /// demangled name to a number: a third-party/cephtrace-style producer that
    /// resolved "the first symbol with that demangled name" hands us the deleting
    /// destructor, or one `rgw_rados_operate` overload's address under both keys,
    /// and the address and descriptor checks would both pass. Provenance is the
    /// only thing that can tell them apart, so an address without it is refused
    /// rather than probed.
    fn provenance_probe(
        &self,
        module_basename: &str,
        function: &str,
    ) -> Result<(u64, String), ProvenanceGap> {
        debug_assert!(
            VARIANT_PROVENANCE_FUNCTIONS.contains(&function),
            "provenance_probe is only meaningful for functions whose demangled name is ambiguous"
        );
        let module = self
            .resolve_module(module_basename)
            .ok_or(ProvenanceGap::NoModule)?;
        let addr = module
            .func2pc
            .get(function)
            .copied()
            .filter(|addr| *addr != 0)
            .ok_or(ProvenanceGap::NoAddress)?;
        if !self.function_has_raw_pointer_descriptor(module_basename, function) {
            return Err(ProvenanceGap::NoDescriptor);
        }
        let linkage = module
            .func2linkage
            .get(function)
            .ok_or(ProvenanceGap::MissingProvenance)?;
        if provenance_rank(function, linkage).is_none() {
            return Err(ProvenanceGap::RejectedLinkage(linkage.clone()));
        }
        Ok((addr, linkage.clone()))
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
        // rgw_process_authenticated base 40 -> req_state::~req_state base 50 => 10.
        assert_eq!(
            function_slot_capacity("rgw_process_authenticated"),
            Some(10)
        );
        // DELIBERATE CHANGE (Phase B): req_state::~req_state used to be the highest
        // base and extend to the map capacity. The two rgw_rados_operate overloads
        // now take bases 60 and 70, so the destructor is bounded by the next base
        // (60 - 50 = 10 slots -- it only ever needs 1, the `this` descriptor).
        assert_eq!(function_slot_capacity(REQ_STATE_DTOR), Some(10));
        // req_state::~req_state base 50 -> rgw_rados_operate(read) base 60 => 10.
        assert_eq!(function_slot_capacity(RGW_RADOS_OPERATE_READ), Some(10));
        // Highest base (rgw_rados_operate(write), 70) extends to the map capacity.
        assert_eq!(
            function_slot_capacity(RGW_RADOS_OPERATE_WRITE),
            Some((HPROBES_MAP_CAPACITY - 70) as usize)
        );
        assert_eq!(function_slot_capacity("Unknown::function"), None);
    }

    /// The two `rgw_rados_operate` overloads must occupy SEPARATE hprobe slots.
    /// Sharing one would force the two definitions' `dpp` descriptors to be
    /// identical -- an assumption ("arg0 is in the same register in both") that
    /// nothing in the artifact proves, and whose violation would make one of the
    /// probes read the wrong register at a hot call site.
    #[test]
    fn rados_operate_overloads_get_distinct_hprobe_slots() {
        let read = function_base_id(RGW_RADOS_OPERATE_READ).expect("read overload has a base id");
        let write =
            function_base_id(RGW_RADOS_OPERATE_WRITE).expect("write overload has a base id");

        assert_ne!(read, write);
        // Mirrors the varids the BPF handlers hardcode (bpf/rgwtrace.bpf.c:
        // uprobe_rgw_rados_operate_read -> 60, ..._write -> 70).
        assert_eq!(read, 60);
        assert_eq!(write, 70);
        // Each needs exactly one var_field (the raw-pointer `dpp`), well inside its
        // reserved range.
        assert!(function_slot_capacity(RGW_RADOS_OPERATE_READ).unwrap() >= 1);
        assert!(function_slot_capacity(RGW_RADOS_OPERATE_WRITE).unwrap() >= 1);
    }

    #[test]
    fn req_state_dtor_slot_pins_the_raw_pointer_descriptor() {
        // varid 50 is read register-only by uprobe_rgw_req_state_dtor, exactly
        // like varid 40: only the raw-pointer sentinel may occupy it.
        let vf = r#"{"location": {"reg": 5, "offset": 0, "stack": false}, "fields": [{"offset": 0, "pointer": false}]}"#;
        let json = json_with_single_var_field("amd64", REQ_STATE_DTOR, vf);
        let info = DwarfInfo::from_str(&json).unwrap();
        assert!(info.function_has_raw_pointer_descriptor("libceph-common.so.2", REQ_STATE_DTOR));
        assert_eq!(info.hprobe_entries()[0].key, 50);

        // A member-deref chain (or any other shape) in that slot would make the
        // BPF handler read a wrong parameter and end the wrong request.
        let bad = r#"{"location": {"reg": 5, "offset": 0, "stack": false}, "fields": [{"offset": 0, "pointer": false}, {"offset": 8, "pointer": true}]}"#;
        let json = json_with_single_var_field("amd64", REQ_STATE_DTOR, bad);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(REQ_STATE_DTOR), "message: {msg}");
        assert!(msg.contains("raw-pointer descriptor"), "message: {msg}");
    }

    // --- imported request-END probe: address + descriptor + variant provenance ---

    /// A radosgw-style module carrying a `req_state::~req_state` address, the
    /// raw-pointer `this` descriptor, and optionally the `func2linkage` variant
    /// provenance for that address.
    fn json_with_request_end_probe(linkage: Option<&str>) -> String {
        let raw_pointer = r#"{"location": {"reg": 5, "offset": 0, "stack": false}, "fields": [{"offset": 0, "pointer": false}]}"#;
        let func2linkage = match linkage {
            Some(linkage) => format!(r#", "func2linkage": {{"{REQ_STATE_DTOR}": "{linkage}"}}"#),
            None => String::new(),
        };
        format!(
            r#"{{"version": "v", "arch": "amd64", "radosgw": {{"build_id": "abc",
               "func2pc": {{"{REQ_STATE_DTOR}": 4096}},
               "func2vf": {{"{REQ_STATE_DTOR}": {{"var_fields": [{raw_pointer}]}}}}{func2linkage}}}}}"#
        )
    }

    #[test]
    fn imported_end_probe_is_available_only_with_a_proven_complete_dtor() {
        // The complete-object destructor (D1): address + descriptor + provenance
        // all check out, so the probe may attach.
        let info =
            DwarfInfo::from_str(&json_with_request_end_probe(Some("_ZN9req_stateD1Ev"))).unwrap();
        assert_eq!(
            info.request_end_probe("radosgw"),
            RequestEndProbe::Available {
                addr: 4096,
                linkage: "_ZN9req_stateD1Ev".to_string(),
            }
        );

        // The base-object destructor (D2) is equally acceptable: on real Ceph
        // builds it is aliased to D1 at the same address.
        let info =
            DwarfInfo::from_str(&json_with_request_end_probe(Some("_ZN9req_stateD2Ev"))).unwrap();
        assert!(matches!(
            info.request_end_probe("radosgw"),
            RequestEndProbe::Available { addr: 4096, .. }
        ));
    }

    #[test]
    fn imported_end_probe_refuses_the_deleting_destructor() {
        // THE import-path hazard: a third-party/cephtrace-style producer that
        // resolved the FIRST destructor with the demangled name `req_state::
        // ~req_state` hands us D0 -- g++ lists it first -- and neither the
        // address nor the descriptor can reveal that. Only the mangled linkage
        // name can, so an address proven to be D0 is REFUSED: attaching the END
        // uprobe to the deleting destructor would probe a function that never
        // runs for a stack-allocated req_state.
        let info =
            DwarfInfo::from_str(&json_with_request_end_probe(Some("_ZN9req_stateD0Ev"))).unwrap();

        let probe = info.request_end_probe("radosgw");

        assert_eq!(
            probe,
            RequestEndProbe::Unavailable(RequestEndProbeGap::RejectedVariant(
                "_ZN9req_stateD0Ev".to_string()
            ))
        );
        let RequestEndProbe::Unavailable(gap) = probe else {
            unreachable!()
        };
        assert!(
            gap.reason().contains("_ZN9req_stateD0Ev"),
            "{}",
            gap.reason()
        );
    }

    #[test]
    fn imported_end_probe_refuses_an_unprovable_variant() {
        // An artifact exported before `func2linkage` existed: the address and the
        // descriptor both validate, but NOTHING proves the address is not the
        // deleting destructor. Fail closed -- no end probe, derived durations, and
        // an explicit reason -- rather than gambling on the producer's choice.
        let info = DwarfInfo::from_str(&json_with_request_end_probe(None)).unwrap();

        let probe = info.request_end_probe("radosgw");

        assert_eq!(
            probe,
            RequestEndProbe::Unavailable(RequestEndProbeGap::MissingVariantProvenance)
        );
        // Old artifacts stay loadable and usable for everything else: refusing
        // the end probe must not fail the import.
        assert_eq!(info.function_addr("radosgw", REQ_STATE_DTOR), Some(4096));

        // A linkage name that is not a destructor mangling at all is equally
        // unprovable and equally refused.
        let info =
            DwarfInfo::from_str(&json_with_request_end_probe(Some("_ZN9req_state6get_idEv")))
                .unwrap();
        assert!(matches!(
            info.request_end_probe("radosgw"),
            RequestEndProbe::Unavailable(RequestEndProbeGap::RejectedVariant(_))
        ));
    }

    #[test]
    fn imported_end_probe_reports_the_missing_half_it_is_missing() {
        // No module for the radosgw key at all.
        let info =
            DwarfInfo::from_str(&json_with_request_end_probe(Some("_ZN9req_stateD1Ev"))).unwrap();
        assert_eq!(
            info.request_end_probe("not-radosgw"),
            RequestEndProbe::Unavailable(RequestEndProbeGap::NoModule)
        );

        // Module present, but no destructor address (the pre-end-probe artifact,
        // and the case native extraction produces when it refuses every variant).
        let vf = var_field_json(4, 0, 1);
        let json = json_with_single_var_field("amd64", "Objecter::_send_op", &vf);
        let info = DwarfInfo::from_str(&json).unwrap();
        assert_eq!(
            info.request_end_probe("libceph-common.so.2"),
            RequestEndProbe::Unavailable(RequestEndProbeGap::NoAddress)
        );

        // Address + provenance, but no register-only `this` descriptor: the BPF
        // handler could not read the req_state* even if the probe attached.
        let json = format!(
            r#"{{"version": "v", "arch": "amd64", "radosgw": {{"build_id": "abc",
               "func2pc": {{"{REQ_STATE_DTOR}": 4096}},
               "func2linkage": {{"{REQ_STATE_DTOR}": "_ZN9req_stateD1Ev"}}}}}}"#
        );
        let info = DwarfInfo::from_str(&json).unwrap();
        assert_eq!(
            info.request_end_probe("radosgw"),
            RequestEndProbe::Unavailable(RequestEndProbeGap::NoDescriptor)
        );
    }

    #[test]
    fn req_state_dtor_stack_located_descriptor_rejected() {
        let vf = r#"{"location": {"reg": 5, "offset": 0, "stack": true}, "fields": [{"offset": 0, "pointer": false}]}"#;
        let json = json_with_single_var_field("amd64", REQ_STATE_DTOR, vf);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        assert!(format!("{err:#}").contains("raw-pointer descriptor"));
    }

    // --- PHASE B: rgw_rados_operate overload binding ------------------------
    //
    // The two REAL mangled names, taken from the verified signatures (Ceph 18.2.4
    // reef and 19.2.4 squid agree; regenerated here with clang++ from the exact
    // declarations, so they are the symbols a real radosgw actually exports):
    //
    //   rgw_rados_operate(DoutPrefixProvider const*, librados::v14_2_0::IoCtx&,
    //                     std::string const&, librados::v14_2_0::ObjectReadOperation*,
    //                     ceph::buffer::v15_2_0::list*, optional_yield, int)
    //   rgw_rados_operate(DoutPrefixProvider const*, librados::v14_2_0::IoCtx&,
    //                     std::string const&, librados::v14_2_0::ObjectWriteOperation*,
    //                     optional_yield, int)
    //
    // Both demangle (name-only) to `rgw_rados_operate`. That collision is the whole
    // problem: it is the same shape as the D0/D1/D2 destructor collision, and the
    // same rule applies -- bind by MANGLED name, never by first match.
    const RADOS_OPERATE_READ_MANGLED: &str = "_Z17rgw_rados_operatePK18DoutPrefixProviderRN8librados7v14_2_05IoCtxERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPNS3_19ObjectReadOperationEPN4ceph6buffer7v15_2_04listE14optional_yieldi";
    const RADOS_OPERATE_WRITE_MANGLED: &str = "_Z17rgw_rados_operatePK18DoutPrefixProviderRN8librados7v14_2_05IoCtxERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPNS3_20ObjectWriteOperationE14optional_yieldi";

    #[test]
    fn rados_operate_overloads_are_told_apart_by_their_mangled_names() {
        assert_eq!(
            rados_operate_overload(RADOS_OPERATE_READ_MANGLED),
            Some(RadosOperateOverload::Read)
        );
        assert_eq!(
            rados_operate_overload(RADOS_OPERATE_WRITE_MANGLED),
            Some(RadosOperateOverload::Write)
        );
        assert_eq!(
            RadosOperateOverload::Read.function(),
            RGW_RADOS_OPERATE_READ
        );
        assert_eq!(
            RadosOperateOverload::Write.function(),
            RGW_RADOS_OPERATE_WRITE
        );
    }

    #[test]
    fn each_overload_key_accepts_only_its_own_mangled_name() {
        // THE anti-first-match guarantee. If the write overload's symbol is listed
        // first (symbol table order is not ours to choose), it must NOT be able to
        // claim the read overload's slot -- and vice versa. `provenance_rank`
        // rejects the mismatched pairing outright, so the binding is decided by the
        // signature, never by position.
        assert_eq!(
            provenance_rank(RGW_RADOS_OPERATE_READ, RADOS_OPERATE_READ_MANGLED),
            Some(0)
        );
        assert_eq!(
            provenance_rank(RGW_RADOS_OPERATE_READ, RADOS_OPERATE_WRITE_MANGLED),
            None,
            "the WRITE overload must never be accepted as the read overload"
        );
        assert_eq!(
            provenance_rank(RGW_RADOS_OPERATE_WRITE, RADOS_OPERATE_WRITE_MANGLED),
            Some(0)
        );
        assert_eq!(
            provenance_rank(RGW_RADOS_OPERATE_WRITE, RADOS_OPERATE_READ_MANGLED),
            None,
            "the READ overload must never be accepted as the write overload"
        );
    }

    #[test]
    fn rados_operate_rejects_signatures_whose_first_parameter_is_not_the_dpp() {
        // The load-bearing safety check. The BPF handler reads arg0 as an opaque
        // identity token and looks it up in the (req_state*, tgid) bridge, which is
        // ONLY sound because arg0 is the request's DoutPrefixProvider* and req_state
        // inherits DoutPrefixProvider at offset 0. If upstream ever reorders the
        // parameters, arg0 stops being the dpp -- and we must refuse to probe rather
        // than key the bridge on an IoCtx& (which would silently correlate nothing,
        // or worse, alias).
        //
        // Same signature, dpp moved off position 0:
        //   rgw_rados_operate(librados::v14_2_0::IoCtx&, DoutPrefixProvider const*,
        //                     librados::v14_2_0::ObjectReadOperation*)
        let dpp_not_first =
            "_Z17rgw_rados_operateRN8librados7v14_2_05IoCtxEPK18DoutPrefixProviderPNS0_19ObjectReadOperationE";
        assert_eq!(rados_operate_overload(dpp_not_first), None);

        // Neither Object{Read,Write}Operation present -> not an overload we know.
        // `rgw_rados_operate(DoutPrefixProvider const*, int)`
        assert_eq!(
            rados_operate_overload("_Z17rgw_rados_operatePK18DoutPrefixProvideri"),
            None
        );
        // A different function that merely starts with the same characters.
        // `rgw_rados_operate_async(DoutPrefixProvider const*)`
        assert_eq!(
            rados_operate_overload("_Z23rgw_rados_operate_asyncPK18DoutPrefixProvider"),
            None
        );
        // Not a mangled name at all.
        assert_eq!(rados_operate_overload("rgw_rados_operate"), None);
        assert_eq!(rados_operate_overload(""), None);
    }

    /// A radosgw-style module carrying both `rgw_rados_operate` overloads: their
    /// addresses, their raw-pointer `dpp` descriptors, and (when `provenance` is
    /// set) the `func2linkage` mangled names proving which overload each address
    /// belongs to.
    fn json_with_rados_operate_probes(
        read_linkage: Option<&str>,
        write_linkage: Option<&str>,
    ) -> String {
        let raw_pointer = r#"{"location": {"reg": 5, "offset": 0, "stack": false}, "fields": [{"offset": 0, "pointer": false}]}"#;
        let mut linkages = Vec::new();
        if let Some(linkage) = read_linkage {
            linkages.push(format!(r#""{RGW_RADOS_OPERATE_READ}": "{linkage}""#));
        }
        if let Some(linkage) = write_linkage {
            linkages.push(format!(r#""{RGW_RADOS_OPERATE_WRITE}": "{linkage}""#));
        }
        let func2linkage = if linkages.is_empty() {
            String::new()
        } else {
            format!(r#", "func2linkage": {{{}}}"#, linkages.join(","))
        };
        format!(
            r#"{{"version": "v", "arch": "amd64", "radosgw": {{"build_id": "abc",
               "func2pc": {{"{RGW_RADOS_OPERATE_READ}": 8192, "{RGW_RADOS_OPERATE_WRITE}": 12288}},
               "func2vf": {{
                 "{RGW_RADOS_OPERATE_READ}": {{"var_fields": [{raw_pointer}]}},
                 "{RGW_RADOS_OPERATE_WRITE}": {{"var_fields": [{raw_pointer}]}}
               }}{func2linkage}}}}}"#
        )
    }

    #[test]
    fn both_overloads_resolve_to_their_own_proven_addresses() {
        let info = DwarfInfo::from_str(&json_with_rados_operate_probes(
            Some(RADOS_OPERATE_READ_MANGLED),
            Some(RADOS_OPERATE_WRITE_MANGLED),
        ))
        .unwrap();

        // Each probe binds to ITS OWN address (8192 vs 12288) -- two distinct
        // uprobes, not one probe attached twice to whichever symbol came first.
        assert_eq!(
            info.rados_operate_probe("radosgw", RGW_RADOS_OPERATE_READ),
            RadosOperateProbe::Available {
                addr: 8192,
                linkage: RADOS_OPERATE_READ_MANGLED.to_string(),
            }
        );
        assert_eq!(
            info.rados_operate_probe("radosgw", RGW_RADOS_OPERATE_WRITE),
            RadosOperateProbe::Available {
                addr: 12288,
                linkage: RADOS_OPERATE_WRITE_MANGLED.to_string(),
            }
        );
    }

    #[test]
    fn an_imported_artifact_that_swapped_the_overloads_is_refused() {
        // THE import-path hazard, and the reason `func2linkage` is re-verified
        // rather than merely stored. A producer that keyed on the DEMANGLED name
        // (all that cephtrace-style artifacts have) sees both overloads as
        // `rgw_rados_operate` and can easily file one overload's address -- or the
        // same address -- under both keys. The address and the descriptor would both
        // look perfectly valid. Only the mangled name reveals the swap, and when it
        // does we REFUSE the probe instead of attaching the read handler to the
        // write overload's entry point.
        let info = DwarfInfo::from_str(&json_with_rados_operate_probes(
            Some(RADOS_OPERATE_WRITE_MANGLED), // swapped!
            Some(RADOS_OPERATE_READ_MANGLED),  // swapped!
        ))
        .unwrap();

        for function in RGW_RADOS_OPERATE_OVERLOADS {
            let probe = info.rados_operate_probe("radosgw", function);
            let RadosOperateProbe::Unavailable(gap) = probe else {
                panic!("{function}: a swapped overload address must be refused");
            };
            assert!(
                matches!(gap.gap, ProvenanceGap::RejectedLinkage(_)),
                "{function}: {gap:?}"
            );
            assert!(
                gap.reason().contains("does not demangle"),
                "{}",
                gap.reason()
            );
        }
    }

    #[test]
    fn an_overload_address_without_provenance_is_refused() {
        // An artifact exported before Phase B (or by a third-party producer): the
        // addresses and descriptors validate, but NOTHING proves which overload each
        // address is. Fail closed -- no per-submit re-seed, an explicit reason -- and
        // the rest of the artifact stays perfectly usable.
        let info = DwarfInfo::from_str(&json_with_rados_operate_probes(None, None)).unwrap();

        for function in RGW_RADOS_OPERATE_OVERLOADS {
            assert_eq!(
                info.rados_operate_probe("radosgw", function),
                RadosOperateProbe::Unavailable(RadosOperateProbeGap {
                    function,
                    gap: ProvenanceGap::MissingProvenance,
                })
            );
        }
        // Still loadable and still carrying the addresses -- refusing the probe must
        // not fail the import.
        assert_eq!(
            info.function_addr("radosgw", RGW_RADOS_OPERATE_READ),
            Some(8192)
        );
    }

    #[test]
    fn overload_probes_degrade_gracefully_when_the_symbols_are_absent() {
        // GRACEFUL DEGRADATION on an older/stripped RGW: no rgw_rados_operate at
        // all. Every gap is reported by name -- never a silent skip -- and the
        // artifact remains fully usable for everything else (Phase A behavior).
        let vf = var_field_json(4, 0, 1);
        let json = json_with_single_var_field("amd64", "Objecter::_send_op", &vf);
        let info = DwarfInfo::from_str(&json).unwrap();

        for function in RGW_RADOS_OPERATE_OVERLOADS {
            assert_eq!(
                info.rados_operate_probe("radosgw", function),
                RadosOperateProbe::Unavailable(RadosOperateProbeGap {
                    function,
                    gap: ProvenanceGap::NoModule,
                }),
                "{function}"
            );
            // Module present but no operate symbols in it.
            let RadosOperateProbe::Unavailable(gap) =
                info.rados_operate_probe("libceph-common.so.2", function)
            else {
                panic!("{function}: must not resolve without an address");
            };
            assert_eq!(gap.gap, ProvenanceGap::NoAddress);
            assert!(!gap.reason().is_empty());
        }
    }

    #[test]
    fn overload_slots_pin_the_raw_pointer_descriptor() {
        // varids 60/70 are read register-only by the two BPF seed handlers, exactly
        // like varids 40 and 50: only the raw-pointer sentinel may occupy them. A
        // member-deref chain here would make the handler read a WRONG parameter and
        // key the bridge on it -- and this slot's parameter is the thing that
        // identifies the request.
        let bad = r#"{"location": {"reg": 5, "offset": 0, "stack": false}, "fields": [{"offset": 0, "pointer": false}, {"offset": 8, "pointer": true}]}"#;
        let json = json_with_single_var_field("amd64", RGW_RADOS_OPERATE_READ, bad);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(RGW_RADOS_OPERATE_READ), "message: {msg}");
        assert!(msg.contains("raw-pointer descriptor"), "message: {msg}");

        // A stack-located dpp cannot be read register-only either.
        let stack = r#"{"location": {"reg": 6, "offset": -24, "stack": true}, "fields": [{"offset": 0, "pointer": false}]}"#;
        let json = json_with_single_var_field("amd64", RGW_RADOS_OPERATE_WRITE, stack);
        let err = DwarfInfo::from_str(&json).unwrap_err();
        assert!(format!("{err:#}").contains("raw-pointer descriptor"));
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
            func2linkage: BTreeMap::new(),
        }
    }

    fn info_with(modules: Vec<(&str, DwarfModule)>) -> DwarfInfo {
        DwarfInfo {
            version: Some("19.2.0".to_string()),
            arch: Some("amd64".to_string()),
            modules: modules
                .into_iter()
                .map(|(name, module)| (name.to_string(), module))
                .collect(),
        }
    }

    fn keys(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    /// F7: hprobe descriptors are keyed by a GLOBAL function id, so a module
    /// that is not an attach target (a stale `radosgw.old` left in the artifact)
    /// used to overwrite the live module's descriptors -- last writer wins -- and
    /// the probe fired at one module's address while reading another's offsets.
    #[test]
    fn hprobes_come_only_from_the_attach_target_modules() {
        let mut stale = module_with(&[("RGWREST::get_handler", 0x2000)], &[]);
        stale.func2vf.insert(
            "RGWREST::get_handler".to_string(),
            FunctionVarFields {
                var_fields: vec![var_field_at(9, 640)],
            },
        );
        let info = info_with(vec![
            (
                "radosgw",
                module_with(
                    &[("RGWREST::get_handler", 0x1000)],
                    &[("RGWREST::get_handler", 1)],
                ),
            ),
            // Sorts AFTER "radosgw", so it used to be the last writer.
            ("radosgw.old", stale),
        ]);

        let entries = info
            .hprobe_entries_for_modules(&keys(&["radosgw"]))
            .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].module, "radosgw");
        assert_eq!(entries[0].field.varloc.reg, sample_var_field().location.reg);
    }

    /// A target key reaches its module through the same soname-aware match the
    /// attach path uses, so `librados.so.2` selects `librados.so.2.0.0`.
    #[test]
    fn hprobe_target_keys_resolve_through_the_soname_fallback() {
        let info = info_with(vec![(
            "libceph-common.so.2.0.0",
            module_with(
                &[("Objecter::_send_op", 0x10)],
                &[("Objecter::_send_op", 2)],
            ),
        )]);

        let entries = info
            .hprobe_entries_for_modules(&keys(&["libceph-common.so.2"]))
            .unwrap();

        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .all(|e| e.module == "libceph-common.so.2.0.0"));
    }

    /// The Ubuntu split (librados carries the addresses, libceph-common the
    /// var_fields) must keep working: an EMPTY descriptor set never conflicts.
    #[test]
    fn hprobes_keep_the_cross_module_split_working() {
        let info = info_with(vec![
            (
                "librados.so.2",
                module_with(&[("Objecter::_send_op", 1)], &[]),
            ),
            (
                "libceph-common.so.2",
                module_with(&[], &[("Objecter::_send_op", 12)]),
            ),
        ]);

        let entries = info
            .hprobe_entries_for_modules(&keys(&["librados.so.2", "libceph-common.so.2"]))
            .unwrap();

        assert_eq!(entries.len(), 12);
    }

    /// Identical descriptors from two selected modules are the same fact twice,
    /// not a conflict, and are installed once.
    #[test]
    fn identical_hprobes_from_two_target_modules_are_deduplicated() {
        let info = info_with(vec![
            (
                "librados.so.2",
                module_with(&[("Objecter::_send_op", 1)], &[("Objecter::_send_op", 3)]),
            ),
            (
                "libceph-common.so.2",
                module_with(&[("Objecter::_send_op", 2)], &[("Objecter::_send_op", 3)]),
            ),
        ]);

        let entries = info
            .hprobe_entries_for_modules(&keys(&["librados.so.2", "libceph-common.so.2"]))
            .unwrap();

        assert_eq!(entries.len(), 3);
    }

    /// F7: `_send_op` present in BOTH librados and libceph-common with DIFFERENT
    /// descriptors cannot share one global hprobe slot: whichever is written
    /// last is read at both addresses. Refuse, naming both modules.
    #[test]
    fn conflicting_hprobes_from_two_target_modules_are_refused() {
        let mut librados = module_with(&[("Objecter::_send_op", 1)], &[]);
        librados.func2vf.insert(
            "Objecter::_send_op".to_string(),
            FunctionVarFields {
                var_fields: vec![var_field_at(5, 16)],
            },
        );
        let info = info_with(vec![
            ("librados.so.2", librados),
            (
                "libceph-common.so.2",
                module_with(&[("Objecter::_send_op", 2)], &[("Objecter::_send_op", 1)]),
            ),
        ]);

        let err = info
            .hprobe_entries_for_modules(&keys(&["librados.so.2", "libceph-common.so.2"]))
            .unwrap_err()
            .to_string();

        assert!(err.contains("librados.so.2"), "{err}");
        assert!(err.contains("libceph-common.so.2"), "{err}");
        assert!(err.contains("Objecter::_send_op"), "{err}");
    }

    fn var_field_at(reg: i32, offset: i32) -> VarFieldJson {
        VarFieldJson {
            location: VarLocationJson {
                reg,
                offset: 0,
                stack: false,
            },
            fields: vec![FieldJson {
                offset,
                pointer: false,
            }],
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
