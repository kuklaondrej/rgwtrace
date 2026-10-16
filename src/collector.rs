#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    classify::{classify_rados, classify_request, RadosRole, RequestClass},
    events::{RadosEvent, RequestEvent, TraceEvent},
};

/// How much longer than the idle correlation TTL an OPEN request (START seen,
/// END not yet) may live before it is force-expired as leaked.
///
/// An open request is NOT idle-expired: with the END probe attached its END is
/// still coming, and expiring it on idleness alone would export a derived-
/// duration span and then export a SECOND span with the same span id when the
/// END finally arrived (see `drain_expired`). But an END can be genuinely LOST
/// (a ring-buffer drop, or a bridge miss in the destructor probe), so an open
/// request still needs an upper bound or it would pin its group forever.
///
/// The bound is a MULTIPLE of the operator's `--correlation-ttl` rather than a
/// second flag: it scales with how patient the operator already asked us to be,
/// and 10x the 120s default (20 minutes) is far longer than any single RGW
/// request while still bounding a lost-END leak. Force-expired open requests are
/// counted in `expired_open_requests`.
const OPEN_REQUEST_TTL_MULTIPLIER: u64 = 10;

/// Bits in the emitted-request tombstone filter: 2^26 bits = 8 MiB, allocated
/// lazily on the first export. See [`EmittedRequests`].
const EMITTED_BLOOM_BITS: u64 = 1 << 26;

/// Hash functions per key. Chosen slightly below the theoretical optimum
/// (~23 for the design capacity) because each one costs a random memory probe and
/// the resulting false-positive rate is already ~1e-7.
const EMITTED_BLOOM_HASHES: u64 = 20;

/// Requests this session can export before the tombstone filter's false-positive
/// rate leaves its design point (~1e-7 at this many keys, rising steeply beyond).
/// Exceeding it is SAFE -- a Bloom filter never produces a false NEGATIVE, so no
/// request can ever be emitted twice -- but it starts costing dropped stragglers,
/// so it is warned about exactly once.
const EMITTED_BLOOM_DESIGN_CAPACITY: u64 = 2_000_000;

/// Tombstone for request keys whose span has already been exported.
///
/// WHY IT MUST NOT FORGET. A span id is a pure function of the request key, so
/// re-creating a group under a key we already exported emits a SECOND span with
/// the SAME trace/span id -- one request, split across two spans, duplicated in
/// the backend. The straggler that causes it is not hypothetical: an OPEN request
/// force-expired at the lifetime backstop is exported with a derived end, and its
/// destructor END can still arrive afterwards.
///
/// WHY A BLOOM FILTER. The previous bounded FIFO (65,536 keys, oldest evicted)
/// did NOT deliver that guarantee: at production request rates its whole memory
/// turns over in seconds, so a force-expired long request's tombstone was gone
/// long before its late END arrived -- and the END then recreated the group and
/// re-emitted the same span id. Exactly the duplicate the tombstone exists to
/// prevent.
///
/// A Bloom filter has NO false negatives, so the no-duplicate guarantee holds for
/// the whole session, in FIXED memory (8 MiB), no matter how many requests are
/// traced. What it can do is return a false POSITIVE, and the consequence of one
/// is a DROP, never a duplicate: a straggler is discarded, or -- if the collision
/// lands on a fresh request's key -- that one request's markers are dropped and
/// its RADOS ops are demoted to background spans. At the design capacity that
/// happens to roughly one request in ten million; past it the rate climbs, which
/// is why crossing the capacity warns.
///
/// (An exact set has no false positives, but its memory grows without bound with
/// the number of requests traced -- ~100 bytes per key, i.e. gigabytes on a
/// long-running gateway. Unbounded growth in a tracer that is supposed to run
/// alongside a production RGW is not a trade we can make; false-positive DROPS at
/// 1e-7, which fail closed, are.)
#[derive(Debug, Default)]
struct EmittedRequests {
    /// Lazily allocated: a `Collector` that never exports a request (every dry-run
    /// unit test, and every run that traces nothing) pays nothing.
    bits: Vec<u64>,
    inserted: u64,
}

impl EmittedRequests {
    /// The `EMITTED_BLOOM_HASHES` bit indices for `key`, derived by
    /// Kirsch-Mitzenmacher double hashing from two independent 64-bit hashes.
    fn indices(key: &str) -> impl Iterator<Item = u64> {
        use std::hash::{Hash, Hasher};
        let mut first = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut first);
        let h1 = first.finish();
        let mut second = std::collections::hash_map::DefaultHasher::new();
        // Salt the second hasher so the two are independent.
        0xa5a5_5a5a_dead_beef_u64.hash(&mut second);
        key.hash(&mut second);
        // Odd step: coprime with the power-of-two table size, so the probe sequence
        // visits distinct slots.
        let h2 = second.finish() | 1;
        (0..EMITTED_BLOOM_HASHES)
            .map(move |i| h1.wrapping_add(i.wrapping_mul(h2)) % EMITTED_BLOOM_BITS)
    }

    /// Has `key` been exported? `false` is CERTAIN (no false negatives); `true` is
    /// near-certain, and a false one only ever causes a drop.
    fn contains(&self, key: &str) -> bool {
        if self.bits.is_empty() {
            return false;
        }
        Self::indices(key).all(|bit| {
            let word = (bit / 64) as usize;
            self.bits[word] & (1 << (bit % 64)) != 0
        })
    }

    fn insert(&mut self, key: &str) {
        if self.bits.is_empty() {
            self.bits = vec![0u64; (EMITTED_BLOOM_BITS / 64) as usize];
        }
        for bit in Self::indices(key) {
            let word = (bit / 64) as usize;
            self.bits[word] |= 1 << (bit % 64);
        }
        self.inserted += 1;
    }
}

#[derive(Debug, Default)]
pub struct Collector {
    requests: BTreeMap<String, RequestBuilder>,
    pending_inference: Vec<RadosEvent>,
    background: Vec<BackgroundRados>,
    diagnostics: TraceDiagnostics,
    infer_correlation: bool,
    inference_window_ns: u64,
    /// Whether the `req_state::~req_state` END probe is attached for this run.
    /// It decides whether a request without an END marker is OPEN (its END is
    /// still coming, so do not idle-expire it) or simply CLOSED-WITHOUT-AN-END
    /// (no END will ever come on this build, so expire it exactly as before the
    /// end probe existed). Defaults to `false`, i.e. the pre-end-probe behavior:
    /// only a live run that actually attached the probe turns it on.
    end_probe_attached: bool,
    /// Request groups already rendered into spans. A span id is a pure function of
    /// the request key, so re-creating a group under a key we already exported
    /// would emit a SECOND span with the SAME trace/span id -- splitting one
    /// request's children across two spans and duplicating telemetry. Straggler
    /// events for these keys are therefore dropped (markers) or demoted to
    /// background (RADOS ops), never re-grouped. See [`EmittedRequests`] for why it
    /// is a Bloom filter and what its one failure mode costs.
    emitted_requests: EmittedRequests,
    /// Whether the "tombstone filter past its design capacity" warning has fired.
    /// Once is enough: it is a property of the run, not of an event.
    emitted_capacity_warned: bool,
    /// Replace every `ceph.rados.object` value with a stable hash of the name
    /// (`--redact-object-names`). RADOS object names carry S3 keys, user and
    /// tenant names and access-key ids; the default endpoint is plain http.
    /// Applied where the attribute is rendered, so classification still sees
    /// the raw name.
    redact_object_names: bool,
}

#[derive(Debug, Default)]
struct RequestBuilder {
    request: Option<RequestEvent>,
    /// End timestamp from the `req_state::~req_state` END probe -- the request's
    /// REAL end. `None` when no END marker arrived: either the end probe is not
    /// attached (older/stripped RGW build) or the request outlived the trace
    /// window. The span end is then derived from the RADOS child bounds, exactly
    /// as before the end probe existed.
    measured_end_ns: Option<u64>,
    rados: Vec<CorrelatedRados>,
    last_seen_ns: u64,
    /// Earliest timestamp seen for this group (marker start or first RADOS
    /// send), i.e. when the request began. `last_seen_ns` bounds IDLENESS;
    /// this bounds LIFETIME, which is what an open request is expired on.
    first_seen_ns: u64,
}

impl RequestBuilder {
    /// An OPEN request is one whose END marker has not arrived on a run where
    /// the END probe is attached -- so the END is still expected and the group
    /// must not be idle-expired out from under it.
    ///
    /// Note this covers a group that has RADOS children but no marker yet: its
    /// key is the request's `trans_id`, which came from a get_handler context,
    /// so a destructor END for that request is still expected too.
    fn is_open(&self, end_probe_attached: bool) -> bool {
        end_probe_attached && self.measured_end_ns.is_none()
    }

    /// Fold one event's bounds into the group's idleness (`last_seen_ns`) and
    /// lifetime (`first_seen_ns`) clocks.
    fn observe(&mut self, begin_ns: u64, end_ns: u64) {
        self.last_seen_ns = self.last_seen_ns.max(end_ns);
        if begin_ns != 0 {
            self.first_seen_ns = if self.first_seen_ns == 0 {
                begin_ns
            } else {
                self.first_seen_ns.min(begin_ns)
            };
        }
    }
}

#[derive(Debug)]
struct CorrelatedRados {
    event: RadosEvent,
    correlation: RadosCorrelation,
}

#[derive(Debug)]
struct BackgroundRados {
    event: RadosEvent,
    reason: BackgroundReason,
}

#[derive(Clone, Copy, Debug)]
enum RadosCorrelation {
    // Thread-UNRESOLVED at ingest: a non-empty `trans_id` proves the RADOS op
    // carries a request identity, but whether it ran on the request's own
    // execute thread (`same_thread`) or was inherited via the cross-thread
    // re-seed bridge (`cross_thread`) can only be decided in `request_spans`,
    // once the request marker's `tid` is known. RADOS events can arrive before
    // their marker, so committing to `same_thread` here would be wrong.
    TransId,
    Inferred,
}

// Late-derived, thread-resolved correlation used only when rendering spans.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolvedCorrelation {
    SameThread,
    CrossThread,
    Inferred,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackgroundReason {
    MissingTransId,
    ClassifiedBackgroundRole,
    NoInferenceCandidate,
    AmbiguousInferenceCandidates,
    /// The op carries a valid `trans_id`, but that request's span was already
    /// exported (it aged out first). Re-grouping the op would emit a duplicate
    /// parent span with the same span id, so the op is kept as background with
    /// this reason instead -- visibly, not silently.
    RequestAlreadyEmitted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum InferenceMatch {
    Match(String),
    NoCandidate,
    Ambiguous,
}

#[derive(Clone, Debug, Serialize)]
pub struct TraceDocument {
    pub service_name: String,
    pub spans: Vec<SpanDocument>,
    pub diagnostics: TraceDiagnostics,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BpfDiagnostics {
    pub ringbuf_request_drops: u64,
    pub ringbuf_rados_drops: u64,
    pub rados_map_drops: u64,
    pub rados_finish_misses: u64,
    pub request_context_drops: u64,
    pub probe_read_failures: u64,
    pub reqstate_map_drops: u64,
    pub reseed_hits: u64,
    pub reseed_misses: u64,
    pub reseed_base_unresolved: u64,
    pub request_end_hits: u64,
    pub request_end_misses: u64,
    pub request_end_base_unresolved: u64,
    pub sendop_stale_ctx_drops: u64,
    pub sendop_unverifiable_ctx: u64,
    pub operate_seed_hits: u64,
    pub operate_seed_misses: u64,
    pub operate_base_unresolved: u64,
    pub sendop_unbridged_ctx_drops: u64,
    pub operate_miss_ctx_cleared: u64,
    pub rgw_op_key_inserts: u64,
    pub rgw_op_key_revokes: u64,
    pub rgw_op_key_revoke_skipped: u64,
    pub rgw_op_key_unresolved: u64,
    pub operate_seed_hits_reqstate: u64,
    pub operate_seed_hits_rgwop: u64,
    pub operate_seed_hits_unattributed: u64,
    pub operate_unresolved_ctx_cleared: u64,
    pub rgw_op_key_revoke_absent: u64,
    pub rgw_op_key_index_drops: u64,
    pub rgw_op_key_disabled: u64,
    pub operate_miss_home_ctx_preserved: u64,
    pub operate_unresolved_home_ctx_preserved: u64,
}

// `Deserialize` is here for the tests only: it is what lets
// `every_diagnostics_field_reaches_every_output_path` build an instance with EVERY
// field populated without hand-listing them (a hand-listed test would rot exactly
// the way the OTLP attribute list did). It is `deny_unknown_fields` so that
// round-trip cannot silently ignore a renamed field.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceDiagnostics {
    pub events_decoded: u64,
    pub decode_errors: u64,
    /// START markers (`RGWREST::get_handler`), i.e. requests whose identity was
    /// captured.
    pub request_markers: u64,
    /// END markers (`req_state::~req_state`), i.e. requests whose end was
    /// MEASURED. Always 0 when the end probe could not attach.
    pub request_end_markers: u64,
    /// Rendered request spans whose end came from the END probe
    /// (`rgw.duration_quality` = `measured` or `measured_extended`).
    pub measured_duration_requests: u64,
    /// Rendered request spans whose end was reconstructed from RADOS child
    /// bounds (`rgw.duration_quality` = `marker` or `rados_bounds`).
    pub derived_duration_requests: u64,
    pub rados_ops: u64,
    pub correlated_rados_ops: u64,
    pub background_rados_ops: u64,
    pub same_thread_correlations: u64,
    pub cross_thread_correlations: u64,
    pub inferred_correlations: u64,
    pub inference_no_candidate_rados_ops: u64,
    pub inference_ambiguous_rados_ops: u64,
    pub missing_trans_id_background_ops: u64,
    pub background_rados_by_role: BTreeMap<String, u64>,
    pub background_rados_by_reason: BTreeMap<String, u64>,
    pub spans_produced: u64,
    pub expired_request_groups: u64,
    /// Request groups force-expired while still OPEN (their END marker never
    /// arrived within `OPEN_REQUEST_TTL_MULTIPLIER * --correlation-ttl`). Their
    /// spans carry a DERIVED end. A nonzero count means END markers are being
    /// lost (ring-buffer drops, or destructor bridge misses), not that requests
    /// are slow.
    pub expired_open_requests: u64,
    /// Request markers (START or END) that arrived for a request whose span had
    /// already been exported. They are dropped rather than re-opening the group,
    /// because a re-opened group would emit a second span with the same span id.
    /// Nonzero means the expiry bounds are too tight for the workload.
    pub late_request_markers_dropped: u64,
    /// Request keys remembered by the no-duplicate tombstone this session (see
    /// `EmittedRequests`). Once it passes `EMITTED_BLOOM_DESIGN_CAPACITY` the
    /// filter's false-positive rate rises -- which costs DROPS, never duplicates --
    /// and a warning is logged once.
    pub emitted_request_keys: u64,
    pub expired_background_rados_ops: u64,
    pub truncated_trans_ids: u64,
    pub truncated_object_names: u64,
    pub truncated_acting_sets: u64,
    pub truncated_rados_ops: u64,
    pub truncated_cls_names: u64,
    pub truncated_method_names: u64,
    pub otlp_queue_dropped_traces: u64,
    pub otlp_queue_dropped_spans: u64,
    pub bpf_ringbuf_request_drops: u64,
    pub bpf_ringbuf_rados_drops: u64,
    pub bpf_rados_map_drops: u64,
    pub bpf_rados_finish_misses: u64,
    /// `rados_ops` entries the userspace sweep deleted because their `sent_ns`
    /// was older than `--rados-ops-stale-after`: ops whose client exited (or
    /// whose `_finish_op` was never probed) before completing, which would
    /// otherwise hold a map slot for the rest of the run. An op that was merely
    /// SLOW past the threshold and completes later shows up as a
    /// `bpf_rados_finish_misses` and emits no event, so a nonzero count on a
    /// healthy cluster means the threshold is too low.
    pub stale_rados_ops_swept: u64,
    pub bpf_request_context_drops: u64,
    pub bpf_probe_read_failures: u64,
    pub bpf_reqstate_map_drops: u64,
    // Cross-thread re-seed bridge coverage counters (informational, not
    // failures): populated only under --correlate-cross-thread. `reseed_hits`
    // is the number of execute-thread re-seeds that inherited a request's
    // context; `reseed_misses` counts fail-closed clears/keeps; and
    // `reseed_base_unresolved` counts req_state* descriptors that were not
    // register-resolvable at entry.
    pub bpf_reseed_hits: u64,
    pub bpf_reseed_misses: u64,
    pub bpf_reseed_base_unresolved: u64,
    // Request-END probe (req_state::~req_state) coverage counters
    // (informational, not failures). `request_end_hits` is the number of
    // destructor firings that resolved a bridged request context and therefore
    // produced a MEASURED request end; `request_end_misses` counts destructors
    // for requests the bridge never saw (started before the trace window, or
    // LRU-evicted); `request_end_base_unresolved` counts `this` pointers that
    // were not register-resolvable at entry.
    pub bpf_request_end_hits: u64,
    pub bpf_request_end_misses: u64,
    pub bpf_request_end_base_unresolved: u64,
    // _send_op request-context liveness gate (`request_ctx_is_live` in
    // bpf/rgwtrace.bpf.c). `sendop_stale_ctx_drops` counts ops that were NOT
    // stamped because the request context left on the submitting thread belonged
    // to a request that has already ended (or whose bridge entry was evicted) --
    // the fail-closed drops: those ops are uncorrelated instead of
    // mis-correlated. `sendop_unverifiable_ctx` counts ops stamped WITHOUT a
    // liveness proof, which happens only when nothing could ever revoke a context
    // (the END probe is not attached, or get_handler could not resolve the
    // req_state* from a register on this build).
    pub bpf_sendop_stale_ctx_drops: u64,
    pub bpf_sendop_unverifiable_ctx: u64,
    // PHASE B: the per-submit re-seed at `rgw_rados_operate` (both overloads),
    // populated only under --correlate-cross-thread. This is the pair to read to
    // tell whether cross-thread correlation is actually working.
    //
    // `operate_seed_hits` counts rados operates whose `dpp` matched a live
    // request's bridge entry, so the submitting thread -- whatever thread the
    // coroutine had migrated onto -- was seeded with that request's context right
    // before the submit. It should track the number of correlated request ops.
    //
    // `operate_seed_misses` counts operates whose `dpp` is NOT a traced request's
    // req_state: a bucket/zone/wrapper dpp, or a background (GC/LC/quota) thread's.
    // These are EXPECTED and are not failures or lost ops -- the miss is the
    // fail-closed path, and a busy gateway will show many. `operate_base_unresolved`
    // counts dpp descriptors that were not register-resolvable at entry.
    pub bpf_operate_seed_hits: u64,
    pub bpf_operate_seed_misses: u64,
    pub bpf_operate_base_unresolved: u64,
    // FAIL-CLOSED drops with no correlation loss ambiguity: an op was NOT stamped
    // because the context on its thread carried no req_state* and therefore could
    // never be bridged, verified, or revoked (Finding 4). A large count means the
    // bridge is dead on this build -- see the get_handler warning at attach.
    pub bpf_sendop_unbridged_ctx_drops: u64,
    // The per-submit re-seed's fail-closed clear: a rados operate whose `dpp` is
    // not a key of any traced request DROPPED the SEEDED request context that was
    // on the submitting thread (`ctx.tid != this tid` -- a copy Phase B migrated
    // here), instead of letting it stamp the op. This is the price of never
    // mis-correlating: request A's context can be left on any pool thread it ran an
    // operate on, and request B can resume on that same thread and submit through a
    // dpp we cannot key. A miss proves nothing about who is running here, so nothing
    // is assumed about a copy PHASE B made.
    pub bpf_operate_miss_ctx_cleared: u64,
    // The per-submit seed's OTHER fail-closed clear: the `dpp` could not be
    // resolved at all (a stack-located descriptor, or a NULL dpp argument). It
    // clears the thread's SEEDED context for exactly the same reason a foreign-dpp
    // miss does -- an unresolved dpp proves nothing about which coroutine is running
    // here -- and is counted separately because it means something completely
    // different: a foreign-dpp miss is the expected steady state, while a nonzero
    // count here means RGW passes null dpps on this path or the descriptor is
    // broken.
    pub bpf_operate_unresolved_ctx_cleared: u64,
    // THE SCOPE OF THAT CLEAR, made visible. An unproven submit PRESERVES a HOME
    // context -- one `get_handler` placed on this very thread for the request that
    // STARTED here (`ctx.tid == this tid`) -- and only clears a SEEDED copy.
    //
    // The clear used to be unscoped, and that cost a live ListObjects request all 16
    // of its `rgw.bucket_list` shard ops: RGW issues sharded bucket lists through the
    // cls_rgw AIO path, which never passes through `rgw_rados_operate`, so those
    // submits correlate purely off the HOME context on the thread -- and ONE
    // foreign-dpp operate on that thread wiped it. Clearing a HOME context also buys
    // no soundness (an AIO submit that never reaches an operate inherits the thread's
    // context either way); see the accepted residual hazard in
    // docs/design-cross-thread-correlation.md 11.
    //
    // Read these against the two `*_ctx_cleared` counters above: they say how often
    // the fail-closed rule fired on a Phase B copy versus how often it declined to
    // touch a context that predates Phase B. A healthy run has both nonzero.
    pub bpf_operate_miss_home_ctx_preserved: u64,
    pub bpf_operate_unresolved_home_ctx_preserved: u64,
    // MULTI-KEY bridge accounting. A request is findable under BOTH its req_state*
    // and the RGWOp* executing it, because RGW passes the RGWOp (not the req_state)
    // as the `dpp` at most call sites in an op's data path.
    //
    // THE REVOCATION IDENTITY (exact, not approximate):
    //
    //   inserts == revokes + revoke_skipped + revoke_absent + in-flight requests
    //
    // It holds because an alternate key is only inserted after its revocation
    // record exists in the never-evicting `rgw_op_keys` map, and the destructor
    // consults that record unconditionally -- including when the request's own
    // canonical LRU entry has been evicted, which is the case that used to strand
    // an alternate key forever and make this identity false.
    //
    // `revoke_skipped` counts destructors that found the alternate key already
    // re-keyed to a NEWER request (a recycled RGWOp address) and correctly left it
    // alone. `revoke_absent` counts keys already gone from the bridge (LRU-evicted)
    // -- nothing to revoke. `unresolved` counts requests with no alternate key at
    // all (no proven `RGWOp*&` descriptor on this build). `index_drops` counts
    // requests whose revocation record could not be created (map full), so the
    // alternate key was refused rather than created unrevocable -- fail closed.
    // `disabled` counts requests that ran with the alternate key switched OFF
    // (--disable-rgw-op-bridge-key), which is what tells "never fired" apart from
    // "never asked".
    pub bpf_rgw_op_key_inserts: u64,
    pub bpf_rgw_op_key_revokes: u64,
    pub bpf_rgw_op_key_revoke_skipped: u64,
    pub bpf_rgw_op_key_revoke_absent: u64,
    pub bpf_rgw_op_key_unresolved: u64,
    pub bpf_rgw_op_key_index_drops: u64,
    pub bpf_rgw_op_key_disabled: u64,
    // WHICH KEY DID THE PER-SUBMIT SEED HIT ON? The single most important pair of
    // numbers on a validation run.
    //
    // The `RGWOp*` alternate key exists ONLY as insurance in case RGW does not pass
    // the `req_state` as the `dpp` at the `rgw_rados_operate` call sites, and it is
    // the one part of the design with a residual mis-correlation hazard that no
    // amount of pointer-identity logic can remove (`RGWHandler_REST_S3Website::
    // retarget` can free and replace an RGWOp while its request is still alive; a
    // different heap object landing on that address would be seeded as that request
    // and the liveness gate would PASS, because the request really is alive).
    //
    //   reqstate ~= hits, rgwop ~= 0  -> the alternate key buys nothing. Disable it
    //                                    (--disable-rgw-op-bridge-key); hazard gone.
    //   rgwop is a large share of hits -> the key is load-bearing; keep it.
    //
    // `unattributed` must be 0: a hit is attributed by comparing the dpp against
    // the bridged value's own keys, exactly one of which can match. Nonzero means
    // the split cannot be trusted.
    pub bpf_operate_seed_hits_reqstate: u64,
    pub bpf_operate_seed_hits_rgwop: u64,
    pub bpf_operate_seed_hits_unattributed: u64,
}

impl TraceDiagnostics {
    /// EVERY diagnostic in this struct, as flat `(name, value)` pairs.
    ///
    /// WHY IT IS DERIVED FROM `Serialize` AND NOT HAND-WRITTEN. There are three
    /// output paths for the run summary -- the JSON document, the end-of-run log
    /// lines, and the OTLP resource attributes -- and only the first one gets every
    /// field for free (serde). The other two used CURATED LISTS, and curated lists
    /// rot: the Phase B counters (`bpf_operate_seed_*`, `bpf_rgw_op_key_*`,
    /// `bpf_sendop_unbridged_ctx_drops`, ...) were added to the struct and never
    /// added to the OTLP list, so an `--output otlp` run -- which never prints the
    /// JSON -- could not distinguish a working cross-thread bridge from an inert
    /// one. The counters that exist to prove the feature works were the exact ones
    /// missing from the only channel a live validation run can read.
    ///
    /// So this is generated from the serde representation, which IS the struct: a
    /// new field reaches every output path the moment it is declared, and cannot be
    /// forgotten. `every_diagnostics_field_reaches_every_output_path` in the tests
    /// below is the tripwire that keeps the other paths wired to this function.
    ///
    /// Counter maps (`background_rados_by_role`, `background_rados_by_reason`) are
    /// flattened to `field.key` entries, so they too survive the trip to a
    /// scalar-only sink like OTLP.
    pub fn counters(&self) -> Vec<(String, u64)> {
        let value = serde_json::to_value(self).expect("TraceDiagnostics serialization cannot fail");
        let serde_json::Value::Object(fields) = value else {
            unreachable!("TraceDiagnostics serializes as a JSON object");
        };

        let mut counters = Vec::with_capacity(fields.len());
        for (name, value) in fields {
            match value {
                serde_json::Value::Number(number) => {
                    counters.push((name, number.as_u64().unwrap_or(0)));
                }
                serde_json::Value::Object(entries) => {
                    for (key, value) in entries {
                        counters.push((format!("{name}.{key}"), value.as_u64().unwrap_or(0)));
                    }
                }
                // Unreachable while every field is a u64 or a counter map, which
                // `every_diagnostics_field_is_a_counter_or_a_counter_map` pins. A
                // future non-counter field would fail that test rather than be
                // silently dropped here.
                _ => {}
            }
        }
        counters
    }

    /// The whole run summary as one greppable `key=value` line, for the log sinks.
    /// Built from [`Self::counters`], so it can never fall behind the struct.
    pub fn summary(&self) -> String {
        self.counters()
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SpanDocument {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub start_ns: u64,
    pub end_ns: u64,
    pub attributes: Vec<Attribute>,
    pub events: Vec<SpanEvent>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SpanEvent {
    pub name: String,
    pub time_ns: u64,
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Attribute {
    pub key: String,
    pub value: AttributeValue,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum AttributeValue {
    String(String),
    U64(u64),
}

impl Collector {
    pub fn with_inferred_correlation(inference_window_ns: u64) -> Self {
        Self {
            infer_correlation: true,
            inference_window_ns,
            ..Self::default()
        }
    }

    pub fn push(&mut self, event: TraceEvent) {
        self.diagnostics.events_decoded += 1;
        match event {
            TraceEvent::RequestStart(request) => {
                // get_handler marker: opens the request (identity + start_ns).
                // Its end_ns is 0; the end comes from the END marker below, or
                // is derived from the RADOS child bounds when no END arrives.
                self.diagnostics.request_markers += 1;
                record_truncation(&mut self.diagnostics, request.truncation);
                let key = request_key(&request);
                if self.reject_already_emitted(&key) {
                    return;
                }
                let builder = self.requests.entry(key).or_default();
                builder.observe(request.start_ns, request.end_ns.max(request.start_ns));
                // Keep an END that already landed (out-of-order ring-buffer
                // delivery is possible): only the identity/start fields are
                // taken from START, never a measured end.
                match builder.request.as_mut() {
                    Some(existing) if builder.measured_end_ns.is_some() => {
                        existing.start_ns = request.start_ns;
                        existing.pid = request.pid;
                        existing.tid = request.tid;
                        existing.trans_id = request.trans_id;
                        existing.truncation = request.truncation;
                    }
                    _ => builder.request = Some(request),
                }
                self.retry_pending_inference();
            }
            TraceEvent::RequestEnd(request) => {
                // req_state::~req_state marker: the request's REAL end. It
                // carries the start_ns seeded at get_handler, so it can also
                // stand in as the request's identity marker if the START event
                // was lost (e.g. a ring-buffer drop).
                self.diagnostics.request_end_markers += 1;
                record_truncation(&mut self.diagnostics, request.truncation);
                let key = request_key(&request);
                if self.reject_already_emitted(&key) {
                    return;
                }
                let builder = self.requests.entry(key).or_default();
                builder.observe(request.start_ns, request.end_ns.max(request.start_ns));
                builder.measured_end_ns = Some(request.end_ns);
                match builder.request.as_mut() {
                    // Adopt the measured end onto the existing marker so the
                    // inference window sees the request's real extent.
                    Some(existing) => existing.end_ns = request.end_ns,
                    None => builder.request = Some(request),
                }
                self.retry_pending_inference();
            }
            TraceEvent::RadosOp(rados) => {
                self.diagnostics.rados_ops += 1;
                record_truncation(&mut self.diagnostics, rados.truncation);
                if rados.trans_id.is_empty() {
                    let role = classify_rados(&rados);
                    if self.infer_correlation && inferable_rados_role(role) {
                        match self.inferred_request_key(&rados) {
                            InferenceMatch::Match(key) => {
                                self.record_correlated_rados(
                                    key,
                                    rados,
                                    RadosCorrelation::Inferred,
                                );
                            }
                            InferenceMatch::NoCandidate | InferenceMatch::Ambiguous => {
                                self.pending_inference.push(rados);
                            }
                        };
                    } else {
                        self.record_background_rados(rados, background_reason_for_role(role));
                    }
                } else if self.emitted_requests.contains(&rados.trans_id) {
                    // This op's request span has ALREADY been exported, so
                    // re-grouping it under that key would emit a second parent
                    // span with the same trace/span id around it. The op itself
                    // is a measured fact, so it is kept as a background span
                    // with an explicit reason rather than dropped or re-parented.
                    self.record_background_rados(rados, BackgroundReason::RequestAlreadyEmitted);
                } else {
                    // A non-empty `trans_id` correlates the op to its request,
                    // but the same_thread/cross_thread split is derived late in
                    // `request_spans` (the marker's `tid` may not be known yet).
                    self.record_correlated_rados(
                        rados.trans_id.clone(),
                        rados,
                        RadosCorrelation::TransId,
                    );
                }
            }
        }
    }

    /// Whether `key` names a request whose span has already been exported, in
    /// which case the caller must NOT re-open a group for it. Counts the drop.
    fn reject_already_emitted(&mut self, key: &str) -> bool {
        if !self.emitted_requests.contains(key) {
            return false;
        }
        self.diagnostics.late_request_markers_dropped += 1;
        true
    }

    /// Remember that `key`'s request span has been exported, so a straggler event
    /// can never resurrect the group and produce a SECOND span with the same span
    /// id (span ids are a pure function of the key).
    ///
    /// The memory is never forgotten for the life of the run -- that is the whole
    /// guarantee -- and it is bounded (8 MiB) because it is a Bloom filter rather
    /// than an exact set. It has no false negatives, so no request can ever be
    /// emitted twice. Past its design capacity its false-POSITIVE rate rises, which
    /// costs dropped stragglers (and, rarely, a dropped fresh request) but can
    /// never duplicate one; the operator is told exactly once.
    fn remember_emitted(&mut self, key: &str) {
        if self.emitted_requests.contains(key) {
            return;
        }
        self.emitted_requests.insert(key);
        self.diagnostics.emitted_request_keys = self.emitted_requests.inserted;
        if self.emitted_requests.inserted > EMITTED_BLOOM_DESIGN_CAPACITY
            && !self.emitted_capacity_warned
        {
            self.emitted_capacity_warned = true;
            warn!(
                exported_requests = self.emitted_requests.inserted,
                design_capacity = EMITTED_BLOOM_DESIGN_CAPACITY,
                "the no-duplicate tombstone filter is past its design capacity. No request can \
                 ever be emitted twice (a Bloom filter has no false negatives), but its \
                 false-positive rate is now rising: late stragglers -- and, increasingly, whole \
                 fresh requests -- will be DROPPED (late_request_markers_dropped / background ops \
                 with reason request_already_emitted). Restart the tracer to reset it"
            );
        }
    }

    /// Declare whether the `req_state::~req_state` END probe is attached for this
    /// run. Live tracing sets it from the actual attach outcome; everything else
    /// leaves it `false`, which preserves the pre-end-probe expiry behavior.
    /// Opt in to hashing object names in the exported attributes. See the
    /// `redact_object_names` field and [`redacted_object_name`].
    pub fn set_redact_object_names(&mut self, redact: bool) {
        self.redact_object_names = redact;
    }

    pub fn set_end_probe_attached(&mut self, attached: bool) {
        self.end_probe_attached = attached;
    }

    fn inferred_request_key(&self, rados: &RadosEvent) -> InferenceMatch {
        if rados.send_tid != 0 {
            let same_thread_match =
                unique_inference_match(self.requests.iter().filter_map(|(key, builder)| {
                    let request = builder.request.as_ref()?;
                    (request.tid == rados.send_tid
                        && inferred_candidate(request, rados, self.inference_window_ns))
                    .then(|| key.clone())
                }));
            if same_thread_match != InferenceMatch::NoCandidate {
                return same_thread_match;
            }
        }

        unique_inference_match(self.requests.iter().filter_map(|(key, builder)| {
            let request = builder.request.as_ref()?;
            inferred_candidate(request, rados, self.inference_window_ns).then(|| key.clone())
        }))
    }

    fn retry_pending_inference(&mut self) {
        let mut remaining = Vec::new();
        for rados in std::mem::take(&mut self.pending_inference) {
            match self.inferred_request_key(&rados) {
                InferenceMatch::Match(key) => {
                    self.record_correlated_rados(key, rados, RadosCorrelation::Inferred);
                }
                InferenceMatch::NoCandidate | InferenceMatch::Ambiguous => remaining.push(rados),
            }
        }
        self.pending_inference = remaining;
    }

    fn finalize_expired_pending_inference(&mut self, cutoff_ns: u64) {
        let mut remaining = Vec::new();
        for rados in std::mem::take(&mut self.pending_inference) {
            if rados_event_time_ns(&rados) <= cutoff_ns {
                self.finalize_pending_inference(rados);
            } else {
                remaining.push(rados);
            }
        }
        self.pending_inference = remaining;
    }

    fn finalize_all_pending_inference(&mut self) {
        for rados in std::mem::take(&mut self.pending_inference) {
            self.finalize_pending_inference(rados);
        }
    }

    fn finalize_pending_inference(&mut self, rados: RadosEvent) {
        match self.inferred_request_key(&rados) {
            InferenceMatch::Match(key) => {
                self.record_correlated_rados(key, rados, RadosCorrelation::Inferred);
            }
            InferenceMatch::NoCandidate => {
                self.record_background_rados(rados, BackgroundReason::NoInferenceCandidate);
            }
            InferenceMatch::Ambiguous => {
                self.record_background_rados(rados, BackgroundReason::AmbiguousInferenceCandidates);
            }
        }
    }

    fn record_correlated_rados(
        &mut self,
        key: String,
        rados: RadosEvent,
        correlation: RadosCorrelation,
    ) {
        self.diagnostics.correlated_rados_ops += 1;
        match correlation {
            // `TransId` is thread-unresolved at ingest: it counts toward
            // `correlated_rados_ops` here, but its same_thread/cross_thread
            // tally is deferred to `request_spans` when the marker is known.
            RadosCorrelation::TransId => {}
            RadosCorrelation::Inferred => self.diagnostics.inferred_correlations += 1,
        }
        let last_seen_ns = rados_event_time_ns(&rados);
        let first_seen_ns = rados.sent_ns.min(rados.finish_ns);
        let builder = self.requests.entry(key).or_default();
        builder.observe(first_seen_ns, last_seen_ns);
        builder.rados.push(CorrelatedRados {
            event: rados,
            correlation,
        });
    }

    fn record_background_rados(&mut self, rados: RadosEvent, reason: BackgroundReason) {
        self.diagnostics.background_rados_ops += 1;
        if rados.trans_id.is_empty() {
            self.diagnostics.missing_trans_id_background_ops += 1;
        }
        match reason {
            BackgroundReason::NoInferenceCandidate => {
                self.diagnostics.inference_no_candidate_rados_ops += 1;
            }
            BackgroundReason::AmbiguousInferenceCandidates => {
                self.diagnostics.inference_ambiguous_rados_ops += 1;
            }
            BackgroundReason::MissingTransId
            | BackgroundReason::ClassifiedBackgroundRole
            | BackgroundReason::RequestAlreadyEmitted => {}
        }
        record_background_breakdown(&mut self.diagnostics, &rados, reason);
        self.background.push(BackgroundRados {
            event: rados,
            reason,
        });
    }

    pub fn record_decode_error(&mut self) {
        self.diagnostics.decode_errors += 1;
    }

    pub fn record_stale_rados_ops_swept(&mut self, swept: u64) {
        self.diagnostics.stale_rados_ops_swept =
            self.diagnostics.stale_rados_ops_swept.saturating_add(swept);
    }

    pub fn record_otlp_queue_drop(&mut self, spans: usize) {
        self.diagnostics.otlp_queue_dropped_traces += 1;
        self.diagnostics.otlp_queue_dropped_spans = self
            .diagnostics
            .otlp_queue_dropped_spans
            .saturating_add(spans as u64);
    }

    pub fn merge_bpf_diagnostics(&mut self, diagnostics: BpfDiagnostics) {
        self.diagnostics.bpf_ringbuf_request_drops = diagnostics.ringbuf_request_drops;
        self.diagnostics.bpf_ringbuf_rados_drops = diagnostics.ringbuf_rados_drops;
        self.diagnostics.bpf_rados_map_drops = diagnostics.rados_map_drops;
        self.diagnostics.bpf_rados_finish_misses = diagnostics.rados_finish_misses;
        self.diagnostics.bpf_request_context_drops = diagnostics.request_context_drops;
        self.diagnostics.bpf_probe_read_failures = diagnostics.probe_read_failures;
        self.diagnostics.bpf_reqstate_map_drops = diagnostics.reqstate_map_drops;
        self.diagnostics.bpf_reseed_hits = diagnostics.reseed_hits;
        self.diagnostics.bpf_reseed_misses = diagnostics.reseed_misses;
        self.diagnostics.bpf_reseed_base_unresolved = diagnostics.reseed_base_unresolved;
        self.diagnostics.bpf_request_end_hits = diagnostics.request_end_hits;
        self.diagnostics.bpf_request_end_misses = diagnostics.request_end_misses;
        self.diagnostics.bpf_request_end_base_unresolved = diagnostics.request_end_base_unresolved;
        self.diagnostics.bpf_sendop_stale_ctx_drops = diagnostics.sendop_stale_ctx_drops;
        self.diagnostics.bpf_sendop_unverifiable_ctx = diagnostics.sendop_unverifiable_ctx;
        self.diagnostics.bpf_operate_seed_hits = diagnostics.operate_seed_hits;
        self.diagnostics.bpf_operate_seed_misses = diagnostics.operate_seed_misses;
        self.diagnostics.bpf_operate_base_unresolved = diagnostics.operate_base_unresolved;
        self.diagnostics.bpf_sendop_unbridged_ctx_drops = diagnostics.sendop_unbridged_ctx_drops;
        self.diagnostics.bpf_operate_miss_ctx_cleared = diagnostics.operate_miss_ctx_cleared;
        self.diagnostics.bpf_rgw_op_key_inserts = diagnostics.rgw_op_key_inserts;
        self.diagnostics.bpf_rgw_op_key_revokes = diagnostics.rgw_op_key_revokes;
        self.diagnostics.bpf_rgw_op_key_revoke_skipped = diagnostics.rgw_op_key_revoke_skipped;
        self.diagnostics.bpf_rgw_op_key_unresolved = diagnostics.rgw_op_key_unresolved;
        self.diagnostics.bpf_operate_seed_hits_reqstate = diagnostics.operate_seed_hits_reqstate;
        self.diagnostics.bpf_operate_seed_hits_rgwop = diagnostics.operate_seed_hits_rgwop;
        self.diagnostics.bpf_operate_seed_hits_unattributed =
            diagnostics.operate_seed_hits_unattributed;
        self.diagnostics.bpf_operate_unresolved_ctx_cleared =
            diagnostics.operate_unresolved_ctx_cleared;
        self.diagnostics.bpf_operate_miss_home_ctx_preserved =
            diagnostics.operate_miss_home_ctx_preserved;
        self.diagnostics.bpf_operate_unresolved_home_ctx_preserved =
            diagnostics.operate_unresolved_home_ctx_preserved;
        self.diagnostics.bpf_rgw_op_key_revoke_absent = diagnostics.rgw_op_key_revoke_absent;
        self.diagnostics.bpf_rgw_op_key_index_drops = diagnostics.rgw_op_key_index_drops;
        self.diagnostics.bpf_rgw_op_key_disabled = diagnostics.rgw_op_key_disabled;
    }

    /// Export every request group and background op that has aged out, and drop
    /// them from the collector.
    ///
    /// Two clocks, because a request group has two very different reasons to be
    /// finished with:
    ///
    /// * CLOSED groups (the END marker arrived, or no END will ever arrive
    ///   because the end probe is not attached) expire on IDLENESS, `ttl_ns`
    ///   since the last event -- the long-standing behavior.
    /// * OPEN groups (END probe attached, END not yet seen) do NOT expire on
    ///   idleness. A long-running request that is simply quiet between RADOS ops
    ///   would otherwise be exported with a derived duration and removed, and its
    ///   destructor END -- arriving seconds later -- would rebuild the group and
    ///   emit a SECOND span with the SAME trace/span id, splitting the request's
    ///   children across two spans. They expire only on LIFETIME, at
    ///   `OPEN_REQUEST_TTL_MULTIPLIER * ttl_ns` since the request began, which is
    ///   the backstop against a lost END (ring-buffer drop, destructor bridge
    ///   miss) pinning the group forever.
    ///
    /// Whatever the reason, an exported key is REMEMBERED: a straggler event can
    /// never re-open it, so no request is ever emitted twice under one span id.
    pub fn drain_expired(
        &mut self,
        service_name: impl Into<String>,
        now_ns: u64,
        ttl_ns: u64,
    ) -> Option<TraceDocument> {
        let cutoff_ns = now_ns.saturating_sub(ttl_ns);
        let open_cutoff_ns =
            now_ns.saturating_sub(ttl_ns.saturating_mul(OPEN_REQUEST_TTL_MULTIPLIER));
        self.retry_pending_inference();
        self.finalize_expired_pending_inference(cutoff_ns);

        let mut spans = Vec::new();
        let mut remaining_requests = BTreeMap::new();
        let mut emitted_keys = Vec::new();
        let end_probe_attached = self.end_probe_attached;

        for (key, request) in std::mem::take(&mut self.requests) {
            let open = request.is_open(end_probe_attached);
            let expired = if open {
                request.first_seen_ns != 0 && request.first_seen_ns <= open_cutoff_ns
            } else {
                request.last_seen_ns != 0 && request.last_seen_ns <= cutoff_ns
            };
            if expired {
                self.diagnostics.expired_request_groups += 1;
                if open {
                    // A request that never delivered its END and outlived the
                    // backstop: exported now (with a derived end) so it cannot
                    // leak, and its key remembered so a very late END cannot
                    // duplicate it.
                    self.diagnostics.expired_open_requests += 1;
                }
                emitted_keys.push(key.clone());
                spans.extend(request_spans(
                    key,
                    request,
                    &mut self.diagnostics,
                    self.redact_object_names,
                ));
            } else {
                remaining_requests.insert(key, request);
            }
        }
        self.requests = remaining_requests;
        for key in emitted_keys {
            self.remember_emitted(&key);
        }

        let mut remaining_background = Vec::new();
        for background in std::mem::take(&mut self.background) {
            if rados_event_time_ns(&background.event) <= cutoff_ns {
                self.diagnostics.expired_background_rados_ops += 1;
                spans.push(background_span(background, self.redact_object_names));
            } else {
                remaining_background.push(background);
            }
        }
        self.background = remaining_background;

        if spans.is_empty() {
            return None;
        }

        let mut diagnostics = self.diagnostics.clone();
        diagnostics.spans_produced = spans.len() as u64;
        Some(TraceDocument {
            service_name: service_name.into(),
            spans,
            diagnostics,
        })
    }

    pub fn into_trace_document(mut self, service_name: impl Into<String>) -> TraceDocument {
        self.retry_pending_inference();
        self.finalize_all_pending_inference();

        let mut spans = Vec::new();

        let redact = self.redact_object_names;
        for (key, request) in self.requests {
            spans.extend(request_spans(key, request, &mut self.diagnostics, redact));
        }

        for background in self.background {
            spans.push(background_span(background, redact));
        }
        self.diagnostics.spans_produced = spans.len() as u64;

        TraceDocument {
            service_name: service_name.into(),
            spans,
            diagnostics: self.diagnostics,
        }
    }
}

fn unique_inference_match(mut candidates: impl Iterator<Item = String>) -> InferenceMatch {
    let Some(candidate) = candidates.next() else {
        return InferenceMatch::NoCandidate;
    };
    if candidates.next().is_some() {
        return InferenceMatch::Ambiguous;
    }
    InferenceMatch::Match(candidate)
}

fn rados_event_time_ns(rados: &RadosEvent) -> u64 {
    rados.finish_ns.max(rados.sent_ns)
}

fn request_key(request: &RequestEvent) -> String {
    if request.trans_id.is_empty() {
        format!(
            "pid:{}:tid:{}:start:{}",
            request.pid, request.tid, request.start_ns
        )
    } else {
        request.trans_id.clone()
    }
}

fn request_spans(
    key: String,
    builder: RequestBuilder,
    diagnostics: &mut TraceDiagnostics,
    redact_object_names: bool,
) -> Vec<SpanDocument> {
    let request_start_ns = builder.request.as_ref().map(|request| request.start_ns);
    let rados_start_ns = builder.rados.iter().map(|rados| rados.event.sent_ns).min();
    let start_ns = request_start_ns
        .into_iter()
        .chain(rados_start_ns)
        .min()
        .unwrap_or_default();
    // The measured end from the `req_state::~req_state` probe, when it fired.
    let measured_end_ns = builder.measured_end_ns;
    // Use the clamped child-span end (`finish_ns.max(sent_ns)`), not the raw
    // `finish_ns`. An inverted op whose `sent_ns` exceeds every `finish_ns` (and
    // the marker's `end_ns`) would otherwise leave the parent ending before the
    // clamped child span, pushing the child outside the parent bounds that the
    // JSON validator enforces.
    let rados_end_ns = builder
        .rados
        .iter()
        .map(|rados| rados_event_time_ns(&rados.event))
        .max();
    // Span end. Children are never clamped INTO the parent -- a RADOS op's own
    // bounds are measured facts, and shrinking them would corrupt the op's
    // reported duration. Instead the parent is EXTENDED to cover any child that
    // lands past the request's end, which keeps the "child within parent"
    // invariant the JSON validator enforces. This is normally impossible with a
    // real end (the destructor runs last), but a late `_finish_op` or an
    // `--correlate-inferred` child can still land outside; when it does, the
    // quality becomes `measured_extended` and the untouched measured end is
    // preserved verbatim in the `rgw.request.measured_end_ns` attribute, so a
    // consumer can always recover the true request duration.
    let end_ns = measured_end_ns
        .or_else(|| builder.request.as_ref().map(|request| request.end_ns))
        .into_iter()
        .chain(rados_end_ns)
        .max()
        .unwrap_or(start_ns)
        // Normalize against out-of-order stamps (e.g. a marker whose end_ns
        // precedes its start_ns): a span must never end before it starts, which
        // the JSON validator also enforces. Raw values are kept on the event.
        .max(start_ns);
    let trans_id = builder
        .request
        .as_ref()
        .map(|request| request.trans_id.as_str())
        .filter(|trans_id| !trans_id.is_empty())
        .unwrap_or(key.as_str());
    let request_class = classify_request(
        trans_id,
        builder
            .rados
            .first()
            .map(|rados| rados.event.object_name.as_str()),
    );
    let trace_id = trace_id(trans_id);
    let request_span_id = span_id(&format!("request:{trans_id}"));
    // The MEASURED start: the get_handler marker's own clock read. `None` only
    // when the group has no marker at all (a `rados_bounds` reconstruction).
    let measured_start_ns = request_start_ns;
    let duration_quality =
        request_duration_quality(measured_start_ns, measured_end_ns, start_ns, end_ns);
    match duration_quality {
        DurationQuality::Measured | DurationQuality::MeasuredExtended => {
            diagnostics.measured_duration_requests += 1;
        }
        DurationQuality::Marker | DurationQuality::RadosBounds => {
            diagnostics.derived_duration_requests += 1;
        }
    }
    // The marker's thread ID is the late-derivation evidence for the
    // same_thread/cross_thread split. A group reconstructed purely from RADOS
    // bounds (no marker) has no thread evidence, so its `TransId` ops stay
    // `same_thread` -- cross_thread requires marker evidence (design §3).
    let marker_tid = builder.request.as_ref().map(|request| request.tid);

    let mut attributes = vec![
        string_attr("rgw.trans_id", trans_id),
        string_attr("rgw.request_class", request_class_name(request_class)),
        string_attr("rgw.duration_quality", duration_quality.name()),
    ];
    // The request marker's thread. Paired with each child's `ceph.rados.send_tid`
    // this is the direct evidence of a coroutine migration (send_tid != tid) and
    // the only way to measure, from the exported trace alone, how much of the
    // correlation came from the same thread versus a bridge.
    if let Some(tid) = marker_tid {
        attributes.push(u64_attr("rgw.request.tid", tid as u64));
    }
    // The untouched MEASURED interval, so a consumer can always recover the true
    // request duration even when the span's bounds had to be stretched to
    // envelope an out-of-bounds child. Emitted per boundary, whenever that
    // boundary was actually measured: the start whenever a request marker exists
    // (get_handler's own clock read), the end whenever the END probe fired.
    if let Some(measured) = measured_start_ns {
        attributes.push(u64_attr("rgw.request.measured_start_ns", measured));
    }
    if let Some(measured) = measured_end_ns {
        attributes.push(u64_attr("rgw.request.measured_end_ns", measured));
    }

    let mut spans = vec![SpanDocument {
        trace_id: trace_id.clone(),
        span_id: request_span_id.clone(),
        parent_span_id: None,
        name: "rgw.request".to_string(),
        start_ns,
        end_ns,
        attributes,
        events: Vec::new(),
    }];

    for rados in builder.rados {
        let resolved = resolve_correlation(rados.correlation, &rados.event, marker_tid);
        // Tally the late-derived split here (Inferred was already counted at
        // ingest); this keeps the invariant
        // `correlated_rados_ops == same_thread + cross_thread + inferred`.
        match resolved {
            ResolvedCorrelation::SameThread => diagnostics.same_thread_correlations += 1,
            ResolvedCorrelation::CrossThread => diagnostics.cross_thread_correlations += 1,
            ResolvedCorrelation::Inferred => {}
        }
        spans.push(rados_child_span(
            rados,
            resolved,
            trace_id.clone(),
            request_span_id.clone(),
            redact_object_names,
        ));
    }

    spans
}

fn resolve_correlation(
    correlation: RadosCorrelation,
    event: &RadosEvent,
    marker_tid: Option<u32>,
) -> ResolvedCorrelation {
    match correlation {
        RadosCorrelation::Inferred => ResolvedCorrelation::Inferred,
        // A `trans_id`-tagged op is `same_thread` when it was submitted on the
        // request's own execute thread, and `cross_thread` only when a marker
        // proves the send thread differed (the re-seed bridge inherited the
        // identity onto another thread). No marker => keep `same_thread`.
        RadosCorrelation::TransId => match marker_tid {
            Some(tid) if event.send_tid != tid => ResolvedCorrelation::CrossThread,
            _ => ResolvedCorrelation::SameThread,
        },
    }
}

fn background_span(background: BackgroundRados, redact_object_names: bool) -> SpanDocument {
    let rados = background.event;
    let start_ns = rados.sent_ns;
    // `_send_op` and `_finish_op` run on different worker threads, so
    // `bpf_ktime_get_boot_ns` can invert across CPUs and yield
    // `finish_ns < sent_ns`. Clamp the span end so it never precedes the start,
    // matching `request_spans`. The reported duration is the
    // `ceph.rados.duration_ns` attribute (`finish_ns.saturating_sub(sent_ns)`,
    // which is 0 when inverted); `end_ns - start_ns` is then also 0, keeping the
    // span fields internally consistent for the JSON validator and OTLP backends.
    // The trailing `rados.op` event's `time_ns` reuses the same clamped value so
    // it keeps matching `end_ns`.
    let end_ns = rados_event_time_ns(&rados);
    let trace_key = format!("background:{}:{}:{}", rados.pid, rados.tid, rados.sent_ns);
    let attributes = rados_attributes(
        &rados,
        "none",
        Some(background.reason.name()),
        redact_object_names,
    );

    SpanDocument {
        trace_id: trace_id(&trace_key),
        span_id: span_id(&trace_key),
        parent_span_id: None,
        name: "rgw.background.rados_op".to_string(),
        start_ns,
        end_ns,
        attributes: attributes.clone(),
        events: vec![rados_span_event(rados, attributes)],
    }
}

fn rados_span_event(rados: RadosEvent, attributes: Vec<Attribute>) -> SpanEvent {
    // Match the clamped `background_span` end so the validator's
    // `event.time_ns == span.end_ns` check holds even when timestamps invert.
    let time_ns = rados_event_time_ns(&rados);

    SpanEvent {
        name: "rados.op".to_string(),
        time_ns,
        attributes,
    }
}

fn rados_child_span(
    rados: CorrelatedRados,
    resolved: ResolvedCorrelation,
    trace_id: String,
    parent_span_id: String,
    redact_object_names: bool,
) -> SpanDocument {
    let event = rados.event;
    let span_key = format!(
        "rados:{}:{}:{}:{}",
        event.pid, event.cid, event.tid, event.sent_ns
    );
    SpanDocument {
        trace_id,
        span_id: span_id(&span_key),
        parent_span_id: Some(parent_span_id),
        name: "rados.op".to_string(),
        start_ns: event.sent_ns,
        // Clamp so the child span never ends before it starts (see
        // `background_span`); `end_ns - start_ns` then matches the
        // `ceph.rados.duration_ns` attribute (0 when timestamps invert).
        end_ns: rados_event_time_ns(&event),
        attributes: rados_attributes(
            &event,
            resolved.name(),
            resolved.reason(),
            redact_object_names,
        ),
        events: Vec::new(),
    }
}

fn rados_attributes(
    rados: &RadosEvent,
    correlation: &'static str,
    correlation_reason: Option<&'static str>,
    redact_object_names: bool,
) -> Vec<Attribute> {
    // Classified on the RAW name, before any redaction: the role heuristics
    // key on object-name prefixes, and the role is what makes a redacted trace
    // still readable (`bucket_index` vs `data` vs `user_meta`).
    let role = classify_rados(rados);
    let object_name = if redact_object_names {
        redacted_object_name(&rados.object_name)
    } else {
        rados.object_name.clone()
    };
    let ops = rados
        .ops
        .iter()
        .map(|op| match (&op.class, &op.method) {
            (Some(class), Some(method)) => format!("call({class}.{method})"),
            _ => op.name.clone(),
        })
        .collect::<Vec<_>>()
        .join(" ");

    let mut attributes = vec![
        u64_attr("ceph.rados.duration_ns", rados.duration_ns),
        // The thread that submitted the op (`_send_op`). Compared against the
        // request marker's `rgw.request.tid` it proves whether the op was
        // submitted on the request's own execute thread or after a coroutine
        // migration -- the evidence behind the same_thread/cross_thread split,
        // and the measurement that tells us whether a cross-thread bridge works.
        u64_attr("ceph.rados.send_tid", rados.send_tid as u64),
        u64_attr("ceph.rados.pool", rados.pool),
        string_attr("ceph.rados.pg", pg_name(rados.pool, rados.pg_seed)),
        u64_attr("ceph.rados.pg_seed", rados.pg_seed as u64),
        u64_attr("ceph.rados.target_osd", rados.target_osd as u64),
        string_attr("ceph.rados.acting", acting_set(&rados.acting)),
        string_attr("ceph.rados.object", object_name),
        string_attr("ceph.rados.ops", &ops),
        string_attr("ceph.rados.rw", format!("{:?}", rados.rw).to_lowercase()),
        u64_attr("ceph.rados.offset", rados.offset),
        u64_attr("ceph.rados.length", rados.length),
        string_attr("rgw.rados_role", rados_role_name(role)),
        string_attr("rgw.correlation", correlation),
    ];
    if let Some(reason) = correlation_reason {
        attributes.push(string_attr("rgw.correlation_reason", reason));
    }
    if redact_object_names {
        // Names the redacted attribute, so a consumer can tell a hash from a
        // name without guessing from its shape.
        attributes.push(string_attr("rgwtrace.redacted", "ceph.rados.object"));
    }
    let truncation = rados.truncation.names();
    if !truncation.is_empty() {
        attributes.push(string_attr("rgwtrace.truncated", truncation.join(",")));
    }
    attributes
}

/// The exported stand-in for an object name under `--redact-object-names`:
/// the FNV-1a 64-bit hash of the name as 16 lowercase hex digits (the same
/// [`fnv1a64`] the span ids use). Stable across runs and hosts, so the ops
/// of one object still group together and can be joined with a hash computed
/// elsewhere, while the key itself (an S3 object key, a `<uid>.buckets` user
/// name, an access-key id) stays home. Not a secrecy primitive against a
/// guessing attacker who knows the candidate names; it keeps names out of a
/// backend that was never meant to hold them.
fn redacted_object_name(name: &str) -> String {
    format!("{:016x}", fnv1a64(name.as_bytes()))
}

fn record_truncation(
    diagnostics: &mut TraceDiagnostics,
    truncation: crate::events::CaptureTruncation,
) {
    if truncation.trans_id {
        diagnostics.truncated_trans_ids += 1;
    }
    if truncation.object_name {
        diagnostics.truncated_object_names += 1;
    }
    if truncation.acting {
        diagnostics.truncated_acting_sets += 1;
    }
    if truncation.rados_ops {
        diagnostics.truncated_rados_ops += 1;
    }
    if truncation.cls_name {
        diagnostics.truncated_cls_names += 1;
    }
    if truncation.method_name {
        diagnostics.truncated_method_names += 1;
    }
}

fn record_background_breakdown(
    diagnostics: &mut TraceDiagnostics,
    rados: &RadosEvent,
    reason: BackgroundReason,
) {
    let role = rados_role_name(classify_rados(rados));
    *diagnostics
        .background_rados_by_role
        .entry(role.to_string())
        .or_default() += 1;
    *diagnostics
        .background_rados_by_reason
        .entry(reason.name().to_string())
        .or_default() += 1;
}

fn background_reason_for_role(role: RadosRole) -> BackgroundReason {
    match role {
        RadosRole::Gc | RadosRole::Notify | RadosRole::Sync | RadosRole::Config => {
            BackgroundReason::ClassifiedBackgroundRole
        }
        _ => BackgroundReason::MissingTransId,
    }
}

fn inferred_candidate(request: &RequestEvent, rados: &RadosEvent, window_ns: u64) -> bool {
    if request.pid != rados.pid {
        return false;
    }
    let request_start = request.start_ns.min(request.end_ns);
    let request_end = request.end_ns.max(request.start_ns);
    let rados_start = rados.sent_ns.min(rados.finish_ns);
    let rados_end = rados.finish_ns.max(rados.sent_ns);
    rados_end >= request_start && rados_start <= request_end.saturating_add(window_ns)
}

fn inferable_rados_role(role: RadosRole) -> bool {
    matches!(
        role,
        RadosRole::Data
            | RadosRole::BucketIndex
            | RadosRole::BucketMeta
            | RadosRole::UserMeta
            | RadosRole::AuthMeta
            | RadosRole::Unknown
    )
}

impl ResolvedCorrelation {
    fn name(self) -> &'static str {
        match self {
            Self::SameThread => "same_thread",
            Self::CrossThread => "cross_thread",
            Self::Inferred => "inferred",
        }
    }

    fn reason(self) -> Option<&'static str> {
        match self {
            Self::SameThread => None,
            // The re-seed bridge inherited the request identity onto the
            // submission thread (design §3); surfaced so consumers can tell a
            // bridged correlation from a native same-thread one.
            Self::CrossThread => Some("reseed_bridge"),
            Self::Inferred => Some("pid_time_window"),
        }
    }
}

impl BackgroundReason {
    fn name(self) -> &'static str {
        match self {
            Self::MissingTransId => "missing_trans_id",
            Self::ClassifiedBackgroundRole => "classified_background_role",
            Self::NoInferenceCandidate => "no_inference_candidate",
            Self::AmbiguousInferenceCandidates => "ambiguous_inference_candidates",
            Self::RequestAlreadyEmitted => "request_already_emitted",
        }
    }
}

fn pg_name(pool: u64, pg_seed: u32) -> String {
    format!("{pool}.{pg_seed:x}")
}

fn acting_set(acting: &[i32]) -> String {
    format!(
        "[{}]",
        acting
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn string_attr(key: impl Into<String>, value: impl Into<String>) -> Attribute {
    Attribute {
        key: key.into(),
        value: AttributeValue::String(value.into()),
    }
}

fn u64_attr(key: impl Into<String>, value: u64) -> Attribute {
    Attribute {
        key: key.into(),
        value: AttributeValue::U64(value),
    }
}

fn request_class_name(class: RequestClass) -> &'static str {
    match class {
        RequestClass::S3Request => "s3_request",
        RequestClass::RgwBackground => "rgw_background",
        RequestClass::RgwStartup => "rgw_startup",
        RequestClass::Unknown => "unknown",
    }
}

/// How a request span's duration was obtained. A consumer MUST be able to tell a
/// really-measured duration from a reconstructed one, so the two families are
/// named distinctly:
///
/// * `measured` -- the `req_state::~req_state` END probe fired and BOTH span
///   bounds are the request's real ones: `start_ns` is the get_handler marker's
///   start and `end_ns` is the destructor's end. This is a true request duration.
/// * `measured_extended` -- the END probe fired, but at least one span boundary
///   had to be stretched off its measured value to envelope a correlated child:
///   a child that ended after the request's real end (a late `_finish_op` or an
///   inferred child) pushes `end_ns` out, and a child that STARTED before the
///   request marker pulls `start_ns` back. Either way part of the span's duration
///   is reconstructed, so it must not claim `measured`. The real interval is
///   preserved in `rgw.request.measured_start_ns` / `rgw.request.measured_end_ns`.
/// * `marker` -- no END marker (the end probe is not attached on this build, or
///   the request outlived the trace window). The span's `end_ns` is
///   RECONSTRUCTED from the correlated RADOS child bounds. This is the
///   pre-end-probe behavior and is NOT a real request duration.
/// * `rados_bounds` -- no request marker at all; the whole span was
///   reconstructed from RADOS timestamps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurationQuality {
    Measured,
    MeasuredExtended,
    Marker,
    RadosBounds,
}

impl DurationQuality {
    fn name(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::MeasuredExtended => "measured_extended",
            Self::Marker => "marker",
            Self::RadosBounds => "rados_bounds",
        }
    }
}

/// Classify a request span's duration from BOTH of its boundaries.
///
/// `measured_start_ns` is the get_handler marker's start (`None` = no marker at
/// all) and `measured_end_ns` the destructor END's end (`None` = no END marker).
/// `span_start_ns`/`span_end_ns` are the bounds actually emitted, which may have
/// been extended off the measured values to envelope a correlated child.
///
/// `measured` requires BOTH emitted bounds to equal their measured values. It is
/// not enough to check the end: the parent's start is extended BACKWARD to the
/// earliest child, so an inferred or late child that began before the request
/// marker moves `start_ns` earlier and makes part of the duration fictional.
/// Advertising that as `measured` would be exactly the lie this label exists to
/// prevent, so any stretched boundary yields `measured_extended`.
fn request_duration_quality(
    measured_start_ns: Option<u64>,
    measured_end_ns: Option<u64>,
    span_start_ns: u64,
    span_end_ns: u64,
) -> DurationQuality {
    match (measured_start_ns, measured_end_ns) {
        // Both emitted bounds ARE the measured ones: a true duration.
        (Some(start), Some(end)) if start == span_start_ns && end == span_end_ns => {
            DurationQuality::Measured
        }
        // An END exists but a boundary was stretched (a child extended the
        // parent, or a measured end preceding its start was clamped up).
        (_, Some(_)) => DurationQuality::MeasuredExtended,
        // A marker but no END: the end is reconstructed from the child bounds.
        (Some(_), None) => DurationQuality::Marker,
        // No marker at all: the whole span comes from RADOS timestamps.
        (None, None) => DurationQuality::RadosBounds,
    }
}

fn rados_role_name(role: RadosRole) -> &'static str {
    match role {
        RadosRole::Data => "data",
        RadosRole::BucketIndex => "bucket_index",
        RadosRole::BucketMeta => "bucket_meta",
        RadosRole::UserMeta => "user_meta",
        RadosRole::AuthMeta => "auth_meta",
        RadosRole::Gc => "gc",
        RadosRole::Notify => "notify",
        RadosRole::Sync => "sync",
        RadosRole::Config => "config",
        RadosRole::Unknown => "unknown",
    }
}

/// A 16-byte (32 hex char) trace id derived from `key`. `pub(crate)` so the OTLP
/// exporter's synthetic run-summary span is minted with the same id scheme as
/// every span the collector produces.
pub(crate) fn trace_id(key: &str) -> String {
    format!(
        "{:016x}{:016x}",
        fnv1a64(key.as_bytes()),
        fnv1a64_with_seed(key.as_bytes(), 1)
    )
}

/// An 8-byte (16 hex char) span id derived from `key`. See [`trace_id`].
pub(crate) fn span_id(key: &str) -> String {
    format!("{:016x}", fnv1a64(key.as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    fnv1a64_with_seed(bytes, 0)
}

fn fnv1a64_with_seed(bytes: &[u8], seed: u64) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64 ^ seed;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{CaptureTruncation, RadosDirection, RadosEvent, RadosOp, RequestEvent};

    fn rados(object_name: &str, trans_id: &str) -> RadosEvent {
        RadosEvent {
            pid: 42,
            send_tid: 7,
            cid: 1,
            tid: 2,
            sent_ns: 10,
            finish_ns: 20,
            duration_ns: 10,
            pool: 16,
            target_osd: 7,
            pg_seed: 1,
            acting: vec![1, 2, 3],
            rw: RadosDirection::Read,
            object_name: object_name.to_string(),
            trans_id: trans_id.to_string(),
            truncation: CaptureTruncation::default(),
            ops: Vec::new(),
            offset: 0,
            length: 0,
        }
    }

    #[test]
    fn emits_rados_ops_as_request_child_spans() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(rados("object", "tx1")));
        push_request(&mut collector, "tx1", 1, 30);

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 2);
        let request = &document.spans[0];
        let rados = &document.spans[1];
        assert_eq!(request.name, "rgw.request");
        assert!(request.events.is_empty());
        // The end probe fired, so the span end IS the request's real end.
        assert_eq!(request.start_ns, 1);
        assert_eq!(request.end_ns, 30);
        assert_eq!(
            string_attribute(request, "rgw.duration_quality"),
            Some("measured")
        );
        assert_eq!(
            u64_attribute(request, "rgw.request.measured_end_ns"),
            Some(30)
        );
        assert_eq!(u64_attribute(request, "rgw.request.tid"), Some(7));
        assert_eq!(rados.name, "rados.op");
        assert_eq!(rados.trace_id, request.trace_id);
        assert_eq!(
            rados.parent_span_id.as_deref(),
            Some(request.span_id.as_str())
        );
        assert_eq!(string_attribute(rados, "ceph.rados.pg"), Some("16.1"));
        assert_eq!(
            string_attribute(rados, "ceph.rados.acting"),
            Some("[1,2,3]")
        );
        assert_eq!(u64_attribute(rados, "ceph.rados.target_osd"), Some(7));
        // The submitting thread is exported so a coroutine migration
        // (send_tid != the request marker's tid) is visible in the trace itself.
        assert_eq!(u64_attribute(rados, "ceph.rados.send_tid"), Some(7));
        assert_eq!(document.diagnostics.events_decoded, 3);
        assert_eq!(document.diagnostics.request_markers, 1);
        assert_eq!(document.diagnostics.request_end_markers, 1);
        assert_eq!(document.diagnostics.measured_duration_requests, 1);
        assert_eq!(document.diagnostics.derived_duration_requests, 0);
        assert_eq!(document.diagnostics.rados_ops, 1);
        assert_eq!(document.diagnostics.correlated_rados_ops, 1);
        assert_eq!(document.diagnostics.background_rados_ops, 0);
        assert_eq!(document.diagnostics.same_thread_correlations, 1);
        assert_eq!(document.diagnostics.missing_trans_id_background_ops, 0);
        assert_eq!(document.diagnostics.spans_produced, 2);
        assert_eq!(
            string_attribute(rados, "rgw.correlation"),
            Some("same_thread")
        );
        assert_eq!(rados.parent_span_id, Some(request.span_id.clone()));
        assert_ne!(rados.span_id, request.span_id);
    }

    #[test]
    fn emits_background_span_without_trans_id() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(rados("notify.0", "")));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 1);
        assert_eq!(document.spans[0].name, "rgw.background.rados_op");
        assert_eq!(document.diagnostics.rados_ops, 1);
        assert_eq!(document.diagnostics.correlated_rados_ops, 0);
        assert_eq!(document.diagnostics.background_rados_ops, 1);
        assert_eq!(document.diagnostics.same_thread_correlations, 0);
        assert_eq!(document.diagnostics.missing_trans_id_background_ops, 1);
        assert_eq!(
            document.diagnostics.background_rados_by_role.get("notify"),
            Some(&1)
        );
        assert_eq!(
            document
                .diagnostics
                .background_rados_by_reason
                .get("classified_background_role"),
            Some(&1)
        );
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.correlation"),
            Some("none")
        );
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.correlation_reason"),
            Some("classified_background_role")
        );
    }

    #[test]
    fn classifies_background_sync_objects_without_inference() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(rados("meta.log.period.1", "")));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(
            string_attribute(&document.spans[0], "rgw.rados_role"),
            Some("sync")
        );
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.correlation_reason"),
            Some("classified_background_role")
        );
        assert_eq!(
            document.diagnostics.background_rados_by_role.get("sync"),
            Some(&1)
        );
    }

    #[test]
    fn inferred_correlation_is_disabled_by_default() {
        let mut collector = Collector::default();
        push_request(&mut collector, "tx1", 1, 30);
        let mut event = rados("object", "");
        event.sent_ns = 40;
        event.finish_ns = 45;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.inferred_correlations, 0);
        assert_eq!(document.diagnostics.background_rados_ops, 1);
        assert!(document
            .spans
            .iter()
            .any(|span| span.name == "rgw.background.rados_op"));
    }

    #[test]
    fn infers_correlation_for_single_pid_time_window_candidate() {
        let mut collector = Collector::with_inferred_correlation(100);
        push_request(&mut collector, "tx1", 1, 30);
        let mut event = rados("object", "");
        event.sent_ns = 40;
        event.finish_ns = 45;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 2);
        assert_eq!(document.diagnostics.correlated_rados_ops, 1);
        assert_eq!(document.diagnostics.inferred_correlations, 1);
        assert_eq!(document.diagnostics.same_thread_correlations, 0);
        assert_eq!(document.diagnostics.background_rados_ops, 0);
        assert_eq!(document.spans[1].trace_id, document.spans[0].trace_id);
        assert_eq!(
            document.spans[1].parent_span_id.as_deref(),
            Some(document.spans[0].span_id.as_str())
        );
        assert_eq!(
            string_attribute(&document.spans[1], "rgw.correlation"),
            Some("inferred")
        );
        assert_eq!(
            string_attribute(&document.spans[1], "rgw.correlation_reason"),
            Some("pid_time_window")
        );
    }

    #[test]
    fn defers_untagged_rados_until_request_marker_arrives() {
        let mut collector = Collector::with_inferred_correlation(100);
        let mut event = rados("object", "");
        event.sent_ns = 20;
        event.finish_ns = 25;
        collector.push(TraceEvent::RadosOp(event));

        push_request(&mut collector, "tx1", 1, 30);

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 2);
        assert_eq!(document.diagnostics.correlated_rados_ops, 1);
        assert_eq!(document.diagnostics.inferred_correlations, 1);
        assert_eq!(document.diagnostics.background_rados_ops, 0);
        assert_eq!(document.diagnostics.inference_no_candidate_rados_ops, 0);
        assert_eq!(document.diagnostics.inference_ambiguous_rados_ops, 0);
        assert_eq!(
            string_attribute(&document.spans[1], "rgw.correlation"),
            Some("inferred")
        );
    }

    #[test]
    fn sender_tid_preferred_over_same_pid_candidates() {
        let mut collector = Collector::with_inferred_correlation(100);
        push_request_with_tid(&mut collector, "tx1", 7, 1, 30);
        push_request_with_tid(&mut collector, "tx2", 9, 1, 30);
        let mut event = rados("object", "");
        event.send_tid = 9;
        event.sent_ns = 40;
        event.finish_ns = 45;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.correlated_rados_ops, 1);
        assert_eq!(document.diagnostics.inferred_correlations, 1);
        assert_eq!(document.diagnostics.inference_ambiguous_rados_ops, 0);
        let rados = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("expected inferred rados child span");
        let parent = document
            .spans
            .iter()
            .find(|span| Some(span.span_id.as_str()) == rados.parent_span_id.as_deref())
            .expect("expected parent request span");
        assert_eq!(string_attribute(parent, "rgw.trans_id"), Some("tx2"));
    }

    #[test]
    fn infers_when_rados_interval_overlaps_request_start() {
        let mut collector = Collector::with_inferred_correlation(0);
        push_request(&mut collector, "tx1", 10, 30);
        let mut event = rados("object", "");
        event.sent_ns = 5;
        event.finish_ns = 15;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.correlated_rados_ops, 1);
        assert_eq!(document.diagnostics.inferred_correlations, 1);
        assert_eq!(document.diagnostics.background_rados_ops, 0);
    }

    #[test]
    fn request_end_probe_produces_measured_duration_span() {
        // The two-marker production stream: START at get_handler, END at the
        // req_state destructor. The span's end IS the request's real end, so the
        // duration is MEASURED, not reconstructed.
        let mut collector = Collector::default();
        push_request(&mut collector, "tx1", 10, 30);

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 1);
        assert_eq!(document.spans[0].name, "rgw.request");
        assert_eq!(document.spans[0].start_ns, 10);
        assert_eq!(document.spans[0].end_ns, 30);
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.duration_quality"),
            Some("measured")
        );
        assert_eq!(
            u64_attribute(&document.spans[0], "rgw.request.measured_end_ns"),
            Some(30)
        );
        assert_eq!(document.diagnostics.request_markers, 1);
        assert_eq!(document.diagnostics.request_end_markers, 1);
        assert_eq!(document.diagnostics.measured_duration_requests, 1);
        assert_eq!(document.diagnostics.derived_duration_requests, 0);
    }

    #[test]
    fn request_without_end_probe_falls_back_to_derived_marker_duration() {
        // BACKWARD COMPATIBILITY: on a build where the end probe cannot attach
        // (symbol missing / stripped / older RGW) only the START marker arrives.
        // The span must still be produced, its end derived from the correlated
        // RADOS child bounds -- exactly the pre-end-probe behavior -- and it must
        // be labelled `marker`, never `measured`.
        let mut collector = Collector::default();
        collector.push(start("tx1", 10));
        let mut child = rados("object", "tx1");
        child.sent_ns = 20;
        child.finish_ns = 100;
        collector.push(TraceEvent::RadosOp(child));

        let document = collector.into_trace_document("rgwtrace");

        let request = &document.spans[0];
        assert_eq!(request.name, "rgw.request");
        assert_eq!(request.start_ns, 10);
        assert_eq!(request.end_ns, 100, "end derived from the child's bounds");
        assert_eq!(
            string_attribute(request, "rgw.duration_quality"),
            Some("marker")
        );
        // No measured end exists, so the attribute must be absent rather than
        // carrying a fabricated value.
        assert_eq!(u64_attribute(request, "rgw.request.measured_end_ns"), None);
        assert_eq!(document.diagnostics.request_markers, 1);
        assert_eq!(document.diagnostics.request_end_markers, 0);
        assert_eq!(document.diagnostics.measured_duration_requests, 0);
        assert_eq!(document.diagnostics.derived_duration_requests, 1);
    }

    #[test]
    fn request_without_end_probe_and_without_children_spans_the_start_instant() {
        // Degenerate fallback: a START marker with no children and no END. The
        // span collapses to a zero-length span at the start instant rather than
        // being dropped or given an invented end.
        let mut collector = Collector::default();
        collector.push(start("tx1", 100));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 1);
        assert_eq!(document.spans[0].start_ns, 100);
        assert_eq!(document.spans[0].end_ns, 100);
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.duration_quality"),
            Some("marker")
        );
    }

    #[test]
    fn measured_request_with_zero_duration_is_a_zero_duration_span() {
        // A request whose measured end equals its start yields a zero-duration
        // span rather than being dropped.
        let mut collector = Collector::default();
        push_request(&mut collector, "tx1", 100, 100);

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 1);
        assert_eq!(document.spans[0].start_ns, 100);
        assert_eq!(document.spans[0].end_ns, 100);
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.duration_quality"),
            Some("measured")
        );
    }

    #[test]
    fn measured_end_before_start_is_normalized_and_not_reported_as_measured() {
        // Defensive: an END whose end_ns precedes its start_ns (e.g. a clock
        // artifact) must still produce a span without panicking, and the span's
        // end_ns is clamped up to start_ns so it never precedes the start -- the
        // JSON validator rejects start_ns > end_ns. Because the emitted end is
        // then NOT the measured value, the span must not claim `measured`; the
        // raw measured value is still exported for inspection.
        let mut collector = Collector::default();
        push_request(&mut collector, "tx1", 100, 50);

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 1);
        assert_eq!(document.spans[0].start_ns, 100);
        assert_eq!(document.spans[0].end_ns, 100);
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.duration_quality"),
            Some("measured_extended")
        );
        assert_eq!(
            u64_attribute(&document.spans[0], "rgw.request.measured_end_ns"),
            Some(50)
        );
    }

    #[test]
    fn measured_request_extends_past_a_child_that_outlives_it() {
        // A correlated child ending after the request's REAL end (a late
        // _finish_op, or an inferred child). The child is never clamped INTO the
        // parent -- its bounds are measured facts -- so the PARENT is extended to
        // keep the child in bounds. That deliberate extension is disclosed:
        // the quality becomes `measured_extended` and the untouched measured end
        // stays available on `rgw.request.measured_end_ns`.
        let mut collector = Collector::default();
        let mut child = rados("object", "tx1");
        child.sent_ns = 20;
        child.finish_ns = 100;
        collector.push(TraceEvent::RadosOp(child));
        push_request(&mut collector, "tx1", 30, 40);

        let document = collector.into_trace_document("rgwtrace");

        let parent = &document.spans[0];
        let rados = &document.spans[1];
        assert_eq!(parent.start_ns, 20);
        assert_eq!(parent.end_ns, 100);
        assert!(parent.start_ns <= rados.start_ns);
        assert!(parent.end_ns >= rados.end_ns, "child must stay in bounds");
        assert_eq!(
            string_attribute(parent, "rgw.duration_quality"),
            Some("measured_extended")
        );
        assert_eq!(
            u64_attribute(parent, "rgw.request.measured_end_ns"),
            Some(40),
            "the real request end must survive the extension"
        );
        assert_eq!(document.diagnostics.measured_duration_requests, 1);
        assert_eq!(document.diagnostics.derived_duration_requests, 0);
    }

    #[test]
    fn measured_request_extended_backward_by_an_early_child_is_not_measured() {
        // FINDING 3. The parent's START is extended BACKWARD to the earliest
        // child (here an op that was already in flight when the request marker
        // fired -- an inferred or late-delivered child). The span's start_ns is
        // then NOT the measured start, so part of its duration is reconstructed:
        // labelling it `measured` would advertise a partly fictional duration as
        // real. Only the END was checked before this fix, so this span claimed
        // `measured`.
        let mut collector = Collector::default();
        let mut child = rados("object", "tx1");
        child.sent_ns = 50;
        child.finish_ns = 150;
        collector.push(TraceEvent::RadosOp(child));
        push_request(&mut collector, "tx1", 100, 200);

        let document = collector.into_trace_document("rgwtrace");

        let parent = &document.spans[0];
        assert_eq!(parent.start_ns, 50, "start extended back to the child");
        assert_eq!(parent.end_ns, 200, "the measured end is untouched");
        assert_eq!(
            string_attribute(parent, "rgw.duration_quality"),
            Some("measured_extended"),
            "a stretched START makes the duration partly derived, like a stretched END"
        );
        // The true measured interval stays recoverable from BOTH boundaries.
        assert_eq!(
            u64_attribute(parent, "rgw.request.measured_start_ns"),
            Some(100)
        );
        assert_eq!(
            u64_attribute(parent, "rgw.request.measured_end_ns"),
            Some(200)
        );
        assert_eq!(document.diagnostics.measured_duration_requests, 1);
    }

    #[test]
    fn unextended_measured_request_exports_both_measured_boundaries() {
        // The clean case: no child pushes either boundary, so the span IS the
        // measured interval -- and both measured boundaries are still exported so
        // a consumer never has to infer them from the span bounds.
        let mut collector = Collector::default();
        let mut child = rados("object", "tx1");
        child.sent_ns = 120;
        child.finish_ns = 180;
        collector.push(TraceEvent::RadosOp(child));
        push_request(&mut collector, "tx1", 100, 200);

        let document = collector.into_trace_document("rgwtrace");

        let parent = &document.spans[0];
        assert_eq!(parent.start_ns, 100);
        assert_eq!(parent.end_ns, 200);
        assert_eq!(
            string_attribute(parent, "rgw.duration_quality"),
            Some("measured")
        );
        assert_eq!(
            u64_attribute(parent, "rgw.request.measured_start_ns"),
            Some(100)
        );
        assert_eq!(
            u64_attribute(parent, "rgw.request.measured_end_ns"),
            Some(200)
        );
    }

    #[test]
    fn rados_bounds_span_has_no_measured_boundary_at_all() {
        // No request marker: neither boundary was measured, so neither may be
        // advertised as such.
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(rados("object", "tx1")));

        let document = collector.into_trace_document("rgwtrace");

        let parent = &document.spans[0];
        assert_eq!(
            string_attribute(parent, "rgw.duration_quality"),
            Some("rados_bounds")
        );
        assert_eq!(u64_attribute(parent, "rgw.request.measured_start_ns"), None);
        assert_eq!(u64_attribute(parent, "rgw.request.measured_end_ns"), None);
    }

    #[test]
    fn request_span_envelopes_inverted_child_clamped_end() {
        // An inverted op (finish < sent) whose sent_ns exceeds the request end
        // and every raw finish_ns. The child span end is clamped to sent_ns, so
        // the parent must also extend to sent_ns or the child escapes the parent
        // bounds the JSON validator enforces.
        let mut collector = Collector::default();
        let mut child = rados("object", "tx1");
        child.sent_ns = 200;
        child.finish_ns = 150;
        collector.push(TraceEvent::RadosOp(child));
        push_request(&mut collector, "tx1", 50, 100);

        let document = collector.into_trace_document("rgwtrace");

        let parent = &document.spans[0];
        let rados = &document.spans[1];
        assert_eq!(rados.name, "rados.op");
        assert_eq!(rados.start_ns, 200);
        assert_eq!(rados.end_ns, 200);
        assert!(parent.start_ns <= rados.start_ns);
        assert!(parent.end_ns >= rados.end_ns);
        assert_eq!(parent.end_ns, 200);
        assert_eq!(
            string_attribute(parent, "rgw.duration_quality"),
            Some("measured_extended")
        );
    }

    #[test]
    fn end_marker_alone_still_produces_a_measured_request() {
        // The START event was lost (e.g. a ring-buffer drop) but the destructor
        // END arrived. The END carries the start_ns seeded at get_handler, so it
        // can stand in as the request's identity marker -- the request is not
        // silently dropped, and its duration is still measured.
        let mut collector = Collector::default();
        collector.push(end("tx1", 10, 30));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 1);
        assert_eq!(document.spans[0].start_ns, 10);
        assert_eq!(document.spans[0].end_ns, 30);
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.duration_quality"),
            Some("measured")
        );
        assert_eq!(document.diagnostics.request_markers, 0);
        assert_eq!(document.diagnostics.request_end_markers, 1);
    }

    #[test]
    fn out_of_order_end_before_start_keeps_the_measured_end() {
        // Ring-buffer delivery is not ordered across probes. An END that lands
        // before its START must not have its measured end overwritten by the
        // START's (zero) end.
        let mut collector = Collector::default();
        collector.push(end("tx1", 10, 30));
        collector.push(start("tx1", 10));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 1);
        assert_eq!(document.spans[0].start_ns, 10);
        assert_eq!(document.spans[0].end_ns, 30);
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.duration_quality"),
            Some("measured")
        );
    }

    #[test]
    fn marks_rados_bounds_duration_without_request_marker() {
        let mut collector = Collector::default();
        let mut child = rados("object", "tx1");
        child.sent_ns = 20;
        child.finish_ns = 100;
        collector.push(TraceEvent::RadosOp(child));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans[0].name, "rgw.request");
        assert_eq!(document.spans[0].start_ns, 20);
        assert_eq!(document.spans[0].end_ns, 100);
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.duration_quality"),
            Some("rados_bounds")
        );
    }

    #[test]
    fn does_not_infer_ambiguous_candidates() {
        let mut collector = Collector::with_inferred_correlation(100);
        push_request(&mut collector, "tx1", 1, 30);
        push_request(&mut collector, "tx2", 1, 30);
        let mut event = rados("object", "");
        event.sent_ns = 40;
        event.finish_ns = 45;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.inferred_correlations, 0);
        assert_eq!(document.diagnostics.inference_ambiguous_rados_ops, 1);
        assert_eq!(document.diagnostics.inference_no_candidate_rados_ops, 0);
        assert_eq!(document.diagnostics.background_rados_ops, 1);
        assert_eq!(
            string_attribute(&document.spans[2], "rgw.correlation_reason"),
            Some("ambiguous_inference_candidates")
        );
        assert_eq!(
            document
                .diagnostics
                .background_rados_by_reason
                .get("ambiguous_inference_candidates"),
            Some(&1)
        );
    }

    #[test]
    fn records_no_candidate_when_inference_window_misses() {
        let mut collector = Collector::with_inferred_correlation(5);
        push_request(&mut collector, "tx1", 1, 30);
        let mut event = rados("object", "");
        event.sent_ns = 40;
        event.finish_ns = 45;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.inferred_correlations, 0);
        assert_eq!(document.diagnostics.inference_no_candidate_rados_ops, 1);
        assert_eq!(document.diagnostics.inference_ambiguous_rados_ops, 0);
        assert_eq!(
            string_attribute(&document.spans[1], "rgw.correlation_reason"),
            Some("no_inference_candidate")
        );
    }

    #[test]
    fn drain_expired_finalizes_pending_no_candidate_once() {
        let mut collector = Collector::with_inferred_correlation(5);
        let mut event = rados("object", "");
        event.sent_ns = 10;
        event.finish_ns = 20;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.drain_expired("rgwtrace", 200, 100).unwrap();

        assert_eq!(document.spans.len(), 1);
        assert_eq!(document.diagnostics.background_rados_ops, 1);
        assert_eq!(document.diagnostics.inference_no_candidate_rados_ops, 1);
        assert_eq!(document.diagnostics.inference_ambiguous_rados_ops, 0);
        assert_eq!(document.diagnostics.expired_background_rados_ops, 1);
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.correlation_reason"),
            Some("no_inference_candidate")
        );

        let remaining = collector.into_trace_document("rgwtrace");
        assert_eq!(remaining.spans.len(), 0);
        assert_eq!(remaining.diagnostics.background_rados_ops, 1);
        assert_eq!(remaining.diagnostics.inference_no_candidate_rados_ops, 1);
    }

    #[test]
    fn drains_only_expired_trace_groups() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(rados("old", "tx-old")));

        let mut fresh = rados("fresh", "tx-fresh");
        fresh.sent_ns = 1_000;
        fresh.finish_ns = 1_010;
        collector.push(TraceEvent::RadosOp(fresh));

        let document = collector.drain_expired("rgwtrace", 200, 100).unwrap();

        assert_eq!(document.spans.len(), 2);
        assert_eq!(document.diagnostics.expired_request_groups, 1);
        assert_eq!(document.diagnostics.spans_produced, 2);

        let remaining = collector.into_trace_document("rgwtrace");
        assert_eq!(remaining.spans.len(), 2);
    }

    // --- open-request expiry: no request may ever be emitted twice (Finding 2) ---

    /// A collector on a run where the `req_state::~req_state` END probe attached,
    /// i.e. one where a request without an END marker is still OPEN.
    fn collector_with_end_probe() -> Collector {
        let mut collector = Collector::default();
        collector.set_end_probe_attached(true);
        collector
    }

    #[test]
    fn long_idle_open_request_is_not_double_emitted_when_its_end_arrives_after_the_ttl() {
        // THE BUG: a long-running request that is merely IDLE (its RADOS children
        // finished long ago, but RGW is still working) was TTL-expired and
        // exported with a derived duration. Its destructor END then arrived and
        // rebuilt the group, exporting a SECOND span with the SAME trace/span id
        // and a measured duration -- one request, two spans, children split
        // across them.
        let mut collector = collector_with_end_probe();
        collector.push(start("tx-slow", 1_000));
        let mut child = rados("object", "tx-slow");
        child.sent_ns = 1_100;
        child.finish_ns = 1_200;
        collector.push(TraceEvent::RadosOp(child));

        // Idle far beyond the TTL (last event at 1_200, cutoff at 9_000) but the
        // END is still coming, so nothing may be exported yet.
        assert!(
            collector.drain_expired("rgwtrace", 10_000, 1_000).is_none(),
            "an OPEN request must not be idle-expired: its END is still coming"
        );

        // The destructor finally fires, long after the idle TTL would have
        // expired the group.
        collector.push(end("tx-slow", 1_000, 12_000));
        let drained = collector
            .drain_expired("rgwtrace", 20_000, 1_000)
            .expect("the now-CLOSED request must expire on the idle TTL");

        let requests: Vec<_> = drained
            .spans
            .iter()
            .filter(|span| span.name == "rgw.request")
            .collect();
        assert_eq!(requests.len(), 1, "exactly one request span");
        assert_eq!(requests[0].start_ns, 1_000);
        assert_eq!(requests[0].end_ns, 12_000, "the REAL, measured end");
        assert_eq!(
            string_attribute(requests[0], "rgw.duration_quality"),
            Some("measured")
        );
        assert_eq!(drained.diagnostics.expired_open_requests, 0);

        // And nothing is left behind to be emitted a second time.
        let remaining = collector.into_trace_document("rgwtrace");
        assert!(
            remaining.spans.is_empty(),
            "the request must not be emitted twice: {:?}",
            remaining.spans
        );
    }

    #[test]
    fn open_request_is_force_expired_by_the_lifetime_backstop_and_never_resurrected() {
        // The backstop: an END that is LOST (ring-buffer drop, or a destructor
        // bridge miss) must not pin its group forever. Past
        // OPEN_REQUEST_TTL_MULTIPLIER * ttl since the request began, the group is
        // exported with a DERIVED end -- and its key is remembered, so an END that
        // shows up even later cannot emit a second span with the same span id.
        let ttl = 1_000;
        let mut collector = collector_with_end_probe();
        collector.push(start("tx-lost-end", 100));

        // Idle-expired? No -- it is open. Lifetime-expired? Not quite yet (one ns
        // short of the backstop), even though it is 10 TTLs past idle.
        assert!(collector
            .drain_expired("rgwtrace", 99 + ttl * OPEN_REQUEST_TTL_MULTIPLIER, ttl)
            .is_none());

        let drained = collector
            .drain_expired("rgwtrace", 200 + ttl * OPEN_REQUEST_TTL_MULTIPLIER, ttl)
            .expect("past the lifetime backstop the leaked request must be exported");
        assert_eq!(drained.spans.len(), 1);
        assert_eq!(
            string_attribute(&drained.spans[0], "rgw.duration_quality"),
            Some("marker"),
            "no END ever arrived, so the end is derived -- never claimed as measured"
        );
        assert_eq!(drained.diagnostics.expired_open_requests, 1);
        let span_id = drained.spans[0].span_id.clone();

        // The very late END must be DROPPED, not turned into a second span.
        collector.push(end("tx-lost-end", 100, 5_000));
        assert_eq!(
            collector.diagnostics.late_request_markers_dropped, 1,
            "a marker for an already-exported request is dropped, and counted"
        );

        let remaining = collector.into_trace_document("rgwtrace");
        assert!(
            !remaining.spans.iter().any(|span| span.span_id == span_id),
            "the exported request must never be emitted a second time"
        );
        assert!(remaining.spans.is_empty());
    }

    #[test]
    fn tombstone_retention_survives_a_production_rate_key_flood_without_duplicating_a_span() {
        // REGRESSION (Finding 5). The tombstone used to be a bounded FIFO of 65,536
        // keys that evicted the oldest. At production request rates its entire
        // memory turns over in seconds -- so a long request that was force-expired
        // at the lifetime backstop had its tombstone EVICTED long before its END
        // finally arrived, and that END then recreated the group and re-emitted the
        // SAME deterministic span id. Exactly the duplicate the tombstone exists to
        // prevent.
        //
        // The filter now has no false negatives for the whole session, so no volume
        // of intervening requests can forget a key.
        let ttl = 1_000;
        let mut collector = collector_with_end_probe();
        collector.push(start("tx-long-running", 100));

        // Force-expire it (its END is lost/late) and record the span id it got.
        let drained = collector
            .drain_expired("rgwtrace", 200 + ttl * OPEN_REQUEST_TTL_MULTIPLIER, ttl)
            .expect("the open request is force-expired at the lifetime backstop");
        assert_eq!(drained.diagnostics.expired_open_requests, 1);
        let span_id = drained.spans[0].span_id.clone();

        // Now flood the collector with FAR more requests than the old FIFO could
        // remember (65,536), each fully exported, so every one of them is
        // tombstoned. Under the old scheme this evicted tx-long-running's key.
        let flood = 200_000;
        for i in 0..flood {
            let key = format!("tx-flood-{i}");
            collector.push(start(&key, 100));
            collector.push(end(&key, 100, 150));
            collector.drain_expired("rgwtrace", 10_000, ttl);
        }
        assert!(
            collector.diagnostics.emitted_request_keys > 65_536,
            "the flood must exceed the OLD bounded memory, or this test proves nothing"
        );

        // The straggler END finally arrives, long after its key would have been
        // evicted from a bounded FIFO.
        collector.push(end("tx-long-running", 100, 5_000));
        assert_eq!(
            collector.diagnostics.late_request_markers_dropped, 1,
            "the late END must still be recognised as belonging to an ALREADY EXPORTED request"
        );

        let remaining = collector.into_trace_document("rgwtrace");
        assert!(
            !remaining.spans.iter().any(|span| span.span_id == span_id),
            "the request was emitted a SECOND time under the same span id: {:?}",
            remaining.spans
        );
        assert!(remaining.spans.is_empty());
    }

    #[test]
    fn the_tombstone_never_forgets_a_key_and_never_claims_an_unknown_one() {
        // The two properties the no-duplicate guarantee rests on:
        //   * NO FALSE NEGATIVES -- an inserted key is always reported present. This
        //     is what makes a duplicate span id impossible.
        //   * A key that was never inserted is (near-certainly) reported absent, so
        //     fresh requests are not spuriously dropped. A collision here is
        //     possible by construction (~1e-7 at the design capacity) and it can
        //     only ever cause a DROP, never a duplicate.
        let mut emitted = EmittedRequests::default();
        assert!(
            !emitted.contains("tx-never-seen"),
            "empty filter claims nothing"
        );

        let inserted: Vec<String> = (0..50_000).map(|i| format!("tx-{i}")).collect();
        for key in &inserted {
            emitted.insert(key);
        }
        for key in &inserted {
            assert!(
                emitted.contains(key),
                "a Bloom filter has NO false negatives: {key} must still be remembered"
            );
        }
        assert_eq!(emitted.inserted, 50_000);

        let false_positives = (0..50_000)
            .filter(|i| emitted.contains(&format!("tx-absent-{i}")))
            .count();
        assert_eq!(
            false_positives, 0,
            "at 50k keys in a 2^26-bit filter the false-positive rate is ~1e-12; \
             {false_positives} collisions means the hashing is broken"
        );
    }

    #[test]
    fn without_the_end_probe_a_start_only_request_still_expires_on_the_idle_ttl() {
        // BACKWARD COMPATIBILITY: on a build where the END probe cannot attach no
        // END will ever arrive, so a START-only request is NOT open -- holding it
        // until the lifetime backstop would delay every export by 10x the TTL.
        // The pre-end-probe idle expiry is exactly right there.
        let mut collector = Collector::default(); // end probe NOT attached
        collector.push(start("tx1", 100));

        let drained = collector
            .drain_expired("rgwtrace", 10_000, 1_000)
            .expect("without an end probe the idle TTL still expires the request");

        assert_eq!(drained.spans.len(), 1);
        assert_eq!(
            string_attribute(&drained.spans[0], "rgw.duration_quality"),
            Some("marker")
        );
        assert_eq!(
            drained.diagnostics.expired_open_requests, 0,
            "nothing is OPEN when no END is expected"
        );
    }

    #[test]
    fn late_rados_op_for_an_already_emitted_request_becomes_background() {
        // A correlated op that arrives after its request's span was exported
        // cannot be re-grouped: rebuilding the group would emit a duplicate
        // parent span with the same span id. The op is a measured fact, so it is
        // kept as a background span with an explicit reason instead of being
        // dropped or re-parented.
        let mut collector = Collector::default();
        push_request(&mut collector, "tx1", 100, 200);
        let drained = collector.drain_expired("rgwtrace", 10_000, 1_000).unwrap();
        let request_span_id = drained.spans[0].span_id.clone();

        let mut late = rados("object", "tx1");
        late.sent_ns = 150;
        late.finish_ns = 190;
        collector.push(TraceEvent::RadosOp(late));

        let remaining = collector.into_trace_document("rgwtrace");
        assert_eq!(remaining.spans.len(), 1);
        assert_eq!(remaining.spans[0].name, "rgw.background.rados_op");
        assert_ne!(remaining.spans[0].span_id, request_span_id);
        assert!(
            !remaining
                .spans
                .iter()
                .any(|span| span.name == "rgw.request"),
            "no duplicate parent span may be created for an already-emitted request"
        );
        assert_eq!(
            string_attribute(&remaining.spans[0], "rgw.correlation_reason"),
            Some("request_already_emitted")
        );
        assert_eq!(
            remaining
                .diagnostics
                .background_rados_by_reason
                .get("request_already_emitted"),
            Some(&1)
        );
    }

    #[test]
    fn drains_expired_background_ops() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(rados("notify.0", "")));

        let document = collector.drain_expired("rgwtrace", 200, 100).unwrap();

        assert_eq!(document.spans.len(), 1);
        assert_eq!(document.diagnostics.expired_background_rados_ops, 1);
        assert!(collector.drain_expired("rgwtrace", 200, 100).is_none());
    }

    #[test]
    fn reports_capture_truncation() {
        let mut collector = Collector::default();
        let mut event = rados("object", "tx1");
        event.truncation = CaptureTruncation {
            trans_id: true,
            object_name: true,
            acting: true,
            rados_ops: true,
            cls_name: true,
            method_name: true,
        };
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.truncated_trans_ids, 1);
        assert_eq!(document.diagnostics.truncated_object_names, 1);
        assert_eq!(document.diagnostics.truncated_acting_sets, 1);
        assert_eq!(document.diagnostics.truncated_rados_ops, 1);
        assert_eq!(document.diagnostics.truncated_cls_names, 1);
        assert_eq!(document.diagnostics.truncated_method_names, 1);
        assert_eq!(
            string_attribute(&document.spans[1], "rgwtrace.truncated"),
            Some("trans_id,object_name,acting,rados_ops,cls_name,method_name")
        );
    }

    #[test]
    fn records_otlp_queue_drops() {
        let mut collector = Collector::default();

        collector.record_otlp_queue_drop(3);
        collector.record_otlp_queue_drop(2);

        let document = collector.into_trace_document("rgwtrace");
        assert_eq!(document.diagnostics.otlp_queue_dropped_traces, 2);
        assert_eq!(document.diagnostics.otlp_queue_dropped_spans, 5);
    }

    #[test]
    fn records_swept_stale_rados_ops_cumulatively() {
        // The sweep runs every few seconds; the counter is a run total, and a BPF
        // diagnostics merge (which overwrites the bpf_* snapshot) must not reset it.
        let mut collector = Collector::default();

        collector.record_stale_rados_ops_swept(3);
        collector.merge_bpf_diagnostics(BpfDiagnostics::default());
        collector.record_stale_rados_ops_swept(4);

        let document = collector.into_trace_document("rgwtrace");
        assert_eq!(document.diagnostics.stale_rados_ops_swept, 7);
        assert!(document
            .diagnostics
            .counters()
            .contains(&("stale_rados_ops_swept".to_string(), 7)));
    }

    #[test]
    fn merges_bpf_diagnostics() {
        let mut collector = Collector::default();

        collector.merge_bpf_diagnostics(BpfDiagnostics {
            ringbuf_request_drops: 1,
            ringbuf_rados_drops: 2,
            rados_map_drops: 3,
            rados_finish_misses: 4,
            request_context_drops: 5,
            probe_read_failures: 6,
            reqstate_map_drops: 7,
            reseed_hits: 8,
            reseed_misses: 9,
            reseed_base_unresolved: 10,
            request_end_hits: 11,
            request_end_misses: 12,
            request_end_base_unresolved: 13,
            sendop_stale_ctx_drops: 14,
            sendop_unverifiable_ctx: 15,
            operate_seed_hits: 16,
            operate_seed_misses: 17,
            operate_base_unresolved: 18,
            sendop_unbridged_ctx_drops: 19,
            operate_miss_ctx_cleared: 20,
            rgw_op_key_inserts: 21,
            rgw_op_key_revokes: 22,
            rgw_op_key_revoke_skipped: 23,
            rgw_op_key_unresolved: 24,
            operate_seed_hits_reqstate: 25,
            operate_seed_hits_rgwop: 26,
            operate_seed_hits_unattributed: 27,
            operate_unresolved_ctx_cleared: 28,
            rgw_op_key_revoke_absent: 29,
            rgw_op_key_index_drops: 30,
            rgw_op_key_disabled: 31,
            operate_miss_home_ctx_preserved: 32,
            operate_unresolved_home_ctx_preserved: 33,
        });

        let document = collector.into_trace_document("rgwtrace");
        assert_eq!(document.diagnostics.bpf_ringbuf_request_drops, 1);
        assert_eq!(document.diagnostics.bpf_ringbuf_rados_drops, 2);
        assert_eq!(document.diagnostics.bpf_rados_map_drops, 3);
        assert_eq!(document.diagnostics.bpf_rados_finish_misses, 4);
        assert_eq!(document.diagnostics.bpf_request_context_drops, 5);
        assert_eq!(document.diagnostics.bpf_probe_read_failures, 6);
        assert_eq!(document.diagnostics.bpf_reqstate_map_drops, 7);
        assert_eq!(document.diagnostics.bpf_reseed_hits, 8);
        assert_eq!(document.diagnostics.bpf_reseed_misses, 9);
        assert_eq!(document.diagnostics.bpf_reseed_base_unresolved, 10);
        assert_eq!(document.diagnostics.bpf_request_end_hits, 11);
        assert_eq!(document.diagnostics.bpf_request_end_misses, 12);
        assert_eq!(document.diagnostics.bpf_request_end_base_unresolved, 13);
        assert_eq!(document.diagnostics.bpf_sendop_stale_ctx_drops, 14);
        assert_eq!(document.diagnostics.bpf_sendop_unverifiable_ctx, 15);
        assert_eq!(document.diagnostics.bpf_operate_seed_hits, 16);
        assert_eq!(document.diagnostics.bpf_operate_seed_misses, 17);
        assert_eq!(document.diagnostics.bpf_operate_base_unresolved, 18);
        assert_eq!(document.diagnostics.bpf_sendop_unbridged_ctx_drops, 19);
        assert_eq!(document.diagnostics.bpf_operate_miss_ctx_cleared, 20);
        assert_eq!(document.diagnostics.bpf_rgw_op_key_inserts, 21);
        assert_eq!(document.diagnostics.bpf_rgw_op_key_revokes, 22);
        assert_eq!(document.diagnostics.bpf_rgw_op_key_revoke_skipped, 23);
        assert_eq!(document.diagnostics.bpf_rgw_op_key_unresolved, 24);
        assert_eq!(document.diagnostics.bpf_operate_seed_hits_reqstate, 25);
        assert_eq!(document.diagnostics.bpf_operate_seed_hits_rgwop, 26);
        assert_eq!(document.diagnostics.bpf_operate_seed_hits_unattributed, 27);
        assert_eq!(document.diagnostics.bpf_operate_unresolved_ctx_cleared, 28);
        assert_eq!(document.diagnostics.bpf_rgw_op_key_revoke_absent, 29);
        assert_eq!(document.diagnostics.bpf_rgw_op_key_index_drops, 30);
        assert_eq!(document.diagnostics.bpf_rgw_op_key_disabled, 31);
        assert_eq!(document.diagnostics.bpf_operate_miss_home_ctx_preserved, 32);
        assert_eq!(
            document
                .diagnostics
                .bpf_operate_unresolved_home_ctx_preserved,
            33
        );
    }

    /// FNV-1a 64 known answers (the published test vectors), so the exported
    /// hash is the one a consumer can recompute.
    #[test]
    fn fnv1a64_matches_the_reference_vectors() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
        assert_eq!(redacted_object_name("a"), "af63dc4c8601ec8c");
    }

    /// `--redact-object-names`: every `ceph.rados.object` -- on correlated
    /// children, on background spans AND on their `rados.op` event, in the
    /// final document and in a periodic drain -- is the hash, the span says so
    /// with `rgwtrace.redacted`, and the role is still classified from the raw
    /// name.
    #[test]
    fn redacts_object_names_at_the_one_point_attributes_are_built() {
        let mut collector = Collector::default();
        collector.set_redact_object_names(true);
        collector.push(start("tx-redact", 100));
        let mut child = rados("bucket/customer-upload.jpg", "tx-redact");
        child.sent_ns = 120;
        child.finish_ns = 130;
        collector.push(TraceEvent::RadosOp(child));
        let mut index = rados(".dir.bucket-id.3", "");
        index.sent_ns = 140;
        index.finish_ns = 150;
        collector.push(TraceEvent::RadosOp(index));
        collector.push(end("tx-redact", 100, 200));

        let document = collector.into_trace_document("rgwtrace");

        let child = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("correlated child span");
        assert_eq!(
            attr(child, "ceph.rados.object"),
            Some(redacted_object_name("bucket/customer-upload.jpg").as_str())
        );
        assert_eq!(attr(child, "rgwtrace.redacted"), Some("ceph.rados.object"));
        assert_eq!(attr(child, "rgw.rados_role"), Some("data"));

        let background = document
            .spans
            .iter()
            .find(|span| span.name == "rgw.background.rados_op")
            .expect("background span");
        let hashed = redacted_object_name(".dir.bucket-id.3");
        assert_eq!(attr(background, "ceph.rados.object"), Some(hashed.as_str()));
        assert_eq!(
            attr(background, "rgwtrace.redacted"),
            Some("ceph.rados.object")
        );
        // Classified from the RAW name, not the hash.
        assert_eq!(attr(background, "rgw.rados_role"), Some("bucket_index"));
        let event_object = background.events[0]
            .attributes
            .iter()
            .find(|attribute| attribute.key == "ceph.rados.object")
            .map(|attribute| &attribute.value);
        assert!(
            matches!(event_object, Some(AttributeValue::String(value)) if *value == hashed),
            "the rados.op event carries the redacted name too: {event_object:?}"
        );

        // The raw names appear NOWHERE in the serialized document.
        let json = serde_json::to_string(&document).unwrap();
        assert!(!json.contains("customer-upload"), "{json}");
        assert!(!json.contains(".dir.bucket-id"), "{json}");
    }

    /// The periodic-drain path renders through the same functions with the
    /// same flag; a flag honored only by the final document would leak every
    /// name a live `--output otlp` run exports.
    #[test]
    fn redaction_applies_to_periodic_drains() {
        let mut collector = Collector::default();
        collector.set_redact_object_names(true);
        let mut background = rados("bucket/drained-object", "");
        background.sent_ns = 10;
        background.finish_ns = 20;
        collector.push(TraceEvent::RadosOp(background));

        let drained = collector
            .drain_expired("rgwtrace", 1_000, 100)
            .expect("the background op has expired");

        let json = serde_json::to_string(&drained).unwrap();
        assert!(!json.contains("drained-object"), "{json}");
        assert!(json.contains(&redacted_object_name("bucket/drained-object")));
    }

    /// Off by default: the golden fixture (below) pins the raw names, and this
    /// pins the absence of the marker attribute.
    #[test]
    fn object_names_are_exported_verbatim_by_default() {
        let mut collector = Collector::default();
        collector.push(start("tx-plain", 100));
        let mut child = rados("bucket/plain-object", "tx-plain");
        child.sent_ns = 120;
        child.finish_ns = 130;
        collector.push(TraceEvent::RadosOp(child));
        collector.push(end("tx-plain", 100, 200));

        let document = collector.into_trace_document("rgwtrace");

        let child = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .unwrap();
        assert_eq!(
            attr(child, "ceph.rados.object"),
            Some("bucket/plain-object")
        );
        assert_eq!(attr(child, "rgwtrace.redacted"), None);
    }

    fn attr<'a>(span: &'a SpanDocument, key: &str) -> Option<&'a str> {
        span.attributes
            .iter()
            .find(|attribute| attribute.key == key)
            .and_then(|attribute| match &attribute.value {
                AttributeValue::String(value) => Some(value.as_str()),
                AttributeValue::U64(_) => None,
            })
    }

    #[test]
    fn collector_trace_matches_golden_fixture() {
        // Mirror the real production event stream: the get_handler entry probe
        // emits the START marker, the request's RADOS children arrive from the
        // send/finish probes, and the req_state destructor emits the END marker
        // carrying the measured end.
        let mut collector = Collector::default();
        collector.push(start("tx-golden", 100));

        let mut child = rados("bucket-object", "tx-golden");
        child.sent_ns = 120;
        child.finish_ns = 190;
        child.duration_ns = 70;
        child.pg_seed = 0x2a;
        child.rw = RadosDirection::Write;
        child.offset = 128;
        child.length = 4096;
        child.ops = vec![
            RadosOp {
                code: 0x2202,
                name: "writefull".to_string(),
                class: None,
                method: None,
            },
            RadosOp {
                code: 0x1401,
                name: "call".to_string(),
                class: Some("cls".to_string()),
                method: Some("method".to_string()),
            },
        ];
        collector.push(TraceEvent::RadosOp(child));

        let mut background = rados("notify.0", "");
        background.sent_ns = 300;
        background.finish_ns = 320;
        background.duration_ns = 20;
        background.ops = vec![RadosOp {
            code: 0x1201,
            name: "read".to_string(),
            class: None,
            method: None,
        }];
        collector.push(TraceEvent::RadosOp(background));

        collector.push(end("tx-golden", 100, 250));

        let actual = serde_json::to_string_pretty(&collector.into_trace_document("rgwtrace"))
            .expect("trace document should serialize");
        let expected = include_str!("../tests/fixtures/collector_trace_golden.json").trim();

        assert_eq!(
            actual, expected,
            "collector trace golden changed:\n{actual}"
        );
    }

    #[test]
    fn resolves_same_thread_when_marker_arrives_after_rados_op() {
        // Ingest-order bug fixed: the RADOS op (send_tid 7) arrives BEFORE its
        // request marker (tid 7). Committing to same_thread at ingest was wrong
        // because the marker's tid is unknown then; the label must still resolve
        // to same_thread once the marker lands.
        let mut op = rados("object", "tx1");
        op.send_tid = 7;
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(op));
        push_request_with_tid(&mut collector, "tx1", 7, 1, 30);

        let document = collector.into_trace_document("rgwtrace");

        let child = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("child rados span");
        assert_eq!(
            string_attribute(child, "rgw.correlation"),
            Some("same_thread")
        );
        assert_eq!(string_attribute(child, "rgw.correlation_reason"), None);
        assert_eq!(document.diagnostics.correlated_rados_ops, 1);
        assert_eq!(document.diagnostics.same_thread_correlations, 1);
        assert_eq!(document.diagnostics.cross_thread_correlations, 0);
    }

    #[test]
    fn resolves_same_thread_when_marker_arrives_before_rados_op() {
        // Reverse ingest order (marker first): must resolve identically.
        let mut op = rados("object", "tx1");
        op.send_tid = 7;
        let mut collector = Collector::default();
        push_request_with_tid(&mut collector, "tx1", 7, 1, 30);
        collector.push(TraceEvent::RadosOp(op));

        let document = collector.into_trace_document("rgwtrace");

        let child = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("child rados span");
        assert_eq!(
            string_attribute(child, "rgw.correlation"),
            Some("same_thread")
        );
        assert_eq!(document.diagnostics.same_thread_correlations, 1);
        assert_eq!(document.diagnostics.cross_thread_correlations, 0);
    }

    #[test]
    fn resolves_cross_thread_when_send_tid_differs_from_marker() {
        // Bridged op: a valid trans_id but submitted on a different thread than
        // the request marker (send_tid 99 != marker tid 7). This is exactly the
        // re-seed-bridge case the late label exists to surface.
        let mut op = rados("object", "tx1");
        op.send_tid = 99;
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(op));
        push_request_with_tid(&mut collector, "tx1", 7, 1, 30);

        let document = collector.into_trace_document("rgwtrace");

        let child = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("child rados span");
        assert_eq!(
            string_attribute(child, "rgw.correlation"),
            Some("cross_thread")
        );
        assert_eq!(
            string_attribute(child, "rgw.correlation_reason"),
            Some("reseed_bridge")
        );
        assert_eq!(document.diagnostics.correlated_rados_ops, 1);
        assert_eq!(document.diagnostics.same_thread_correlations, 0);
        assert_eq!(document.diagnostics.cross_thread_correlations, 1);
    }

    #[test]
    fn phase_b_migrated_data_path_lands_as_cross_thread_children() {
        // PHASE B, collector half. The DELETE from the live capture: its whole data
        // path (bucket_prepare_op / obj_remove / bucket_complete_op) was submitted
        // AFTER the coroutine migrated off the get_handler thread, so before Phase B
        // all three ops arrived with no trans_id and were emitted as
        // `rgw.background.rados_op` (reason `missing_trans_id`).
        //
        // With the per-submit re-seed, each op arrives already stamped with the
        // request's trans_id and carrying the MIGRATED thread as its send_tid, while
        // the request marker still carries the get_handler thread. That mismatch is
        // exactly what the late label reads, so all three become `cross_thread`
        // children of the request -- not background ops, and not `same_thread`
        // (which would misrepresent where the work happened).
        let mut collector = Collector::default();
        for (object, send_tid) in [
            ("bucket.index", 201),
            ("obj.remove", 202),
            // A pool thread can be reused -- including the get_handler thread. That
            // op is genuinely same_thread and must be labelled as such.
            ("bucket.complete", 7),
        ] {
            let mut op = rados(object, "tx-delete");
            op.send_tid = send_tid;
            collector.push(TraceEvent::RadosOp(op));
        }
        push_request_with_tid(&mut collector, "tx-delete", 7, 1, 30);

        let document = collector.into_trace_document("rgwtrace");

        let children: Vec<&SpanDocument> = document
            .spans
            .iter()
            .filter(|span| span.name == "rados.op")
            .collect();
        assert_eq!(children.len(), 3, "every op must be a child of the request");

        let labels: Vec<Option<&str>> = children
            .iter()
            .map(|span| string_attribute(span, "rgw.correlation"))
            .collect();
        assert_eq!(
            labels
                .iter()
                .filter(|l| **l == Some("cross_thread"))
                .count(),
            2,
            "the two ops submitted after a migration are cross_thread: {labels:?}"
        );
        assert_eq!(
            labels.iter().filter(|l| **l == Some("same_thread")).count(),
            1,
            "the op that happened to submit on the handler thread stays same_thread: {labels:?}"
        );

        let d = &document.diagnostics;
        assert_eq!(
            d.background_rados_ops, 0,
            "no op of this request may be reported as a background op any more"
        );
        assert_eq!(d.correlated_rados_ops, 3);
        assert_eq!(d.cross_thread_correlations, 2);
        assert_eq!(d.same_thread_correlations, 1);
        assert_eq!(
            d.correlated_rados_ops,
            d.same_thread_correlations + d.cross_thread_correlations + d.inferred_correlations,
            "counter equation must hold"
        );
    }

    #[test]
    fn marker_less_rados_bounds_group_stays_same_thread() {
        // A group reconstructed purely from RADOS bounds (no request marker) has
        // no thread evidence, so cross_thread cannot be asserted: it keeps
        // same_thread (design §3), preserving today's behavior.
        let mut op = rados("object", "tx1");
        op.send_tid = 99; // would differ from a marker, but there is no marker
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(op));

        let document = collector.into_trace_document("rgwtrace");

        let child = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("child rados span");
        assert_eq!(
            string_attribute(
                document
                    .spans
                    .iter()
                    .find(|span| span.name == "rgw.request")
                    .expect("request span"),
                "rgw.duration_quality"
            ),
            Some("rados_bounds")
        );
        assert_eq!(
            string_attribute(child, "rgw.correlation"),
            Some("same_thread")
        );
        assert_eq!(document.diagnostics.same_thread_correlations, 1);
        assert_eq!(document.diagnostics.cross_thread_correlations, 0);
    }

    #[test]
    fn correlation_counter_equation_holds_on_mixed_scenario() {
        // correlated_rados_ops == same_thread + cross_thread + inferred, on a
        // scenario mixing same_thread, cross_thread (bridged), inferred, and an
        // uncorrelated background op.
        let mut collector = Collector::with_inferred_correlation(100);

        // same_thread: send_tid == marker tid.
        push_request_with_tid(&mut collector, "tx-same", 7, 1, 30);
        let mut same = rados("same", "tx-same");
        same.send_tid = 7;
        collector.push(TraceEvent::RadosOp(same));

        // cross_thread: bridged op, send_tid != marker tid.
        push_request_with_tid(&mut collector, "tx-cross", 7, 1, 30);
        let mut cross = rados("cross", "tx-cross");
        cross.send_tid = 4242;
        collector.push(TraceEvent::RadosOp(cross));

        // inferred: untagged op inside a lone request's window.
        push_request_with_tid(&mut collector, "tx-inf", 55, 200, 230);
        let mut inferred = rados("inferred", "");
        inferred.send_tid = 55;
        inferred.sent_ns = 240;
        inferred.finish_ns = 245;
        collector.push(TraceEvent::RadosOp(inferred));

        // background: untagged op with a classified background role.
        collector.push(TraceEvent::RadosOp(rados("notify.0", "")));

        let document = collector.into_trace_document("rgwtrace");
        let d = &document.diagnostics;

        assert_eq!(d.same_thread_correlations, 1);
        assert_eq!(d.cross_thread_correlations, 1);
        assert_eq!(d.inferred_correlations, 1);
        assert_eq!(d.background_rados_ops, 1);
        assert_eq!(
            d.correlated_rados_ops,
            d.same_thread_correlations + d.cross_thread_correlations + d.inferred_correlations,
            "counter equation must hold"
        );
    }

    fn request(trans_id: &str, start_ns: u64, end_ns: u64) -> RequestEvent {
        request_with_tid(trans_id, 7, start_ns, end_ns)
    }

    fn request_with_tid(trans_id: &str, tid: u32, start_ns: u64, end_ns: u64) -> RequestEvent {
        RequestEvent {
            start_ns,
            end_ns,
            pid: 42,
            tid,
            trans_id: trans_id.to_string(),
            truncation: CaptureTruncation::default(),
        }
    }

    /// The get_handler START marker: identity + start, never an end.
    fn start(trans_id: &str, start_ns: u64) -> TraceEvent {
        start_with_tid(trans_id, 7, start_ns)
    }

    fn start_with_tid(trans_id: &str, tid: u32, start_ns: u64) -> TraceEvent {
        TraceEvent::RequestStart(request_with_tid(trans_id, tid, start_ns, 0))
    }

    /// The req_state::~req_state END marker: carries the seeded start plus the
    /// MEASURED end.
    fn end(trans_id: &str, start_ns: u64, end_ns: u64) -> TraceEvent {
        end_with_tid(trans_id, 7, start_ns, end_ns)
    }

    fn end_with_tid(trans_id: &str, tid: u32, start_ns: u64, end_ns: u64) -> TraceEvent {
        TraceEvent::RequestEnd(request_with_tid(trans_id, tid, start_ns, end_ns))
    }

    /// The full production event stream for one request on a build where the end
    /// probe IS attached: START at get_handler, END at the req_state destructor.
    fn push_request(collector: &mut Collector, trans_id: &str, start_ns: u64, end_ns: u64) {
        push_request_with_tid(collector, trans_id, 7, start_ns, end_ns);
    }

    fn push_request_with_tid(
        collector: &mut Collector,
        trans_id: &str,
        tid: u32,
        start_ns: u64,
        end_ns: u64,
    ) {
        collector.push(start_with_tid(trans_id, tid, start_ns));
        collector.push(end_with_tid(trans_id, tid, start_ns, end_ns));
    }

    fn string_attribute<'a>(span: &'a SpanDocument, key: &str) -> Option<&'a str> {
        span.attributes.iter().find_map(|attribute| {
            if attribute.key == key {
                if let AttributeValue::String(value) = &attribute.value {
                    return Some(value.as_str());
                }
            }
            None
        })
    }

    fn u64_attribute(span: &SpanDocument, key: &str) -> Option<u64> {
        span.attributes.iter().find_map(|attribute| {
            if attribute.key == key {
                if let AttributeValue::U64(value) = attribute.value {
                    return Some(value);
                }
            }
            None
        })
    }

    #[test]
    fn child_span_clamps_inverted_timestamps() {
        // The send and finish probes run on different worker threads, so
        // boot-clock reads can invert across CPUs and give finish_ns < sent_ns.
        let mut event = rados("bucket-object", "tx-inv");
        event.sent_ns = 200;
        event.finish_ns = 100;
        // Mirror the production derivation (events.rs): saturating_sub -> 0.
        event.duration_ns = event.finish_ns.saturating_sub(event.sent_ns);

        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(event));
        push_request(&mut collector, "tx-inv", 50, 300);

        let document = collector.into_trace_document("rgwtrace");
        let child = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("child rados span should exist");

        assert!(
            child.start_ns <= child.end_ns,
            "child start_ns {} must not exceed end_ns {}",
            child.start_ns,
            child.end_ns
        );
        let duration = u64_attribute(child, "ceph.rados.duration_ns").expect("duration attribute");
        assert_eq!(
            duration,
            child.end_ns - child.start_ns,
            "reported duration must equal end-start"
        );
        assert_eq!(
            duration, 0,
            "inverted timestamps clamp to a zero-length span"
        );
    }

    #[test]
    fn background_span_clamps_inverted_timestamps() {
        let mut event = rados("notify.0", "");
        event.sent_ns = 200;
        event.finish_ns = 100;
        event.duration_ns = event.finish_ns.saturating_sub(event.sent_ns);

        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");
        let background = document
            .spans
            .iter()
            .find(|span| span.name == "rgw.background.rados_op")
            .expect("background rados span should exist");

        assert!(
            background.start_ns <= background.end_ns,
            "background start_ns {} must not exceed end_ns {}",
            background.start_ns,
            background.end_ns
        );
        let duration =
            u64_attribute(background, "ceph.rados.duration_ns").expect("duration attribute");
        assert_eq!(duration, background.end_ns - background.start_ns);
        assert_eq!(duration, 0);
        // The trailing rados.op event's time_ns must keep matching the clamped
        // end_ns (the JSON validator enforces this equality).
        assert_eq!(background.events.len(), 1);
        assert_eq!(background.events[0].time_ns, background.end_ns);
    }

    #[test]
    fn spans_keep_non_zero_duration_when_ordered() {
        // Regression guard: correctly ordered timestamps must survive the clamp.
        let mut child = rados("bucket-object", "tx-ok");
        child.sent_ns = 100;
        child.finish_ns = 175;
        child.duration_ns = child.finish_ns - child.sent_ns;

        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(child));
        push_request(&mut collector, "tx-ok", 50, 300);

        let document = collector.into_trace_document("rgwtrace");
        let child_span = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("child rados span should exist");
        assert_eq!(child_span.start_ns, 100);
        assert_eq!(child_span.end_ns, 175);
        assert_eq!(child_span.end_ns - child_span.start_ns, 75);
        assert_eq!(
            u64_attribute(child_span, "ceph.rados.duration_ns"),
            Some(75)
        );

        let mut background = rados("notify.0", "");
        background.sent_ns = 400;
        background.finish_ns = 460;
        background.duration_ns = background.finish_ns - background.sent_ns;

        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(background));

        let document = collector.into_trace_document("rgwtrace");
        let background_span = document
            .spans
            .iter()
            .find(|span| span.name == "rgw.background.rados_op")
            .expect("background rados span should exist");
        assert_eq!(background_span.end_ns - background_span.start_ns, 60);
        assert_eq!(
            u64_attribute(background_span, "ceph.rados.duration_ns"),
            Some(60)
        );
        assert_eq!(background_span.events[0].time_ns, background_span.end_ns);
    }
}
