//! PHASE B: the per-submit cross-thread re-seed at `rgw_rados_operate`, and the
//! MULTI-KEY bridge that makes it hit.
//!
//! WHAT THIS FILE PROVES. Three mechanisms designed separately meet on one hot
//! path: the Phase B seed, the multi-key bridge (a request is findable by its
//! `req_state*` AND by the `RGWOp*` executing it), and the `_send_op` liveness
//! gate. If a Phase-B-seeded context were rejected by that gate, or if the dpp RGW
//! actually passes were not one of the keys, the whole feature would silently do
//! nothing -- every op would still come out as a background op, `operate_seed_hits`
//! would still be counted, and nothing would look broken. Those interactions are
//! therefore EXECUTED here, not reasoned about.
//!
//! And one thing it proves NEGATIVELY: that a request's context can never stamp an
//! op submitted by a DIFFERENT request that happens to be running on a thread the
//! first request once ran on. Mis-correlation is strictly worse than no
//! correlation.
//!
//! HOW. `RgwtraceBpf` below is a transcription of the map operations in
//! `bpf/rgwtrace.bpf.c` -- the same maps, the same keys, the same order of
//! operations, the same fail-closed branches. Every method cites the C function it
//! mirrors. A hand-written model can drift from the code it models, so
//! `model_matches_the_bpf_source` at the bottom pins the load-bearing lines of the
//! C to this model: if someone changes what the C does, that test fails and this
//! whole file must be re-derived.

use std::collections::HashMap;

const RGWTRACE_BPF: &str = include_str!("../bpf/rgwtrace.bpf.c");

/// `struct rgw_request_ctx` (bpf/rgwtrace.bpf.c). Only the members the
/// correlation logic reads; the wire fields are irrelevant here.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestCtx {
    /// Boot-clock read at `RGWREST::get_handler` entry. Half of the liveness
    /// gate's identity check.
    start_ns: u64,
    /// tgid.
    pid: u32,
    /// The thread `get_handler` ran on -- NOT the thread this copy sits on. The
    /// other half of the identity check, and (via the request marker) the thing
    /// the collector compares an op's `send_tid` against to decide
    /// same_thread vs cross_thread.
    tid: u32,
    /// The request's `req_state*`: the CANONICAL bridge key. The one the liveness
    /// gate re-derives, and the one the destructor revokes.
    req_state_ptr: u64,
    /// The `RGWOp*` executing this request: the ALTERNATE bridge key, learned at
    /// rgw_process_authenticated. 0 when unknown. Carried inside the VALUE purely
    /// so the destructor -- which only knows the req_state* -- can revoke it too.
    rgw_op_ptr: u64,
    trans_id: String,
}

/// What `uprobe_send_op` did with the context it found on the submitting thread.
#[derive(Debug, Eq, PartialEq)]
enum SendOp {
    /// A trans_id was stamped onto the op: it will be a child of that request.
    Stamped { trans_id: String, send_tid: u32 },
    /// Nothing was stamped: the op is emitted uncorrelated (the collector reports
    /// it as `rgw.background.rados_op`, reason `missing_trans_id`).
    Background { send_tid: u32 },
}

impl SendOp {
    fn trans_id(&self) -> Option<&str> {
        match self {
            Self::Stamped { trans_id, .. } => Some(trans_id),
            Self::Background { .. } => None,
        }
    }
}

/// `struct rgw_op_key_record` (bpf/rgwtrace.bpf.c): the ALTERNATE key plus the
/// identity of the request that owns it, keyed by that request's CANONICAL key.
///
/// It exists so the destructor can revoke the alternate key EVEN IF the request's
/// canonical bridge entry has been LRU-evicted -- which is why it lives in a plain
/// HASH (`rgw_op_keys`) that never evicts, rather than being read back out of the
/// LRU bridge value.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RgwOpKeyRecord {
    rgw_op_ptr: u64,
    start_ns: u64,
    owner_tid: u32,
}

/// The BPF side, transcribed from `bpf/rgwtrace.bpf.c`.
#[derive(Default)]
struct RgwtraceBpf {
    /// `rgw_requests`: plain HASH, tid -> ctx. Holds a COPY of the context per
    /// thread. NEVER LRU (per-CPU freelists evict live entries on many-core hosts).
    rgw_requests: HashMap<u32, RequestCtx>,
    /// `rgw_ctx_by_reqstate`: the MULTI-KEY bridge, (pointer, tgid) -> ctx. A
    /// request is inserted under its req_state* at get_handler and under its RGWOp*
    /// at rgw_process_authenticated; BOTH are deleted at the destructor. LRU_HASH:
    /// entries CAN be evicted, which `evict_bridge_entry` below models.
    rgw_ctx_by_reqstate: HashMap<(u64, u32), RequestCtx>,
    /// `rgw_op_keys`: plain HASH, canonical key -> the alternate key's revocation
    /// record. NEVER evicts, which is the whole point.
    rgw_op_keys: HashMap<(u64, u32), RgwOpKeyRecord>,
    /// `REQUEST_END_PROBE_ATTACHED`: without the END probe nothing can revoke a
    /// context, so the liveness gate is switched off -- and, in userspace, the
    /// per-submit re-seed is not attached at all (see `phase_b_attached`).
    end_probe_attached: bool,
    /// `RGW_OP_BRIDGE_KEY_ENABLED`: the operator's kill switch for the `RGWOp*`
    /// alternate key (`--disable-rgw-op-bridge-key`). Default ON.
    rgw_op_key_enabled: bool,
    /// Whether userspace attached the `rgw_rados_operate` probes. Mirrors
    /// `attach_probes`: they are attached ONLY when the END probe attached, because
    /// nothing would revoke bridge entries otherwise.
    phase_b_attached: bool,
    diag: HashMap<&'static str, u64>,
}

impl RgwtraceBpf {
    /// The supported production configuration: END probe attached, so bridge
    /// entries are revoked at request end and Phase B is enabled; alternate key ON.
    fn with_end_probe() -> Self {
        Self {
            end_probe_attached: true,
            rgw_op_key_enabled: true,
            phase_b_attached: true,
            ..Self::default()
        }
    }

    /// A build whose destructor probe could not attach. Phase B is DISABLED there
    /// (userspace refuses to attach it), and the liveness gate is off.
    fn without_end_probe() -> Self {
        Self {
            end_probe_attached: false,
            rgw_op_key_enabled: true,
            phase_b_attached: false,
            ..Self::default()
        }
    }

    /// The production config with the `RGWOp*` alternate key switched OFF
    /// (`--disable-rgw-op-bridge-key`): requests are keyed by req_state* alone.
    fn without_rgw_op_key() -> Self {
        Self {
            rgw_op_key_enabled: false,
            ..Self::with_end_probe()
        }
    }

    /// LRU eviction of ONE bridge entry. The bridge is an LRU_HASH, and eviction is
    /// per-entry: a request's canonical entry can be evicted while its alternate
    /// entry survives. That asymmetry is exactly what used to strand alternate keys.
    fn evict_bridge_entry(&mut self, key: (u64, u32)) {
        self.rgw_ctx_by_reqstate.remove(&key);
    }

    fn count(&mut self, key: &'static str) {
        *self.diag.entry(key).or_default() += 1;
    }

    fn diag(&self, key: &'static str) -> u64 {
        self.diag.get(key).copied().unwrap_or(0)
    }

    /// `uprobe_rgw_get_handler`: seeds this thread and populates the bridge under
    /// the request's CANONICAL key. The alternate key is not known yet.
    fn get_handler(
        &mut self,
        tid: u32,
        pid: u32,
        req_state_ptr: u64,
        trans_id: &str,
        start_ns: u64,
    ) {
        let ctx = RequestCtx {
            start_ns,
            pid,
            tid,
            req_state_ptr,
            rgw_op_ptr: 0,
            trans_id: trans_id.to_string(),
        };
        self.rgw_requests.insert(tid, ctx.clone());
        // BPF_ANY: overwrite-on-reuse is the aliasing cure for a recycled
        // req_state address.
        self.rgw_ctx_by_reqstate.insert((req_state_ptr, pid), ctx);
    }

    /// `uprobe_rgw_process_authenticated`: re-seeds the execute thread AND registers
    /// the request's ALTERNATE key (the `RGWOp*` read through the `RGWOp*& op`
    /// parameter). `rgw_op` is `None` on a build with no proven descriptor.
    fn process_authenticated(&mut self, rsp: u64, rgw_op: Option<u64>, tgid: u32, tid: u32) {
        let Some(bridged) = self.rgw_ctx_by_reqstate.get(&(rsp, tgid)).cloned() else {
            // Miss: fail closed. A FOREIGN context on this thread is cleared.
            if self
                .rgw_requests
                .get(&tid)
                .is_some_and(|cur| cur.req_state_ptr != rsp || cur.pid != tgid)
            {
                self.rgw_requests.remove(&tid);
            }
            self.count("reseed_misses");
            return;
        };

        let mut ctx_copy = bridged;
        let op_ptr = if self.rgw_op_key_enabled {
            rgw_op
        } else {
            None
        };
        match op_ptr {
            _ if !self.rgw_op_key_enabled => self.count("rgw_op_key_disabled"),
            // An alternate key is only created when the CANONICAL key is known:
            // an entry the destructor cannot find is an entry it cannot revoke,
            // and an unrevocable key is exactly the mis-correlation hazard.
            Some(op_ptr) if op_ptr != 0 && ctx_copy.req_state_ptr != 0 => {
                // THE REVOCATION RECORD IS WRITTEN FIRST. It is what the destructor
                // reads to learn the alternate key, and it lives in a map that never
                // evicts -- so a key is only ever created once its revocation is
                // guaranteed. (The C also declines to insert the key at all if the
                // record cannot be written; the model's map is unbounded, so that
                // fail-closed branch is asserted on the C source instead.)
                self.rgw_op_keys.insert(
                    (rsp, tgid),
                    RgwOpKeyRecord {
                        rgw_op_ptr: op_ptr,
                        start_ns: ctx_copy.start_ns,
                        owner_tid: ctx_copy.tid,
                    },
                );
                ctx_copy.rgw_op_ptr = op_ptr;
                // Write the alternate key back into the CANONICAL entry (this is
                // what lets a seed report WHICH key it hit)...
                self.rgw_ctx_by_reqstate
                    .insert((rsp, tgid), ctx_copy.clone());
                // ...and insert the same value under the alternate key. BPF_ANY:
                // a recycled RGWOp address is re-keyed to its new owner here,
                // which always happens before that request submits any op.
                self.rgw_ctx_by_reqstate
                    .insert((op_ptr, tgid), ctx_copy.clone());
                self.count("rgw_op_key_inserts");
            }
            _ => self.count("rgw_op_key_unresolved"),
        }

        self.rgw_requests.insert(tid, ctx_copy);
        self.count("reseed_hits");
    }

    /// `reseed_thread_from_reqstate`: the shared helper. Looks the request up in
    /// the bridge under ANY of its keys and, on a hit, seeds `rgw_requests[tid]`
    /// with a COPY of the bridge value. Returns WHICH key matched, or `None` on a
    /// miss.
    ///
    /// The copy is the crux of the Phase A/Phase B interaction: the seeded
    /// context's `start_ns`, `tid` and `pid` are the BRIDGE ENTRY's own, so the
    /// liveness gate -- which re-derives the CANONICAL key from the copy and
    /// compares exactly those fields -- matches by construction, whichever key the
    /// seed came in through.
    ///
    /// The key attribution compares the dpp against the bridged value's OWN keys, so
    /// it is exact: a value is only ever stored under a key it names.
    fn reseed_thread_from_reqstate(&mut self, dpp: u64, tgid: u32, tid: u32) -> Option<SeedVia> {
        let bridged = self.rgw_ctx_by_reqstate.get(&(dpp, tgid))?.clone();
        let via = if bridged.req_state_ptr == dpp {
            SeedVia::ReqState
        } else if bridged.rgw_op_ptr == dpp {
            SeedVia::RgwOp
        } else {
            SeedVia::Unattributed
        };
        self.rgw_requests.insert(tid, bridged);
        Some(via)
    }

    /// PHASE B -- `rgw_rados_operate_seed` (both overloads). The `dpp` is used as
    /// an OPAQUE IDENTITY TOKEN: looked up by value, never dereferenced.
    ///
    /// On a MISS it FAILS CLOSED and clears the thread's context. A miss proves the
    /// dpp is not a request we track; it does NOT prove that the context lingering
    /// on this pool thread belongs to the coroutine running here right now. Nothing
    /// available at this probe can prove that, so nothing is assumed.
    ///
    /// `dpp == 0` models an UNRESOLVED dpp (a null argument, or a descriptor that is
    /// not register-resident). It proves exactly as little as a foreign dpp, so it
    /// fails closed the same way -- counted separately, because the two mean
    /// completely different things.
    fn rgw_rados_operate(&mut self, dpp: u64, tgid: u32, tid: u32) {
        assert!(
            self.phase_b_attached,
            "the operate probes are not attached in this configuration"
        );
        if dpp == 0 {
            self.count("operate_base_unresolved");
            self.drop_thread_ctx(tid, "operate_unresolved_ctx_cleared");
            return;
        }
        if let Some(via) = self.reseed_thread_from_reqstate(dpp, tgid, tid) {
            self.count("operate_seed_hits");
            self.count(match via {
                SeedVia::ReqState => "operate_seed_hits_reqstate",
                SeedVia::RgwOp => "operate_seed_hits_rgwop",
                SeedVia::Unattributed => "operate_seed_hits_unattributed",
            });
            return;
        }
        self.count("operate_seed_misses");
        self.drop_thread_ctx(tid, "operate_miss_ctx_cleared");
    }

    /// `operate_drop_thread_ctx`: the fail-closed clear, counted under the reason it
    /// happened for.
    fn drop_thread_ctx(&mut self, tid: u32, diag: &'static str) {
        if self.rgw_requests.remove(&tid).is_some() {
            self.count(diag);
        }
    }

    /// `request_ctx_is_live`: the `_send_op` stamp gate.
    fn request_ctx_is_live(&mut self, ctx: &RequestCtx) -> bool {
        if !self.end_probe_attached {
            // Nothing can revoke a context on this build, so the bridge carries no
            // liveness information at all and the gate is off entirely.
            self.count("sendop_unverifiable_ctx");
            return true;
        }
        if ctx.req_state_ptr == 0 {
            // Never bridged => never findable, never revocable, never verifiable.
            // With a revoking END probe present, that FAILS CLOSED.
            self.count("sendop_unbridged_ctx_drops");
            return false;
        }
        // Key rebuilt FROM THE COPY, then identity-checked against the bridge --
        // presence alone is not enough, because req_state is stack-allocated in
        // process_request and its address is recycled by the next request.
        match self.rgw_ctx_by_reqstate.get(&(ctx.req_state_ptr, ctx.pid)) {
            Some(bridged) if bridged.start_ns == ctx.start_ns && bridged.tid == ctx.tid => true,
            _ => {
                self.count("sendop_stale_ctx_drops");
                false
            }
        }
    }

    /// `uprobe_send_op`: stamps the request identity onto the op, but only through
    /// the liveness gate.
    fn send_op(&mut self, tid: u32) -> SendOp {
        let Some(ctx) = self.rgw_requests.get(&tid).cloned() else {
            return SendOp::Background { send_tid: tid };
        };
        if !self.request_ctx_is_live(&ctx) {
            return SendOp::Background { send_tid: tid };
        }
        SendOp::Stamped {
            trans_id: ctx.trans_id,
            send_tid: tid,
        }
    }

    /// `uprobe_rgw_req_state_dtor`: the request END. Deletes EVERY bridge key of
    /// this request (the canonical one when it is still there; the alternate one
    /// only while it still describes this request), and clears this thread's context
    /// only when it is still this request's own.
    ///
    /// A MISSING CANONICAL ENTRY DOES NOT SHORT-CIRCUIT ANY OF THIS. The canonical
    /// entry lives in an LRU and can be evicted on its own; the alternate key it
    /// named would then be stranded forever if the destructor gave up here. So the
    /// revocation is driven by the never-evicting `rgw_op_keys` record instead.
    fn req_state_dtor(&mut self, rsp: u64, tgid: u32, tid: u32) {
        match self.rgw_ctx_by_reqstate.remove(&(rsp, tgid)) {
            Some(_) => self.count("request_end_hits"),
            None => self.count("request_end_misses"),
        }

        if let Some(record) = self.rgw_op_keys.remove(&(rsp, tgid)) {
            let okey = (record.rgw_op_ptr, tgid);
            match self.rgw_ctx_by_reqstate.get(&okey) {
                // Still ours: revoke it. A key that outlives its request is a
                // mis-correlation source (RGWOp addresses are recycled).
                Some(alt)
                    if alt.start_ns == record.start_ns
                        && alt.tid == record.owner_tid
                        && alt.pid == tgid =>
                {
                    self.rgw_ctx_by_reqstate.remove(&okey);
                    self.count("rgw_op_key_revokes");
                }
                // Already re-keyed by a NEWER request that reused the address:
                // deleting would revoke a LIVE request's key.
                Some(_) => self.count("rgw_op_key_revoke_skipped"),
                // Already gone (LRU-evicted): nothing to revoke, and nothing left
                // that could outlive the request.
                None => self.count("rgw_op_key_revoke_absent"),
            }
        }

        if self
            .rgw_requests
            .get(&tid)
            .is_some_and(|cur| cur.req_state_ptr == rsp && cur.pid == tgid)
        {
            self.rgw_requests.remove(&tid);
        }
    }

    /// Every alternate key currently in the bridge, i.e. the keys that are NOT a
    /// request's own canonical key. The revocation invariant is a statement about
    /// exactly this set.
    fn live_alternate_keys(&self) -> Vec<(u64, u32)> {
        self.rgw_ctx_by_reqstate
            .iter()
            .filter(|((ptr, _), ctx)| ctx.req_state_ptr != *ptr)
            .map(|(key, _)| *key)
            .collect()
    }
}

/// Which bridge key a per-submit seed matched on. The whole reason the split is
/// counted: it decides whether the `RGWOp*` alternate key -- and the S3-website
/// retarget hazard it carries -- is worth keeping at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SeedVia {
    ReqState,
    RgwOp,
    Unattributed,
}

const TGID: u32 = 4242;
/// The Beast thread `get_handler` runs on, i.e. the request marker's tid.
const HANDLER_TID: u32 = 100;
/// An `io_context_pool` thread the coroutine migrated onto at a later yield.
const MIGRATED_TID: u32 = 201;
/// Yet another one -- an asio coroutine migrates at EVERY yield, not once.
const MIGRATED_TID_2: u32 = 202;
/// A request's `req_state*`, which is also one of its two dpp identities
/// (req_state inherits DoutPrefixProvider at offset 0 -- VERIFIED in DWARF at
/// extraction time, not assumed).
const REQ_STATE: u64 = 0x7fff_0000_1000;
/// The `RGWOp*` executing that request: its OTHER dpp identity, and the one RGW
/// actually passes at most call sites inside `op->execute()`.
const RGW_OP: u64 = 0x5555_0000_2000;
/// A dpp RGW passes to `rgw_rados_operate` that is NEITHER: a stack
/// DoutPrefix/DoutPrefixPipe wrapper, or a background thread's. Its VALUE is all we
/// ever touch, so its concrete type does not matter -- which is the point.
const FOREIGN_DPP: u64 = 0x7fff_0000_9999;

/// Start a request the way RGW does: get_handler, then rgw_process_authenticated
/// (which registers the RGWOp* alternate key), both on the Beast thread.
fn start_request(bpf: &mut RgwtraceBpf, rsp: u64, op: u64, trans_id: &str, start_ns: u64) {
    bpf.get_handler(HANDLER_TID, TGID, rsp, trans_id, start_ns);
    bpf.process_authenticated(rsp, Some(op), TGID, HANDLER_TID);
}

// ---------------------------------------------------------------------------
// FINDING 1: the multi-key bridge. Without it, Phase B recovers NOTHING.
// ---------------------------------------------------------------------------

#[test]
fn a_request_is_findable_by_both_its_req_state_and_its_rgw_op() {
    // THE headline test. RGW threads a `const DoutPrefixProvider* dpp` down its
    // data path, and at most call sites inside an op's execute() that pointer is
    // the RGWOp (`this`), NOT the req_state. A bridge keyed only on the req_state*
    // would MISS on the entire op data path: every lookup a foreign-dpp miss, every
    // counter healthy, zero ops recovered, a no-op feature shipped.
    //
    // So BOTH identities must resolve the same request, on any thread.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx0001", 1_000);

    // The dpp is the RGWOp (the common case in an op's data path).
    bpf.rgw_rados_operate(RGW_OP, TGID, MIGRATED_TID);
    assert_eq!(
        bpf.send_op(MIGRATED_TID),
        SendOp::Stamped {
            trans_id: "tx0001".to_string(),
            send_tid: MIGRATED_TID,
        },
        "an op submitted under the RGWOp dpp must correlate to its request"
    );

    // The dpp is the req_state (the frames that pass `s` down).
    bpf.rgw_rados_operate(REQ_STATE, TGID, MIGRATED_TID_2);
    assert_eq!(
        bpf.send_op(MIGRATED_TID_2),
        SendOp::Stamped {
            trans_id: "tx0001".to_string(),
            send_tid: MIGRATED_TID_2,
        },
        "an op submitted under the req_state dpp must correlate to the same request"
    );

    assert_eq!(bpf.diag("operate_seed_hits"), 2);
    assert_eq!(bpf.diag("operate_seed_misses"), 0);
    assert_eq!(bpf.diag("rgw_op_key_inserts"), 1);
    assert_eq!(
        bpf.diag("sendop_stale_ctx_drops"),
        0,
        "a context seeded through EITHER key must satisfy the liveness gate, which \
         re-derives the CANONICAL key from the copy"
    );
}

#[test]
fn the_destructor_revokes_every_key_the_request_was_inserted_under() {
    // A key that outlives its request is a mis-correlation source: RGWOp is
    // heap-allocated and its address IS recycled. The destructor only knows the
    // req_state*, which is exactly why the alternate key is carried inside the
    // context VALUE -- so it can be found and deleted here.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx0001", 1_000);
    assert!(bpf.rgw_ctx_by_reqstate.contains_key(&(REQ_STATE, TGID)));
    assert!(bpf.rgw_ctx_by_reqstate.contains_key(&(RGW_OP, TGID)));

    bpf.req_state_dtor(REQ_STATE, TGID, HANDLER_TID);

    assert!(
        !bpf.rgw_ctx_by_reqstate.contains_key(&(REQ_STATE, TGID)),
        "the canonical key must be revoked at request end"
    );
    assert!(
        !bpf.rgw_ctx_by_reqstate.contains_key(&(RGW_OP, TGID)),
        "the ALTERNATE key must be revoked too -- a surviving key can seed a DEAD request"
    );
    assert!(
        bpf.rgw_ctx_by_reqstate.is_empty(),
        "no key of an ended request may survive: {:?}",
        bpf.rgw_ctx_by_reqstate.keys().collect::<Vec<_>>()
    );
    assert_eq!(bpf.diag("rgw_op_key_revokes"), 1);
    assert_eq!(bpf.diag("rgw_op_key_inserts"), 1);
}

#[test]
fn a_recycled_rgw_op_address_cannot_resurrect_a_dead_request() {
    // The alternate key's own recycling hazard, stated directly. RGWOp is heap
    // allocated: after request A ends, request B's RGWOp can land on A's freed
    // address. If A's key had survived (or if B's insert did not overwrite it), B's
    // ops would be stamped as A.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx-old", 1_000);
    bpf.req_state_dtor(REQ_STATE, TGID, HANDLER_TID);

    // A NEW request, whose RGWOp reuses the same heap address (and whose req_state
    // reuses the same stack address -- both are recycled in practice).
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx-new", 2_000);

    bpf.rgw_rados_operate(RGW_OP, TGID, MIGRATED_TID);
    assert_eq!(
        bpf.send_op(MIGRATED_TID).trans_id(),
        Some("tx-new"),
        "the recycled address must resolve to its CURRENT owner, never the dead one"
    );
}

#[test]
fn a_destructor_never_revokes_a_key_a_newer_request_now_owns() {
    // The other side of recycling: request B takes over A's RGWOp address (B's
    // rgw_process_authenticated re-keys it, which always precedes any op B submits).
    // A's destructor then runs. If it deleted the alternate key blindly, it would
    // revoke a LIVE request's key and silently cost B its whole data path.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx-a", 1_000);

    // B starts on another thread, and its RGWOp is allocated at the address A's
    // RGWOp already occupies (A's op object was, say, retargeted away and freed).
    let b_req_state = REQ_STATE + 0x1000;
    bpf.get_handler(HANDLER_TID + 1, TGID, b_req_state, "tx-b", 1_500);
    bpf.process_authenticated(b_req_state, Some(RGW_OP), TGID, HANDLER_TID + 1);

    // Now A ends.
    bpf.req_state_dtor(REQ_STATE, TGID, HANDLER_TID);

    assert_eq!(
        bpf.diag("rgw_op_key_revoke_skipped"),
        1,
        "A's destructor must NOT revoke the key B now owns"
    );
    assert_eq!(bpf.diag("rgw_op_key_revokes"), 0);

    // ...and B still correlates through it.
    bpf.rgw_rados_operate(RGW_OP, TGID, MIGRATED_TID);
    assert_eq!(bpf.send_op(MIGRATED_TID).trans_id(), Some("tx-b"));
}

#[test]
fn a_request_without_a_proven_rgw_op_descriptor_still_correlates_by_req_state() {
    // GRACEFUL DEGRADATION. On a build where the `RGWOp*&` descriptor could not be
    // PROVEN from DWARF, no alternate key is created. The request keeps working
    // through its req_state* -- fewer ops correlate, none are mis-correlated -- and
    // the gap is counted.
    let mut bpf = RgwtraceBpf::with_end_probe();
    bpf.get_handler(HANDLER_TID, TGID, REQ_STATE, "tx0001", 1_000);
    bpf.process_authenticated(REQ_STATE, None, TGID, HANDLER_TID);

    assert_eq!(bpf.diag("rgw_op_key_unresolved"), 1);
    assert_eq!(bpf.diag("rgw_op_key_inserts"), 0);

    bpf.rgw_rados_operate(REQ_STATE, TGID, MIGRATED_TID);
    assert_eq!(bpf.send_op(MIGRATED_TID).trans_id(), Some("tx0001"));

    // An op submitted under the RGWOp dpp simply misses -- uncorrelated, not wrong.
    bpf.rgw_rados_operate(RGW_OP, TGID, MIGRATED_TID_2);
    assert_eq!(bpf.send_op(MIGRATED_TID_2).trans_id(), None);
}

// ---------------------------------------------------------------------------
// FINDING 2: a foreign-dpp MISS must never let another LIVE request's context
// stamp this submit.
// ---------------------------------------------------------------------------

#[test]
fn a_foreign_dpp_miss_cannot_stamp_another_live_requests_trans_id() {
    // THE mis-correlation scenario, executed. Both requests are ALIVE throughout, so
    // the liveness gate -- which proves only that a cached request still EXISTS --
    // cannot tell them apart. Only the fail-closed clear can.
    //
    //   1. Request A runs an operate on pool thread T  -> A's context is seeded on T.
    //   2. A yields (its coroutine parks awaiting the RADOS completion).
    //   3. Request B resumes on T and submits through a dpp we cannot key.
    //   4. B's op must NOT be stamped as A.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx-A", 1_000);

    let b_req_state = REQ_STATE + 0x1000;
    let b_rgw_op = RGW_OP + 0x1000;
    bpf.get_handler(HANDLER_TID + 1, TGID, b_req_state, "tx-B", 1_100);
    bpf.process_authenticated(b_req_state, Some(b_rgw_op), TGID, HANDLER_TID + 1);

    // 1. A runs an operate on the shared pool thread T.
    let shared_pool_tid = MIGRATED_TID;
    bpf.rgw_rados_operate(RGW_OP, TGID, shared_pool_tid);
    assert_eq!(
        bpf.send_op(shared_pool_tid).trans_id(),
        Some("tx-A"),
        "pre-condition: A's own op on T is correlated"
    );

    // 2./3. A yields; B resumes on T and submits through a wrapper dpp.
    bpf.rgw_rados_operate(FOREIGN_DPP, TGID, shared_pool_tid);

    // 4. THE ASSERTION. B's op is uncorrelated -- NOT stamped as A.
    let op = bpf.send_op(shared_pool_tid);
    assert_ne!(
        op.trans_id(),
        Some("tx-A"),
        "MIS-CORRELATION: request B's op was stamped with request A's trans_id"
    );
    assert_eq!(
        op,
        SendOp::Background {
            send_tid: shared_pool_tid
        },
        "an op we cannot attribute must be uncorrelated, not attributed to a guess"
    );

    // A is still alive -- so the liveness gate would have HAPPILY passed A's context.
    // The clear is what saved us, and it is counted.
    assert!(bpf.rgw_ctx_by_reqstate.contains_key(&(REQ_STATE, TGID)));
    assert_eq!(bpf.diag("sendop_stale_ctx_drops"), 0);
    assert_eq!(bpf.diag("operate_miss_ctx_cleared"), 1);

    // And A itself is not damaged: its next operate re-seeds it wherever it lands.
    bpf.rgw_rados_operate(RGW_OP, TGID, shared_pool_tid);
    assert_eq!(bpf.send_op(shared_pool_tid).trans_id(), Some("tx-A"));
}

#[test]
fn a_foreign_dpp_miss_costs_coverage_and_the_cost_is_counted() {
    // The price of failing closed, stated honestly: a request's OWN operate through
    // a dpp we cannot key (a stack DoutPrefix wrapper) loses its correlation, even
    // though a hit one operate earlier had established the context correctly. That
    // is a KNOWN UNKNOWN -- an uncorrelated op -- and it is counted. The alternative
    // (keeping the context) is a LIE, as the test above shows.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx0001", 1_000);

    bpf.rgw_rados_operate(RGW_OP, TGID, MIGRATED_TID);
    assert_eq!(bpf.send_op(MIGRATED_TID).trans_id(), Some("tx0001"));

    // The same request, same thread, an operate through a wrapper dpp.
    bpf.rgw_rados_operate(FOREIGN_DPP, TGID, MIGRATED_TID);
    assert_eq!(
        bpf.send_op(MIGRATED_TID).trans_id(),
        None,
        "this op is genuinely A's, and we give it up rather than risk stamping someone else's"
    );
    assert_eq!(bpf.diag("operate_miss_ctx_cleared"), 1);

    // The multi-key bridge is what keeps this cost small: the very next operate,
    // through either of A's identities, hits again.
    bpf.rgw_rados_operate(REQ_STATE, TGID, MIGRATED_TID);
    assert_eq!(bpf.send_op(MIGRATED_TID).trans_id(), Some("tx0001"));
}

// ---------------------------------------------------------------------------
// The core Phase B behaviors.
// ---------------------------------------------------------------------------

#[test]
fn a_phase_b_seeded_context_passes_the_send_op_liveness_gate() {
    // If this fails, Phase B silently does nothing: every op it seeds for would be
    // dropped by the gate and reported as a background op, while `operate_seed_hits`
    // happily counted the seed.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx0001", 1_000);

    // The coroutine yields and resumes on a DIFFERENT pool thread. Without Phase B,
    // an op submitted here finds nothing: this is precisely the lost ops from the
    // live capture.
    assert_eq!(
        bpf.send_op(MIGRATED_TID),
        SendOp::Background {
            send_tid: MIGRATED_TID
        },
        "pre-condition: a migrated thread carries no context of its own"
    );

    bpf.rgw_rados_operate(RGW_OP, TGID, MIGRATED_TID);

    assert_eq!(
        bpf.send_op(MIGRATED_TID),
        SendOp::Stamped {
            trans_id: "tx0001".to_string(),
            send_tid: MIGRATED_TID,
        }
    );
    assert_eq!(bpf.diag("operate_seed_hits"), 1);
    assert_eq!(
        bpf.diag("sendop_stale_ctx_drops"),
        0,
        "a Phase-B-seeded context must never be dropped as stale"
    );
    assert_eq!(
        bpf.diag("sendop_unverifiable_ctx"),
        0,
        "with the END probe attached the context is VERIFIED live, not merely assumed"
    );
}

#[test]
fn phase_b_ops_are_labelled_cross_thread_not_same_thread() {
    // The collector derives same_thread vs cross_thread by comparing an op's
    // send_tid against the request MARKER's tid. Phase B seeds a COPY of the bridge
    // entry, whose `tid` stays the get_handler thread -- it is NOT rewritten to the
    // thread being seeded. So the marker keeps saying "this request started on
    // thread 100" while the op says "I was submitted on thread 201", and the op is
    // correctly labelled cross_thread.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx0001", 1_000);
    bpf.rgw_rados_operate(RGW_OP, TGID, MIGRATED_TID);

    let SendOp::Stamped { send_tid, .. } = bpf.send_op(MIGRATED_TID) else {
        panic!("expected a stamped op");
    };

    let marker_tid = bpf.rgw_ctx_by_reqstate[&(REQ_STATE, TGID)].tid;
    assert_eq!(
        marker_tid, HANDLER_TID,
        "the marker keeps the get_handler tid"
    );
    assert_ne!(
        send_tid, marker_tid,
        "a Phase-B op submitted after a migration must look cross_thread to the collector"
    );

    // And a submit that happens to occur ON the get_handler thread still looks
    // same_thread -- Phase B does not fabricate migrations.
    bpf.rgw_rados_operate(RGW_OP, TGID, HANDLER_TID);
    let SendOp::Stamped { send_tid, .. } = bpf.send_op(HANDLER_TID) else {
        panic!("expected a stamped op");
    };
    assert_eq!(send_tid, marker_tid);
}

#[test]
fn phase_b_recovers_a_multi_yield_data_path_across_several_threads() {
    // The DELETE from the live capture: its ENTIRE data path was lost, because the
    // coroutine had migrated away from every seeded thread by the time each op was
    // submitted, and it migrates AGAIN between ops. N seed sites cannot cover this;
    // a seed at every submit can.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx-delete", 1_000);

    let mut stamped = Vec::new();
    for (op, tid) in [
        ("rgw.bucket_prepare_op", MIGRATED_TID),
        ("rgw.obj_remove", MIGRATED_TID_2),
        // Back onto the handler thread: pool threads are reused, and the third op
        // must correlate just as well.
        ("rgw.bucket_complete_op", HANDLER_TID),
    ] {
        // The dpp RGW passes on an op's data path is the RGWOp.
        bpf.rgw_rados_operate(RGW_OP, TGID, tid);
        stamped.push((op, bpf.send_op(tid).trans_id().map(str::to_string)));
    }

    for (op, trans_id) in &stamped {
        assert_eq!(
            trans_id.as_deref(),
            Some("tx-delete"),
            "{op} must be correlated to its request"
        );
    }
    assert_eq!(bpf.diag("operate_seed_hits"), 3);
    assert_eq!(bpf.diag("sendop_stale_ctx_drops"), 0);
}

// ---------------------------------------------------------------------------
// Fail-closed: a foreign dpp correlates nothing and breaks nothing.
// ---------------------------------------------------------------------------

#[test]
fn a_foreign_dpp_misses_the_bridge_and_correlates_nothing() {
    // RGW passes many non-request DoutPrefixProviders to rgw_rados_operate (stack
    // wrappers, and the GC/LC/quota background threads). They must correlate
    // NOTHING -- and they do, structurally: the pointer value is not a key in the
    // bridge, so the lookup misses. Nothing is dereferenced, so a wrong-typed dpp
    // cannot even produce a wrong answer.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx0001", 1_000);

    let background_tid = 900;
    bpf.rgw_rados_operate(FOREIGN_DPP, TGID, background_tid);

    assert_eq!(
        bpf.send_op(background_tid),
        SendOp::Background {
            send_tid: background_tid
        },
        "a foreign dpp must not correlate its op to any request"
    );
    assert_eq!(bpf.diag("operate_seed_hits"), 0);
    assert_eq!(bpf.diag("operate_seed_misses"), 1);
}

#[test]
fn a_foreign_dpp_cannot_borrow_another_requests_identity() {
    // The mis-correlation hazard, stated directly: a foreign dpp must never resolve
    // to SOME request just because a request exists. The bridge is keyed by the
    // pointer value, so only the request one of whose identities IS that pointer can
    // be found -- there is no nearest-match, no fallback, no "the only live request".
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx0001", 1_000);

    let fresh_tid = 777;
    bpf.rgw_rados_operate(FOREIGN_DPP, TGID, fresh_tid);

    assert!(!bpf.rgw_requests.contains_key(&fresh_tid));
    assert_eq!(bpf.send_op(fresh_tid).trans_id(), None);
}

#[test]
fn a_cross_process_dpp_collision_cannot_correlate() {
    // The bridge is PID-scoped: `--pid` is optional, so two radosgw processes can
    // hold the same req_state (or RGWOp) address. The (ptr, tgid) key keeps them
    // apart.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx0001", 1_000);

    let other_tgid = TGID + 1;
    bpf.rgw_rados_operate(REQ_STATE, other_tgid, MIGRATED_TID);
    bpf.rgw_rados_operate(RGW_OP, other_tgid, MIGRATED_TID_2);

    assert_eq!(bpf.diag("operate_seed_misses"), 2);
    assert_eq!(bpf.send_op(MIGRATED_TID).trans_id(), None);
    assert_eq!(bpf.send_op(MIGRATED_TID_2).trans_id(), None);
}

// ---------------------------------------------------------------------------
// Phase A's invariants must survive Phase B's much larger population of copies.
// ---------------------------------------------------------------------------

#[test]
fn a_context_phase_b_left_on_a_pool_thread_is_revoked_when_its_request_ends() {
    // Phase B scatters context copies across MANY more threads than Phase A did,
    // and the destructor can only revoke the copy on the ONE thread it runs on.
    // Every other copy outlives its request -- which is exactly why the _send_op
    // liveness gate exists. A later op on such a thread must NOT inherit the dead
    // request's trans_id.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx0001", 1_000);
    bpf.rgw_rados_operate(RGW_OP, TGID, MIGRATED_TID);
    assert_eq!(bpf.send_op(MIGRATED_TID).trans_id(), Some("tx0001"));

    bpf.req_state_dtor(REQ_STATE, TGID, HANDLER_TID);
    assert!(
        bpf.rgw_requests.contains_key(&MIGRATED_TID),
        "the leftover copy is still there -- which is why the gate, not the dtor, is the defence"
    );

    assert_eq!(
        bpf.send_op(MIGRATED_TID),
        SendOp::Background {
            send_tid: MIGRATED_TID
        },
        "an ENDED request's leftover context must never stamp a later op"
    );
    assert_eq!(bpf.diag("sendop_stale_ctx_drops"), 1);
}

#[test]
fn a_recycled_req_state_address_does_not_validate_a_dead_context() {
    // req_state is stack-allocated in process_request, so the NEXT request on the
    // same Beast thread routinely reuses the SAME address -- and therefore the same
    // bridge key. A pure presence check would see the new request's entry and stamp
    // the OLD request's trans_id. The identity check (start_ns + tid) stops that.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx-old", 1_000);
    bpf.rgw_rados_operate(RGW_OP, TGID, MIGRATED_TID); // leaves a copy of tx-old
    bpf.req_state_dtor(REQ_STATE, TGID, HANDLER_TID);

    // A NEW request lands on the same stack address, recreating the same key (its
    // RGWOp is elsewhere on the heap this time).
    let new_rgw_op = RGW_OP + 0x4000;
    start_request(&mut bpf, REQ_STATE, new_rgw_op, "tx-new", 2_000);

    // The stale copy of tx-old on the pool thread now finds a bridge entry under
    // its key -- but a DIFFERENT one. It must be rejected, not stamped as tx-old
    // (a lie) and not stamped as tx-new (a different lie).
    assert_eq!(
        bpf.send_op(MIGRATED_TID),
        SendOp::Background {
            send_tid: MIGRATED_TID
        }
    );
    assert_eq!(bpf.diag("sendop_stale_ctx_drops"), 1);

    // The new request, seeded by Phase B on that same pool thread, correlates fine.
    bpf.rgw_rados_operate(new_rgw_op, TGID, MIGRATED_TID);
    assert_eq!(bpf.send_op(MIGRATED_TID).trans_id(), Some("tx-new"));
}

// ---------------------------------------------------------------------------
// FINDING 3 / FINDING 4: degradation paths.
// ---------------------------------------------------------------------------

#[test]
fn without_the_end_probe_phase_b_is_not_attached_at_all() {
    // FINDING 3. Without the END probe NOTHING deletes bridge entries, so an entry
    // outlives its request forever -- and the per-submit re-seed looks EVERY rados
    // operate's dpp up in that bridge. A recycled req_state stack address, a
    // recycled RGWOp heap address, or a numerically-matching foreign dpp would then
    // HIT a long-dead request's entry, and the liveness gate (switched off, because
    // it has no revoker to consult) would fail OPEN and stamp it.
    //
    // So userspace does not attach the operate probes at all, and behavior degrades
    // to Phase A: seeds only at get_handler / rgw_process_authenticated.
    let mut bpf = RgwtraceBpf::without_end_probe();
    assert!(
        !bpf.phase_b_attached,
        "Phase B must not be attached without the END probe"
    );

    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx0001", 1_000);

    // A submit on the seed thread still correlates (unverified -- and counted as
    // such), exactly as it did before any of this existed.
    assert_eq!(bpf.send_op(HANDLER_TID).trans_id(), Some("tx0001"));
    assert_eq!(bpf.diag("sendop_unverifiable_ctx"), 1);

    // A submit on a migrated thread finds nothing: uncorrelated, never wrong.
    assert_eq!(
        bpf.send_op(MIGRATED_TID),
        SendOp::Background {
            send_tid: MIGRATED_TID
        }
    );
    assert_eq!(bpf.diag("operate_seed_hits"), 0);
}

#[test]
fn a_context_with_no_req_state_pointer_fails_closed_when_the_end_probe_is_attached() {
    // FINDING 4. A context with no req_state* was never bridged (get_handler could
    // not resolve the pointer from a register on this build). It can never be found
    // through the bridge -- so the destructor's lookup MISSES and returns before
    // clearing it off the thread -- and it therefore lingers on that pooled thread
    // for the rest of the run. Treating it as proof of life let a long-dead request
    // stamp later ops submitted from that thread.
    //
    // With a revoking END probe attached, it now FAILS CLOSED.
    let mut bpf = RgwtraceBpf::with_end_probe();
    // req_state_ptr = 0: the descriptor was stack-located, so nothing was bridged.
    bpf.get_handler(HANDLER_TID, TGID, 0, "tx-unbridged", 1_000);

    assert_eq!(
        bpf.send_op(HANDLER_TID),
        SendOp::Background {
            send_tid: HANDLER_TID
        },
        "an unverifiable, unrevocable context must not stamp an op"
    );
    assert_eq!(bpf.diag("sendop_unbridged_ctx_drops"), 1);
    assert_eq!(
        bpf.diag("sendop_unverifiable_ctx"),
        0,
        "this must NOT take the fail-open path -- that path exists only for builds with no END probe"
    );

    // The destructor cannot revoke it either (its bridge lookup misses), which is
    // exactly why the gate has to be the one to refuse it.
    bpf.req_state_dtor(REQ_STATE, TGID, HANDLER_TID);
    assert_eq!(bpf.diag("request_end_misses"), 1);
    assert!(bpf.rgw_requests.contains_key(&HANDLER_TID));
    assert_eq!(bpf.send_op(HANDLER_TID).trans_id(), None);
}

#[test]
fn without_the_end_probe_an_unbridged_context_still_stamps_as_it_always_did() {
    // The counterpart to the test above: with NO end probe, nothing revokes
    // anything, the gate is off entirely, and behavior is the pre-liveness-gate one
    // (stamp what get_handler put on this thread) -- counted as UNVERIFIABLE so it
    // is never silently presented as proven. Fail-closed here would mean a build
    // with no end probe correlates nothing at all, which is a regression, not a
    // safety improvement: without a re-seed there is no way for a foreign request's
    // context to reach this thread in the first place.
    let mut bpf = RgwtraceBpf::without_end_probe();
    bpf.get_handler(HANDLER_TID, TGID, 0, "tx-unbridged", 1_000);

    assert_eq!(bpf.send_op(HANDLER_TID).trans_id(), Some("tx-unbridged"));
    assert_eq!(bpf.diag("sendop_unverifiable_ctx"), 1);
    assert_eq!(bpf.diag("sendop_unbridged_ctx_drops"), 0);
}

// ---------------------------------------------------------------------------
// FINDING (fail-closed hole): an UNRESOLVED / NULL dpp must fail closed too.
// ---------------------------------------------------------------------------

#[test]
fn an_unresolved_dpp_cannot_stamp_another_live_requests_trans_id() {
    // The same mis-correlation as the foreign-dpp case, through the other door.
    // The zero/unresolved-dpp path used to `return 0` WITHOUT clearing the thread's
    // context, while the foreign-dpp path cleared it -- so everything the
    // fail-closed rule bought was available to be lost through a null dpp.
    //
    //   1. Request A runs an operate on pool thread T -> A's context is seeded on T.
    //   2. A yields.
    //   3. Request B resumes on T and submits with an unresolvable/null dpp.
    //   4. A is STILL ALIVE, so the liveness gate would happily pass A's context.
    //      B's op must NOT be stamped as A.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx-A", 1_000);

    let shared_pool_tid = MIGRATED_TID;
    bpf.rgw_rados_operate(RGW_OP, TGID, shared_pool_tid);
    assert_eq!(
        bpf.send_op(shared_pool_tid).trans_id(),
        Some("tx-A"),
        "pre-condition: A's own op on T is correlated"
    );

    // The null/unresolved dpp.
    bpf.rgw_rados_operate(0, TGID, shared_pool_tid);

    let op = bpf.send_op(shared_pool_tid);
    assert_ne!(
        op.trans_id(),
        Some("tx-A"),
        "MIS-CORRELATION: an unresolved dpp let request A's context stamp another op"
    );
    assert_eq!(
        op,
        SendOp::Background {
            send_tid: shared_pool_tid
        }
    );

    // A is still alive -- the liveness gate was never going to save us here.
    assert!(bpf.rgw_ctx_by_reqstate.contains_key(&(REQ_STATE, TGID)));
    assert_eq!(bpf.diag("sendop_stale_ctx_drops"), 0);

    // Counted, and counted DISTINCTLY from the foreign-dpp miss: "RGW passed a null
    // dpp" and "RGW passed a wrapper dpp" are different diagnoses.
    assert_eq!(bpf.diag("operate_unresolved_ctx_cleared"), 1);
    assert_eq!(bpf.diag("operate_miss_ctx_cleared"), 0);
    assert_eq!(bpf.diag("operate_base_unresolved"), 1);

    // And A itself is not damaged: its next operate re-seeds it.
    bpf.rgw_rados_operate(REQ_STATE, TGID, shared_pool_tid);
    assert_eq!(bpf.send_op(shared_pool_tid).trans_id(), Some("tx-A"));
}

// ---------------------------------------------------------------------------
// FINDING (false invariant): revocation must be TOTAL, including when the LRU
// evicts a request's canonical entry out from under it.
// ---------------------------------------------------------------------------

#[test]
fn an_lru_eviction_of_the_canonical_entry_still_revokes_the_alternate_key() {
    // THE STRANDED-KEY CASE. The bridge is an LRU_HASH and eviction is PER ENTRY: a
    // request's canonical entry can be evicted while its alternate entry survives.
    // The destructor used to recover the alternate key from the canonical VALUE, so
    // a canonical miss made it return early -- and the alternate key it never
    // learned about stayed in the map forever.
    //
    // The key is now recovered from `rgw_op_keys` (a plain HASH; it never evicts),
    // which the destructor consults whether or not the canonical entry is still
    // there. So the request leaves NOTHING behind.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx0001", 1_000);
    assert_eq!(bpf.diag("rgw_op_key_inserts"), 1);

    // The LRU evicts the CANONICAL entry only. The alternate one survives.
    bpf.evict_bridge_entry((REQ_STATE, TGID));
    assert!(bpf.rgw_ctx_by_reqstate.contains_key(&(RGW_OP, TGID)));

    bpf.req_state_dtor(REQ_STATE, TGID, HANDLER_TID);

    // The canonical lookup missed (there was no END to emit)...
    assert_eq!(bpf.diag("request_end_misses"), 1);
    assert_eq!(bpf.diag("request_end_hits"), 0);
    // ...and the alternate key was STILL revoked. This is the assertion the old
    // code failed.
    assert_eq!(bpf.diag("rgw_op_key_revokes"), 1);
    assert!(
        bpf.live_alternate_keys().is_empty(),
        "the request's alternate key outlived it: {:?}",
        bpf.live_alternate_keys()
    );
    assert!(bpf.rgw_op_keys.is_empty(), "the revocation record leaked");
}

#[test]
fn an_evicted_alternate_entry_is_accounted_for_rather_than_silently_ignored() {
    // The other half of the eviction story: the ALTERNATE entry is the one evicted.
    // There is then nothing to delete -- but the destructor must still say so, or
    // `inserts - revokes` would show a phantom leak forever.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx0001", 1_000);

    bpf.evict_bridge_entry((RGW_OP, TGID));
    bpf.req_state_dtor(REQ_STATE, TGID, HANDLER_TID);

    assert_eq!(bpf.diag("rgw_op_key_revokes"), 0);
    assert_eq!(bpf.diag("rgw_op_key_revoke_absent"), 1);
    assert!(bpf.live_alternate_keys().is_empty());
    assert!(bpf.rgw_op_keys.is_empty());
}

#[test]
fn the_revocation_identity_holds_across_a_churning_run() {
    // THE INVARIANT, EXECUTED, in the form the health metric claims it:
    //
    //   inserts == revokes + revoke_skipped + revoke_absent + in-flight
    //
    // Churn everything that used to break it: LRU evictions of canonical entries,
    // LRU evictions of alternate entries, and a recycled RGWOp address re-keyed by a
    // newer request while the older one is still to be destructed.
    let mut bpf = RgwtraceBpf::with_end_probe();

    // 20 requests, each with its own req_state and RGWOp.
    for i in 0..20u64 {
        let rsp = REQ_STATE + i * 0x100;
        let op = RGW_OP + i * 0x100;
        start_request(&mut bpf, rsp, op, &format!("tx{i:04}"), 1_000 + i);
        // Evict some canonical entries, and some alternate ones.
        if i % 5 == 0 {
            bpf.evict_bridge_entry((rsp, TGID));
        }
        if i % 7 == 0 {
            bpf.evict_bridge_entry((op, TGID));
        }
    }

    // A recycled RGWOp address: request 21 reuses request 3's RGWOp pointer while
    // request 3 has not been destructed yet.
    let recycled_op = RGW_OP + 3 * 0x100;
    let late_rsp = REQ_STATE + 0x9000;
    start_request(&mut bpf, late_rsp, recycled_op, "tx-late", 9_000);

    // Destruct the first 20; leave the late one IN FLIGHT.
    for i in 0..20u64 {
        bpf.req_state_dtor(REQ_STATE + i * 0x100, TGID, HANDLER_TID);
    }

    let inserts = bpf.diag("rgw_op_key_inserts");
    let revokes = bpf.diag("rgw_op_key_revokes");
    let skipped = bpf.diag("rgw_op_key_revoke_skipped");
    let absent = bpf.diag("rgw_op_key_revoke_absent");
    let in_flight = 1; // the late request

    assert_eq!(inserts, 21);
    assert_eq!(
        inserts,
        revokes + skipped + absent + in_flight,
        "the documented revocation identity is false: inserts={inserts} revokes={revokes} \
         skipped={skipped} absent={absent} in_flight={in_flight}"
    );
    // Request 3's dtor found its alternate key already owned by the LATE request and
    // correctly refused to revoke a LIVE request's key.
    assert_eq!(skipped, 1);

    // The ONLY alternate key left in the bridge belongs to the request still in
    // flight. Nothing was stranded.
    assert_eq!(bpf.live_alternate_keys(), vec![(recycled_op, TGID)]);
    assert_eq!(bpf.rgw_op_keys.len(), 1);
}

// ---------------------------------------------------------------------------
// THE MEASUREMENT (F6): which key do the seeds actually hit, and can the RGWOp
// key be dropped without breaking anything?
// ---------------------------------------------------------------------------

#[test]
fn seed_hits_are_split_by_which_key_matched() {
    // This split is the number the RGWOp key's fate is decided on. If RGW passes the
    // req_state as the dpp, `seed_hits_rgwop` stays 0 and the alternate key -- along
    // with the S3-website-retarget mis-correlation hazard it carries -- can simply be
    // switched off. If it does not, the key is load-bearing. Either way it is a
    // measurement, not an argument, so it must actually be measurable.
    let mut bpf = RgwtraceBpf::with_end_probe();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx0001", 1_000);

    bpf.rgw_rados_operate(REQ_STATE, TGID, MIGRATED_TID);
    bpf.rgw_rados_operate(RGW_OP, TGID, MIGRATED_TID);
    bpf.rgw_rados_operate(RGW_OP, TGID, MIGRATED_TID_2);
    bpf.rgw_rados_operate(FOREIGN_DPP, TGID, MIGRATED_TID_2);

    assert_eq!(bpf.diag("operate_seed_hits"), 3);
    assert_eq!(bpf.diag("operate_seed_hits_reqstate"), 1);
    assert_eq!(bpf.diag("operate_seed_hits_rgwop"), 2);
    assert_eq!(bpf.diag("operate_seed_misses"), 1);
    // The split must be exhaustive: every hit is attributed to exactly one key.
    assert_eq!(bpf.diag("operate_seed_hits_unattributed"), 0);
    assert_eq!(
        bpf.diag("operate_seed_hits"),
        bpf.diag("operate_seed_hits_reqstate")
            + bpf.diag("operate_seed_hits_rgwop")
            + bpf.diag("operate_seed_hits_unattributed")
    );
}

#[test]
fn disabling_the_rgw_op_key_leaves_req_state_correlation_fully_working() {
    // The kill switch, exercised end to end. With the alternate key off:
    //   * no alternate key is ever created (so the retarget hazard cannot exist),
    //   * req_state-keyed correlation still works exactly as before,
    //   * ops whose dpp is the RGWOp miss -- uncorrelated, never wrong,
    //   * and the fact the key was OFF is counted, so an empty rgwop column can be
    //     told apart from a key that was on and never fired.
    let mut bpf = RgwtraceBpf::without_rgw_op_key();
    start_request(&mut bpf, REQ_STATE, RGW_OP, "tx0001", 1_000);

    assert_eq!(bpf.diag("rgw_op_key_disabled"), 1);
    assert_eq!(bpf.diag("rgw_op_key_inserts"), 0);
    assert!(bpf.live_alternate_keys().is_empty());
    assert!(bpf.rgw_op_keys.is_empty());

    // req_state-keyed cross-thread correlation is untouched.
    bpf.rgw_rados_operate(REQ_STATE, TGID, MIGRATED_TID);
    assert_eq!(bpf.send_op(MIGRATED_TID).trans_id(), Some("tx0001"));
    assert_eq!(bpf.diag("operate_seed_hits_reqstate"), 1);

    // An RGWOp dpp now misses: coverage lost, correctness kept.
    bpf.rgw_rados_operate(RGW_OP, TGID, MIGRATED_TID_2);
    assert_eq!(bpf.send_op(MIGRATED_TID_2).trans_id(), None);
    assert_eq!(bpf.diag("operate_seed_hits_rgwop"), 0);

    // The request still ends cleanly, and leaves nothing behind.
    bpf.req_state_dtor(REQ_STATE, TGID, HANDLER_TID);
    assert_eq!(bpf.diag("request_end_hits"), 1);
    assert!(bpf.rgw_ctx_by_reqstate.is_empty());
}

// ---------------------------------------------------------------------------
// Keep the model honest.
// ---------------------------------------------------------------------------

#[test]
fn model_matches_the_bpf_source() {
    // The tests above are only worth anything if this model still describes the C.
    // These assertions pin the load-bearing behaviors; changing any of them in
    // bpf/rgwtrace.bpf.c breaks this test and forces the model to be re-derived.

    // 1. A seed COPIES the whole bridge value into rgw_requests. This is what makes
    //    the seeded context's start_ns/tid/pid the bridge entry's own, and hence
    //    what makes the liveness gate match by construction -- through EITHER key.
    assert!(RGWTRACE_BPF.contains("__builtin_memcpy(&ctx_copy, bridged, sizeof(ctx_copy));"));
    assert!(RGWTRACE_BPF.contains("bpf_map_update_elem(&rgw_requests, &tid, &ctx_copy, BPF_ANY)"));

    // 2. The gate rebuilds the CANONICAL bridge key from the copy and compares
    //    exactly start_ns and tid -- all of which the memcpy above carried over.
    assert!(RGWTRACE_BPF.contains("make_reqstate_key(ctx->req_state_ptr, ctx->pid)"));
    assert!(RGWTRACE_BPF.contains(concat!(
        "  if (bridged == 0 || bridged->start_ns != ctx->start_ns ||\n",
        "      bridged->tid != ctx->tid) {"
    )));
    // ...and an unbridged context fails closed when the END probe is attached.
    assert!(RGWTRACE_BPF.contains(concat!(
        "  if (ctx->req_state_ptr == 0) {\n",
        "    count_diag(RGWTRACE_DIAG_SENDOP_UNBRIDGED_CTX_DROPS);\n",
        "    return 0;\n",
        "  }"
    )));

    // 3. Phase B seeds through the shared helper (no second bridge), for both
    //    overloads, and FAILS CLOSED on a miss -- AND on an unresolved/null dpp,
    //    which proves exactly as little -- by clearing the thread's context.
    assert!(RGWTRACE_BPF.contains("int via = reseed_thread_from_reqstate(dpp, tgid, tid);"));
    assert!(RGWTRACE_BPF.contains("if (via != BRIDGE_SEED_MISS) {"));
    assert!(RGWTRACE_BPF.contains("return rgw_rados_operate_seed(ctx, 60);"));
    assert!(RGWTRACE_BPF.contains("return rgw_rados_operate_seed(ctx, 70);"));
    assert!(RGWTRACE_BPF.contains(concat!(
        "static __always_inline void operate_drop_thread_ctx(__u32 tid, __u32 diag) {\n",
        "  if (bpf_map_lookup_elem(&rgw_requests, &tid) != 0) {\n",
        "    bpf_map_delete_elem(&rgw_requests, &tid);\n",
        "    count_diag(diag);\n",
        "  }\n",
        "}"
    )));
    assert!(RGWTRACE_BPF
        .contains("operate_drop_thread_ctx(tid, RGWTRACE_DIAG_OPERATE_MISS_CTX_CLEARED);"));
    assert!(RGWTRACE_BPF
        .contains("operate_drop_thread_ctx(tid, RGWTRACE_DIAG_OPERATE_UNRESOLVED_CTX_CLEARED);"));

    // 3b. A hit is attributed to the key it came in through by comparing the dpp
    //     against the bridged value's OWN keys -- exact, not inferred.
    assert!(RGWTRACE_BPF.contains(concat!(
        "  if (bridged->req_state_ptr == dpp)\n",
        "    via = BRIDGE_SEED_VIA_REQSTATE;\n",
        "  else if (bridged->rgw_op_ptr == dpp)\n",
        "    via = BRIDGE_SEED_VIA_RGWOP;"
    )));

    // 4. The MULTI-KEY bridge: the RGWOp* is read through the `RGWOp*&` parameter
    //    (slot 41), stored in the value, and inserted as a second key -- only when
    //    the canonical key exists, only when the key is ENABLED, and only after its
    //    revocation record has been written, so every key is revocable.
    assert!(RGWTRACE_BPF.contains("int varid_op = 41;"));
    assert!(RGWTRACE_BPF.contains("    op_ptr = fetch_param_ptr_ref(ctx, op_vf);"));
    assert!(RGWTRACE_BPF.contains("} else if (op_ptr != 0 && ctx_copy.req_state_ptr != 0) {"));
    assert!(RGWTRACE_BPF.contains("      ctx_copy.rgw_op_ptr = op_ptr;"));
    assert!(RGWTRACE_BPF.contains("struct reqstate_key okey = make_reqstate_key(op_ptr, tgid);"));
    assert!(RGWTRACE_BPF.contains("volatile __u32 RGW_OP_BRIDGE_KEY_ENABLED = 0;"));
    assert!(RGWTRACE_BPF
        .contains("if (bpf_map_update_elem(&rgw_op_keys, &rkey, &record, BPF_ANY) != 0) {"));

    // 5. The destructor revokes BOTH keys, and the alternate one only while it is
    //    still this request's (a recycled RGWOp address may already belong to a
    //    newer, LIVE request). The alternate key comes from the NEVER-EVICTING
    //    `rgw_op_keys` record, not from the LRU bridge value -- that is what makes
    //    revocation survive an eviction of the canonical entry.
    assert_eq!(
        RGWTRACE_BPF
            .matches("bpf_map_delete_elem(&rgw_ctx_by_reqstate, &rkey)")
            .count(),
        1
    );
    assert_eq!(
        RGWTRACE_BPF
            .matches("bpf_map_delete_elem(&rgw_ctx_by_reqstate, &okey)")
            .count(),
        1
    );
    assert!(RGWTRACE_BPF.contains(
        "  struct rgw_op_key_record *record = bpf_map_lookup_elem(&rgw_op_keys, &rkey);"
    ));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_RGWOP_KEY_REVOKE_SKIPPED)"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_RGWOP_KEY_REVOKE_ABSENT)"));
    // The revocation record map is a plain HASH. An LRU here would reintroduce the
    // stranded-key bug the record exists to fix.
    assert!(RGWTRACE_BPF.contains(concat!(
        "  __uint(type, BPF_MAP_TYPE_HASH);\n",
        "  __type(key, struct reqstate_key);\n",
        "  __type(value, struct rgw_op_key_record);\n",
    )));

    // 6. The seeded copy's `tid` is NOT rewritten to the seeded thread anywhere --
    //    that is what preserves the cross_thread label. The only writes to a ctx
    //    `tid` field are get_handler's own `fallback.tid = thread_id`.
    assert_eq!(
        RGWTRACE_BPF.matches(".tid = thread_id;").count(),
        1,
        "only get_handler may set a context's tid; a re-seed must copy it verbatim"
    );
    assert!(!RGWTRACE_BPF.contains("ctx_copy.tid ="));

    // 7. The request/op state maps are still plain HASH (LRU per-CPU freelists evict
    //    LIVE entries on >=64-CPU hosts).
    assert!(RGWTRACE_BPF.contains(concat!(
        "  __uint(type, BPF_MAP_TYPE_HASH);\n",
        "  __type(key, __u32);\n",
        "  __type(value, struct rgw_request_ctx);\n",
    )));

    // 8. No return probes, anywhere. A uretprobe on an asio fiber path crashed RGW.
    assert!(!RGWTRACE_BPF.contains("SEC(\"uretprobe"));

    // 9. The dpp is never dereferenced in the per-submit seed. (The ONE read in the
    //    process_authenticated probe is of the `RGWOp*&` REFERENCE's pointee, whose
    //    type DWARF proves -- it is not a read through a dpp.)
    let seed_start = RGWTRACE_BPF
        .find("static __always_inline int rgw_rados_operate_seed(")
        .expect("phase B seed handler");
    let seed = &RGWTRACE_BPF[seed_start..];
    let seed = &seed[..seed
        .find("\nSEC(\"uprobe\")")
        .expect("seed is followed by its stubs")];
    assert!(!seed.contains("probe_read"));
    assert!(!seed.contains("fetch_var_member_addr"));
}
