/* SPDX-License-Identifier: GPL-2.0-only */
/* Derived from Ceph cephtrace/radostrace BPF tracing code; see NOTICE. */

#ifndef RGWTRACE_EVENTS_H
#define RGWTRACE_EVENTS_H

#include "ceph_abi.h"

enum rgwtrace_event_type {
  RGWTRACE_EVENT_REQUEST_START = 1,
  RGWTRACE_EVENT_REQUEST_END = 2,
  RGWTRACE_EVENT_RADOS_OP = 3,
};

enum rgwtrace_truncation_flags {
  RGWTRACE_TRUNC_TRANS_ID = 1 << 0,
  RGWTRACE_TRUNC_OBJECT_NAME = 1 << 1,
  RGWTRACE_TRUNC_ACTING = 1 << 2,
  RGWTRACE_TRUNC_RADOS_OPS = 1 << 3,
  RGWTRACE_TRUNC_CLS_NAME = 1 << 4,
  RGWTRACE_TRUNC_METHOD_NAME = 1 << 5,
};

enum rgwtrace_diag_counter {
  RGWTRACE_DIAG_RINGBUF_REQUEST_DROPS = 0,
  RGWTRACE_DIAG_RINGBUF_RADOS_DROPS = 1,
  RGWTRACE_DIAG_RADOS_MAP_DROPS = 2,
  RGWTRACE_DIAG_RADOS_FINISH_MISSES = 3,
  RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS = 4,
  RGWTRACE_DIAG_PROBE_READ_FAILURES = 5,
  RGWTRACE_DIAG_REQSTATE_MAP_DROPS = 6,
  RGWTRACE_DIAG_RESEED_HITS = 7,
  RGWTRACE_DIAG_RESEED_MISSES = 8,
  RGWTRACE_DIAG_RESEED_BASE_UNRESOLVED = 9,
  /*
   * Request-END probe (req_state::~req_state) coverage. HITS: the destructor
   * resolved a bridged context, so the request span carries a MEASURED end.
   * MISSES: the destructor fired for a req_state the bridge never saw (request
   * started before the trace window, or the bridge entry was LRU-evicted) --
   * that request falls back to a derived end. BASE_UNRESOLVED: the `this`
   * pointer was not register-resolvable at entry.
   */
  RGWTRACE_DIAG_REQUEST_END_HITS = 10,
  RGWTRACE_DIAG_REQUEST_END_MISSES = 11,
  RGWTRACE_DIAG_REQUEST_END_BASE_UNRESOLVED = 12,
  /*
   * _send_op request-context liveness gate (see `request_ctx_is_live` in
   * bpf/rgwtrace.bpf.c). A request's context is COPIED onto every thread it was
   * seeded/re-seeded onto, and only the copy on the thread the destructor runs
   * on is revoked -- so every other copy outlives the request. Before stamping a
   * trans_id, _send_op therefore re-validates the copy against the
   * (req_state*, tgid) bridge, whose entry is deleted exactly at request end.
   *
   * STALE_CTX_DROPS: the copy failed that check (the request has ended, its
   * req_state address was recycled by a NEWER request, or the bridge entry was
   * LRU-evicted while the request was still alive). The op is left UNCORRELATED
   * rather than mis-attributed -- fail-closed. A nonzero count is expected under
   * cross-thread re-seed; a large count relative to correlated ops means bridge
   * entries are being evicted (see rgw_ctx_by_reqstate sizing).
   *
   * UNVERIFIABLE_CTX: the context was stamped WITHOUT a liveness proof, which is
   * possible only when the END probe is not attached on this build -- nothing can
   * revoke a bridge entry there, so its presence carries no liveness information
   * and the gate is switched off entirely (pre-liveness-gate behavior). Counted,
   * never silent.
   *
   * UNBRIDGED_CTX_DROPS: the END probe IS attached, but this context carries no
   * req_state* (get_handler could not resolve it from a register), so it has no
   * bridge entry, can never be revoked, and can never be verified. With a
   * revoking END probe present, an unverifiable context FAILS CLOSED: the op is
   * left uncorrelated rather than stamped from a context that may belong to a
   * request that ended long ago. A nonzero count here means the whole bridge is
   * dead on this build (see the get_handler descriptor warning at attach).
   */
  RGWTRACE_DIAG_SENDOP_STALE_CTX_DROPS = 13,
  RGWTRACE_DIAG_SENDOP_UNVERIFIABLE_CTX = 14,
  /*
   * Phase B: the per-submit re-seed at rgw_rados_operate (both overloads), the
   * last common frame before a RADOS submit. It fires on EVERY rados operate in
   * the process, request-driven or not, and its `dpp` argument is an OPAQUE
   * IDENTITY TOKEN -- only a req_state's own dpp can hit the bridge.
   *
   * SEED_HITS: the dpp matched a live request's (req_state*, tgid) bridge entry,
   * so this thread -- whatever thread the coroutine migrated onto -- was seeded
   * with that request's context immediately before the submit. This is the
   * counter that proves cross-thread correlation is working.
   *
   * SEED_MISSES: the dpp is NOT one of the identities a traced request is keyed
   * by (its req_state*, or the RGWOp* executing it). Overwhelmingly this is a
   * FOREIGN dpp (a stack DoutPrefix/DoutPrefixPipe wrapper, or a background
   * GC/LC/quota thread's dpp), which is the expected, fail-closed steady state:
   * it correlates nothing and touches nothing. A miss is NOT an error; a high
   * miss rate is normal on a busy gateway doing background work.
   *
   * SEED_BASE_UNRESOLVED: the dpp parameter was not register-resolvable at entry
   * (a stack-located descriptor), so no seed was even attempted.
   *
   * MISS_CTX_CLEARED: a miss that ALSO cleared a SEEDED request context left on
   * this thread (`ctx->tid != current tid`, i.e. a COPY Phase B migrated here from
   * the request's get_handler thread). A miss proves the submit about to happen is
   * not one we can attribute, and it does NOT prove that the copy lingering on this
   * pool thread belongs to the coroutine currently running here (request A can
   * leave its context on every thread it ever ran an operate on; request B can then
   * resume on one of them). So the copy is dropped rather than trusted: the op comes
   * out uncorrelated instead of stamped with another live request's trans_id. These
   * are the ops Phase B gives up on to stay honest.
   */
  RGWTRACE_DIAG_OPERATE_SEED_HITS = 15,
  RGWTRACE_DIAG_OPERATE_SEED_MISSES = 16,
  RGWTRACE_DIAG_OPERATE_BASE_UNRESOLVED = 17,
  RGWTRACE_DIAG_SENDOP_UNBRIDGED_CTX_DROPS = 18,
  RGWTRACE_DIAG_OPERATE_MISS_CTX_CLEARED = 19,
  /*
   * MULTI-KEY BRIDGE. A request is findable in rgw_ctx_by_reqstate under EVERY
   * dpp identity RGW may plausibly pass to rgw_rados_operate on its behalf:
   *
   *   * its `req_state*` (inserted at get_handler), and
   *   * the `RGWOp*` executing it (inserted at rgw_process_authenticated, read
   *     through the `RGWOp*& op` parameter).
   *
   * RGW threads a `const DoutPrefixProvider* dpp` down its data path, and at most
   * call sites inside an op's execute() that pointer is the RGWOp (`this`), not
   * the req_state. Keying only on the req_state* would make the per-submit re-seed
   * miss on exactly those sites -- i.e. on the whole op data path.
   *
   * THE REVOCATION IDENTITY (this is the invariant, stated exactly):
   *
   *   INSERTS == REVOKES + REVOKE_SKIPPED + REVOKE_ABSENT + (alternate keys of
   *              requests still in flight)
   *
   * It holds because an alternate key is only ever inserted AFTER its revocation
   * record has been created in `rgw_op_keys` (a plain HASH -- never evicted), and
   * the destructor consults that record UNCONDITIONALLY, including when the
   * request's own canonical LRU entry has been evicted. A failed bridge insert
   * deletes the record again, so a record always corresponds to a live key.
   *
   * RGWOP_KEY_INSERTS: alternate keys added. Should track request count.
   * RGWOP_KEY_REVOKES: alternate keys deleted at request end. Every inserted key
   *   MUST be revoked -- a key that outlives its request is a mis-correlation
   *   source, because RGWOp is heap-allocated and its address gets recycled.
   * RGWOP_KEY_REVOKE_SKIPPED: the destructor found the alternate key already
   *   OWNED BY A NEWER request (the RGWOp address was recycled and re-keyed by
   *   that request), so it did NOT delete it. Deleting would have revoked a LIVE
   *   request's key. The key is still revoked in the sense that matters: it no
   *   longer refers to the dead request. Expected to be small but nonzero on a
   *   busy gateway.
   * RGWOP_KEY_REVOKE_ABSENT: the revocation record named an alternate key that is
   *   no longer in the bridge at all (LRU-evicted). Nothing to delete; the key is
   *   gone, so the invariant holds. A large count means the bridge is under
   *   eviction pressure and correlation coverage is degrading.
   * RGWOP_KEY_UNRESOLVED: the `RGWOp*& op` parameter could not be read (no
   *   descriptor on this build, or the user read failed), so the request is keyed
   *   by its req_state* alone. Correlation degrades; nothing is mis-attributed.
   * RGWOP_KEY_INDEX_DROPS: the revocation record could not be created (the
   *   rgw_op_keys map is full), so the alternate key was NOT inserted. FAIL
   *   CLOSED: an unrevocable key is exactly the mis-correlation hazard this design
   *   refuses to create, so the request is keyed by its req_state* alone.
   * RGWOP_KEY_DISABLED: the alternate key is switched OFF for this run
   *   (--disable-rgw-op-bridge-key). Counted, not silent: it is the difference
   *   between "the RGWOp key never fired" and "the RGWOp key was not asked to".
   */
  RGWTRACE_DIAG_RGWOP_KEY_INSERTS = 20,
  RGWTRACE_DIAG_RGWOP_KEY_REVOKES = 21,
  RGWTRACE_DIAG_RGWOP_KEY_REVOKE_SKIPPED = 22,
  RGWTRACE_DIAG_RGWOP_KEY_UNRESOLVED = 23,
  /*
   * WHICH KEY DID THE PER-SUBMIT SEED HIT ON? This split is the measurement the
   * `RGWOp*` alternate key exists to justify.
   *
   * The alternate key is INSURANCE: it is only needed if RGW does not pass the
   * `req_state` as the `dpp` at the rgw_rados_operate call sites. It also carries
   * a mis-correlation hazard that no amount of pointer-identity logic can remove
   * (RGWHandler_REST_S3Website::retarget can free and replace the RGWOp while its
   * request is still alive; a DIFFERENT DoutPrefixProvider heap object landing on
   * that address would be seeded as that request, and the liveness gate would pass
   * because the request genuinely IS alive -- see
   * docs/design-cross-thread-correlation.md 10.1).
   *
   * So the decision is a measurement, not a debate:
   *
   *   SEED_HITS_REQSTATE ~ SEED_HITS and SEED_HITS_RGWOP ~ 0
   *       -> the alternate key buys NOTHING. Disable it
   *          (--disable-rgw-op-bridge-key) and the retarget hazard disappears.
   *   SEED_HITS_RGWOP is a large fraction of SEED_HITS
   *       -> the alternate key is load-bearing; keep it and live with the hazard.
   *
   * SEED_HITS_UNATTRIBUTED must be 0. A hit is attributed by comparing the `dpp`
   * against the bridged value's own req_state_ptr / rgw_op_ptr, and by
   * construction exactly one of them equals it. A nonzero count means the bridge
   * value no longer describes its own keys, and the split above cannot be trusted.
   */
  RGWTRACE_DIAG_OPERATE_SEED_HITS_REQSTATE = 24,
  RGWTRACE_DIAG_OPERATE_SEED_HITS_RGWOP = 25,
  RGWTRACE_DIAG_OPERATE_SEED_HITS_UNATTRIBUTED = 26,
  /*
   * The per-submit seed's OTHER fail-closed clear: the `dpp` could not be resolved
   * at all (no descriptor in `hprobes`, a stack-located descriptor, or a NULL dpp
   * argument). Distinct from OPERATE_MISS_CTX_CLEARED, which is a resolved dpp
   * that simply is not one of a traced request's keys.
   *
   * It must clear the thread's context for exactly the same reason a foreign-dpp
   * miss must: an unresolved dpp proves NOTHING about which coroutine is running
   * on this pool thread, and the context lingering here may belong to another live
   * request whose trans_id would then be stamped onto this submit.
   */
  RGWTRACE_DIAG_OPERATE_UNRESOLVED_CTX_CLEARED = 27,
  RGWTRACE_DIAG_RGWOP_KEY_REVOKE_ABSENT = 28,
  RGWTRACE_DIAG_RGWOP_KEY_INDEX_DROPS = 29,
  RGWTRACE_DIAG_RGWOP_KEY_DISABLED = 30,
  /*
   * THE OTHER HALF OF THE FAIL-CLOSED CLEAR: the unproven submit found a HOME
   * context on this thread and PRESERVED it.
   *
   * A HOME context is one `RGWREST::get_handler` placed on this very thread for the
   * request that STARTED here (`ctx->tid == current tid`; `ctx->tid` is the
   * get_handler thread and is copied verbatim by every re-seed, so the test is
   * exact). A SEEDED context is a copy a re-seed migrated onto a thread that is NOT
   * the request's get_handler thread (`ctx->tid != current tid`).
   *
   * The clear is scoped to SEEDED contexts because those are the ones Phase B
   * created. An unscoped clear shipped a measured regression: RGW issues a sharded
   * `rgw.bucket_list` through the cls_rgw AIO path, which never passes through
   * `rgw_rados_operate`, so those submits correlate purely off the HOME context
   * get_handler left on the thread. ONE foreign-dpp operate on that thread wiped it
   * and stranded all 16 shard ops of a live ListObjects request. Clearing a HOME
   * context also buys no soundness: an AIO submit that never reaches an operate
   * inherits whatever context is on the thread either way (the accepted residual
   * hazard -- see docs/design-cross-thread-correlation.md SS11).
   *
   * MISS_HOME_CTX_PRESERVED: a foreign-dpp miss left a HOME context alone. Expected
   *   and healthy: it is the same-thread correlation path continuing to work.
   * UNRESOLVED_HOME_CTX_PRESERVED: the same, for a dpp that could not be resolved at
   *   all. A nonzero count here still means null/unresolvable dpps are reaching this
   *   probe (read it together with OPERATE_BASE_UNRESOLVED).
   *
   * Read against MISS_CTX_CLEARED / UNRESOLVED_CTX_CLEARED, these say how often the
   * fail-closed rule fired on a Phase B copy versus how often it declined to touch a
   * context that predates Phase B.
   */
  RGWTRACE_DIAG_OPERATE_MISS_HOME_CTX_PRESERVED = 31,
  RGWTRACE_DIAG_OPERATE_UNRESOLVED_HOME_CTX_PRESERVED = 32,
  RGWTRACE_DIAG_COUNTERS = 33,
};

struct rgwtrace_request_event {
  __u64 start_ns;
  __u64 end_ns;
  __u32 pid;
  __u32 tid;
  __u32 flags;
  char trans_id[MAX_TRANS_ID];
};

struct rgwtrace_rados_event {
  __u64 cid;
  __u64 tid;
  __u64 sent_ns;
  __u64 finish_ns;
  __u64 pool;
  __u64 offset;
  __u64 length;
  __u32 pid;
  __u32 send_tid;
  __u32 target_osd;
  __u32 pg_seed;
  __u16 rw;
  __u32 ops_size;
  __u32 flags;
  int acting[MAX_ACTING];
  __u16 ops[MAX_RADOS_OPS];
  struct cls_op cls_ops[MAX_RADOS_OPS];
  char trans_id[MAX_TRANS_ID];
  char object_name[MAX_OBJECT_NAME];
};

struct rgwtrace_event {
  __u32 type;
  union {
    struct rgwtrace_request_event request;
    struct rgwtrace_rados_event rados;
  } data;
};

#endif
