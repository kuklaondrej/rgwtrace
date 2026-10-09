/* SPDX-License-Identifier: GPL-2.0-only */
/* Derived from Ceph cephtrace/radostrace BPF tracing code; see NOTICE. */

#define BPF_KERNEL_SPACE

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

#include "rgwtrace_events.h"

char LICENSE[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, RGWTRACE_DIAG_COUNTERS);
} diagnostics SEC(".maps");

static __always_inline void count_diag(__u32 key) {
  __u64 *counter = bpf_map_lookup_elem(&diagnostics, &key);
  if (counter != 0)
    *counter += 1;
}

static __always_inline int rgwtrace_probe_read_user(void *dst, __u32 size,
                                                    const void *unsafe_ptr) {
  int ret = bpf_probe_read_user(dst, size, unsafe_ptr);
  if (ret != 0)
    count_diag(RGWTRACE_DIAG_PROBE_READ_FAILURES);
  return ret;
}

static __always_inline int rgwtrace_probe_read_user_str(void *dst, __u32 size,
                                                        const void *unsafe_ptr) {
  int ret = bpf_probe_read_user_str(dst, size, unsafe_ptr);
  if (ret < 0)
    count_diag(RGWTRACE_DIAG_PROBE_READ_FAILURES);
  return ret;
}

#include "bpf_utils.h"

struct rados_op_state {
  struct rgwtrace_rados_event event;
};

struct rgw_request_ctx {
  __u64 start_ns;
  __u32 pid;
  __u32 tid;
  __u32 flags;
  char trans_id[MAX_TRANS_ID];
  /*
   * BPF-internal only: the request's req_state* captured at get_handler. This is
   * the CANONICAL bridge key -- the one the liveness gate re-derives and the one
   * the destructor revokes -- because the destructor is the only probe that can
   * name the request, and all it has is `this` (the req_state*). Not a wire field
   * -- emit_request_event copies only the on-wire members, so rgwtrace_events.h /
   * events.rs are unaffected.
   */
  __u64 req_state_ptr;
  /*
   * BPF-internal only: the ALTERNATE bridge key, i.e. the RGWOp* executing this
   * request, read at rgw_process_authenticated through the `RGWOp*& op`
   * parameter. 0 when unknown (key disabled, probe absent, descriptor unproven,
   * read failed).
   *
   * It is carried INSIDE the context value so that a seed can say WHICH of the
   * request's keys the `dpp` matched (`reseed_thread_from_reqstate`): the value
   * names both of its own keys, so the attribution is exact rather than inferred.
   * That split is the measurement the alternate key's existence is decided on.
   *
   * It is NOT what the destructor revokes from -- that is the `rgw_op_keys` record,
   * which lives in a never-evicting plain HASH precisely because this value lives
   * in an LRU and can be evicted while the key it names survives.
   */
  __u64 rgw_op_ptr;
};

static struct rados_op_state zero_rados_op = {};

/*
 * Deliberately plain HASH, NOT LRU_HASH. Both maps have explicit lifecycle
 * deletes on their finish/exit paths, so under normal operation they self-drain.
 * LRU_HASH is actively harmful here: its per-CPU freelists reserve ~128 nodes
 * per logical CPU, so on many-core hosts (>=64 CPUs) 128*cores approaches
 * max_entries and the allocator evicts LIVE, in-flight entries once more than
 * ~128 ops are outstanding -- an evicted rados_ops entry makes _finish_op's
 * lookup miss and the op event is never emitted. Plain HASH never evicts live
 * entries; when genuinely full (e.g. leaked entries) it only rejects NEW inserts
 * with E2BIG, which is counted via the existing drop counters. Rejecting new
 * inserts is strictly less harmful than silently killing op emission.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct client_op_key);
  __type(value, struct rados_op_state);
  __uint(max_entries, 8192);
} rados_ops SEC(".maps");

/* Plain HASH for the same reason as rados_ops (see above): LRU per-CPU
 * freelists evict live in-flight entries on many-core hosts; plain HASH only
 * rejects new inserts when full, and rgw_requests has explicit lifecycle
 * deletes. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct rgw_request_ctx);
  __uint(max_entries, 8192);
} rgw_requests SEC(".maps");

/*
 * Cross-thread context bridge (design-cross-thread-correlation.md). Keyed by
 * (dpp-identity, tgid): an OPAQUE POINTER plus the process id, because pointers
 * can collide across address spaces while --pid is optional. PID-scoped; the u32
 * pad is explicit and zeroed on every key so hashing is deterministic.
 *
 * MULTI-KEY. One request is inserted under EVERY dpp identity RGW might plausibly
 * pass for it to rgw_rados_operate:
 *
 *   * its `req_state*`   -- inserted at get_handler. CANONICAL: this is the key
 *                           the liveness gate re-derives and the destructor
 *                           revokes, because `this` is all the destructor has.
 *   * the `RGWOp*`       -- inserted at rgw_process_authenticated. RGW threads a
 *                           `const DoutPrefixProvider*` down its data path, and
 *                           inside an op's execute() that pointer is usually the
 *                           RGWOp (`this`), not the req_state. Without this key
 *                           the per-submit re-seed misses on the entire op data
 *                           path.
 *
 * Both keys map to the SAME value (byte-identical `rgw_request_ctx`), so it does
 * not matter which one a seed came through: the seeded copy always carries the
 * canonical req_state_ptr, and the liveness gate always re-checks THAT.
 *
 * CAPACITY. Phase B multiplies the LOOKUP rate on this map (one lookup per rados
 * operate in the whole process, most of them foreign-dpp misses) but not the
 * insert rate: entries are created once per traced request (x2 keys) and deleted
 * at that request's destructor -- BOTH of them. Occupancy is bounded by in-flight
 * requests x2, not by op volume.
 *
 * The LRU_HASH allocator reserves ~128 free nodes per CPU that touches the map,
 * which is what makes an undersized LRU evict LIVE entries on many-core hosts
 * (the regression that forced rados_ops/rgw_requests back to plain HASH). With
 * max_entries = 131072 the reservation is a small fraction even on very wide
 * hosts, and what is left over dwarfs any plausible in-flight request count:
 *
 *   64 CPUs:  128*64  =  8192 reserved -> 122880 usable -> 61440 requests
 *   128 CPUs: 128*128 = 16384 reserved -> 114688 usable -> 57344 requests
 *   256 CPUs: 128*256 = 32768 reserved ->  98304 usable -> 49152 requests
 *
 * (The doubling from 65536 is exactly the multi-key factor: the per-REQUEST
 * headroom is unchanged from the single-key design.) Lookups also keep a live
 * request's entries hot in the LRU, which makes a live-entry eviction less likely
 * than the raw occupancy suggests.
 *
 * Unlike rados_ops / rgw_requests above, this map is deliberately LRU_HASH. The
 * END probe (req_state::~req_state) deletes every key of a request at its end, so
 * under a normal RGW build the map self-drains and holds only in-flight requests
 * -- but the END probe is OPTIONAL, and with it absent nothing deletes anything.
 * That is why an absent END probe DISABLES the per-submit re-seed entirely
 * (userspace does not attach the operate probes): a bridge nobody revokes cannot
 * answer "is this dpp a LIVE request?", and a stale entry hit by a recycled
 * address would stamp a dead request's trans_id. LRU eviction then merely bounds
 * the map's growth; its consumers fail closed on a missing entry, so eviction
 * degrades correlation rather than corrupting it.
 */
struct reqstate_key {
  __u64 req_state_ptr;
  __u32 tgid;
  __u32 _pad;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct reqstate_key);
  __type(value, struct rgw_request_ctx);
  __uint(max_entries, 131072);
} rgw_ctx_by_reqstate SEC(".maps");

/*
 * The ALTERNATE KEY'S REVOCATION RECORD, keyed by the request's CANONICAL key.
 *
 * WHY THIS EXISTS AND WHY IT IS NOT THE LRU. The destructor is the only probe
 * that can name a request, and all it has is the `req_state*`. To revoke the
 * request's ALTERNATE key (the RGWOp*) it must first learn what that key WAS.
 * Carrying it inside the canonical bridge value is not enough: rgw_ctx_by_reqstate
 * is an LRU, and it can evict the CANONICAL entry while the ALTERNATE one
 * survives. The destructor's canonical lookup then misses, it never learns the
 * alternate key, and that key OUTLIVES its request. (The _send_op liveness gate
 * still refuses to stamp from such an orphan -- it re-derives the canonical key,
 * which is gone -- so this was never a mis-correlation. But it made the documented
 * "every inserted key is revoked" invariant and the `inserts - revokes` health
 * metric FALSE, and a false invariant is a bug in its own right.)
 *
 * So the revocation record lives in a PLAIN HASH, which never evicts: if the
 * record was written, the destructor WILL find it. That is what makes revocation
 * TOTAL rather than merely usual.
 *
 * It is safe as a plain HASH for the same reason rados_ops/rgw_requests are: it
 * has an explicit lifecycle delete (the destructor, whose probe -- see
 * `attach_probes` -- is attached BEFORE get_handler can create the first bridge
 * entry, so no record can ever be created without its revoker already live). When
 * genuinely full it rejects NEW inserts with E2BIG, and we then decline to insert
 * the alternate key at all (RGWTRACE_DIAG_RGWOP_KEY_INDEX_DROPS): fail closed --
 * never create a key nobody can revoke.
 *
 * Sized by IN-FLIGHT REQUESTS (one record per request that has an alternate key),
 * not by op volume: 16384 is ~16x Ceph's default rgw_max_concurrent_requests
 * (1024). It is deliberately NOT LRU: on >=64-CPU hosts LRU per-CPU freelists
 * evict live entries, which is precisely the failure this map exists to prevent.
 */
struct rgw_op_key_record {
  /* The alternate bridge key this request was inserted under. */
  __u64 rgw_op_ptr;
  /* Identity of the OWNING request, so the destructor can tell "still mine" from
   * "already re-keyed by a newer request that reused this RGWOp address". Kept
   * here (not read back from the canonical entry) precisely because the canonical
   * entry may be gone. */
  __u64 start_ns;
  __u32 owner_tid;
  __u32 _pad;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct reqstate_key);
  __type(value, struct rgw_op_key_record);
  __uint(max_entries, 16384);
} rgw_op_keys SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, struct VarField);
  __uint(max_entries, 8192);
} hprobes SEC(".maps");

/*
 * Sized at runtime from --ringbuf-size (bpf_map__set_max_entries on the open
 * object; a ring buffer cannot be resized after load). The declared value is
 * only the default that flag mirrors. See the flag's help for the sizing math.
 */
#define RGWTRACE_DEFAULT_RINGBUF_BYTES (16 * 1024 * 1024)

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, RGWTRACE_DEFAULT_RINGBUF_BYTES);
} events SEC(".maps");

/*
 * Set to 1 by userspace AFTER the request-END probe (req_state::~req_state) has
 * successfully attached; stays 0 on any build where it could not (missing/
 * unprovable destructor variant, no register-only `this` descriptor, or a kernel
 * attach failure). Not `const volatile`: it is written after load, through the
 * .bss array map.
 *
 * It gates `request_ctx_is_live` below. The END probe is the ONLY thing that
 * deletes a bridge entry, so without it "entry present in rgw_ctx_by_reqstate"
 * carries no liveness information at all -- every entry lingers forever -- and a
 * liveness gate keyed on it would be pure overhead that can only produce false
 * "alive" answers. With the probe absent we therefore keep the pre-existing
 * stamp-whatever-is-on-this-thread behavior (and say so in the diagnostics via
 * RGWTRACE_DIAG_SENDOP_UNVERIFIABLE_CTX) rather than pretending to validate.
 *
 * ORDERING IS PART OF THE CONTRACT. Userspace publishes this (and every global
 * below) AFTER the destructor probe has attached and BEFORE any probe that can
 * create or consume a bridge entry -- see `ATTACH_ORDER` in src/live/linux.rs. If
 * get_handler could attach first, a request could pass it and complete before its
 * destructor probe was live, leaving a bridge entry that nothing would ever
 * revoke; once the flag then flipped to 1 that stale entry would pass the identity
 * check and let a later submit inherit a DEAD request's trans_id.
 */
volatile __u32 REQUEST_END_PROBE_ATTACHED = 0;

/*
 * Is the `RGWOp*` ALTERNATE bridge key enabled for this run? Published by
 * userspace from --disable-rgw-op-bridge-key (default: ENABLED), before the
 * process_authenticated probe -- the only writer of that key -- is attached.
 *
 * WHY IT IS SWITCHABLE. The alternate key is INSURANCE against RGW not passing the
 * `req_state` as the `dpp` at the rgw_rados_operate call sites, and it is the one
 * part of this design with a residual mis-correlation hazard that more
 * pointer-identity logic cannot remove: RGWHandler_REST_S3Website::retarget can
 * free and replace an RGWOp while its request is still ALIVE, so another
 * DoutPrefixProvider heap object can land on that address and be seeded as that
 * request -- and the liveness gate passes, because the request really is alive.
 *
 * Whether that risk buys anything is a MEASUREMENT, not an argument: compare
 * RGWTRACE_DIAG_OPERATE_SEED_HITS_REQSTATE against
 * RGWTRACE_DIAG_OPERATE_SEED_HITS_RGWOP on a real rig. If the RGWOp key never
 * fires, turn it off with this flag -- no rebuild -- and the hazard is gone. It
 * defaults ON so the measurement can be taken at all.
 *
 * The initializer is 0 because it lives in .bss; the real value is written after
 * load and before attach. A missed write therefore degrades (no alternate key)
 * rather than enabling something unproven -- fail-safe in the right direction.
 */
volatile __u32 RGW_OP_BRIDGE_KEY_ENABLED = 0;

const volatile __u32 CEPH_OSD_OP_SIZE = 0;
const volatile __u32 CEPH_OSD_OP_EXTENT_OFFSET_OFFSET = 0;
const volatile __u32 CEPH_OSD_OP_EXTENT_LENGTH_OFFSET = 0;
const volatile __u32 CEPH_OSD_OP_CLS_CLASS_OFFSET = 0;
const volatile __u32 CEPH_OSD_OP_CLS_METHOD_OFFSET = 0;
const volatile __u32 CEPH_OSD_OP_BUFFER_CARRIAGE_OFFSET = 0;
const volatile __u32 CEPH_OSD_OP_BUFFER_RAW_OFFSET = 0;
const volatile __u32 CEPH_OSD_OP_BUFFER_DATA_OFFSET = 0;

static __always_inline void emit_request_event(__u32 type,
                                               struct rgw_request_ctx *ctx,
                                               __u64 end_ns) {
  /* Reserved at request-record size, not the full union (see
   * struct rgwtrace_request_record). */
  struct rgwtrace_request_record *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (e == 0) {
    count_diag(RGWTRACE_DIAG_RINGBUF_REQUEST_DROPS);
    return;
  }

  __builtin_memset(e, 0, sizeof(*e));
  e->type = type;
  e->request.start_ns = ctx->start_ns;
  e->request.end_ns = end_ns;
  e->request.pid = ctx->pid;
  e->request.tid = ctx->tid;
  e->request.flags = ctx->flags;
  __builtin_memcpy(e->request.trans_id, ctx->trans_id,
                   sizeof(e->request.trans_id));
  bpf_ringbuf_submit(e, 0);
}

/*
 * Build a (dpp-identity, tgid) bridge key. The identity is a req_state* or an
 * RGWOp* -- both are just opaque pointer values here. The u32 pad is explicitly
 * zeroed on every construction so hashing stays deterministic.
 */
static __always_inline struct reqstate_key make_reqstate_key(__u64 req_state_ptr,
                                                             __u32 tgid) {
  struct reqstate_key rkey = {};
  rkey.req_state_ptr = req_state_ptr;
  rkey.tgid = tgid;
  return rkey;
}

/*
 * Which of a request's bridge keys a seed came in through. The whole point of
 * splitting this out is that the answer decides whether the `RGWOp*` alternate key
 * -- and the S3-website-retarget mis-correlation hazard it carries -- earns its
 * place at all. See RGWTRACE_DIAG_OPERATE_SEED_HITS_RGWOP in rgwtrace_events.h.
 */
#define BRIDGE_SEED_MISS 0
/* The dpp was the request's `req_state*` -- the CANONICAL key. */
#define BRIDGE_SEED_VIA_REQSTATE 1
/* The dpp was the `RGWOp*` executing the request -- the ALTERNATE key. */
#define BRIDGE_SEED_VIA_RGWOP 2
/* Hit, but the dpp is neither of the bridged value's own keys. IMPOSSIBLE by
 * construction (a value is only ever stored under a key it names). Counted rather
 * than assumed away, because if it ever fires, the REQSTATE/RGWOP split -- the
 * number the RGWOp key's fate is decided on -- is not trustworthy. */
#define BRIDGE_SEED_VIA_UNATTRIBUTED 3

/*
 * Core of the cross-thread re-seed: look the request context up in the MULTI-KEY
 * (dpp-identity, tgid) bridge and, on a hit, seed rgw_requests[tid] with it so a
 * RADOS op submitted on this thread inherits the request's trans_id. Returns
 * BRIDGE_SEED_MISS on a miss, or WHICH KEY matched on a hit; callers own the
 * diagnostics and the fail-closed handling of a miss.
 *
 * The key is attributed by comparing `dpp` against the bridged value's own
 * `req_state_ptr` / `rgw_op_ptr`. That is exact, not heuristic: a value is only
 * ever inserted under a key it names.
 *
 * The map value is copied to the stack before being used as an update source: a
 * direct map-value pointer is not a safe update source for the verifier.
 *
 * Factored out deliberately: the Phase B rgw_rados_operate seed re-uses this
 * body verbatim (there the key is the `dpp` pointer, which is numerically equal
 * to the req_state* -- or to the RGWOp* -- because both types inherit
 * DoutPrefixProvider at offset 0, which extraction VERIFIES in DWARF rather than
 * assuming; see `dpp_base_offset` in src/dwarf_native.rs).
 */
static __always_inline int reseed_thread_from_reqstate(__u64 dpp, __u32 tgid,
                                                       __u32 tid) {
  struct reqstate_key rkey = make_reqstate_key(dpp, tgid);
  struct rgw_request_ctx *bridged =
      bpf_map_lookup_elem(&rgw_ctx_by_reqstate, &rkey);
  if (bridged == 0)
    return BRIDGE_SEED_MISS;

  int via = BRIDGE_SEED_VIA_UNATTRIBUTED;
  if (bridged->req_state_ptr == dpp)
    via = BRIDGE_SEED_VIA_REQSTATE;
  else if (bridged->rgw_op_ptr == dpp)
    via = BRIDGE_SEED_VIA_RGWOP;

  struct rgw_request_ctx ctx_copy = {};
  __builtin_memcpy(&ctx_copy, bridged, sizeof(ctx_copy));
  if (bpf_map_update_elem(&rgw_requests, &tid, &ctx_copy, BPF_ANY) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
  return via;
}

/*
 * Is the request context sitting on this thread still that of a LIVE request?
 *
 * WHY THIS EXISTS. rgw_requests is keyed by tid and holds a COPY of the request
 * context. A request's context is copied onto its get_handler thread and onto
 * every thread the cross-thread bridge re-seeds it onto. The END probe can only
 * revoke the copy on the ONE thread the destructor runs on (it must not clear
 * another live request's context off a shared Beast pool thread). Every other
 * copy therefore outlives its request, and a later op submitted from such a
 * thread -- a subsequent request, or a background op -- would inherit a DEAD
 * request's trans_id and be attributed to the wrong request. Mis-correlation is
 * strictly worse than no correlation: it is confidently wrong telemetry.
 *
 * THE SIGNAL. rgw_ctx_by_reqstate[(req_state*, tgid)] is created at get_handler
 * and DELETED at the destructor, i.e. exactly at request end. Its presence is
 * therefore the liveness bit, and it needs no new map, no new counter, and no
 * write on the hot path.
 *
 * PRESENCE IS NOT ENOUGH -- req_state ADDRESSES ARE RECYCLED. req_state is
 * stack-allocated inside process_request, so consecutive requests on the same
 * Beast worker thread routinely reuse the SAME address, and the (req_state*,
 * tgid) key is then reused by a genuinely NEW request. A pure presence check
 * would see the new request's entry and happily stamp the OLD request's
 * trans_id. So we also compare the bridged entry's IDENTITY against the copy:
 * `start_ns` (the get_handler boot-clock read, which is distinct for any two
 * requests -- two get_handler entries cannot observe the same nanosecond on the
 * same thread, and a different thread implies a different stack address) and
 * `tid` (the get_handler thread). Matching identity means the entry still
 * describes the very request this copy came from; a recycled address yields a
 * different start_ns and is rejected.
 *
 * COST. One extra hash lookup plus two scalar compares, and only on the path
 * that was about to stamp a trans_id anyway. _send_op already performs ~12
 * hprobes lookups and ~15 bpf_probe_read_user calls per op, so this is a small
 * single-digit percentage of the probe's existing work. A cheaper sound design
 * does not exist: any generation/epoch scheme still has to fetch the request's
 * current generation from somewhere, which is the same lookup, plus a new map.
 *
 * FAIL-CLOSED. If the bridge entry was LRU-evicted while its request was still
 * alive, this reports "not live" and the op is left UNCORRELATED (counted in
 * RGWTRACE_DIAG_SENDOP_STALE_CTX_DROPS). That is a deliberate trade: an
 * uncorrelated op is a known unknown, a mis-correlated one is a lie. Note the
 * lookup here also keeps a live request's bridge entry hot in the LRU, which is
 * what makes such an eviction unlikely in the first place.
 *
 * A CONTEXT WITH NO req_state* ALSO FAILS CLOSED (when the END probe is attached).
 * Such a context was never bridged (get_handler could not resolve the req_state*
 * from a register on this build), so it can never be found through the bridge --
 * which means the destructor's lookup misses and returns BEFORE clearing it off
 * this thread, and it lingers on a pooled thread for the rest of the run. Trusting
 * it would let a long-dead request stamp later ops. It is dropped and counted
 * (RGWTRACE_DIAG_SENDOP_UNBRIDGED_CTX_DROPS); userspace additionally warns at
 * attach time, because a build in this state correlates NOTHING and must not look
 * merely quiet.
 */
static __always_inline int request_ctx_is_live(struct rgw_request_ctx *ctx) {
  if (REQUEST_END_PROBE_ATTACHED == 0) {
    /*
     * Nothing can revoke a context on this build: the bridge is insert-only, so
     * "entry present" carries no liveness information whatsoever and a gate keyed
     * on it could only ever answer "alive". There is no evidence to consult, so
     * keep the pre-liveness-gate behavior (stamp what get_handler put here) and
     * say so in the diagnostics. The per-submit re-seed is NOT attached in this
     * state (see attach_probes), so the only contexts that can be on a thread are
     * ones get_handler or the process_authenticated re-seed put there.
     */
    count_diag(RGWTRACE_DIAG_SENDOP_UNVERIFIABLE_CTX);
    return 1;
  }

  if (ctx->req_state_ptr == 0) {
    count_diag(RGWTRACE_DIAG_SENDOP_UNBRIDGED_CTX_DROPS);
    return 0;
  }

  struct reqstate_key rkey = make_reqstate_key(ctx->req_state_ptr, ctx->pid);
  struct rgw_request_ctx *bridged =
      bpf_map_lookup_elem(&rgw_ctx_by_reqstate, &rkey);
  if (bridged == 0 || bridged->start_ns != ctx->start_ns ||
      bridged->tid != ctx->tid) {
    count_diag(RGWTRACE_DIAG_SENDOP_STALE_CTX_DROPS);
    return 0;
  }
  return 1;
}

SEC("uprobe")
int uprobe_rgw_get_handler(struct pt_regs *ctx) {
  int varid = 30;
  __u32 thread_id = get_tid();
  struct rgw_request_ctx fallback = {};
  bpf_map_delete_elem(&rgw_requests, &thread_id);
  struct rgw_request_ctx *request = bpf_map_lookup_elem(&rgw_requests, &thread_id);

  if (request == 0) {
    fallback.start_ns = bpf_ktime_get_boot_ns();
    fallback.pid = get_pid();
    fallback.tid = thread_id;
    if (bpf_map_update_elem(&rgw_requests, &thread_id, &fallback, 0) != 0) {
      count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
      return 0;
    }
    request = bpf_map_lookup_elem(&rgw_requests, &thread_id);
    if (request == 0) {
      count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
      return 0;
    }
  }

  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  int trans_id_len = 0;
  if (vf == 0)
    return 0;

  __u64 v = fetch_register(ctx, vf->varloc.reg);
  /*
   * Reuse the exact slot-30 base register value (and its stack disposition)
   * for the cross-thread reqstate bridge below. Register-only by design: a
   * stack-located descriptor cannot encode the req_state* here, so the bridge
   * is skipped and we fall back to main's same-thread behavior.
   */
  bool req_state_is_reg = !vf->varloc.stack;
  __u64 req_state_base = v;
  __u64 len_addr = fetch_var_member_addr(v, vf);
  rgwtrace_probe_read_user(&trans_id_len, sizeof(trans_id_len), (void *)len_addr);

  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf == 0)
    return 0;

  __u64 trans_id_base = 0;
  v = fetch_register(ctx, vf->varloc.reg);
  __u64 base_addr = fetch_var_member_addr(v, vf);
  rgwtrace_probe_read_user(&trans_id_base, sizeof(trans_id_base), (void *)base_addr);

  if (trans_id_len > 0 && trans_id_base > 0) {
    if (trans_id_len >= MAX_TRANS_ID)
      request->flags |= RGWTRACE_TRUNC_TRANS_ID;
    rgwtrace_probe_read_user_str(request->trans_id, sizeof(request->trans_id),
                                 (void *)trans_id_base);
    /*
     * START marker. get_handler entry is the earliest point at which the request
     * identity (trans_id) is known, so it opens the request span. Its end is
     * supplied by the req_state::~req_state END probe below; end_ns is 0 here
     * because this probe knows nothing about when the request finishes, and
     * fabricating one would be a lie. When the END probe cannot attach (stripped
     * binary / unresolvable symbol / older RGW), the collector falls back to
     * deriving the end from the correlated RADOS child bounds and labels the span
     * duration_quality = "marker" instead of "measured".
     */
    emit_request_event(RGWTRACE_EVENT_REQUEST_START, request, 0);
  }

  /*
   * Populate the context bridge under the request's CANONICAL key (its
   * req_state*). Placed after the trans_id read + marker emission so those are
   * byte-for-byte unaffected. Only when the slot-30 req_state* came from a
   * register (register-only by design) and is non-null. Overwrite-on-reuse
   * (BPF_ANY) is the aliasing cure for a recycled stack address.
   *
   * The ALTERNATE key (the executing RGWOp*) is added later, at
   * rgw_process_authenticated, because that is the first site where the RGWOp is
   * available as a probeable parameter. The context inserted here therefore has
   * rgw_op_ptr == 0 (the fresh `fallback` above is zeroed), and the
   * process_authenticated probe writes it back into this very entry.
   *
   * Read by uprobe_rgw_process_authenticated (the opt-in cross-thread re-seed),
   * by the per-submit re-seed at rgw_rados_operate, and by uprobe_rgw_req_state_dtor
   * (the request-END probe, which is the map's only deleter). When the req_state*
   * is unresolvable the bridge is simply not populated, and every consumer
   * degrades: no re-seed, no measured end, and -- with the END probe attached --
   * _send_op refuses to stamp from the unbridged context (fail-closed).
   */
  if (req_state_is_reg && req_state_base > 0) {
    request->req_state_ptr = req_state_base;
    struct reqstate_key rkey = make_reqstate_key(req_state_base, get_pid());
    if (bpf_map_update_elem(&rgw_ctx_by_reqstate, &rkey, request, BPF_ANY) != 0)
      count_diag(RGWTRACE_DIAG_REQSTATE_MAP_DROPS);
  }

  return 0;
}

/*
 * Request-END probe: req_state::~req_state (the COMPLETE/BASE object destructor,
 * D1/D2 -- never the deleting dtor D0; see `dtor_variant_rank` in
 * src/dwarf_native.rs, which is what makes that choice deterministic).
 *
 * This is the true, unconditional end of an RGW request: req_state is
 * stack-allocated in process_request, so the destructor runs at scope exit --
 * after logging and after client_io->complete_request(). It is an ENTRY uprobe
 * and must NEVER be a uretprobe: uretprobes patch the return address on the
 * stack and asio switches fiber stacks underneath the probe, which is exactly
 * why the old process_request return probe crashed RGW live.
 *
 * Its only parameter is `this` (req_state*), read register-only through the
 * varid-50 raw-pointer descriptor -- the same shape as the varid-40
 * rgw_process_authenticated descriptor. The register comes from DWARF; nothing
 * about the ABI is hardcoded here.
 *
 * On a bridge hit the request's context (with the start_ns seeded at
 * get_handler) is emitted as a REQUEST_END carrying a REAL end_ns, and EVERY
 * bridge key of that request is deleted -- these are the only deletes on
 * rgw_ctx_by_reqstate and they bound the map instead of relying purely on LRU
 * eviction. On a miss we emit nothing: a request whose get_handler was never seen
 * (started before the trace window, or LRU-evicted) has no start to pair the end
 * with -- but the cleanup below STILL RUNS, because a missing canonical entry does
 * not mean the request has no other keys left to revoke.
 *
 * REVOKING EVERY KEY IS A CORRECTNESS REQUIREMENT, NOT HOUSEKEEPING. The request
 * is findable under its req_state* AND under the RGWOp* that executed it. The
 * destructor only has the req_state*, so the alternate key is recorded in
 * `rgw_op_keys` -- a PLAIN HASH, keyed by the canonical key -- purely so it can be
 * revoked here. It is deliberately not read back from the canonical bridge value:
 * that value lives in an LRU and can be evicted while the alternate key survives,
 * which would strand the alternate key forever. A surviving key is at best a lie
 * in the health metrics and at worst a mis-correlation source: RGWOp is
 * heap-allocated, its address is recycled, and a later foreign dpp landing on that
 * address would seed a DEAD request's context.
 */
SEC("uprobe")
int uprobe_rgw_req_state_dtor(struct pt_regs *ctx) {
  int varid = 50;
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf == 0)
    return 0;

  __u64 rsp = fetch_param_ptr(ctx, vf);
  if (rsp == 0) {
    count_diag(RGWTRACE_DIAG_REQUEST_END_BASE_UNRESOLVED);
    return 0;
  }

  __u32 tgid = get_pid();
  __u32 tid = get_tid();

  struct reqstate_key rkey = make_reqstate_key(rsp, tgid);
  struct rgw_request_ctx *bridged =
      bpf_map_lookup_elem(&rgw_ctx_by_reqstate, &rkey);
  if (bridged == 0) {
    /*
     * No canonical entry: this request's get_handler was never seen, or its entry
     * was LRU-evicted. There is no START to pair an END with, so nothing is
     * emitted -- but we must NOT return here. The alternate-key revocation below
     * is driven by `rgw_op_keys`, which is exactly the case an evicted canonical
     * entry used to strand.
     */
    count_diag(RGWTRACE_DIAG_REQUEST_END_MISSES);
  } else {
    count_diag(RGWTRACE_DIAG_REQUEST_END_HITS);
    /*
     * Emit straight from the map value, exactly as get_handler does: the context
     * is only READ here (emit_request_event copies it into the ringbuf record),
     * and the entry is deleted afterwards. The copy-to-the-stack-first rule
     * applies to map values used as an UPDATE SOURCE (see
     * reseed_thread_from_reqstate), not as a read source -- and a full on-stack
     * copy here would blow the 512-byte BPF stack budget for this program.
     *
     * Only a request whose trans_id was captured at get_handler has a START
     * marker; emitting an END for a context without one would fabricate a request
     * span with a synthetic key. The cleanup below still runs either way.
     */
    if (bridged->trans_id[0] != 0)
      emit_request_event(RGWTRACE_EVENT_REQUEST_END, bridged,
                         bpf_ktime_get_boot_ns());

    bpf_map_delete_elem(&rgw_ctx_by_reqstate, &rkey);
  }

  /*
   * Revoke the ALTERNATE key (the executing RGWOp*).
   *
   * The record comes from `rgw_op_keys`, NOT from the canonical bridge value: the
   * bridge is an LRU and the canonical entry may already be gone (that is the
   * `bridged == 0` branch above), while the alternate entry it named lives on.
   * Reading the key from a never-evicting plain HASH is what makes revocation
   * TOTAL -- i.e. what makes "every inserted alternate key is revoked" a fact
   * rather than a hope, and `inserts - revokes` a health metric rather than noise.
   *
   * The record also carries the OWNING request's identity, because we must only
   * delete the alternate entry while it still belongs to THIS request. RGWOp is
   * heap-allocated and its address is recycled: a NEWER request may already have
   * re-keyed this very address to itself (BPF_ANY overwrite at its own
   * rgw_process_authenticated, which always precedes any op it submits). Deleting
   * then would revoke a LIVE request's key and silently cost that request its whole
   * data path -- so we identity-check first and count the skip instead.
   */
  struct rgw_op_key_record *record = bpf_map_lookup_elem(&rgw_op_keys, &rkey);
  if (record != 0) {
    __u64 op_ptr = record->rgw_op_ptr;
    __u64 start_ns = record->start_ns;
    __u32 owner_tid = record->owner_tid;
    bpf_map_delete_elem(&rgw_op_keys, &rkey);

    struct reqstate_key okey = make_reqstate_key(op_ptr, tgid);
    struct rgw_request_ctx *alt = bpf_map_lookup_elem(&rgw_ctx_by_reqstate, &okey);
    if (alt == 0) {
      /* The alternate entry is already gone (LRU-evicted). Nothing to revoke:
       * the key does not exist, so it cannot outlive its request. */
      count_diag(RGWTRACE_DIAG_RGWOP_KEY_REVOKE_ABSENT);
    } else if (alt->start_ns == start_ns && alt->tid == owner_tid &&
               alt->pid == tgid) {
      bpf_map_delete_elem(&rgw_ctx_by_reqstate, &okey);
      count_diag(RGWTRACE_DIAG_RGWOP_KEY_REVOKES);
    } else {
      count_diag(RGWTRACE_DIAG_RGWOP_KEY_REVOKE_SKIPPED);
    }
  }

  /*
   * Clear this thread's request context ONLY when it still belongs to THIS
   * request. RGW/Beast pool threads are shared: after a coroutine migration the
   * context sitting on this tid may belong to another in-flight request, and
   * clearing it would silently un-correlate that request's RADOS ops.
   */
  struct rgw_request_ctx *cur = bpf_map_lookup_elem(&rgw_requests, &tid);
  if (cur != 0 && cur->req_state_ptr == rsp && cur->pid == tgid)
    bpf_map_delete_elem(&rgw_requests, &tid);

  return 0;
}

/*
 * Cross-thread re-seed bridge (design-cross-thread-correlation.md Stage 3), and
 * -- since the bridge became MULTI-KEY -- the place where a request's ALTERNATE
 * dpp identity is registered.
 *
 * Gated behind --correlate-cross-thread: the userspace attach code only wires
 * this probe up (to radosgw, at rgw_process_authenticated) when the flag is
 * set AND the varid-40 var_field is present, so with the flag off this program
 * is compiled but never attached and stays fully dormant.
 *
 * rgw_process_authenticated runs on the request execute thread T_e, whose
 * req_state* is pointer-identical to the one get_handler stored in
 * rgw_ctx_by_reqstate. On a hit we re-seed rgw_requests[T_e] with that
 * authoritative context so any RADOS op submitted synchronously on T_e inherits
 * the request's trans_id. On a miss we FAIL CLOSED: a foreign/stale context
 * lingering on this TID is deleted so _send_op stamps nothing rather than
 * mis-correlating; this request's own fresh context (same req_state*, same
 * tgid) is kept so a same-thread submit stays correlated.
 *
 * THE RGWOp* KEY. `op` (varid 41) is a `RGWOp*&` -- a REFERENCE to the caller's
 * pointer -- so the register holds an `RGWOp**` and exactly one user read of the
 * POINTEE yields the RGWOp*. That read is safe and proven: DWARF extraction only
 * emits this descriptor after verifying the parameter's type is a reference to a
 * pointer to `RGWOp`, and that `RGWOp` inherits `DoutPrefixProvider` at offset 0
 * (so the RGWOp* and the dpp RGW passes for it are numerically equal). The VALUE
 * is then used ONLY as an opaque bridge key -- never dereferenced.
 *
 * Why here: RGW threads a `const DoutPrefixProvider* dpp` down its data path, and
 * at most call sites inside `op->execute()` that dpp is the RGWOp (`this`), NOT
 * the req_state. Without this key the per-submit re-seed would miss on the entire
 * op data path and Phase B would recover nothing. This is the earliest site where
 * the executing RGWOp is available as a probeable parameter -- it is created by
 * `handler->get_op()` (whose result is a RETURN value, and return probes are
 * forbidden here) and passed straight into this function.
 *
 * The alternate key is written INTO the canonical entry's value before being used
 * as a key, so the destructor -- which only knows the req_state* -- can find and
 * REVOKE it. Both keys must die together.
 *
 * This eager clear is a first line of defence, not the whole one: it only fires
 * on threads that actually reach rgw_process_authenticated. The context copies
 * this probe scatters onto execute threads are revoked for good by the _send_op
 * liveness gate (request_ctx_is_live), which re-checks EVERY context against the
 * bridge before stamping.
 */
SEC("uprobe")
int uprobe_rgw_process_authenticated(struct pt_regs *ctx) {
  int varid = 40;
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf == 0)
    return 0;

  /*
   * Raw-pointer descriptor: the req_state* parameter's own value, register-only
   * at entry. A stack-located (unresolvable) descriptor yields 0, so we fail
   * closed and fall back to main's same-thread behavior.
   */
  __u64 rsp = fetch_param_ptr(ctx, vf);
  if (rsp == 0) {
    count_diag(RGWTRACE_DIAG_RESEED_BASE_UNRESOLVED);
    return 0;
  }

  __u32 tgid = get_pid();
  __u32 tid = get_tid();

  struct reqstate_key rkey = make_reqstate_key(rsp, tgid);
  struct rgw_request_ctx *bridged =
      bpf_map_lookup_elem(&rgw_ctx_by_reqstate, &rkey);
  if (bridged == 0) {
    /*
     * Miss: fail closed. If this thread still carries some OTHER request's
     * context (a different req_state* or a different process), clear it so
     * _send_op cannot stamp a stale/foreign trans_id. A context that is this
     * request's own is left in place so a same-thread submit stays correlated.
     */
    struct rgw_request_ctx *cur = bpf_map_lookup_elem(&rgw_requests, &tid);
    if (cur != 0 && (cur->req_state_ptr != rsp || cur->pid != tgid))
      bpf_map_delete_elem(&rgw_requests, &tid);
    count_diag(RGWTRACE_DIAG_RESEED_MISSES);
    return 0;
  }

  /* Copy to the stack: a map-value pointer is not a safe update source. */
  struct rgw_request_ctx ctx_copy = {};
  __builtin_memcpy(&ctx_copy, bridged, sizeof(ctx_copy));

  /*
   * Register the ALTERNATE key -- unless it is switched off for this run, in which
   * case the `RGWOp*&` parameter is not even read (see RGW_OP_BRIDGE_KEY_ENABLED:
   * the key is insurance, and it carries the website-retarget hazard, so it must
   * be droppable without a rebuild once the rig data says it buys nothing).
   */
  __u64 op_ptr = 0;
  if (RGW_OP_BRIDGE_KEY_ENABLED != 0) {
    int varid_op = 41;
    struct VarField *op_vf = bpf_map_lookup_elem(&hprobes, &varid_op);
    op_ptr = fetch_param_ptr_ref(ctx, op_vf);
  }

  if (RGW_OP_BRIDGE_KEY_ENABLED == 0) {
    /* Off by operator request. Counted so an empty RGWOp column in the run summary
     * can be told apart from an RGWOp key that was on and never fired. */
    count_diag(RGWTRACE_DIAG_RGWOP_KEY_DISABLED);
  } else if (op_ptr != 0 && ctx_copy.req_state_ptr != 0) {
    /*
     * A key nobody can revoke must never exist. So the REVOCATION RECORD is
     * written FIRST, and the alternate key is only inserted once the record is in
     * place:
     *
     *   record written -> key inserted   => the destructor will find the record
     *                                       (rgw_op_keys is a plain HASH; it never
     *                                       evicts) and revoke the key. TOTAL.
     *   record refused (map full)        => no key is inserted at all. FAIL CLOSED.
     *   record written, key insert fails => the record is deleted again, so it can
     *                                       never name a key that does not exist.
     *
     * Requires the canonical req_state* to be known (ctx_copy.req_state_ptr != 0):
     * the record is keyed by it, and without it the destructor could not look the
     * record up.
     */
    struct rgw_op_key_record record = {};
    record.rgw_op_ptr = op_ptr;
    record.start_ns = ctx_copy.start_ns;
    record.owner_tid = ctx_copy.tid;
    if (bpf_map_update_elem(&rgw_op_keys, &rkey, &record, BPF_ANY) != 0) {
      count_diag(RGWTRACE_DIAG_RGWOP_KEY_INDEX_DROPS);
    } else {
      ctx_copy.rgw_op_ptr = op_ptr;
      /*
       * Persist the alternate key inside the CANONICAL entry too. This is NOT what
       * the destructor revokes from (that is the record above, which survives an
       * LRU eviction of this entry); it is what lets a seed report WHICH key it hit
       * on (see reseed_thread_from_reqstate), and it keeps the two entries' values
       * identical.
       */
      if (bpf_map_update_elem(&rgw_ctx_by_reqstate, &rkey, &ctx_copy, BPF_ANY) != 0)
        count_diag(RGWTRACE_DIAG_REQSTATE_MAP_DROPS);

      struct reqstate_key okey = make_reqstate_key(op_ptr, tgid);
      /*
       * BPF_ANY: overwrite-on-reuse. A recycled RGWOp address is re-keyed to the
       * request that now owns it, and this always happens BEFORE that request
       * submits any op -- so a stale alternate key can never win a lookup against
       * its live owner.
       */
      if (bpf_map_update_elem(&rgw_ctx_by_reqstate, &okey, &ctx_copy, BPF_ANY) != 0) {
        count_diag(RGWTRACE_DIAG_REQSTATE_MAP_DROPS);
        /* The key was never inserted, so the record must not claim it was: a
         * record that names a nonexistent key would show up at the destructor as a
         * phantom REVOKE_ABSENT and corrupt the revocation identity. */
        bpf_map_delete_elem(&rgw_op_keys, &rkey);
      } else {
        count_diag(RGWTRACE_DIAG_RGWOP_KEY_INSERTS);
      }
    }
  } else {
    /*
     * No alternate key on this build/request: the request stays findable by its
     * req_state* alone. Ops submitted under an RGWOp dpp then MISS and are left
     * uncorrelated -- degraded, never wrong.
     */
    count_diag(RGWTRACE_DIAG_RGWOP_KEY_UNRESOLVED);
  }

  /* Hit: re-seed this execute thread with the authoritative context. */
  if (bpf_map_update_elem(&rgw_requests, &tid, &ctx_copy, BPF_ANY) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
  count_diag(RGWTRACE_DIAG_RESEED_HITS);
  return 0;
}

/*
 * PHASE B -- the per-submit re-seed. This is the probe that actually makes
 * cross-thread correlation work.
 *
 * WHY N SEED SITES CANNOT WORK. RGW/Beast runs each S3 request as an asio
 * coroutine that MIGRATES to a different io_context pool thread at every
 * `optional_yield`. Context written to rgw_requests[tid] at get_handler (and,
 * once, at rgw_process_authenticated) is abandoned at the very next yield, so a
 * RADOS op submitted after that migration finds nothing on its thread and is
 * emitted as an uncorrelated background op. A coroutine that yields M times needs
 * the context re-established at EVERY submit, not at N fixed instants.
 *
 * THE SITE. rgw_rados_operate is the last common frame before a RADOS submit: the
 * librados submit (`aio_operate` -> `op_submit` -> `_send_op`) runs
 * SYNCHRONOUSLY, on this very thread, inside this call, and only then does the
 * coroutine suspend awaiting completion. Seeding rgw_requests[current_tid] here
 * therefore puts the request's context on whatever thread the coroutine happens
 * to be running on at this instant, immediately before the submit -- no matter
 * how many times it has migrated. It exists as an out-of-line `T` symbol in TWO
 * overloads (ObjectReadOperation and ObjectWriteOperation); BOTH are probed, by
 * this same program body, bound by MANGLED linkage name in userspace so neither
 * can silently attach to the other's address.
 *
 * WHY IT NEEDS NO NEW MAP. `dpp` is arg0 of both overloads. Both `req_state` and
 * `RGWOp` inherit DoutPrefixProvider at DW_AT_data_member_location 0x00 -- which
 * extraction VERIFIES in DWARF (`dpp_base_offset` in src/dwarf_native.rs) and
 * refuses to guess -- so a request's dpp is numerically equal to its `req_state*`
 * or to its `RGWOp*`, both of which are keys in the MULTI-KEY bridge. The existing
 * bridge and the existing reseed helper apply verbatim.
 *
 * !!! THE dpp IS AN OPAQUE IDENTITY TOKEN. NEVER DEREFERENCE IT. !!!
 * Do not read through it, do not apply an inheritance offset to it, do not assume
 * its concrete type. RGW passes MANY other DoutPrefixProvider implementations
 * here -- stack DoutPrefix/DoutPrefixPipe wrappers, background/GC/LC threads --
 * whose pointers are neither req_state* nor RGWOp*. We only ever use the pointer
 * VALUE as a hash key. A foreign dpp simply MISSES the rgw_ctx_by_reqstate lookup
 * and correlates nothing; it cannot be mistaken for a request, and no memory is
 * ever read through it, so a wrong-typed dpp cannot produce a wrong answer or a
 * wild read. That is what makes this design safe where the "walk the dpp to reach
 * trans_id" approach (design doc SS7) was not: that one needed the dpp's CONCRETE
 * TYPE and a multiple-inheritance offset, and got them wrong. If you are tempted
 * to add a bpf_probe_read_user through `dpp` -- don't. Fail-closed by construction
 * is the entire point.
 *
 * WHY A MISS CLEARS A *SEEDED* CONTEXT. This is the fail-closed rule that makes
 * the per-submit seed safe, and it is not optional:
 *
 *   Request A runs an operate on pool thread T -- the seed puts A's context on T.
 *   A yields. Request B resumes on T and submits through a dpp we cannot key.
 *   If the miss left T alone, A's context would still be sitting there; A is
 *   genuinely still ALIVE, so the _send_op liveness gate would PASS it; and B's op
 *   would be stamped with A's trans_id. Confidently wrong.
 *
 * The liveness gate proves only that the cached request still EXISTS -- never that
 * it is the coroutine executing on this thread RIGHT NOW. Nothing available at
 * this probe can prove that (see the design doc's "current-coroutine identity"
 * section: the asio fiber stack is not a sound discriminator, because coroutine
 * stacks are pool-allocated and can neighbor each other). So on a miss we assume
 * NOTHING about a context PHASE B ITSELF SCATTERED onto this thread: it is
 * dropped, and the op this call is about to submit comes out uncorrelated.
 *
 * WHY A MISS MUST *NOT* CLEAR A *HOME* CONTEXT. The clear above was originally
 * unscoped -- any context on the thread was dropped -- and that shipped a real
 * regression, measured on a live cluster: a ListObjects request LOST all 16 of its
 * `rgw.bucket_list` shard ops, which the pre-Phase-B build correlated fine.
 *
 *   RGW issues those 16 shard reads through the cls_rgw AIO path
 *   (CLSRGWIssueBucketList -> IoCtx::aio_operate), which NEVER passes through
 *   rgw_rados_operate. They correlated only because get_handler had seeded
 *   rgw_requests[T] on the request's OWN thread T and nothing ever cleared it. One
 *   single foreign-dpp operate on T (the run showed exactly ONE) then wiped that
 *   context, and every one of the 16 later AIO submits on T found nothing.
 *
 * So the clear must be SCOPED to the contexts Phase B is responsible for:
 *
 *   HOME   (ctx->tid == current tid): get_handler put this context on this very
 *          thread, for the request that STARTED here. It is the pre-Phase-B
 *          same-thread correlation path, it predates this probe, and Phase B has no
 *          claim on it. PRESERVED. Clearing it buys nothing anyway: an AIO submit
 *          that never reaches an operate would keep inheriting whatever context is
 *          on the thread regardless, so the mis-correlation window the unscoped
 *          clear was meant to close stays open either way (see the ACCEPTED
 *          RESIDUAL HAZARD below).
 *   SEEDED (ctx->tid != current tid): a COPY that a re-seed migrated onto a thread
 *          that is NOT the request's get_handler thread. It is a Phase B artifact
 *          with no ownership claim on this thread, and leaving it here is exactly
 *          the stale-copy hazard Phase B multiplies. CLEARED.
 *
 * ctx->tid is the get_handler thread and is copied VERBATIM by every seed (nothing
 * ever rewrites it -- that is what keeps the collector's cross_thread label
 * honest), so this test is exact, not a heuristic.
 *
 * The two outcomes are counted separately (RGWTRACE_DIAG_OPERATE_*_CTX_CLEARED vs
 * RGWTRACE_DIAG_OPERATE_*_HOME_CTX_PRESERVED) so a live run shows how often each
 * happens.
 *
 * ACCEPTED RESIDUAL HAZARD (pre-existing, NOT introduced by Phase B). Preserving a
 * HOME context means another coroutine that migrates onto that request's home
 * thread and submits through a path that never reaches rgw_rados_operate (the AIO
 * path above) still inherits that request's trans_id. That hazard is inherent to
 * thread-keyed correlation on the non-operate submit path: it existed before Phase
 * B, passed the zero-mis-correlation e2e gate, and no clear at THIS probe can close
 * it (the submit in question never gets here). It is documented in
 * docs/design-cross-thread-correlation.md SS11, not papered over.
 *
 * The cost of the clear is real and is counted (RGWTRACE_DIAG_OPERATE_MISS_CTX_
 * CLEARED): a request's OWN operate through a wrapper dpp, on a MIGRATED thread,
 * loses its correlation. That is a coverage loss. Stamping it would be a
 * correctness loss, and one mis-correlated op poisons the entire tool's
 * credibility -- an uncorrelated op is a known unknown, a mis-correlated one is a
 * lie. The multi-key bridge is what keeps this cost small: a request's own operates
 * are keyed by BOTH its req_state* and its RGWOp*, so they HIT rather than miss.
 *
 * COST. One hprobes lookup, one register read (no user memory access), one bridge
 * lookup, and -- only on a hit -- one stack copy plus one rgw_requests update. No
 * probe_read_user at all, no loops. This is a small fraction of the work _send_op
 * already does for the very op this call is about to submit, and it is dwarfed by
 * the RADOS round-trip that follows.
 */
static __always_inline void operate_drop_seeded_ctx(__u32 tid, __u32 cleared_diag,
                                                    __u32 preserved_diag) {
  struct rgw_request_ctx *cur = bpf_map_lookup_elem(&rgw_requests, &tid);
  if (cur == 0)
    return;

  /* HOME: this thread is the get_handler thread of the request whose context is
   * sitting here. Not a Phase B copy; not Phase B's to drop. */
  if (cur->tid == tid) {
    count_diag(preserved_diag);
    return;
  }

  /* SEEDED: a Phase B copy on a thread that does not own the request. */
  bpf_map_delete_elem(&rgw_requests, &tid);
  count_diag(cleared_diag);
}

static __always_inline int rgw_rados_operate_seed(struct pt_regs *ctx, int varid) {
  __u32 tgid = get_pid();
  __u32 tid = get_tid();

  /*
   * Register-only raw-pointer descriptor: the dpp parameter's own VALUE. The
   * register comes from DWARF (arg0 => rdi => DWARF reg 5 on x86-64, but nothing
   * here assumes that).
   *
   * AN UNRESOLVED dpp FAILS CLOSED EXACTLY LIKE A FOREIGN ONE, and for exactly the
   * same reason. A missing descriptor, a stack-located descriptor, or a NULL `dpp`
   * argument all leave us unable to say WHICH request is submitting here -- and
   * that is precisely the state in which the context lingering on this pool thread
   * must not be trusted. Request A can leave its context on every thread it ever
   * ran an operate on; request B can then resume on one of them and submit through
   * an unresolvable dpp; A is genuinely still ALIVE, so the _send_op liveness gate
   * would PASS A's context and stamp B's op with A's trans_id. Returning early
   * without clearing (the old behavior) was therefore a mis-correlation source and
   * not merely a coverage gap.
   *
   * It clears a SEEDED context only, exactly like the foreign-dpp miss: a HOME
   * context (one get_handler placed on its own request's thread) is not a Phase B
   * copy and is preserved -- see operate_drop_seeded_ctx.
   *
   * The clear is counted SEPARATELY from the foreign-dpp miss, because the two say
   * completely different things: a foreign-dpp miss is the expected steady state on
   * a busy gateway, while a nonzero OPERATE_UNRESOLVED_CTX_CLEARED means either
   * that RGW passes null dpps on this path or that this build's descriptor is
   * broken -- and in the latter case correlation is dead and must not look quiet.
   * (Userspace additionally refuses to attach these probes at all without a proven
   * descriptor, so the descriptor-shaped causes should be unreachable in practice.)
   */
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf == 0) {
    count_diag(RGWTRACE_DIAG_OPERATE_BASE_UNRESOLVED);
    operate_drop_seeded_ctx(tid, RGWTRACE_DIAG_OPERATE_UNRESOLVED_CTX_CLEARED,
                            RGWTRACE_DIAG_OPERATE_UNRESOLVED_HOME_CTX_PRESERVED);
    return 0;
  }

  __u64 dpp = fetch_param_ptr(ctx, vf);
  if (dpp == 0) {
    count_diag(RGWTRACE_DIAG_OPERATE_BASE_UNRESOLVED);
    operate_drop_seeded_ctx(tid, RGWTRACE_DIAG_OPERATE_UNRESOLVED_CTX_CLEARED,
                            RGWTRACE_DIAG_OPERATE_UNRESOLVED_HOME_CTX_PRESERVED);
    return 0;
  }

  /*
   * The seeded context is a COPY of the bridge entry, so its start_ns/tid/pid are
   * the bridge entry's own. _send_op's liveness gate re-derives the bridge key
   * from that copy and compares those same fields, so a Phase-B-seeded context
   * matches its bridge entry BY CONSTRUCTION and is stamped rather than dropped.
   * Its `tid` stays the get_handler thread (not this one), which is exactly what
   * makes the collector label the resulting op `cross_thread` when the submit
   * happened on a migrated thread.
   *
   * WHICH KEY the dpp matched is counted separately from the fact that it matched.
   * That split is the whole measurement behind the `RGWOp*` alternate key: if RGW
   * turns out to pass the req_state as the dpp here, the alternate key -- and the
   * S3-website-retarget hazard it carries -- can simply be switched off.
   */
  int via = reseed_thread_from_reqstate(dpp, tgid, tid);
  if (via != BRIDGE_SEED_MISS) {
    count_diag(RGWTRACE_DIAG_OPERATE_SEED_HITS);
    if (via == BRIDGE_SEED_VIA_REQSTATE)
      count_diag(RGWTRACE_DIAG_OPERATE_SEED_HITS_REQSTATE);
    else if (via == BRIDGE_SEED_VIA_RGWOP)
      count_diag(RGWTRACE_DIAG_OPERATE_SEED_HITS_RGWOP);
    else
      count_diag(RGWTRACE_DIAG_OPERATE_SEED_HITS_UNATTRIBUTED);
    return 0;
  }

  count_diag(RGWTRACE_DIAG_OPERATE_SEED_MISSES);

  /* Miss: fail closed (see the header comment). Assume nothing about a context
   * PHASE B put on this thread -- but do not touch the HOME context that
   * get_handler put here for this thread's own request, which Phase B did not
   * create and which the pre-Phase-B same-thread path depends on. */
  operate_drop_seeded_ctx(tid, RGWTRACE_DIAG_OPERATE_MISS_CTX_CLEARED,
                          RGWTRACE_DIAG_OPERATE_MISS_HOME_CTX_PRESERVED);
  return 0;
}

/*
 * rgw_rados_operate(dpp, IoCtx&, string const&, ObjectReadOperation*, list*,
 * optional_yield, int) -- the READ overload. Its dpp descriptor is hprobe slot 60.
 */
SEC("uprobe")
int uprobe_rgw_rados_operate_read(struct pt_regs *ctx) {
  return rgw_rados_operate_seed(ctx, 60);
}

/*
 * rgw_rados_operate(dpp, IoCtx&, string const&, ObjectWriteOperation*,
 * optional_yield, int) -- the WRITE overload. Its dpp descriptor is hprobe slot
 * 70.
 *
 * The two overloads get SEPARATE hprobe slots (rather than sharing one) so that
 * each address is only ever read with the descriptor extracted from that same
 * definition. They are expected to agree (dpp is arg0 in both), but "expected to
 * agree" is not a thing this code needs to rely on.
 */
SEC("uprobe")
int uprobe_rgw_rados_operate_write(struct pt_regs *ctx) {
  return rgw_rados_operate_seed(ctx, 70);
}

SEC("uprobe")
int uprobe_send_op(struct pt_regs *ctx) {
  int varid = 0;
  struct client_op_key key = {};
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);

  if (vf != 0) {
    __u64 v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    rgwtrace_probe_read_user(&key.tid, sizeof(key.tid), (void *)tid_addr);
  }

  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf != 0) {
    __u64 v = fetch_register(ctx, vf->varloc.reg);
    __u64 cid_addr = fetch_var_member_addr(v, vf);
    rgwtrace_probe_read_user(&key.cid, sizeof(key.cid), (void *)cid_addr);
  }

  if (bpf_map_update_elem(&rados_ops, &key, &zero_rados_op, 0) != 0) {
    count_diag(RGWTRACE_DIAG_RADOS_MAP_DROPS);
    return 0;
  }
  struct rados_op_state *state = bpf_map_lookup_elem(&rados_ops, &key);
  if (state == 0) {
    count_diag(RGWTRACE_DIAG_RADOS_MAP_DROPS);
    return 0;
  }

  struct rgwtrace_rados_event *event = &state->event;
  __builtin_memset(event, 0, sizeof(*event));
  event->sent_ns = bpf_ktime_get_boot_ns();
  event->tid = key.tid;
  event->cid = key.cid;

  __u32 thread_id = get_tid();
  event->send_tid = thread_id;
  struct rgw_request_ctx *request = bpf_map_lookup_elem(&rgw_requests, &thread_id);
  /*
   * Stamp the request identity onto the op ONLY while the request that context
   * belongs to is still alive (see request_ctx_is_live). A context copy left
   * behind on a pooled thread by an ENDED request must never stamp a later op --
   * that would attribute it to the wrong request. A rejected context leaves the
   * op uncorrelated, which the collector then reports as background/inferred.
   */
  if (request != 0 && request_ctx_is_live(request)) {
    event->flags |= request->flags & RGWTRACE_TRUNC_TRANS_ID;
    __builtin_memcpy(event->trans_id, request->trans_id,
                     sizeof(event->trans_id));
  }

  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf != 0) {
    __u64 v = fetch_register(ctx, vf->varloc.reg);
    __u64 osd_addr = fetch_var_member_addr(v, vf);
    rgwtrace_probe_read_user(&event->target_osd, sizeof(event->target_osd),
                             (void *)osd_addr);
  }

  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  int name_len = 0;
  if (vf != 0) {
    __u64 v = fetch_register(ctx, vf->varloc.reg);
    __u64 len_addr = fetch_var_member_addr(v, vf);
    rgwtrace_probe_read_user(&name_len, sizeof(name_len), (void *)len_addr);
  }

  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  __u64 name_base = 0;
  if (vf != 0) {
    __u64 v = fetch_register(ctx, vf->varloc.reg);
    __u64 name_base_addr = fetch_var_member_addr(v, vf);
    rgwtrace_probe_read_user(&name_base, sizeof(name_base),
                             (void *)name_base_addr);
  }

  __u32 read_len = 0;
  if (name_len > 0) {
    if (name_len >= MAX_OBJECT_NAME) {
      event->flags |= RGWTRACE_TRUNC_OBJECT_NAME;
      read_len = MAX_OBJECT_NAME - 1;
    } else {
      read_len = name_len;
    }
  }
  read_len &= MAX_OBJECT_NAME - 1;
  asm volatile("%0 &= 127" : "+r"(read_len));
  if (read_len > 0 && name_base > 0)
    rgwtrace_probe_read_user(event->object_name, read_len, (void *)name_base);

  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf != 0) {
    __u64 v = fetch_register(ctx, vf->varloc.reg);
    __u64 flags_addr = fetch_var_member_addr(v, vf);
    rgwtrace_probe_read_user(&event->rw, sizeof(event->rw), (void *)flags_addr);
  }

  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf != 0) {
    __u64 v = fetch_register(ctx, vf->varloc.reg);
    __u64 pool_addr = fetch_var_member_addr(v, vf);
    rgwtrace_probe_read_user(&event->pool, sizeof(event->pool), (void *)pool_addr);
  }

  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf != 0) {
    __u64 v = fetch_register(ctx, vf->varloc.reg);
    __u64 seed_addr = fetch_var_member_addr(v, vf);
    rgwtrace_probe_read_user(&event->pg_seed, sizeof(event->pg_seed),
                             (void *)seed_addr);
  }

  for (int i = 0; i < MAX_ACTING; ++i)
    event->acting[i] = -1;

  ++varid;
  __u64 acting_start = 0;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf == 0)
    return 0;
  __u64 v = fetch_register(ctx, vf->varloc.reg);
  __u64 acting_start_addr = fetch_var_member_addr(v, vf);
  rgwtrace_probe_read_user(&acting_start, sizeof(acting_start),
                           (void *)acting_start_addr);

  ++varid;
  __u64 acting_finish = 0;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf == 0)
    return 0;
  v = fetch_register(ctx, vf->varloc.reg);
  __u64 acting_finish_addr = fetch_var_member_addr(v, vf);
  rgwtrace_probe_read_user(&acting_finish, sizeof(acting_finish),
                           (void *)acting_finish_addr);

  if (acting_start > 0 && acting_finish >= acting_start) {
    __u64 acting_bytes = acting_finish - acting_start;
    if ((acting_bytes % sizeof(int)) == 0) {
      int acting_size = acting_bytes / sizeof(int);
      if (acting_size > MAX_ACTING) {
        event->flags |= RGWTRACE_TRUNC_ACTING;
        acting_size = MAX_ACTING;
      }
      for (int i = 0; i < MAX_ACTING; ++i) {
        if (i >= acting_size)
          break;
        if (rgwtrace_probe_read_user(&(event->acting[i]), sizeof(int),
                                     (void *)(acting_start + i * sizeof(int))) != 0) {
          event->acting[i] = -1;
          break;
        }
      }
    }
  }

  ++varid;
  __u64 ops_start = 0;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf == 0)
    return 0;
  v = fetch_register(ctx, vf->varloc.reg);
  __u64 ops_start_addr = fetch_var_member_addr(v, vf);
  rgwtrace_probe_read_user(&ops_start, sizeof(ops_start),
                           (void *)ops_start_addr);

  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf == 0)
    return 0;
  v = fetch_register(ctx, vf->varloc.reg);
  __u64 ops_size_addr = fetch_var_member_addr(v, vf);
  rgwtrace_probe_read_user(&event->ops_size, sizeof(event->ops_size),
                           (void *)ops_size_addr);

  if (event->ops_size > MAX_RADOS_OPS) {
    event->flags |= RGWTRACE_TRUNC_RADOS_OPS;
    event->ops_size = MAX_RADOS_OPS;
  }
  for (__u32 i = 0; i < MAX_RADOS_OPS; ++i) {
    if (i >= event->ops_size)
      break;

    rgwtrace_probe_read_user(&(event->ops[i]), sizeof(event->ops[i]),
                             (void *)ops_start);
    if (ceph_osd_op_extent(event->ops[i])) {
      rgwtrace_probe_read_user(
          &event->offset, sizeof(event->offset),
          (void *)(ops_start + CEPH_OSD_OP_EXTENT_OFFSET_OFFSET));
      rgwtrace_probe_read_user(
          &event->length, sizeof(event->length),
          (void *)(ops_start + CEPH_OSD_OP_EXTENT_LENGTH_OFFSET));
    } else if (ceph_osd_op_call(event->ops[i])) {
      __u8 cls_len = 0;
      __u8 method_len = 0;
      rgwtrace_probe_read_user(&cls_len, sizeof(cls_len),
                               (void *)ops_start + CEPH_OSD_OP_CLS_CLASS_OFFSET);
      rgwtrace_probe_read_user(&method_len, sizeof(method_len),
                               (void *)ops_start + CEPH_OSD_OP_CLS_METHOD_OFFSET);

      __u64 carriage = 0;
      __u64 raw = 0;
      __u64 data = 0;
      rgwtrace_probe_read_user(&carriage, sizeof(carriage),
                               (void *)ops_start + CEPH_OSD_OP_BUFFER_CARRIAGE_OFFSET);
      rgwtrace_probe_read_user(&raw, sizeof(raw),
                               (void *)carriage + CEPH_OSD_OP_BUFFER_RAW_OFFSET);
      rgwtrace_probe_read_user(&data, sizeof(data),
                               (void *)raw + CEPH_OSD_OP_BUFFER_DATA_OFFSET);

      /*
       * The call indata is `class || method || payload`, so the method starts
       * at the class name's FULL wire length. Only the COPY lengths are
       * clamped; cls_len itself is never rewritten, because clamping it used to
       * move the method read into the middle of a long class name (`refcount`,
       * `timeindex`) and garble the method with no truncation flag.
       */
      __u32 cls_read_len = cls_len;
      if (cls_len >= sizeof(event->cls_ops[i].cls_name)) {
        event->flags |= RGWTRACE_TRUNC_CLS_NAME;
        cls_read_len = sizeof(event->cls_ops[i].cls_name) - 1;
      }
      __u32 method_read_len = method_len;
      if (method_len >= sizeof(event->cls_ops[i].method_name)) {
        event->flags |= RGWTRACE_TRUNC_METHOD_NAME;
        method_read_len = sizeof(event->cls_ops[i].method_name) - 1;
      }
      cls_read_len &= sizeof(event->cls_ops[i].cls_name) - 1;
      asm volatile("%0 &= 15" : "+r"(cls_read_len));
      method_read_len &= sizeof(event->cls_ops[i].method_name) - 1;
      asm volatile("%0 &= 31" : "+r"(method_read_len));
      rgwtrace_probe_read_user(event->cls_ops[i].cls_name, cls_read_len,
                               (void *)data);
      rgwtrace_probe_read_user(event->cls_ops[i].method_name, method_read_len,
                               (void *)(data + cls_len));
    }

    ops_start += CEPH_OSD_OP_SIZE;
  }

  return 0;
}

SEC("uprobe")
int uprobe_finish_op(struct pt_regs *ctx) {
  int varid = 20;
  struct client_op_key key = {};
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);

  if (vf != 0) {
    __u64 v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    rgwtrace_probe_read_user(&key.tid, sizeof(key.tid), (void *)tid_addr);
  }

  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf != 0) {
    __u64 v = fetch_register(ctx, vf->varloc.reg);
    __u64 cid_addr = fetch_var_member_addr(v, vf);
    rgwtrace_probe_read_user(&key.cid, sizeof(key.cid), (void *)cid_addr);
  }

  struct rados_op_state *state = bpf_map_lookup_elem(&rados_ops, &key);
  if (state == 0) {
    count_diag(RGWTRACE_DIAG_RADOS_FINISH_MISSES);
    return 0;
  }

  state->event.finish_ns = bpf_ktime_get_boot_ns();
  state->event.pid = get_pid();

  struct rgwtrace_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (e == 0) {
    count_diag(RGWTRACE_DIAG_RINGBUF_RADOS_DROPS);
    bpf_map_delete_elem(&rados_ops, &key);
    return 0;
  }

  __builtin_memset(e, 0, sizeof(*e));
  e->type = RGWTRACE_EVENT_RADOS_OP;
  e->data.rados = state->event;
  bpf_ringbuf_submit(e, 0);
  bpf_map_delete_elem(&rados_ops, &key);
  return 0;
}
