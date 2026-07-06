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
   * BPF-internal only: the request's req_state* captured at get_handler, used
   * to key the cross-thread rgw_ctx_by_reqstate bridge. Not a wire field --
   * emit_request_event copies only the on-wire members, so rgwtrace_events.h /
   * events.rs are unaffected.
   */
  __u64 req_state_ptr;
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
 * Cross-thread context bridge (design-cross-thread-correlation.md). Populated at
 * get_handler, read at rgw_process_authenticated under --correlate-cross-thread.
 * Keyed by (req_state*, tgid) because req_state pointers can collide across
 * address spaces while --pid is optional. PID-scoped; the u32 pad is explicit
 * and zeroed on every key so hashing is deterministic.
 *
 * Unlike rados_ops / rgw_requests above, this map is deliberately LRU_HASH: it
 * is insert-only (there is NO lifecycle delete), so it needs eviction to bound
 * growth, and its consumers fail closed on stale entries (they re-check the
 * req_state pointer and tgid identity). Eviction of a stale entry here is
 * harmless, so LRU is correct precisely where it is wrong for the two
 * lifecycle-managed maps.
 *
 * max_entries is sized well above the two lifecycle maps because LRU_HASH
 * reserves ~128 free nodes per CPU that touches it: on a 64-CPU host an
 * 8192-entry LRU map is entirely consumed by per-CPU freelists and evicts live
 * entries continuously (the regression that forced rados_ops/rgw_requests back
 * to plain HASH). Here eviction only degrades bridge hit rate rather than
 * dropping ops, but 65536 keeps 128*cores well under capacity so correlation
 * stays useful on the many-core hosts that exposed the freelist behavior.
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
  __uint(max_entries, 65536);
} rgw_ctx_by_reqstate SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, struct VarField);
  __uint(max_entries, 8192);
} hprobes SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

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
  struct rgwtrace_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (e == 0) {
    count_diag(RGWTRACE_DIAG_RINGBUF_REQUEST_DROPS);
    return;
  }

  __builtin_memset(e, 0, sizeof(*e));
  e->type = type;
  e->data.request.start_ns = ctx->start_ns;
  e->data.request.end_ns = end_ns;
  e->data.request.pid = ctx->pid;
  e->data.request.tid = ctx->tid;
  e->data.request.flags = ctx->flags;
  __builtin_memcpy(e->data.request.trans_id, ctx->trans_id,
                   sizeof(e->data.request.trans_id));
  bpf_ringbuf_submit(e, 0);
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
     * Single-marker model: RGWREST::get_handler is the only safe request probe.
     * RGW offers no request-completion probe (a process_request return probe was
     * observed to crash RGW live), so exactly one marker is emitted -- the END
     * event carries both the seeded start_ns and the probe-time end_ns. No
     * REQUEST_START is emitted; it would be informationally redundant.
     */
    emit_request_event(RGWTRACE_EVENT_REQUEST_END, request,
                       bpf_ktime_get_boot_ns());
  }

  /*
   * Stage 1: populate the (req_state*, tgid)-keyed context bridge. Placed after
   * the trans_id read + marker emission so those are byte-for-byte unaffected.
   * Only when the slot-30 req_state* came from a register (register-only by
   * design) and is non-null. Overwrite-on-reuse (BPF_ANY) is the aliasing cure.
   * Nothing reads this map yet, so live behavior is unchanged.
   */
  if (req_state_is_reg && req_state_base > 0) {
    request->req_state_ptr = req_state_base;
    struct reqstate_key rkey = {};
    rkey.req_state_ptr = req_state_base;
    rkey.tgid = get_pid();
    if (bpf_map_update_elem(&rgw_ctx_by_reqstate, &rkey, request, BPF_ANY) != 0)
      count_diag(RGWTRACE_DIAG_REQSTATE_MAP_DROPS);
  }

  return 0;
}

/*
 * Cross-thread re-seed bridge (design-cross-thread-correlation.md Stage 3).
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
 * tgid) is kept so a same-thread submit stays correlated. _send_op is
 * unchanged.
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

  struct reqstate_key rkey = {};
  rkey.req_state_ptr = rsp;
  rkey.tgid = tgid;

  struct rgw_request_ctx *bridged =
      bpf_map_lookup_elem(&rgw_ctx_by_reqstate, &rkey);
  if (bridged != 0) {
    /*
     * Hit: re-seed this execute thread with the authoritative context. Copy
     * the map value onto the stack first so the update reads a verifier-known
     * source (a direct map-value pointer as the update source is not a safe
     * pattern here).
     */
    struct rgw_request_ctx ctx_copy = {};
    __builtin_memcpy(&ctx_copy, bridged, sizeof(ctx_copy));
    count_diag(RGWTRACE_DIAG_RESEED_HITS);
    if (bpf_map_update_elem(&rgw_requests, &tid, &ctx_copy, BPF_ANY) != 0)
      count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
    return 0;
  }

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
  if (request != 0) {
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

      if (cls_len >= sizeof(event->cls_ops[i].cls_name)) {
        event->flags |= RGWTRACE_TRUNC_CLS_NAME;
        cls_len = sizeof(event->cls_ops[i].cls_name) - 1;
      }
      if (method_len >= sizeof(event->cls_ops[i].method_name)) {
        event->flags |= RGWTRACE_TRUNC_METHOD_NAME;
        method_len = sizeof(event->cls_ops[i].method_name) - 1;
      }
      __u32 cls_read_len = cls_len;
      cls_read_len &= sizeof(event->cls_ops[i].cls_name) - 1;
      asm volatile("%0 &= 7" : "+r"(cls_read_len));
      __u32 method_read_len = method_len;
      method_read_len &= sizeof(event->cls_ops[i].method_name) - 1;
      asm volatile("%0 &= 31" : "+r"(method_read_len));
      rgwtrace_probe_read_user(event->cls_ops[i].cls_name, cls_read_len,
                               (void *)data);
      rgwtrace_probe_read_user(event->cls_ops[i].method_name, method_read_len,
                               (void *)data + cls_len);
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
