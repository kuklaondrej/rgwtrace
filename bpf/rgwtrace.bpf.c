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
  __u64 rgw_request_id;
  __u32 pid;
  __u32 tid;
  __u32 flags;
  char rgw_req_id[MAX_RGW_REQ_ID];
  char trans_id[MAX_TRANS_ID];
};

#define RGWTRACE_ACTIVE_CTX_DEPTH 8
#define RGWTRACE_ACTIVE_CTX_TTL_NS 100000000ULL
#define RGWTRACE_RADOS_WRITER_AIO_OFFSET 0x08
#define RGWTRACE_RADOS_WRITER_DPP_OFFSET 0x2f8
#define RGWTRACE_RADOS_WRITER_CTOR_SLOT_OFFSET 0x1a8
#define RGWTRACE_PIPE_NEXT_OFFSET 0x08
#define RGWTRACE_HEAD_PROCESSOR_PROCESSOR_OFFSET 0x30
#define RGWTRACE_PUT_PROCESSOR_WRITER_OFFSET 0x2c8
#define RGWTRACE_MANIFEST_PROCESSOR_DPP_OFFSET 0xf70

#if defined(__TARGET_ARCH_x86)
#define RGWTRACE_ABI_THIS_REG 5
#elif defined(__TARGET_ARCH_arm64)
#define RGWTRACE_ABI_THIS_REG 0
#endif

struct active_rgw_context_frame {
  __u8 valid;
  __u64 expires_ns;
  struct rgw_request_ctx request;
};

struct active_rgw_context_stack {
  __u32 depth;
  struct active_rgw_context_frame frames[RGWTRACE_ACTIVE_CTX_DEPTH];
};

struct objecter_op_ctx {
  struct rgw_request_ctx request;
  __u32 source;
};

struct pending_data_processor_ctx {
  __u64 out_processor;
  __u64 dpp;
};

struct pending_stripe_obj_ctx {
  __u64 writer;
  __u64 stripe_obj;
  struct rgw_request_ctx request;
};

static struct rados_op_state zero_rados_op = {};
static struct active_rgw_context_stack zero_active_stack = {};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct client_op_key);
  __type(value, struct rados_op_state);
  __uint(max_entries, 8192);
} rados_ops SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct rgw_request_ctx);
  __uint(max_entries, 8192);
} rgw_requests SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u64);
  __type(value, struct rgw_request_ctx);
  __uint(max_entries, 16384);
} rgw_requests_by_req SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u64);
  __type(value, struct rgw_request_ctx);
  __uint(max_entries, 16384);
} rgw_req_states SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u64);
  __type(value, struct rgw_request_ctx);
  __uint(max_entries, 16384);
} rgw_ops SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u64);
  __type(value, struct rgw_request_ctx);
  __uint(max_entries, 16384);
} rgw_dpps SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u64);
  __type(value, struct rgw_request_ctx);
  __uint(max_entries, 16384);
} rgw_aios SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u64);
  __type(value, struct rgw_request_ctx);
  __uint(max_entries, 16384);
} rados_writers SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u64);
  __type(value, struct rgw_request_ctx);
  __uint(max_entries, 16384);
} rgw_rados_objs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64);
  __type(value, struct objecter_op_ctx);
  __uint(max_entries, 16384);
} objecter_ops SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct active_rgw_context_stack);
  __uint(max_entries, 8192);
} active_rgw_contexts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct pending_data_processor_ctx);
  __uint(max_entries, 8192);
} pending_data_processors SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct pending_stripe_obj_ctx);
  __uint(max_entries, 8192);
} pending_stripe_objs SEC(".maps");

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
const volatile bool RGWTRACE_ATTACH_SCOPED_RETURN_PROBES = false;

static __always_inline void copy_request_ctx(struct rgw_request_ctx *dst,
                                             const struct rgw_request_ctx *src) {
  __builtin_memcpy(dst, src, sizeof(*dst));
}

static __always_inline void read_string_field(struct pt_regs *ctx,
                                              int len_varid,
                                              int base_varid,
                                              char *dst,
                                              __u32 dst_size,
                                              __u32 *flags,
                                              __u32 trunc_flag) {
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &len_varid);
  __u64 value_len = 0;
  if (vf == 0)
    return;

  __u64 v = fetch_var_value(ctx, vf);
  __u64 len_addr = fetch_var_member_addr(v, vf);
  rgwtrace_probe_read_user(&value_len, sizeof(value_len), (void *)len_addr);

  vf = bpf_map_lookup_elem(&hprobes, &base_varid);
  if (vf == 0)
    return;

  __u64 value_base = 0;
  v = fetch_var_value(ctx, vf);
  __u64 base_addr = fetch_var_member_addr(v, vf);
  rgwtrace_probe_read_user(&value_base, sizeof(value_base), (void *)base_addr);

  if (value_len > 0 && value_base > 0) {
    if (value_len >= dst_size)
      *flags |= trunc_flag;
    rgwtrace_probe_read_user_str(dst, dst_size, (void *)value_base);
  }
}

static __always_inline void copy_request_ctx_to_rados_event(
    struct rgwtrace_rados_event *event,
    struct rgw_request_ctx *request,
    __u32 source) {
  event->rgw_request_id = request->rgw_request_id;
  event->flags |= request->flags & RGWTRACE_TRUNC_TRANS_ID;
  event->correlation_source = source;
  __builtin_memcpy(event->rgw_req_id, request->rgw_req_id,
                   sizeof(event->rgw_req_id));
  __builtin_memcpy(event->trans_id, request->trans_id,
                   sizeof(event->trans_id));
}

static __always_inline int push_active_request_ctx(struct rgw_request_ctx *request) {
  __u32 thread_id = get_tid();
  __u64 now = bpf_ktime_get_boot_ns();
  __u64 expires_ns = bpf_ktime_get_boot_ns() + RGWTRACE_ACTIVE_CTX_TTL_NS;
  struct active_rgw_context_stack *stack =
      bpf_map_lookup_elem(&active_rgw_contexts, &thread_id);
  if (stack == 0) {
    if (bpf_map_update_elem(&active_rgw_contexts, &thread_id,
                            &zero_active_stack, 0) != 0) {
      count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
      return 0;
    }
    stack = bpf_map_lookup_elem(&active_rgw_contexts, &thread_id);
    if (stack == 0) {
      count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
      return 0;
    }
  }

  /*
   * Without return probes, keep one fresh frame reusable for short multi-submit
   * RADOS paths instead of growing the stack indefinitely. With return probes
   * enabled, push real stack frames and let uretprobes pop them.
   */
  if (!RGWTRACE_ATTACH_SCOPED_RETURN_PROBES) {
#pragma unroll
    for (int i = RGWTRACE_ACTIVE_CTX_DEPTH - 1; i >= 0; --i) {
      if (stack->depth > i) {
        if (stack->frames[i].valid && stack->frames[i].expires_ns >= now) {
          stack->frames[i].expires_ns = expires_ns;
          if (request != 0)
            copy_request_ctx(&stack->frames[i].request, request);
          return 0;
        }
      }
    }
    if (stack->depth > 0)
      stack->depth = 0;
  }

  __u32 idx = stack->depth;
  if (idx >= RGWTRACE_ACTIVE_CTX_DEPTH) {
    if (idx < 1024)
      stack->depth = idx + 1;
    else
      stack->depth = RGWTRACE_ACTIVE_CTX_DEPTH + 1;
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
    return 0;
  }

#pragma unroll
  for (int i = 0; i < RGWTRACE_ACTIVE_CTX_DEPTH; ++i) {
    if (idx == i) {
      stack->frames[i].valid = request != 0;
      stack->frames[i].expires_ns = expires_ns;
      if (request != 0)
        copy_request_ctx(&stack->frames[i].request, request);
    }
  }
  stack->depth = idx + 1;
  return 0;
}

static __always_inline void clear_active_request_ctx(void) {
  __u32 thread_id = get_tid();
  bpf_map_delete_elem(&active_rgw_contexts, &thread_id);
}

static __always_inline void pop_active_request_ctx(void) {
  __u32 thread_id = get_tid();
  struct active_rgw_context_stack *stack =
      bpf_map_lookup_elem(&active_rgw_contexts, &thread_id);
  if (stack == 0)
    return;

  if (stack->depth == 0) {
    bpf_map_delete_elem(&active_rgw_contexts, &thread_id);
    return;
  }

  stack->depth -= 1;
  if (stack->depth == 0)
    bpf_map_delete_elem(&active_rgw_contexts, &thread_id);
}

static __always_inline int copy_current_active_request_ctx(
    struct rgw_request_ctx *request, bool consume) {
  __u32 thread_id = get_tid();
  __u64 now = bpf_ktime_get_boot_ns();
  struct active_rgw_context_stack *stack =
      bpf_map_lookup_elem(&active_rgw_contexts, &thread_id);
  if (stack == 0 || stack->depth == 0)
    return 0;

#pragma unroll
  for (int i = RGWTRACE_ACTIVE_CTX_DEPTH - 1; i >= 0; --i) {
    if (stack->depth > i) {
      if (stack->frames[i].valid) {
        if (stack->frames[i].expires_ns < now) {
          stack->frames[i].valid = 0;
          continue;
        }
        copy_request_ctx(request, &stack->frames[i].request);
        if (consume) {
          stack->frames[i].valid = 0;
          stack->depth = i;
          if (i == 0)
            bpf_map_delete_elem(&active_rgw_contexts, &thread_id);
        }
        return 1;
      }
    }
  }
  bpf_map_delete_elem(&active_rgw_contexts, &thread_id);
  return 0;
}

static __always_inline struct rgw_request_ctx *
lookup_current_thread_request(void) {
  __u32 thread_id = get_tid();
  return bpf_map_lookup_elem(&rgw_requests, &thread_id);
}

static __always_inline struct rgw_request_ctx *
prefer_newer_current_thread_request(struct rgw_request_ctx *request) {
  if (request == 0)
    return 0;

  struct rgw_request_ctx *current = lookup_current_thread_request();
  if (current != 0 && current->start_ns > request->start_ns)
    return current;

  return request;
}

static __always_inline int push_current_request_ctx_no_clear(void) {
  struct rgw_request_ctx *request = lookup_current_thread_request();
  if (request == 0)
    return 0;

  push_active_request_ctx(request);
  return 1;
}

static __always_inline struct rgw_request_ctx *
lookup_request_ctx_for_dpp(__u64 dpp) {
  if (dpp != 0) {
    struct rgw_request_ctx *request = bpf_map_lookup_elem(&rgw_ops, &dpp);
    if (request != 0)
      return prefer_newer_current_thread_request(request);
    request = bpf_map_lookup_elem(&rgw_req_states, &dpp);
    if (request != 0)
      return prefer_newer_current_thread_request(request);
    request = bpf_map_lookup_elem(&rgw_dpps, &dpp);
    return prefer_newer_current_thread_request(request);
  }
  return 0;
}

static __always_inline int push_context_for_dpp_no_clear(__u64 dpp) {
  struct rgw_request_ctx *request = lookup_request_ctx_for_dpp(dpp);
  if (request == 0)
    return 0;
  push_active_request_ctx(request);
  return 1;
}

static __always_inline int cache_writer_context_from_dpp(__u64 writer,
                                                         __u64 dpp) {
  struct rgw_request_ctx *request = lookup_request_ctx_for_dpp(dpp);
  if (request == 0) {
    request = lookup_current_thread_request();
  }
  if (request == 0)
    return 0;
  if (dpp != 0 &&
      bpf_map_update_elem(&rgw_dpps, &dpp, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
  if (writer != 0 &&
      bpf_map_update_elem(&rados_writers, &writer, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
  push_active_request_ctx(request);
  return 1;
}

static __always_inline int cache_writer_for_request(__u64 writer,
                                                    struct rgw_request_ctx *request) {
  if (writer == 0 || request == 0)
    return 0;
  if (bpf_map_update_elem(&rados_writers, &writer, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);

  __u64 aio = 0;
  rgwtrace_probe_read_user(&aio, sizeof(aio),
                           (void *)(writer + RGWTRACE_RADOS_WRITER_AIO_OFFSET));
  if (aio != 0 &&
      bpf_map_update_elem(&rgw_aios, &aio, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);

  __u64 dpp = 0;
  rgwtrace_probe_read_user(&dpp, sizeof(dpp),
                           (void *)(writer + RGWTRACE_RADOS_WRITER_DPP_OFFSET));
  if (dpp != 0 &&
      bpf_map_update_elem(&rgw_dpps, &dpp, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);

  return 1;
}

static __always_inline struct rgw_request_ctx *
lookup_request_ctx_for_writer_aio(__u64 writer) {
  if (writer == 0)
    return 0;
  __u64 aio = 0;
  rgwtrace_probe_read_user(&aio, sizeof(aio),
                           (void *)(writer + RGWTRACE_RADOS_WRITER_AIO_OFFSET));
  if (aio == 0)
    return 0;
  struct rgw_request_ctx *request = bpf_map_lookup_elem(&rgw_aios, &aio);
  if (request != 0)
    return request;
  return lookup_request_ctx_for_dpp(aio);
}

static __always_inline struct rgw_request_ctx *
lookup_request_ctx_for_writer(__u64 writer) {
  struct rgw_request_ctx *request = 0;
  if (writer != 0) {
    request = bpf_map_lookup_elem(&rados_writers, &writer);
    if (request == 0 && writer > RGWTRACE_PUT_PROCESSOR_WRITER_OFFSET) {
      __u64 processor = writer - RGWTRACE_PUT_PROCESSOR_WRITER_OFFSET;
      request = bpf_map_lookup_elem(&rados_writers, &processor);
    }
  }
  return prefer_newer_current_thread_request(request);
}

static __always_inline int push_context_for_rados_obj_no_clear(__u64 obj) {
  struct rgw_request_ctx *request = 0;
  if (obj != 0)
    request = bpf_map_lookup_elem(&rgw_rados_objs, &obj);
  if (request == 0)
    return 0;
  request = prefer_newer_current_thread_request(request);
  push_active_request_ctx(request);
  return 1;
}

static __always_inline int push_context_for_writer_no_clear(__u64 writer) {
  struct rgw_request_ctx *request = lookup_request_ctx_for_writer(writer);
  if (request == 0)
    return 0;
  cache_writer_for_request(writer, request);
  push_active_request_ctx(request);
  return 1;
}

static __always_inline int cache_writer_from_active_context(__u64 writer) {
  if (writer == 0)
    return 0;
  struct rgw_request_ctx active = {};
  if (copy_current_active_request_ctx(&active, false) == 0)
    return 0;
  cache_writer_for_request(writer, &active);
  push_active_request_ctx(&active);
  return 1;
}

static __always_inline int
cache_manifest_processor_ctor_context(__u64 processor, __u64 dpp, __u64 aio) {
  if (processor == 0)
    return 0;

  struct rgw_request_ctx *request = lookup_request_ctx_for_dpp(dpp);
  if (request == 0) {
    request = lookup_current_thread_request();
  }
  if (request == 0)
    return 0;

  if (bpf_map_update_elem(&rados_writers, &processor, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);

  __u64 writer = processor + RGWTRACE_PUT_PROCESSOR_WRITER_OFFSET;
  if (bpf_map_update_elem(&rados_writers, &writer, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);

  if (dpp != 0 &&
      bpf_map_update_elem(&rgw_dpps, &dpp, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);

  if (aio != 0 &&
      bpf_map_update_elem(&rgw_aios, &aio, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);

  push_active_request_ctx(request);
  return 1;
}

static __always_inline __u64 direct_var_value(struct pt_regs *ctx, int varid) {
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf == 0)
    return 0;
  return fetch_var_value(ctx, vf);
}

static __always_inline __u64 pointer_member_value(struct pt_regs *ctx,
                                                  int varid) {
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf == 0)
    return 0;

  __u64 base = fetch_var_value(ctx, vf);
  __u64 member_addr = fetch_var_member_addr(base, vf);
  __u64 member = 0;
  rgwtrace_probe_read_user(&member, sizeof(member), (void *)member_addr);
  return member;
}

static __always_inline __u64 member_address(struct pt_regs *ctx, int varid) {
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf == 0)
    return 0;

  __u64 base = fetch_var_value(ctx, vf);
  return fetch_var_member_addr(base, vf);
}

static __always_inline int
cache_embedded_writer_for_request(__u64 processor,
                                  struct rgw_request_ctx *request) {
  if (processor == 0)
    return 0;
  if (request == 0)
    return 0;
  __u64 writer = processor + RGWTRACE_PUT_PROCESSOR_WRITER_OFFSET;
  if (bpf_map_update_elem(&rados_writers, &processor, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
  cache_writer_for_request(writer, request);

  __u64 dpp = 0;
  rgwtrace_probe_read_user(&dpp, sizeof(dpp),
                           (void *)(processor +
                                    RGWTRACE_MANIFEST_PROCESSOR_DPP_OFFSET));
  if (dpp != 0 &&
      bpf_map_update_elem(&rgw_dpps, &dpp, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
  push_active_request_ctx(request);
  return 1;
}

static __always_inline int
cache_data_processor_chain_for_request(__u64 processor,
                                       struct rgw_request_ctx *request) {
  if (processor == 0 || request == 0)
    return 0;

  if (bpf_map_update_elem(&rados_writers, &processor, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);

  __u64 next = 0;
  rgwtrace_probe_read_user(&next, sizeof(next),
                           (void *)(processor + RGWTRACE_PIPE_NEXT_OFFSET));
  if (next != 0) {
    if (bpf_map_update_elem(&rados_writers, &next, request, 0) != 0)
      count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
    cache_writer_for_request(next, request);
  }

  __u64 next_next = 0;
  if (next != 0) {
    rgwtrace_probe_read_user(&next_next, sizeof(next_next),
                             (void *)(next + RGWTRACE_PIPE_NEXT_OFFSET));
    if (next_next != 0)
      cache_writer_for_request(next_next, request);
  }

  push_active_request_ctx(request);
  return 1;
}

static __always_inline struct rgw_request_ctx *
lookup_request_ctx_for_processor_or_dpp(__u64 processor, __u64 dpp) {
  struct rgw_request_ctx *request = lookup_request_ctx_for_dpp(dpp);
  if (request != 0)
    return request;

  request = lookup_current_thread_request();
  if (request != 0)
    return request;

  if (processor != 0) {
    __u64 processor_dpp = 0;
    rgwtrace_probe_read_user(&processor_dpp, sizeof(processor_dpp),
                             (void *)(processor +
                                      RGWTRACE_MANIFEST_PROCESSOR_DPP_OFFSET));
    request = lookup_request_ctx_for_dpp(processor_dpp);
    if (request != 0)
      return request;
  }

  return 0;
}

static __always_inline int cache_embedded_writer_from_processor(__u64 processor) {
  struct rgw_request_ctx *request =
      lookup_request_ctx_for_processor_or_dpp(processor, 0);
  if (request == 0)
    return 0;
  return cache_embedded_writer_for_request(processor, request);
}

static __always_inline int cache_data_processor_output(struct pt_regs *ctx,
                                                       int processor_varid,
                                                       int out_varid,
                                                       int dpp_varid,
                                                       int writer_varid) {
  __u64 processor = direct_var_value(ctx, processor_varid);
  __u64 out_processor = direct_var_value(ctx, out_varid);
  __u64 dpp = pointer_member_value(ctx, dpp_varid);
  __u32 thread_id = get_tid();
  struct rgw_request_ctx *request =
      lookup_request_ctx_for_processor_or_dpp(processor, dpp);
  if (request == 0)
    return 0;

  if (dpp != 0 &&
      bpf_map_update_elem(&rgw_dpps, &dpp, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);

  if (processor != 0)
    cache_embedded_writer_from_processor(processor);

  __u64 writer = member_address(ctx, writer_varid);
  if (writer != 0)
    cache_writer_for_request(writer, request);

  if (out_processor == 0)
    return 0;

  struct pending_data_processor_ctx pending = {};
  pending.out_processor = out_processor;
  pending.dpp = dpp;
  if (bpf_map_update_elem(&pending_data_processors, &thread_id, &pending, 0) !=
      0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
  push_active_request_ctx(request);
  return 1;
}

static __always_inline int cache_processor_context(struct pt_regs *ctx,
                                                   int processor_varid,
                                                   int dpp_varid,
                                                   int writer_varid) {
  __u64 processor = direct_var_value(ctx, processor_varid);
  __u64 dpp = pointer_member_value(ctx, dpp_varid);
  struct rgw_request_ctx *request =
      lookup_request_ctx_for_processor_or_dpp(processor, dpp);
  if (request == 0)
    return 0;

  if (dpp != 0 &&
      bpf_map_update_elem(&rgw_dpps, &dpp, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);

  int cached = cache_embedded_writer_for_request(processor, request);
  __u64 writer = member_address(ctx, writer_varid);
  if (writer != 0) {
    cache_writer_for_request(writer, request);
    if (cached == 0)
      push_active_request_ctx(request);
    cached = 1;
  }
  return cached;
}

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
  e->data.request.rgw_request_id = ctx->rgw_request_id;
  e->data.request.pid = ctx->pid;
  e->data.request.tid = ctx->tid;
  e->data.request.flags = ctx->flags;
  __builtin_memcpy(e->data.request.trans_id, ctx->trans_id,
                   sizeof(e->data.request.trans_id));
  __builtin_memcpy(e->data.request.rgw_req_id, ctx->rgw_req_id,
                   sizeof(e->data.request.rgw_req_id));
  bpf_ringbuf_submit(e, 0);
}

SEC("uprobe")
int uprobe_process_request(struct pt_regs *ctx) {
  int varid = 40;
  __u32 thread_id = get_tid();
  struct rgw_request_ctx request = {};

  clear_active_request_ctx();

  request.start_ns = bpf_ktime_get_boot_ns();
  request.pid = get_pid();
  request.tid = thread_id;

  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  __u64 req = 0;
  if (vf != 0) {
    req = fetch_var_value(ctx, vf);
    __u64 id_addr = fetch_var_member_addr(req, vf);
    rgwtrace_probe_read_user(&request.rgw_request_id,
                             sizeof(request.rgw_request_id),
                             (void *)id_addr);
  }

  if (bpf_map_update_elem(&rgw_requests, &thread_id, &request, 0) != 0) {
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
    return 0;
  }

  if (req != 0) {
    if (bpf_map_update_elem(&rgw_requests_by_req, &req, &request, 0) != 0)
      count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
  }

  emit_request_event(RGWTRACE_EVENT_REQUEST_START, &request, 0);
  return 0;
}

SEC("uprobe")
int uprobe_rgw_get_handler(struct pt_regs *ctx) {
  int varid = 30;
  __u32 thread_id = get_tid();
  struct rgw_request_ctx fallback = {};
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
  __u64 req_state = 0;
  if (vf == 0)
    return 0;

  req_state = fetch_var_value(ctx, vf);
  __u64 id_addr = fetch_var_member_addr(req_state, vf);
  rgwtrace_probe_read_user(&request->rgw_request_id,
                           sizeof(request->rgw_request_id), (void *)id_addr);

  request->flags = 0;
  __builtin_memset(request->rgw_req_id, 0, sizeof(request->rgw_req_id));
  __builtin_memset(request->trans_id, 0, sizeof(request->trans_id));

  read_string_field(ctx, 31, 32, request->rgw_req_id,
                    sizeof(request->rgw_req_id), &request->flags,
                    RGWTRACE_TRUNC_TRANS_ID);
  read_string_field(ctx, 33, 34, request->trans_id,
                    sizeof(request->trans_id), &request->flags,
                    RGWTRACE_TRUNC_TRANS_ID);

  if (req_state != 0) {
    if (bpf_map_update_elem(&rgw_req_states, &req_state, request, 0) != 0)
      count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
  }

  emit_request_event(RGWTRACE_EVENT_REQUEST_END, request,
                     bpf_ktime_get_boot_ns());

  return 0;
}

SEC("uprobe")
int uprobe_rgw_op_init(struct pt_regs *ctx) {
  __u64 op = direct_var_value(ctx, 50);
  __u64 req_state = direct_var_value(ctx, 51);
  if (op == 0 || req_state == 0)
    return 0;

  struct rgw_request_ctx *request =
      bpf_map_lookup_elem(&rgw_req_states, &req_state);
  if (request == 0)
    return 0;

  if (bpf_map_update_elem(&rgw_ops, &op, request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
  return 0;
}

SEC("uprobe")
int uprobe_rados_writer_ctor(struct pt_regs *ctx) {
  count_diag(RGWTRACE_DIAG_RADOS_WRITER_CTOR_HITS);
  __u64 writer = fetch_register(ctx, RGWTRACE_ABI_THIS_REG);
  __u64 dpp = direct_var_value(ctx, 101);
  __u64 ctor_aio = direct_var_value(ctx, 102);
  if (cache_writer_context_from_dpp(writer, dpp) != 0) {
    __u64 aio = ctor_aio;
    if (aio != 0) {
      __u32 thread_id = get_tid();
      struct rgw_request_ctx *request =
          bpf_map_lookup_elem(&rgw_requests, &thread_id);
      if (request == 0)
        request = lookup_request_ctx_for_dpp(dpp);
      if (request != 0) {
        if (bpf_map_update_elem(&rgw_aios, &aio, request, 0) != 0)
          count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
        __u64 writer_from_slot = aio + RGWTRACE_RADOS_WRITER_CTOR_SLOT_OFFSET;
        if (bpf_map_update_elem(&rados_writers, &writer_from_slot, request,
                                0) != 0)
          count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
        if (dpp != 0 &&
            bpf_map_update_elem(&rgw_aios, &dpp, request, 0) != 0)
          count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
      }
    }
    count_diag(RGWTRACE_DIAG_RADOS_WRITER_CTOR_CONTEXTS);
  }
  return 0;
}

SEC("uprobe")
int uprobe_manifest_processor_ctor(struct pt_regs *ctx) {
  count_diag(RGWTRACE_DIAG_RADOS_WRITER_CTOR_HITS);
  __u64 processor = direct_var_value(ctx, 200);
  __u64 dpp = direct_var_value(ctx, 201);
  __u64 aio = direct_var_value(ctx, 202);
  if (cache_manifest_processor_ctor_context(processor, dpp, aio) != 0)
    count_diag(RGWTRACE_DIAG_RADOS_WRITER_CTOR_CONTEXTS);
  return 0;
}

SEC("uprobe")
int uprobe_put_processor_prepare(struct pt_regs *ctx) {
  count_diag(RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_HITS);
  if (cache_processor_context(ctx, 110, 111, 112) != 0) {
    count_diag(RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_CONTEXTS);
    return 0;
  }
  if (cache_processor_context(ctx, 114, 115, 116) != 0) {
    count_diag(RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_CONTEXTS);
    return 0;
  }
  if (cache_processor_context(ctx, 117, 118, 119) != 0) {
    count_diag(RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_CONTEXTS);
    return 0;
  }
  return 0;
}

SEC("uprobe")
int uprobe_put_processor_process_first_chunk(struct pt_regs *ctx) {
  count_diag(RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_HITS);
  if (cache_data_processor_output(ctx, 120, 121, 122, 123) != 0) {
    count_diag(RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_CONTEXTS);
    return 0;
  }
  if (cache_data_processor_output(ctx, 130, 131, 132, 133) != 0) {
    count_diag(RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_CONTEXTS);
    return 0;
  }
  if (cache_data_processor_output(ctx, 140, 141, 142, 143) != 0)
    count_diag(RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_CONTEXTS);
  return 0;
}

SEC("uprobe")
int uprobe_put_processor_complete(struct pt_regs *ctx) {
  count_diag(RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_HITS);
  if (cache_processor_context(ctx, 160, 161, 162) != 0) {
    count_diag(RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_CONTEXTS);
    return 0;
  }
  if (cache_processor_context(ctx, 170, 171, 172) != 0) {
    count_diag(RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_CONTEXTS);
    return 0;
  }
  if (cache_processor_context(ctx, 180, 181, 182) != 0)
    count_diag(RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_CONTEXTS);
  return 0;
}

SEC("uprobe")
int uprobe_rados_writer_set_stripe_obj(struct pt_regs *ctx) {
  __u64 writer = direct_var_value(ctx, 210);
  __u64 stripe_obj = member_address(ctx, 211);
  if (writer == 0 || stripe_obj == 0)
    return 0;

  struct pending_stripe_obj_ctx pending = {};
  pending.writer = writer;
  pending.stripe_obj = stripe_obj;

  struct rgw_request_ctx *request = lookup_request_ctx_for_writer(writer);
  if (request != 0) {
    copy_request_ctx(&pending.request, request);
  } else if (copy_current_active_request_ctx(&pending.request, false) == 0) {
    request = lookup_current_thread_request();
    if (request == 0)
      return 0;
    copy_request_ctx(&pending.request, request);
  }

  cache_writer_for_request(writer, &pending.request);
  push_active_request_ctx(&pending.request);

  __u32 thread_id = get_tid();
  if (bpf_map_update_elem(&pending_stripe_objs, &thread_id, &pending, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
  return 0;
}

SEC("uretprobe")
int uretprobe_rados_writer_set_stripe_obj(struct pt_regs *ctx) {
  __u32 thread_id = get_tid();
  struct pending_stripe_obj_ctx *pending =
      bpf_map_lookup_elem(&pending_stripe_objs, &thread_id);
  if (pending == 0)
    return 0;

  if (pending->stripe_obj != 0 &&
      bpf_map_update_elem(&rgw_rados_objs, &pending->stripe_obj,
                          &pending->request, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
  push_active_request_ctx(&pending->request);
  bpf_map_delete_elem(&pending_stripe_objs, &thread_id);
  return 0;
}

SEC("uprobe")
int uprobe_head_object_processor_process(struct pt_regs *ctx) {
  count_diag(RGWTRACE_DIAG_HEAD_OBJECT_PROCESSOR_PROCESS_HITS);
  __u64 processor = direct_var_value(ctx, 150);
  struct rgw_request_ctx *request =
      lookup_request_ctx_for_processor_or_dpp(processor, 0);
  if (request == 0)
    return 0;

  count_diag(RGWTRACE_DIAG_HEAD_OBJECT_PROCESSOR_PROCESS_CONTEXTS);
  cache_embedded_writer_for_request(processor, request);

  __u64 data_processor = 0;
  rgwtrace_probe_read_user(
      &data_processor, sizeof(data_processor),
      (void *)(processor + RGWTRACE_HEAD_PROCESSOR_PROCESSOR_OFFSET));
  if (data_processor != 0)
    cache_data_processor_chain_for_request(data_processor, request);
  else
    push_active_request_ctx(request);

  return 0;
}

SEC("uretprobe")
int uretprobe_put_processor_process_first_chunk(struct pt_regs *ctx) {
  __u32 thread_id = get_tid();
  struct pending_data_processor_ctx *pending =
      bpf_map_lookup_elem(&pending_data_processors, &thread_id);
  if (pending == 0)
    return 0;

  __u64 processor = 0;
  rgwtrace_probe_read_user(&processor, sizeof(processor),
                           (void *)pending->out_processor);
  if (processor != 0) {
    struct rgw_request_ctx *request =
        lookup_request_ctx_for_processor_or_dpp(processor, pending->dpp);
    if (request != 0)
      cache_data_processor_chain_for_request(processor, request);
  }

  bpf_map_delete_elem(&pending_data_processors, &thread_id);
  return 0;
}

SEC("uretprobe")
int uretprobe_head_object_processor_process(struct pt_regs *ctx) {
  pop_active_request_ctx();
  return 0;
}

SEC("uprobe")
int uprobe_rgw_rados_operate(struct pt_regs *ctx) {
  count_diag(RGWTRACE_DIAG_RGW_RADOS_OPERATE_HITS);
  if (push_context_for_dpp_no_clear(direct_var_value(ctx, 60)) != 0) {
    count_diag(RGWTRACE_DIAG_RGW_RADOS_OPERATE_CONTEXTS);
    return 0;
  }
  if (push_context_for_dpp_no_clear(direct_var_value(ctx, 61)) != 0) {
    count_diag(RGWTRACE_DIAG_RGW_RADOS_OPERATE_CONTEXTS);
    return 0;
  }
  if (push_context_for_dpp_no_clear(direct_var_value(ctx, 62)) != 0) {
    count_diag(RGWTRACE_DIAG_RGW_RADOS_OPERATE_CONTEXTS);
    return 0;
  }
  if (push_context_for_dpp_no_clear(direct_var_value(ctx, 63)) != 0) {
    count_diag(RGWTRACE_DIAG_RGW_RADOS_OPERATE_CONTEXTS);
    return 0;
  }
  struct rgw_request_ctx active = {};
  if (copy_current_active_request_ctx(&active, false) != 0) {
    push_active_request_ctx(&active);
    count_diag(RGWTRACE_DIAG_RGW_RADOS_OPERATE_CONTEXTS);
    return 0;
  }
  if (push_current_request_ctx_no_clear() != 0) {
    count_diag(RGWTRACE_DIAG_RGW_RADOS_OPERATE_CONTEXTS);
    return 0;
  }
  clear_active_request_ctx();
  return 0;
}

SEC("uprobe")
int uprobe_rgw_write_meta(struct pt_regs *ctx) {
  count_diag(RGWTRACE_DIAG_RGW_WRITE_META_HITS);
  if (push_context_for_dpp_no_clear(direct_var_value(ctx, 190)) != 0) {
    count_diag(RGWTRACE_DIAG_RGW_WRITE_META_CONTEXTS);
    return 0;
  }
  if (push_context_for_dpp_no_clear(direct_var_value(ctx, 191)) != 0) {
    count_diag(RGWTRACE_DIAG_RGW_WRITE_META_CONTEXTS);
    return 0;
  }
  struct rgw_request_ctx active = {};
  if (copy_current_active_request_ctx(&active, false) != 0) {
    push_active_request_ctx(&active);
    count_diag(RGWTRACE_DIAG_RGW_WRITE_META_CONTEXTS);
    return 0;
  }
  if (push_current_request_ctx_no_clear() != 0) {
    count_diag(RGWTRACE_DIAG_RGW_WRITE_META_CONTEXTS);
    return 0;
  }
  clear_active_request_ctx();
  return 0;
}

SEC("uprobe")
int uprobe_rados_writer_process(struct pt_regs *ctx) {
  count_diag(RGWTRACE_DIAG_RADOS_WRITER_PROCESS_HITS);
  __u64 writer = direct_var_value(ctx, 70);
  if (push_context_for_writer_no_clear(writer) != 0) {
    count_diag(RGWTRACE_DIAG_RADOS_WRITER_PROCESS_CONTEXTS);
    return 0;
  }
  __u64 dpp = pointer_member_value(ctx, 71);
  if (cache_writer_context_from_dpp(writer, dpp) != 0) {
    count_diag(RGWTRACE_DIAG_RADOS_WRITER_PROCESS_CONTEXTS);
    return 0;
  }
  if (cache_writer_from_active_context(writer) != 0) {
    count_diag(RGWTRACE_DIAG_RADOS_WRITER_PROCESS_CONTEXTS);
    return 0;
  }
  clear_active_request_ctx();
  return 0;
}

SEC("uprobe")
int uprobe_rados_writer_write_exclusive(struct pt_regs *ctx) {
  count_diag(RGWTRACE_DIAG_RADOS_WRITER_WRITE_EXCLUSIVE_HITS);
  __u64 writer = direct_var_value(ctx, 80);
  if (push_context_for_writer_no_clear(writer) != 0) {
    count_diag(RGWTRACE_DIAG_RADOS_WRITER_WRITE_EXCLUSIVE_CONTEXTS);
    return 0;
  }
  __u64 dpp = pointer_member_value(ctx, 81);
  if (cache_writer_context_from_dpp(writer, dpp) != 0) {
    count_diag(RGWTRACE_DIAG_RADOS_WRITER_WRITE_EXCLUSIVE_CONTEXTS);
    return 0;
  }
  if (cache_writer_from_active_context(writer) != 0) {
    count_diag(RGWTRACE_DIAG_RADOS_WRITER_WRITE_EXCLUSIVE_CONTEXTS);
    return 0;
  }
  clear_active_request_ctx();
  return 0;
}

SEC("uprobe")
int uprobe_rgw_rados_obj_aio_operate(struct pt_regs *ctx) {
  __u64 obj = direct_var_value(ctx, 220);
  struct rgw_request_ctx *request = 0;
  if (obj != 0)
    request = bpf_map_lookup_elem(&rgw_rados_objs, &obj);
  if (request == 0) {
    obj = direct_var_value(ctx, 221);
    if (obj != 0)
      request = bpf_map_lookup_elem(&rgw_rados_objs, &obj);
  }
  if (request == 0)
    return 0;

  push_active_request_ctx(request);
  return 0;
}

SEC("uprobe")
int uprobe_rgw_rados_obj_operate(struct pt_regs *ctx) {
  if (push_context_for_dpp_no_clear(direct_var_value(ctx, 240)) != 0) {
    count_diag(RGWTRACE_DIAG_RGW_RADOS_OPERATE_CONTEXTS);
    return 0;
  }
  if (push_context_for_dpp_no_clear(direct_var_value(ctx, 241)) != 0) {
    count_diag(RGWTRACE_DIAG_RGW_RADOS_OPERATE_CONTEXTS);
    return 0;
  }
  if (push_context_for_dpp_no_clear(direct_var_value(ctx, 242)) != 0) {
    count_diag(RGWTRACE_DIAG_RGW_RADOS_OPERATE_CONTEXTS);
    return 0;
  }
  if (push_context_for_dpp_no_clear(direct_var_value(ctx, 243)) != 0) {
    count_diag(RGWTRACE_DIAG_RGW_RADOS_OPERATE_CONTEXTS);
    return 0;
  }
  if (push_current_request_ctx_no_clear() != 0) {
    count_diag(RGWTRACE_DIAG_RGW_RADOS_OPERATE_CONTEXTS);
    return 0;
  }
  return 0;
}

SEC("uprobe")
int uprobe_aio_get(struct pt_regs *ctx) {
  if (push_context_for_rados_obj_no_clear(direct_var_value(ctx, 230)) != 0)
    return 0;
  if (push_context_for_rados_obj_no_clear(direct_var_value(ctx, 231)) != 0)
    return 0;
  return 0;
}

SEC("uprobe")
int uprobe_librados_operate(struct pt_regs *ctx) {
  struct rgw_request_ctx active = {};
  if (copy_current_active_request_ctx(&active, false) != 0) {
    push_active_request_ctx(&active);
    count_diag(RGWTRACE_DIAG_RGW_RADOS_OPERATE_CONTEXTS);
    return 0;
  }
  if (push_current_request_ctx_no_clear() != 0) {
    count_diag(RGWTRACE_DIAG_RGW_RADOS_OPERATE_CONTEXTS);
    return 0;
  }
  return 0;
}

SEC("uretprobe")
int uretprobe_rgw_rados_scope(struct pt_regs *ctx) {
  pop_active_request_ctx();
  return 0;
}

SEC("uprobe")
int uprobe_objecter_op_submit(struct pt_regs *ctx) {
  count_diag(RGWTRACE_DIAG_OBJECTER_OP_SUBMIT_HITS);
  __u64 op = direct_var_value(ctx, 90);
  if (op == 0) {
    count_diag(RGWTRACE_DIAG_OBJECTER_OP_SUBMIT_MISSES);
    return 0;
  }

  struct objecter_op_ctx op_ctx = {};
  op_ctx.source = RGWTRACE_CORRELATION_OP_SUBMIT_CONTEXT;
  if (copy_current_active_request_ctx(&op_ctx.request, false) == 0) {
    struct rgw_request_ctx *request = lookup_current_thread_request();
    if (request == 0) {
      count_diag(RGWTRACE_DIAG_OBJECTER_OP_SUBMIT_MISSES);
      return 0;
    }
    copy_request_ctx(&op_ctx.request, request);
    op_ctx.source = RGWTRACE_CORRELATION_SAME_THREAD;
    count_diag(RGWTRACE_DIAG_OBJECTER_OP_SUBMIT_SAME_THREAD_CONTEXTS);
  } else {
    count_diag(RGWTRACE_DIAG_OBJECTER_OP_SUBMIT_ACTIVE_CONTEXTS);
  }

  if (bpf_map_update_elem(&objecter_ops, &op, &op_ctx, 0) != 0)
    count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS);
  return 0;
}

SEC("uprobe")
int uprobe_send_op(struct pt_regs *ctx) {
  int varid = 0;
  struct client_op_key key = {};
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  __u64 objecter_op = 0;

  if (vf != 0) {
    __u64 v = fetch_var_value(ctx, vf);
    objecter_op = v;
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
  struct rgw_request_ctx *request = 0;
  struct objecter_op_ctx *op_ctx = 0;
  struct rgw_request_ctx active_request = {};
  if (objecter_op != 0)
    op_ctx = bpf_map_lookup_elem(&objecter_ops, &objecter_op);
  if (op_ctx != 0) {
    request = &op_ctx->request;
    copy_request_ctx_to_rados_event(event, request, op_ctx->source);
  } else {
    if (copy_current_active_request_ctx(&active_request, false) != 0) {
      request = &active_request;
      copy_request_ctx_to_rados_event(
          event, request, RGWTRACE_CORRELATION_ACTIVE_CONTEXT);
    }
  }
  if (request == 0)
    request = bpf_map_lookup_elem(&rgw_requests, &thread_id);
  if (request != 0) {
    if (event->correlation_source == RGWTRACE_CORRELATION_NONE)
      copy_request_ctx_to_rados_event(
          event, request, RGWTRACE_CORRELATION_SAME_THREAD);
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
  __u64 objecter_op = 0;

  if (vf != 0) {
    __u64 v = fetch_var_value(ctx, vf);
    objecter_op = v;
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
    if (objecter_op != 0)
      bpf_map_delete_elem(&objecter_ops, &objecter_op);
    return 0;
  }

  state->event.finish_ns = bpf_ktime_get_boot_ns();
  state->event.pid = get_pid();

  struct rgwtrace_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (e == 0) {
    count_diag(RGWTRACE_DIAG_RINGBUF_RADOS_DROPS);
    bpf_map_delete_elem(&rados_ops, &key);
    if (objecter_op != 0)
      bpf_map_delete_elem(&objecter_ops, &objecter_op);
    return 0;
  }

  __builtin_memset(e, 0, sizeof(*e));
  e->type = RGWTRACE_EVENT_RADOS_OP;
  e->data.rados = state->event;
  bpf_ringbuf_submit(e, 0);
  bpf_map_delete_elem(&rados_ops, &key);
  if (objecter_op != 0)
    bpf_map_delete_elem(&objecter_ops, &objecter_op);
  return 0;
}
