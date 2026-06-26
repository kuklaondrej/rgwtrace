/* SPDX-License-Identifier: GPL-2.0-only */
/* Derived from Ceph cephtrace/radostrace BPF tracing code; see NOTICE. */

#ifndef RGWTRACE_EVENTS_H
#define RGWTRACE_EVENTS_H

#include "ceph_abi.h"

#define MAX_RGW_REQ_ID 128

enum rgwtrace_event_type {
  RGWTRACE_EVENT_REQUEST_START = 1,
  RGWTRACE_EVENT_REQUEST_END = 2,
  RGWTRACE_EVENT_RADOS_OP = 3,
};

enum rgwtrace_correlation_source {
  RGWTRACE_CORRELATION_NONE = 0,
  RGWTRACE_CORRELATION_OP_SUBMIT_CONTEXT = 1,
  RGWTRACE_CORRELATION_ACTIVE_CONTEXT = 2,
  RGWTRACE_CORRELATION_SAME_THREAD = 3,
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
  RGWTRACE_DIAG_RGW_RADOS_OPERATE_HITS = 6,
  RGWTRACE_DIAG_RGW_RADOS_OPERATE_CONTEXTS = 7,
  RGWTRACE_DIAG_RADOS_WRITER_PROCESS_HITS = 8,
  RGWTRACE_DIAG_RADOS_WRITER_PROCESS_CONTEXTS = 9,
  RGWTRACE_DIAG_RADOS_WRITER_WRITE_EXCLUSIVE_HITS = 10,
  RGWTRACE_DIAG_RADOS_WRITER_WRITE_EXCLUSIVE_CONTEXTS = 11,
  RGWTRACE_DIAG_OBJECTER_OP_SUBMIT_HITS = 12,
  RGWTRACE_DIAG_OBJECTER_OP_SUBMIT_ACTIVE_CONTEXTS = 13,
  RGWTRACE_DIAG_OBJECTER_OP_SUBMIT_SAME_THREAD_CONTEXTS = 14,
  RGWTRACE_DIAG_OBJECTER_OP_SUBMIT_MISSES = 15,
  RGWTRACE_DIAG_RADOS_WRITER_CTOR_HITS = 16,
  RGWTRACE_DIAG_RADOS_WRITER_CTOR_CONTEXTS = 17,
  RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_HITS = 18,
  RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_CONTEXTS = 19,
  RGWTRACE_DIAG_HEAD_OBJECT_PROCESSOR_PROCESS_HITS = 20,
  RGWTRACE_DIAG_HEAD_OBJECT_PROCESSOR_PROCESS_CONTEXTS = 21,
  RGWTRACE_DIAG_RGW_WRITE_META_HITS = 22,
  RGWTRACE_DIAG_RGW_WRITE_META_CONTEXTS = 23,
  RGWTRACE_DIAG_COUNTERS = 24,
};

struct rgwtrace_request_event {
  __u64 start_ns;
  __u64 end_ns;
  __u64 rgw_request_id;
  __u32 pid;
  __u32 tid;
  __u32 flags;
  char trans_id[MAX_TRANS_ID];
  char rgw_req_id[MAX_RGW_REQ_ID];
};

struct rgwtrace_rados_event {
  __u64 cid;
  __u64 tid;
  __u64 sent_ns;
  __u64 finish_ns;
  __u64 rgw_request_id;
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
  __u32 correlation_source;
  int acting[MAX_ACTING];
  __u16 ops[MAX_RADOS_OPS];
  struct cls_op cls_ops[MAX_RADOS_OPS];
  char trans_id[MAX_TRANS_ID];
  char rgw_req_id[MAX_RGW_REQ_ID];
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
