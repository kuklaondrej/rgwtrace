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
  RGWTRACE_DIAG_COUNTERS = 7,
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
