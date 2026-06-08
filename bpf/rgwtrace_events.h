#ifndef RGWTRACE_EVENTS_H
#define RGWTRACE_EVENTS_H

#include "ceph_abi.h"

enum rgwtrace_event_type {
  RGWTRACE_EVENT_REQUEST_START = 1,
  RGWTRACE_EVENT_REQUEST_END = 2,
  RGWTRACE_EVENT_RADOS_OP = 3,
};

struct rgwtrace_request_event {
  __u64 start_ns;
  __u64 end_ns;
  __u32 pid;
  __u32 tid;
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
  __u32 target_osd;
  __u32 pg_seed;
  __u16 rw;
  __u32 ops_size;
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
