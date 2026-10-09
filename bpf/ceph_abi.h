/* SPDX-License-Identifier: GPL-2.0-only */
/* Derived from Ceph cephtrace/radostrace BPF tracing code; see NOTICE. */

#ifndef RGWTRACE_CEPH_ABI_H
#define RGWTRACE_CEPH_ABI_H

#define MAX_ACTING 16
#define MAX_TRANS_ID 128
#define MAX_OBJECT_NAME 128
#define MAX_RADOS_OPS 3

#define CEPH_OSD_FLAG_WRITE 0x0020

#define CEPH_OSD_OP_MODE_RD 0x1000
#define CEPH_OSD_OP_MODE_WR 0x2000
#define CEPH_OSD_OP_TYPE_DATA 0x0200
#define CEPH_OSD_OP_TYPE_EXEC 0x0400

#define __CEPH_OSD_OP(mode, type, nr) \
  (CEPH_OSD_OP_MODE_##mode | CEPH_OSD_OP_TYPE_##type | (nr))

#define CEPH_OSD_OP_READ __CEPH_OSD_OP(RD, DATA, 1)
#define CEPH_OSD_OP_STAT __CEPH_OSD_OP(RD, DATA, 2)
#define CEPH_OSD_OP_MAPEXT __CEPH_OSD_OP(RD, DATA, 3)
#define CEPH_OSD_OP_SPARSE_READ __CEPH_OSD_OP(RD, DATA, 5)
#define CEPH_OSD_OP_SYNC_READ __CEPH_OSD_OP(RD, DATA, 11)
#define CEPH_OSD_OP_WRITE __CEPH_OSD_OP(WR, DATA, 1)
#define CEPH_OSD_OP_WRITEFULL __CEPH_OSD_OP(WR, DATA, 2)
#define CEPH_OSD_OP_ZERO __CEPH_OSD_OP(WR, DATA, 4)
#define CEPH_OSD_OP_APPEND __CEPH_OSD_OP(WR, DATA, 6)
#define CEPH_OSD_OP_OMAPGETKEYS __CEPH_OSD_OP(RD, DATA, 17)
#define CEPH_OSD_OP_OMAPSETVALS __CEPH_OSD_OP(WR, DATA, 21)
#define CEPH_OSD_OP_CMPEXT __CEPH_OSD_OP(RD, DATA, 32)
#define CEPH_OSD_OP_CALL __CEPH_OSD_OP(RD, EXEC, 1)

struct cls_op {
  char cls_name[8];
  char method_name[32];
};

/*
 * rados_ops key. The tgid scopes it to one process: (cid, tid) are only unique
 * within one Objecter, and a failed probe read leaves both at 0, so without it
 * two processes (or two failed reads) would share one in-flight entry. The pad
 * is explicit so a `= {}` key hashes deterministically. BPF-internal: userspace
 * never reads this map, so there is no Rust mirror.
 */
struct client_op_key {
  __u64 cid;
  __u64 tid;
  __u32 tgid;
  __u32 _pad;
};

struct VarLocation {
  int reg;
  int offset;
  bool stack;
};

struct Field {
  int offset;
  bool pointer;
};

struct VarField {
  struct VarLocation varloc;
  struct Field fields[10];
  int size;
};

static inline int ceph_osd_op_call(int op) {
  return op == CEPH_OSD_OP_CALL;
}

static inline int ceph_osd_op_extent(int op) {
  return op == CEPH_OSD_OP_READ || op == CEPH_OSD_OP_SPARSE_READ ||
         op == CEPH_OSD_OP_SYNC_READ || op == CEPH_OSD_OP_WRITE ||
         op == CEPH_OSD_OP_WRITEFULL || op == CEPH_OSD_OP_ZERO ||
         op == CEPH_OSD_OP_APPEND || op == CEPH_OSD_OP_MAPEXT ||
         op == CEPH_OSD_OP_CMPEXT || op == CEPH_OSD_OP_OMAPSETVALS ||
         op == CEPH_OSD_OP_OMAPGETKEYS;
}

#endif
