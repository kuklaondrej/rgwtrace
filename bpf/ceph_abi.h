/* SPDX-License-Identifier: GPL-2.0-only */
/* Derived from Ceph cephtrace/radostrace BPF tracing code; see NOTICE. */

#ifndef RGWTRACE_CEPH_ABI_H
#define RGWTRACE_CEPH_ABI_H

#define MAX_ACTING 16
#define MAX_TRANS_ID 128
#define MAX_OBJECT_NAME 128
#define MAX_RADOS_OPS 3
/*
 * Object class name buffer. 16 holds every in-tree Ceph object class name
 * (the longest, `timeindex` / `2pc_queue`, is 9 bytes) plus the NUL; longer
 * names are copied as 15 bytes and flagged RGWTRACE_TRUNC_CLS_NAME.
 */
#define MAX_CLS_NAME 16
#define MAX_METHOD_NAME 32

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
  char cls_name[MAX_CLS_NAME];
  char method_name[MAX_METHOD_NAME];
};

struct client_op_key {
  __u64 cid;
  __u64 tid;
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
  /*
   * Nonzero for a slot userspace populated. `hprobes` is an ARRAY, whose
   * lookups never miss for an in-range key: an unpopulated slot reads as all
   * zeroes, which would otherwise pass for a "register 0" descriptor.
   */
  __u32 present;
};

/* Mirrored by VarFieldKernel in src/dwarf_json.rs, which asserts the same size. */
#define RGWTRACE_VAR_FIELD_SIZE 100
/*
 * Number of `hprobes` slots. Keys are `function base id + var_field index`
 * (FUNCTION_BASE_IDS in src/dwarf_json.rs: 0, 20, 30, 40, 50, 60, 70), so the
 * highest base, 70, gets 10 slots.
 */
#define RGWTRACE_HPROBE_SLOTS 80
_Static_assert(sizeof(struct VarField) == RGWTRACE_VAR_FIELD_SIZE,
               "struct VarField layout drifted from VarFieldKernel in src/dwarf_json.rs");

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
