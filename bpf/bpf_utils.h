/* SPDX-License-Identifier: GPL-2.0-only */
/* Derived from Ceph cephtrace/radostrace BPF tracing code; see NOTICE. */

#ifndef RGWTRACE_BPF_UTILS_H
#define RGWTRACE_BPF_UTILS_H

static __always_inline __u32 get_pid(void) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  return pid_tgid >> 32;
}

static __always_inline __u32 get_tid(void) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  return (__u32)pid_tgid;
}

#define READ_CTX_U64(ctx, offset)                                             \
  ({                                                                          \
    __u64 value;                                                              \
    asm volatile("%0 = *(u64 *)(%1 + " #offset ")"                           \
                 : "=r"(value)                                               \
                 : "r"(ctx));                                                \
    value;                                                                    \
  })

static __noinline __u64 fetch_register(const struct pt_regs *const ctx, int reg) {
#if defined(__TARGET_ARCH_x86)
  if (reg == 0)
    return READ_CTX_U64(ctx, 80);
  else if (reg == 1)
    return READ_CTX_U64(ctx, 96);
  else if (reg == 2)
    return READ_CTX_U64(ctx, 88);
  else if (reg == 3)
    return READ_CTX_U64(ctx, 40);
  else if (reg == 4)
    return READ_CTX_U64(ctx, 104);
  else if (reg == 5)
    return READ_CTX_U64(ctx, 112);
  else if (reg == 6)
    return READ_CTX_U64(ctx, 32);
  else if (reg == 7)
    return READ_CTX_U64(ctx, 152);
  else if (reg == 8)
    return READ_CTX_U64(ctx, 72);
  else if (reg == 9)
    return READ_CTX_U64(ctx, 64);
  else if (reg == 10)
    return READ_CTX_U64(ctx, 56);
  else if (reg == 11)
    return READ_CTX_U64(ctx, 48);
  else if (reg == 12)
    return READ_CTX_U64(ctx, 24);
  else if (reg == 13)
    return READ_CTX_U64(ctx, 16);
  else if (reg == 14)
    return READ_CTX_U64(ctx, 8);
  else if (reg == 15)
    return READ_CTX_U64(ctx, 0);
#elif defined(__TARGET_ARCH_arm64)
  const struct user_pt_regs *regs = (const struct user_pt_regs *)ctx;
  if (reg >= 0 && reg <= 30)
    return regs->regs[reg];
  else if (reg == 31)
    return regs->sp;
#else
#error "Unsupported architecture: only x86 and arm64 are supported"
#endif

  return 0;
}

static __always_inline __u64 fetch_var_member_addr(__u64 cur_addr,
                                                   struct VarField *vf) {
  if (vf == 0 || cur_addr == 0)
    return 0;

  int raw_size = vf->size;
  __u32 size = 0;
  if (raw_size > 0)
    size = raw_size;
  if (size > 10)
    size = 10;

  __u64 tmpaddr = 0;
  if (vf->varloc.stack) {
    cur_addr += vf->varloc.offset;
    if (vf->fields[1].pointer) {
      rgwtrace_probe_read_user(&tmpaddr, sizeof(tmpaddr), (void *)cur_addr);
      cur_addr = tmpaddr;
    }
  }

  cur_addr += vf->fields[1].offset;

#define RGWTRACE_APPLY_VAR_FIELD(IDX)                                         \
  do {                                                                        \
    if (size <= (IDX))                                                        \
      return cur_addr;                                                        \
    if (vf->fields[IDX].pointer) {                                            \
      rgwtrace_probe_read_user(&tmpaddr, sizeof(tmpaddr), (void *)cur_addr);  \
      cur_addr = tmpaddr + vf->fields[IDX].offset;                            \
    } else {                                                                  \
      cur_addr += vf->fields[IDX].offset;                                     \
    }                                                                         \
  } while (0)

  RGWTRACE_APPLY_VAR_FIELD(2);
  RGWTRACE_APPLY_VAR_FIELD(3);
  RGWTRACE_APPLY_VAR_FIELD(4);
  RGWTRACE_APPLY_VAR_FIELD(5);
  RGWTRACE_APPLY_VAR_FIELD(6);
  RGWTRACE_APPLY_VAR_FIELD(7);
  RGWTRACE_APPLY_VAR_FIELD(8);
  RGWTRACE_APPLY_VAR_FIELD(9);

#undef RGWTRACE_APPLY_VAR_FIELD

  return cur_addr;
}

static __always_inline __u64 fetch_var_value(const struct pt_regs *const ctx,
                                             struct VarField *vf) {
  if (vf == 0)
    return 0;

  __u64 value = fetch_register(ctx, vf->varloc.reg);
  if (vf->varloc.stack) {
    __u64 addr = value + vf->varloc.offset;
    rgwtrace_probe_read_user(&value, sizeof(value), (void *)addr);
  } else {
    value += vf->varloc.offset;
  }
  return value;
}

#endif
