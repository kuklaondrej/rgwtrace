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

  __u64 tmpaddr = 0;
  if (vf->varloc.stack) {
    cur_addr += vf->varloc.offset;
    if (vf->fields[1].pointer) {
      rgwtrace_probe_read_user(&tmpaddr, sizeof(tmpaddr), (void *)cur_addr);
      cur_addr = tmpaddr;
    }
  }

  cur_addr += vf->fields[1].offset;

  for (int i = 2; i < 10; i++) {
    if (i >= vf->size)
      break;
    if (vf->fields[i].pointer) {
      rgwtrace_probe_read_user(&tmpaddr, sizeof(tmpaddr), (void *)cur_addr);
      cur_addr = tmpaddr + vf->fields[i].offset;
    } else {
      cur_addr += vf->fields[i].offset;
    }
  }

  return cur_addr;
}

/*
 * Raw-pointer parameter fetch for register-at-entry descriptors: return the
 * value of the parameter's ABI register, or 0 when the descriptor is
 * stack-located (post-prologue spill). Register-only by design -- it never
 * composes a varloc via fetch_var_member_addr, so there is no double-varloc
 * risk. Callers treat 0 as "unresolved" and fail closed.
 */
static __always_inline __u64 fetch_param_ptr(const struct pt_regs *const ctx,
                                             struct VarField *vf) {
  if (vf == 0 || vf->varloc.stack)
    return 0;
  return fetch_register(ctx, vf->varloc.reg);
}

/*
 * Reference-to-pointer parameter fetch. A C++ REFERENCE to a pointer (`RGWOp*&
 * op`) is passed as the ADDRESS of the caller's pointer variable, so the ABI
 * register holds a `RGWOp**` and exactly ONE user read yields the `RGWOp*`
 * itself.
 *
 * This is a read of the POINTEE, not a struct-field walk: no member offset is
 * applied, no inheritance offset is assumed, and the pointed-at type is proven
 * from DWARF (`reference -> pointer -> RGWOp`) before the descriptor that leads
 * here is ever emitted (see `probe_function_var_fields` in src/dwarf_native.rs).
 * The VALUE it returns is used only as an opaque bridge key -- it is never
 * dereferenced.
 *
 * Fails closed: 0 on an unresolved (stack-located) descriptor or a failed read.
 */
static __always_inline __u64 fetch_param_ptr_ref(const struct pt_regs *const ctx,
                                                 struct VarField *vf) {
  __u64 addr = fetch_param_ptr(ctx, vf);
  if (addr == 0)
    return 0;
  __u64 value = 0;
  if (rgwtrace_probe_read_user(&value, sizeof(value), (void *)addr) != 0)
    return 0;
  return value;
}

#endif
