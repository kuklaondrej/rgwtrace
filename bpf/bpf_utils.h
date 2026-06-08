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

static __noinline __u64 fetch_register(const struct pt_regs *const ctx, int reg) {
  __u64 v = 0;

#if defined(__TARGET_ARCH_x86)
  if (reg == 0)
    v = ctx->rax;
  else if (reg == 1)
    v = ctx->rdx;
  else if (reg == 2)
    v = ctx->rcx;
  else if (reg == 3)
    v = ctx->rbx;
  else if (reg == 4)
    v = ctx->rsi;
  else if (reg == 5)
    v = ctx->rdi;
  else if (reg == 6)
    v = ctx->rbp;
  else if (reg == 7)
    v = ctx->rsp;
  else if (reg == 8)
    v = ctx->r8;
  else if (reg == 9)
    v = ctx->r9;
  else if (reg == 10)
    v = ctx->r10;
  else if (reg == 11)
    v = ctx->r11;
  else if (reg == 12)
    v = ctx->r12;
  else if (reg == 13)
    v = ctx->r13;
  else if (reg == 14)
    v = ctx->r14;
  else if (reg == 15)
    v = ctx->r15;
#elif defined(__TARGET_ARCH_arm64)
  const struct user_pt_regs *regs = (const struct user_pt_regs *)ctx;
  if (reg >= 0 && reg <= 30)
    v = regs->regs[reg];
  else if (reg == 31)
    v = regs->sp;
#else
#error "Unsupported architecture: only x86 and arm64 are supported"
#endif

  return v;
}

static __always_inline __u64 fetch_var_member_addr(__u64 cur_addr,
                                                   struct VarField *vf) {
  if (vf == 0 || cur_addr == 0)
    return 0;

  __u64 tmpaddr = 0;
  if (vf->varloc.stack) {
    cur_addr += vf->varloc.offset;
    if (vf->fields[1].pointer) {
      bpf_probe_read_user(&tmpaddr, sizeof(tmpaddr), (void *)cur_addr);
      cur_addr = tmpaddr;
    }
  }

  cur_addr += vf->fields[1].offset;

  for (int i = 2; i < 10; i++) {
    if (i >= vf->size)
      break;
    if (vf->fields[i].pointer) {
      bpf_probe_read_user(&tmpaddr, sizeof(tmpaddr), (void *)cur_addr);
      cur_addr = tmpaddr + vf->fields[i].offset;
    } else {
      cur_addr += vf->fields[i].offset;
    }
  }

  return cur_addr;
}

#endif
