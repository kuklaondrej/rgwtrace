/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Bench-only "trivial trap" uprobe. It is deliberately NOT part of
 * bpf/rgwtrace.bpf.c: its entire purpose is to isolate the cost of the
 * uprobe trap machinery itself (int3 -> kernel -> BPF prog dispatch -> return)
 * with a program body that does the least possible work. Comparing a synthetic
 * function probed by this program against the same function with no probe yields
 * t_trap; comparing a real rgwtrace program against this yields that program's
 * marginal body cost t_prog.
 *
 * It increments a per-CPU counter so the harness can PROVE the trap actually
 * fired for every call (attach succeeded, pid filter matched), rather than
 * silently measuring an unattached no-op.
 */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} trap_count SEC(".maps");

SEC("uprobe")
int bench_trap(struct pt_regs *ctx) {
  __u32 key = 0;
  __u64 *counter = bpf_map_lookup_elem(&trap_count, &key);
  if (counter != 0)
    *counter += 1;
  return 0;
}
