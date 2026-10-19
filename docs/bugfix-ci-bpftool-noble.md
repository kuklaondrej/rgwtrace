# CI: bpftool install and lab-workflow lint on Ubuntu 24.04

## What happened

Every CI run on `main` after the CI-hardening change (commit 63f5cb4) went
red, and every Dependabot PR inherited the failures. Two unrelated causes:

- **Verify (ubuntu-24.04, ubuntu-24.04-arm)**: the apt step asked for
  `bpftool`. On Ubuntu 24.04 that is a virtual package provided by
  `linux-tools-common`, so apt fails with `has no installation candidate`
  before cargo runs. Linux code was never compiled or load-tested in CI; the
  green macOS job only proved the apt-free path.
- **policy**: actionlint runs shellcheck over `docs/lab/workflows/*.yml` and
  flagged SC2016 on the single-quoted script passed to `lxc exec ... bash -c`.
  The quoting is intentional: the script must expand inside the VM.

## Fix

- A dedicated "Install bpftool" step installs `linux-tools-common` and
  `linux-tools-generic`. The kernel-flavour package for the runner's Azure
  kernel (`linux-azure-6.17-tools-*`) ships perf and cpupower but no bpftool,
  so the exact-flavour route is a dead end. The wrapper from
  `linux-tools-common` execs `/usr/lib/linux-tools/$(uname -r)/bpftool`; the
  step points that path at the generic package's binary when the wrapper
  cannot find one. bpftool is a userspace tool, so the generic build loads
  programs on the running kernel. Verified in an `ubuntu:24.04` container
  where the same fallback path is exercised.
- `# shellcheck disable=SC2016` on the lab build step, with a comment saying
  why.
- `ci.yml` now triggers `push` only on `main`, so a PR branch gets one run
  instead of a `push` run plus a `pull_request` run.
