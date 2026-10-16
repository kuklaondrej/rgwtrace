# Privileged test lab

The files in `workflows/` are templates, not active public-repository workflows.
Copy them into `.github/workflows/` in a separate **private** lab repository.
Enable Dependabot GitHub Actions updates in the lab repository to maintain its
pinned action commits. The templates select a reviewed 40-character SHA from `kuklaondrej/rgwtrace`; do not test
a moving branch name. Source checkout assumes that source repository is public;
while it remains private, grant the lab a read-only source credential explicitly.
Do not put source credentials in the test VM.

For E2E, use a dedicated lab runner with LXD initialized and no production
credentials or routes to production services. The runner must be able to create
VMs (`lxd` group). The workflow copies source into a fresh VM, installs Rust
1.90.0 there, builds there, runs there, and destroys the VM afterward. Arbitrary
Cargo build scripts never run on the persistent host. Review changes to the lab
workflow itself before using them. Run the 5.8 workflow on a disposable VM whose
runner carries `kernel-5.8`; the workflow checks the actual kernel as well.
Destroy that runner VM externally after the job, even when the job fails.

Configure the `privileged-tests` environment with maintainer approval and
restricted deployment branches. Environment checks and the private-repo job
condition are defense in depth; the security boundary is the private runner
registration and disposable test machines. Remove the old runner registration
from the source repository before publication. No YAML change can do that.

E2E dispatch requires baseline and cross-thread GET/PUT coverage thresholds,
each finite and greater than zero. Establish and record repeated healthy-run
baselines for the pinned Ceph build; do not lower thresholds in response to a
regression. The no-END case currently uses baseline thresholds. All three
profiles require distinct shard coverage for every LIST:

| Profile | Required evidence |
| --- | --- |
| baseline | measured request ends and baseline correlation coverage |
| cross-thread | measured ends, cross-thread children, per-submit bridge hits |
| no-end | missing-destructor warning, derived durations, no per-submit seeds |

The no-END case removes destructor metadata from a copy of the exported JSON;
it does not simulate every possible kernel attach error. A build lacking the
required bridge descriptors fails the cross-thread profile; use a supported
build to establish coverage instead of accepting a silent skip.

Retain source SHA, kernel, Ceph metadata, thresholds, manifests, trace, and logs.
Treat artifacts as untrusted input and inspect them before sharing. The lab's
S3 credentials are synthetic, scoped to the disposable VM. If a runner dies
before cleanup, delete the named `rgwtrace-e2e-*` VM before reusing the host.

Run current-kernel E2E and minimum-kernel loading before relevant merges and
releases. Hosted PR CI covers current-kernel BPF loading on x86-64 and ARM64;
that is not equivalent to a live Ceph test or minimum-kernel execution.
