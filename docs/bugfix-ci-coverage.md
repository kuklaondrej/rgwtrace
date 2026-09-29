# CI coverage and public-contribution preparation

The documented verification gate and CI had diverged: CI omitted the Python
verifier tests and root Cargo commands omitted the benchmark workspace member.
The local macOS gate also failed, while some DWARF fixtures silently returned
without assertions. Privileged workflows built untrusted source on a persistent
host before entering the test VM.

CI now calls the workspace gate on Linux x86-64/ARM64 and macOS, audits a pinned
cargo-audit installation separately, validates workflow syntax, scans Git history,
and loads BPF on hosted Linux runners. The stable aggregate `rust` check fails
when any dependency fails or is skipped. Actions use immutable commits and
read-only permissions. The rustls lockfile update addresses RUSTSEC-2026-0285; chacha20 is updated off
a yanked version. The remaining build-dependency warning is reviewed in
[dependency audit](dependency-audit.md) and remains visible.

macOS fixtures read clang's dSYM debug object and use the executable for the
independent symbol-address oracle. The destructor shape oracle selects the same
variant rank and recognizes expression locations as well as lists. Pointer
location fixtures use a pointer instead of an aggregate split across registers;
ordinary extraction fixtures use -O1 to exercise supported entry locations.
Linux x86-64 requires every built-in fixture to reach its assertions. The external
Ceph oracle is explicitly ignored unless invoked with its required input files.
Non-Linux builds exclude Linux-only entry points while retaining portable tests.
The benchmark uses a portable pointer cast for uname output so ARM64 Clippy
does not fail on the platform-specific signedness of C char.

Privileged workflows are private-lab templates. E2E compiles inside its disposable
VM and runs baseline, cross-thread, and missing-END profiles. Required coverage
cannot default to zero or silently skip; each LIST must retain the configured
number of distinct shard objects. Regression tests first reproduced acceptance
of missing evidence, then verified its rejection.

These changes do not enable GitHub rules, unregister runners, or establish fresh
live Ceph measurements. See the publication checklist and lab runbook for those
remaining steps. Source-string checks and handwritten BPF models remain useful
regressions, not substitutes for actual kernel and Ceph execution.
