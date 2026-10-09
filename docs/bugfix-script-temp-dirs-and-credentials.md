# Bugfix: private temp directories, credentials off argv, pinned images

## What happened

A security review of the operational scripts (they run as root on storage
nodes) found a cluster of hygiene problems. None of them is a bug in the
tracer; all of them are about what the surrounding scripts write, where, and
what they trust.

1. `scripts/stage0-crossthread-probe.sh` wrote its generated `stage0.bt` into
   the predictable `/tmp/rgwtrace-stage0` with `mkdir -p` and `cat >`, then ran
   it with a privileged `bpftrace`. Any local user who pre-created that
   directory could plant a symlink (so `cat >` wrote elsewhere as root) or, if
   they raced the write, choose the program bpftrace executed: arbitrary kernel
   and process memory reads as root.
2. `tests/e2e/functional-test-microceph-rgw.sh` used the predictable
   `/tmp/rgwtrace-e2e`, wrote there as root with `rm -f` then `>`, persisted
   `rgw-user.json` with the S3 secret in it, created the RGW user with a
   well-known key pair (`RGWTRACEACCESSKEY001` / `rgwtrace-secret-key-...`,
   also printed in `docs/stage0-runbook.md`), and only purged the user when the
   run succeeded, so a failed run left a credentialed user on the host.
3. `scripts/export-upstream-ceph-dwarf.sh` used `/tmp/rgwtrace-cargo-home` and
   `/tmp/rgwtrace-target` as root. Cargo honours `$CARGO_HOME/config.toml`
   (`build.rustc-wrapper`, `[target].runner`, ...), so a planted config was
   root code execution. The script also piped `sh.rustup.rs` into `sh`, fetched
   the Ceph APT key without checking its fingerprint, and would happily rewrite
   APT sources on a shared host.
4. `scripts/bench-rgw-ab.sh` and the e2e test passed `--secret-key` to
   `tests/e2e/s3-workload.py` on argv, which every local user can read in
   `ps` / `/proc/<pid>/cmdline`; the bench `--dry-run` printed it too.
5. `.dockerignore` only excluded `target/`, `dist/` and `.git`, so
   `COPY . /workspace` in `docker/Dockerfile` baked local benchmark results,
   traces, agent state (`.claude/`, `.codex-smoke-*`, over 1 GB locally) and
   env files into image layers. The base image floated on a tag.

## Why

Predictable paths under `/tmp` are shared with every local account. A script
that runs as root and trusts such a path is trusting every user on the box.
Secrets on argv and in artifact files leak the same way. These scripts were
written for single-user lab VMs, where none of this matters; they are now
also run on hosts that are not.

## The fix

### One shared check: `scripts/lib/private-dir.sh`

Every writable directory the privileged scripts use goes through
`rgwtrace_require_private_dir DIR`:

- The default is always a fresh `mktemp -d` directory
  (`rgwtrace_private_tmpdir PREFIX`, mode 0700), and the scripts set
  `umask 077` so every file they create is private too.
- A caller-supplied directory that does not exist is created with
  `mkdir -m 0700` **without** `-p`: `mkdir` fails on an existing path of any
  kind, so a planted symlink cannot be followed and there is no window between
  "check" and "create".
- An existing directory must be a real directory (not a symlink), owned by the
  current uid, and must have no group/other write bits. `/tmp` itself is
  refused (world-writable; the sticky bit does not stop another user from
  creating entries in it).
- Every ancestor is checked too, before anything is created: it must be owned
  by root or the current uid, and be either not group/other writable or
  sticky. Otherwise another user could rename our (correctly owned, 0700)
  directory away after the check and put theirs at the same path, which the
  scripts then write to and execute from by name. A sticky `/tmp` passes
  because only an entry's owner can rename it there; a 0777 non-sticky
  `/srv/shared` does not. Symlink components on the path must be owned by
  root or us, since anyone else could re-point them. Covered by
  `tests/scripts/private-dir-test.sh`, which `scripts/verify.sh` runs.

The check uses GNU `stat -c` and falls back to BSD `stat -f` only so it can be
exercised on macOS; the scripts remain Linux-only.

The strictness is deliberate: the review asked to refuse a missing directory
outright, but the e2e workflows pre-set `ARTIFACT_DIR=/tmp/rgwtrace-e2e`
inside a fresh VM, and creating the directory ourselves (atomically, 0700) is
exactly as safe as asking the operator to do it first.

### Per script

- **stage0**: `STAGE0_OUTDIR` defaults to `mktemp -d`; a supplied one is
  checked before `stage0.bt` is written.
- **e2e**: `ARTIFACT_DIR` defaults to `mktemp -d` and is checked otherwise.
  The RGW user is created without key flags, so `radosgw-admin` generates a
  random key pair per run and the secret never appears on any command line
  (`RGW_ACCESS_KEY` + `RGW_SECRET_KEY` together still force fixed keys). The
  persisted `rgw-user.json` has `secret_key` fields replaced by `<redacted>`.
  `cleanup` purges the user on every exit path unless `KEEP_E2E_RESOURCES=1`,
  in which case it prints how to read the keys back.
- **export**: refuses to run outside a container (`/.dockerenv`,
  `/run/.containerenv`, `$container`) unless `RGWTRACE_ALLOW_HOST_EXPORT=1`.
  `ARTIFACT_DIR`, `CARGO_HOME`, `RUSTUP_HOME` and `CARGO_TARGET_DIR` live in
  private directories, each passed through the same check (the toolchain
  binaries cargo runs as root live under `RUSTUP_HOME`). `rustup-init` is downloaded as a pinned release binary
  (`RUSTUP_INIT_VERSION`, currently 1.29.1) and compared with the SHA-256
  rustup publishes next to it, recorded in the script per architecture; the
  comment there says how to refresh it. The Ceph release key is downloaded to
  a private file and its fingerprint compared with the pinned
  `08B73419AC32B4E966C1A330E84AC2C0460F3994` before it is dearmored into the
  keyring, and the file must contain exactly one primary key: `gpg --dearmor`
  installs the whole file, so a second key appended by a compromised mirror
  would otherwise be trusted by APT even though only the first was checked. Ceph's docs do not print the full fingerprint; the long key ID
  `E84AC2C0460F3994` is the one published in Ceph's 2015 signing-key security
  notice, and the pinned fingerprint ends in exactly that ID (computed from the
  key served by `download.ceph.com` on 2026-10-09). The `dwarf-artifact`
  workflow now creates the bind-mounted artifact directory root-owned 0700 and
  hands it back to the runner user afterwards, since the script refuses a
  directory it does not own.
- **s3-workload.py**: `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` are
  preferred and override the flags; `--access-key` / `--secret-key` stay for
  compatibility, and a `--secret-key` on argv prints a warning.
- **bench**: no default credentials; keys come from `RGW_*` or `AWS_*` env and
  are exported to the workload, never placed in its argv. `print_cmd` redacts
  `--secret-key` / `--access-key` values as a second line of defence.
- **Docker**: `.dockerignore` is an allowlist of the build inputs;
  `docker/Dockerfile` pins `rust:1.90-bookworm` by its multi-arch index digest
  and keeps the tag for readability.

### Deliberately not done here

`scripts/verify.sh` (pin `cargo-audit`) and `.gitignore` (`__pycache__/`,
`*.py[cod]`, `.codex-smoke-*`) are already covered by the open
public-contribution-readiness PR and were left alone to avoid conflicting
edits.

## How to verify

```sh
# shell
docker run --rm -v "$PWD":/mnt koalaman/shellcheck:stable -x \
  scripts/lib/private-dir.sh scripts/stage0-crossthread-probe.sh \
  scripts/export-upstream-ceph-dwarf.sh scripts/bench-rgw-ab.sh \
  tests/e2e/functional-test-microceph-rgw.sh

# credentials never reach argv, even in the plan
RGW_ACCESS_KEY=a RGW_SECRET_KEY=b scripts/bench-rgw-ab.sh --dry-run | grep -c secret   # 0

# the image context is only the allowlist
docker build -f docker/Dockerfile -t rgwtrace-check . && \
  docker run --rm rgwtrace-check ls /workspace
```
