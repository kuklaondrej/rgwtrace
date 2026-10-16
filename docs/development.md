# Building and testing

[Documentation index](README.md) · [Project overview](../README.md)

Run the commands below from the repository root.

## Native build

Install Rust through rustup; the repository pins Rust **1.90.0**, including
rustfmt and clippy, in [`rust-toolchain.toml`](../rust-toolchain.toml).

On Debian/Ubuntu, install the host build dependencies:

```sh
sudo apt-get update
sudo apt-get install -y clang libelf-dev linux-libc-dev llvm pkg-config zlib1g-dev
```

Build the CLI:

```sh
cargo build --release
```

The binary is `target/release/rgwtrace`. Live tracing requires Linux
(x86_64 or aarch64) with eBPF and uprobes enabled. macOS builds support metadata
validation and other offline workflows; they cannot attach live probes.

## Linux container build

Build a Linux `amd64` binary from macOS or Linux with Docker or Podman:

```sh
./scripts/build-linux-container.sh
```

The script builds `docker/Dockerfile` with `--platform linux/amd64` and copies the binary to `dist/rgwtrace-linux-amd64`.

Override the runtime or output directory when needed:

```sh
CONTAINER_RUNTIME=podman OUTPUT_DIR=/tmp ./scripts/build-linux-container.sh
```

The container build targets Linux `amd64`; native macOS builds support offline workflows only.

## Local verification

Run the fast no-cluster verification loop before live testing:

```sh
./scripts/verify.sh
```

The default tests cover imported DWARF dry-run CLI output, synthetic collector trace golden output, raw event conversion, OTLP encoding, native DWARF parsing helpers, e2e JSON verifier self-tests, and BPF source regressions. Linux CI also covers ring-buffer event decoding without attaching probes.

CI uses the pinned Rust toolchain in `rust-toolchain.toml` and runs `cargo audit`. Run the audit locally when dependency or toolchain inputs change:

```sh
VERIFY_AUDIT=1 ./scripts/verify.sh
```

On Linux, run a real verifier load check when changing BPF code:

```sh
sudo scripts/verify-bpf-load.sh
```

The repository also has a manual `BPF Verify Linux 5.8` workflow for a self-hosted runner labeled `kernel-5.8`.

Use live RGW/Ceph testing only after the fast suite passes or when validating probe attachment against a real runtime.

## Live end-to-end testing

The GitHub `E2E` workflow runs the privileged MicroCeph RGW test inside a fresh LXD VM sandbox on a self-hosted Linux runner. The runner host must have LXD installed and initialized ahead of time; CI does not install or initialize LXD.

Prepare the self-hosted runner host once:

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends snapd
sudo snap install lxd
sudo lxd init
sudo usermod -aG lxd <runner-user>
```

When prompted by `lxd init`, create a local bridge and choose an IPv4 subnet that does not overlap host routes, such as `10.250.0.1/24`; enable IPv4 NAT and disable IPv6 if it is not needed.

Restart the GitHub runner service so the `lxd` group membership applies.

Verify as the runner user with `lxc info`; optionally smoke-test a VM:

```sh
lxc info
lxc launch ubuntu:24.04 rgwtrace-smoke --vm
lxc delete -f rgwtrace-smoke
```

Run the privileged MicroCeph RGW e2e test directly on Linux when validating live request capture:

```sh
cargo build --release
sudo tests/e2e/functional-test-microceph-rgw.sh
```

The e2e test bootstraps MicroCeph, enables RGW, drives S3 traffic, captures `rgwtrace` JSON, and verifies request spans, RADOS child spans, diagnostics, correlation, and current role categories. It preserves `preflight.json`, `trace.json`, `workload.jsonl`, and logs under `/tmp/rgwtrace-e2e`.

By default, the e2e test installs MicroCeph from `reef/stable` and fails early unless the snap resolves to Ceph package version `18.2.4-0ubuntu1~cloud0`. It writes `microceph-version.txt`, `microceph-metadata.yaml`, `microceph-manifest.yaml`, and `microceph-manifest-ceph.txt` under `/tmp/rgwtrace-e2e` so the traced version is explicit.

Override the pin when needed:

```sh
sudo MICROCEPH_CHANNEL=reef/stable \
  MICROCEPH_EXPECTED_CEPH_VERSION=18.2.4-0ubuntu1~cloud0 \
  tests/e2e/functional-test-microceph-rgw.sh
```

If MicroCeph is already installed at a different version, the test fails rather than switching it automatically. Set `MICROCEPH_ALLOW_CHANNEL_SWITCH=1` only on disposable test hosts.

If native DWARF is unavailable for the MicroCeph snap, pass matching probe metadata explicitly:

```sh
sudo RGWTRACE_DWARF_JSON=/path/to/rgwtrace_dwarf.json tests/e2e/functional-test-microceph-rgw.sh
```

See the [correlation gate](../RUNBOOK.md#end-to-end-objectrequest-correlation-gate)
for workload coverage and interpretation, and [AGENTS.md](../AGENTS.md) for
repository conventions and correctness constraints.

## Publishing releases

Two workflows publish durable GitHub Release assets. Both upload into a draft
first and publish only after every upload succeeds. Reruns can repair a draft;
a published release is never overwritten. Only the publishing jobs have
`contents: write` permission.

### CLI binaries

1. Update the root package version in `Cargo.toml` and refresh `Cargo.lock`.
2. Run `scripts/verify.sh` and merge the change.
3. Tag that commit with the matching stable version and push the tag:

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

The [binary workflow](../.github/workflows/release.yml) checks that the tag
matches `Cargo.toml`, runs the verification gate on native x86_64 and ARM64
Linux runners, and builds with Rust 1.90.0 and `--locked`. It extracts each
archive and smoke-tests the packaged binary with `--version` and an offline
JSON dry run. Both architectures and both OS variants must succeed before publication.
CentOS builds run inside `docker/Dockerfile.centos9-builder` on native runners,
using `scripts/build-centos9-release.sh`. They run the same verification gate
and compile against CentOS Stream 9's glibc 2.34. The packaged archives are
then tested in a separate clean CentOS container with only runtime dependencies
and the smoke-test tools installed. Build dependencies cannot mask missing
runtime libraries in this check.

Assets are `rgwtrace-v<VERSION>-<TARGET>.tar.gz` (Ubuntu baseline),
`rgwtrace-v<VERSION>-<TARGET>-centos9.tar.gz` (CentOS 9), and `SHA256SUMS`. Each archive
contains the executable (with embedded BPF program), GPL license, README,
runbook, installation instructions, resolved shared-library list, and an
offline fixture. Standard archives target glibc 2.35+ (Ubuntu 22.04 baseline);
CentOS 9 archives target glibc 2.34. Both need libelf and zlib runtime packages. Alpine/musl is not supported by these
archives. They are not guaranteed to run on older glibc systems.

The first release must be triggered by a real matching tag; manual reruns must
also select that tag. This workflow currently accepts stable `vX.Y.Z` tags,
not prereleases. It does not bump versions or create version tags. Binary
releases become GitHub's latest release. Live tracing still requires the
kernel/privileges described in the runbook; CI smoke tests do not claim live
compatibility with every kernel or Ceph build.

### DWARF catalog

The [DWARF release workflow](../.github/workflows/dwarf-release.yml) runs weekly,
on version tags, or manually. Its curated matrix is
[`release/dwarf-matrix.json`](../release/dwarf-matrix.json). As checked on
2026-10-16, it contains 34 amd64 builds: each version below on both Ubuntu
22.04 (Jammy) and CentOS Stream 9 (upstream EL9 RPMs).

| Series | Included versions |
| --- | --- |
| Reef | 18.2.0, 18.2.1, 18.2.2, 18.2.4, 18.2.5, 18.2.6, 18.2.7, 18.2.8 |
| Squid | 19.2.0 through 19.2.7 |
| Tentacle | 20.2.4 (latest at the time of the matrix update) |

Reef 18.2.3 was an early build re-tagged upstream as 18.2.4; there is no
separate official package repository to export. See the
[Reef release notes](https://docs.ceph.com/en/latest/releases/reef/#v18-2-4-reef).
The current endpoints are documented by the
[Squid](https://docs.ceph.com/en/latest/releases/squid/) and
[Tentacle](https://docs.ceph.com/en/latest/releases/tentacle/) release notes.
Historical coverage lets existing deployments be traced; inclusion is not an
upgrade recommendation.

Each row specifies `os`, `os_version`, the export container `image`, `ceph`,
`arch`, and the exact `package_version`. Ubuntu rows pin `X.Y.Z-1jammy`;
CentOS Stream rows pin `X.Y.Z-0.el9`. All required packages were checked in
`https://download.ceph.com/debian-X.Y.Z/dists/jammy/main/binary-amd64/Packages.gz`
and `https://download.ceph.com/rpm-X.Y.Z/el9/x86_64/` before adding these rows.
Repository availability does not establish that extraction or live tracing
works: each build must still pass the workflow's export and preflight gates.

The CentOS exporter enables CRB and EPEL for dependencies, configures signed
upstream Ceph x86_64/noarch repositories, and installs the exact runtime and
`-debuginfo` RPM revisions (including `ceph-debuginfo`). It captures RPM names,
version-release strings, and native `x86_64` architecture in `packages.txt`;
the catalog uses `amd64` consistently across distributions. This covers
upstream EL9 builds, not arbitrary CentOS Storage SIG rebuilds. Ubuntu's own
packages, MicroCeph, Proxmox, and arbitrary cephadm images also need their own
matching build IDs. For CentOS 9, use the `-centos9` binary release archive.
The DWARF exporter builds its own executable inside the CentOS container.

To extend coverage, check that the versioned upstream repository publishes all
runtime/debug packages listed in `scripts/export-upstream-ceph-dwarf.sh` at
the selected revision, then add an explicit matrix entry. The current exporter
is amd64-only; ARM64 binary availability does not imply ARM64 DWARF coverage.
New Ceph versions require a matrix change; the schedule rechecks listed
versions, it does not discover and approve new versions automatically. Jobs
run with `max-parallel: 4` to limit concurrent debug-package downloads.

The exporter installs upstream binaries and debug packages, records the exact
installed Debian or RPM package revisions, extracts JSON, and runs offline preflight
against those binaries. `scripts/package-dwarf.py` is the publication gate:

- A successful preflight and all required probe checks are mandatory.
- RGW, librados, librbd, and libceph-common need matching, nonempty build IDs.
- Package provenance and metadata must match the requested version/architecture.
- Optional request-END and cross-thread probe warnings remain publishable and
  are preserved in the manifest and index. Full exported metadata, including
  linkage provenance and DPP descriptors, is preserved without rewriting.

Each bundle contains `native-dwarf.json`, `manifest.json`, `preflight.json`,
package revisions, OS/repository provenance, and usage instructions. The
release's `index.json` lists every bundle, its checksum, build IDs, exporter
commit, and optional capability checks. `SHA256SUMS` covers all assets. Catalogs
use content-derived `dwarf-<hash>` release tags and do not replace the latest
binary release. Repeating the same export produces the same catalog identity;
changed metadata, exporter commit, or provenance creates a new snapshot. Old
releases remain available for old deployments. Each snapshot indexes its own
matrix results, not the union of all previous releases.

Currently scheduled runs rebuild the matrix before checking the catalog's
identity; unchanged published catalogs are skipped at publication. A failed
matrix entry prevents publication of the entire snapshot. Raw exports and
logs are retained as 14-day Actions diagnostic artifacts, including failed
preflight output. The older manual `DWARF Artifact` workflow remains useful
for investigating unsupported builds and never publishes a Release.

Packaging tests run with `python3 -m unittest discover -s tests -p 'test_release.py'`
and are included in `scripts/verify.sh` and CI. Workflow syntax can be checked
with `actionlint`. Publishing needs the repository's Actions token to have
write access to releases; no personal access token is required.
