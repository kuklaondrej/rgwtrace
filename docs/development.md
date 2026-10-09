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

The default tests cover imported DWARF dry-run CLI output, synthetic collector trace golden output, raw event conversion, OTLP encoding, native DWARF parsing helpers (including adversarial DWARF/ELF inputs built in memory: reference cycles, 100 000-deep DIE trees, oversized files and compressed-section bombs, see `src/dwarf_native_robustness_tests.rs`), e2e JSON verifier self-tests, and BPF source regressions. Linux CI also covers ring-buffer event decoding without attaching probes.

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
