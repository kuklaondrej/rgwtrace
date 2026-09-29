# Building and testing

[Documentation index](README.md) · [Project overview](../README.md)

Run the commands below from the repository root.

## Native build

Install Rust through rustup; the repository pins Rust **1.90.0**, including
rustfmt and clippy, in [`rust-toolchain.toml`](../rust-toolchain.toml).

On Debian/Ubuntu, install the host build dependencies:

```sh
sudo apt-get update
sudo apt-get install -y clang libelf-dev linux-libc-dev llvm pkg-config zlib1g-dev g++ dwz binutils
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

Hosted CI checks Linux x86-64, Linux ARM64, and macOS ARM64. All jobs run the
workspace tests (including `bench`), fmt, Clippy, and Python verifier checks.
Linux jobs also compile and load the BPF programs on the runner kernel. Audit
and workflow/history scanning run separately; the stable `rust` check requires
all jobs to succeed. Dependency auditing also runs weekly to catch advisories
without waiting for a code change.

Linux x86-64 CI sets `RGWTRACE_REQUIRE_DWARF_FIXTURES=1`: a missing tool or an
unexercised fixture assertion fails the suite. Other platforms report fixture
skip reasons (use `cargo test --workspace --locked -- --show-output` to display them); compiler-specific LTO/DWZ shapes are guaranteed by the x86-64 job.
The external Ceph oracle is explicitly ignored unless requested:

```sh
RGWTRACE_ORACLE_JSON=/path/to/dwarf.json \
RGWTRACE_ORACLE_TARGETS=/path/to/radosgw:/path/to/libceph-common.so.2 \
RGWTRACE_ORACLE_COMPARE_FUNC2VF=1 \
cargo test compares_native_output_to_cephtrace_json_oracle_when_configured -- --ignored
```

Use live RGW/Ceph testing only after the fast suite passes or when validating probe attachment against a real runtime.

## Live end-to-end testing

Privileged workflow templates live in [`lab/workflows/`](lab/workflows/), outside
this repository's active workflows. Install them in a **private lab repository**
after following [lab setup](lab/README.md). Do not register a persistent
self-hosted runner with a public repository. E2E builds and runs inside a fresh
LXD VM and selects an explicitly reviewed full source SHA.

Run directly only on a disposable Linux test machine. Supply positive coverage
thresholds established for that Ceph build and profile:

```sh
cargo build --release --locked
sudo env E2E_PROFILE=baseline \
  REQUIRE_GET_READ_CORRELATION="$BASELINE_GET_RATE" \
  REQUIRE_PUT_WRITE_CORRELATION="$BASELINE_PUT_RATE" \
  tests/e2e/functional-test-microceph-rgw.sh
```

Repeat with `E2E_PROFILE=cross-thread` and `E2E_PROFILE=no-end`, using the
corresponding measured thresholds. A cross-thread run with no actual bridge
activity fails; it does not silently become a baseline test.

The e2e test bootstraps MicroCeph, enables RGW, drives S3 traffic, captures `rgwtrace` JSON, and verifies request spans, RADOS child spans, diagnostics, correlation, and current role categories. It preserves `preflight.json`, `trace.json`, `workload.jsonl`, and logs under `/tmp/rgwtrace-e2e`.

By default, the e2e test installs MicroCeph from `reef/stable` and fails early unless the snap resolves to Ceph package version `18.2.4-0ubuntu1~cloud0`. It writes `microceph-version.txt`, `microceph-metadata.yaml`, `microceph-manifest.yaml`, and `microceph-manifest-ceph.txt` under `/tmp/rgwtrace-e2e` so the traced version is explicit.

Override the pin when needed:

```sh
sudo env REQUIRE_GET_READ_CORRELATION="$BASELINE_GET_RATE" \
  REQUIRE_PUT_WRITE_CORRELATION="$BASELINE_PUT_RATE" \
  MICROCEPH_CHANNEL=reef/stable \
  MICROCEPH_EXPECTED_CEPH_VERSION=18.2.4-0ubuntu1~cloud0 \
  tests/e2e/functional-test-microceph-rgw.sh
```

If MicroCeph is already installed at a different version, the test fails rather than switching it automatically. Set `MICROCEPH_ALLOW_CHANNEL_SWITCH=1` only on disposable test hosts.

If native DWARF is unavailable for the MicroCeph snap, pass matching probe metadata explicitly:

```sh
sudo env REQUIRE_GET_READ_CORRELATION="$BASELINE_GET_RATE" \
  REQUIRE_PUT_WRITE_CORRELATION="$BASELINE_PUT_RATE" \
  RGWTRACE_DWARF_JSON=/path/to/rgwtrace_dwarf.json \
  tests/e2e/functional-test-microceph-rgw.sh
```

See the [correlation gate](../RUNBOOK.md#end-to-end-objectrequest-correlation-gate)
for workload coverage and interpretation, and [AGENTS.md](../AGENTS.md) for
repository conventions and correctness constraints.
