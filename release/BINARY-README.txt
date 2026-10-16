# rgwtrace Linux binaries

Linux binaries for **x86_64** and **ARM64**, built with Rust 1.90.0. Choose an archive for your operating system and architecture:

- `...-<TARGET>.tar.gz` — Ubuntu 22.04 baseline; requires glibc 2.35 or newer.

  Ubuntu/Debian runtime dependencies:

  ```sh
  sudo apt-get install libelf1 zlib1g
  ```

- `...-<TARGET>-centos9.tar.gz` — built on CentOS Stream 9; uses glibc 2.34.

  CentOS 9 runtime dependencies:

  ```sh
  sudo dnf install elfutils-libelf zlib
  ```

`<TARGET>` is `x86_64-unknown-linux-gnu` or `aarch64-unknown-linux-gnu`. CentOS archives are smoke-tested in a clean CentOS Stream 9 container with runtime dependencies installed. You do not need a compiler or Rust installation.

## Download and verify

Download the archive for your architecture and `SHA256SUMS` from this release. Verify the downloaded archive; other archives may be absent:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

Extract the archive and check the binary:

```sh
./rgwtrace --version
./rgwtrace --import-json minimal_dwarf.json --dry-run --output json
```

The `minimal_dwarf.json` fixture is for offline testing only; it cannot be used for live tracing.

## Live tracing

Live tracing requires Linux BPF/perf support, root or equivalent privileges, and Ceph debug symbols or a matching DWARF catalog artifact. For a downloaded DWARF bundle, validate it against the running RGW before tracing:

```sh
sudo ./rgwtrace --pid 12345 --import-json /path/to/native-dwarf.json --preflight
sudo ./rgwtrace --pid 12345 --import-json /path/to/native-dwarf.json --timeout 30 --output json
```

Never override a build-ID mismatch to make a catalog artifact fit. See `RUNBOOK.md` for kernel, container, and privilege requirements.

## DWARF catalogs and source

DWARF catalogs are published separately as releases named `dwarf-<content-hash>`. Binary releases remain the latest release. DWARF support depends on the exact Ceph build. These binaries have passed offline checks, but have not been live-tested on every Ceph build.

Source is available at this release's Git tag and is licensed under GPL-2.0-only.
