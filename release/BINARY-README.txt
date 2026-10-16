Linux binaries for x86_64 and ARM64, built with Rust 1.90.0.
Choose the archive for your operating system and architecture:

  * ...-<TARGET>.tar.gz: Ubuntu 22.04 baseline, requires glibc 2.35+.
    Ubuntu/Debian runtime dependencies:
      sudo apt-get install libelf1 zlib1g
  * ...-<TARGET>-centos9.tar.gz: built on CentOS Stream 9, glibc 2.34.
    CentOS 9 runtime dependencies:
      sudo dnf install elfutils-libelf zlib

TARGET is x86_64-unknown-linux-gnu or aarch64-unknown-linux-gnu.
CentOS archives are smoke-tested in a clean CentOS Stream 9 container with
runtime dependencies installed. No compiler or Rust installation is needed.

Download the archive for your architecture and SHA256SUMS from this release.
Verify the downloaded archive (other archives may be absent):
  sha256sum --check --ignore-missing SHA256SUMS
Extract it, then run:
  ./rgwtrace --version
  ./rgwtrace --import-json minimal_dwarf.json --dry-run --output json
The fixture is only for offline testing, not live tracing.

Live tracing requires Linux BPF/perf support, root or equivalent privileges,
and Ceph debug symbols or a matching DWARF catalog artifact. For a downloaded
DWARF bundle, validate against the running RGW before tracing:
  sudo ./rgwtrace --pid 12345 --import-json /path/to/native-dwarf.json --preflight
  sudo ./rgwtrace --pid 12345 --import-json /path/to/native-dwarf.json --timeout 30 --output json
Never override a build-ID mismatch to make a catalog artifact fit.
See RUNBOOK.md for kernel, container and privilege requirements.

DWARF catalogs are separate releases named dwarf-<content hash>; binary
releases remain the latest release. DWARF support varies by exact Ceph build.
These builds have passed offline checks, not a live test on every Ceph build.
Source is available at this release's Git tag (GPL-2.0-only).
