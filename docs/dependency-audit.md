# Dependency audit review

Reviewed 2026-09-29 with cargo-audit 0.22.2 and the current RustSec database.
The lockfile updates rustls to 0.23.45 (RUSTSEC-2026-0285), rustls-webpki to
0.103.15, and the yanked chacha20 0.10.1 to 0.10.2.

One informational `unsound` warning remains: **RUSTSEC-2026-0186** in
`memmap2 0.5.10`, pulled in by the Linux build dependency `libbpf-cargo 0.24.8`.
The affected APIs are the range-based advise/flush methods. In the resolved
libbpf-cargo source, `src/gen/mod.rs` uses `Mmap::map` to read the generated BPF
object; it does not call those affected methods. rgwtrace has no direct memmap2
usage. This review is scoped to the locked dependency version and current call
sites, not a claim that the affected crate is safe for arbitrary uses.

Audits fail on vulnerabilities, yanked crates, and unmaintained crates.
The informational unsound warning remains visible in every audit; no advisory ignore has been added.
Reassess it when changing build dependencies. Moving to a newer libbpf-cargo
family should be tested as a separate BPF toolchain upgrade, including live
attachment and minimum-kernel validation. Cargo audit's successful exit means
no blocking vulnerabilities, not an empty warning list.

Source: [RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0186.html).
