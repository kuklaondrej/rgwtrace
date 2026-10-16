# Fix dependency audit failures in release CI

CI for PR #16 failed at `cargo audit` because the committed lockfile contained
10 vulnerability findings across three transitive dependencies. The failures
were reported by the current RustSec database, after the ordinary Rust tests
and clippy had passed.

The dependency update keeps Rust 1.90.0 and the existing runtime features:

| Dependency | Previous | Updated | Reason |
| --- | --- | --- | --- |
| `quinn-proto` | 0.11.16 | 0.11.18 | Fix the reported connection/stream resource-exhaustion and panic advisories |
| `rustls` | 0.23.40 | 0.23.46 | Fix the reported handshake, session-debug, decompression, and key-exchange advisories |
| `object` | 0.39.1 | 0.40.0 | Permit the patched `ruzstd` dependency while retaining compressed ELF/DWARF support |
| `ruzstd` | 0.8.3 | 0.9.1 | Fix the decompression-bomb advisory RUSTSEC-2026-0344 |
| `chacha20` | 0.10.1 | 0.10.2 | Replace the yanked release reported by audit |

`rustls-webpki` also advances from 0.103.13 to 0.103.15 during resolution.
No advisory is ignored and the audit check remains enabled. `object` 0.40
requires Rust 1.85, below the pinned toolchain. Existing ELF/DWARF and OTLP tests
cover the affected integration paths; the failing CI audit is the regression
reproducer.

Validation: `cargo audit`, `scripts/verify.sh`, and `cargo build --release --locked`
on Linux with Rust 1.90.0. The pre-existing, non-fatal `memmap2` 0.5.10 warning
comes from `libbpf-cargo` 0.24.8 and is separate from the vulnerability failures;
upgrading that build dependency requires a coordinated libbpf migration.
