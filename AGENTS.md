# AGENTS.md

Guidance for AI coding agents working in this repo. Keep it accurate as the code changes.

## Overview

`rgwtrace` is a Rust CLI that traces **Ceph RADOS Gateway (RGW)** request activity using **eBPF uprobes**, correlates each RGW request with its child RADOS ops, and exports request-oriented telemetry as JSON or OTLP/HTTP protobuf.

Pipeline:

```
native DWARF or cephtrace JSON  ->  hprobes map  ->  eBPF uprobes  ->  ring buffer  ->  Rust events  ->  spans  ->  JSON or OTLP protobuf
```

Licensed GPL-2.0-only (the `bpf/` code is derived from Ceph `cephtrace`/`radostrace`). For depth, read `ARCHITECTURE.md` (stage-by-stage internals) and `RUNBOOK.md` (operations/troubleshooting); `README.md` has the overview.

## Toolchain

- Rust pinned to **1.90.0** (`rust-toolchain.toml`), edition 2021. Use this exact version.
- Host build deps (Debian/Ubuntu): `clang libelf-dev linux-libc-dev llvm pkg-config zlib1g-dev`.
- Builds on macOS, but **live tracing is Linux-only** (x86_64/aarch64). `build.rs` no-ops off Linux and `live.rs` bails at runtime. `build.rs` generates the BPF skeleton (`rgwtrace.skel.rs`) from `bpf/rgwtrace.bpf.c` via `libbpf-cargo`.

## Build / test / lint

- Build: `cargo build` / `cargo build --release` (→ `target/release/rgwtrace`)
- Format: `cargo fmt --check` (fix with `cargo fmt`)
- Lint: `cargo clippy --all-targets -- -D warnings` (warnings are errors)
- Test: `cargo test` (inline unit tests + `tests/cli_dry_run.rs`, `tests/bpf_source.rs`; fixtures in `tests/fixtures/`)
- JSON self-test, no cluster: `python3 tests/e2e/verify-rgwtrace-json.py --self-test`
- BPF verifier load check (Linux + root): `sudo scripts/verify-bpf-load.sh`

**Canonical pre-commit gate:** `scripts/verify.sh` — runs fmt check, `cargo test`, clippy (deny warnings), the Python self-test, release packaging tests (`tests/test_release.py`), and `git diff --check`. Opt-in env flags: `VERIFY_AUDIT=1` (cargo audit), `VERIFY_BPF_LOAD=1`, `VERIFY_CONTAINER_BUILD=1`. CI (`.github/workflows/ci.yml`) mirrors this gate and adds `cargo audit` + a release build.

## Running locally

- Dry run (works anywhere the binary builds):
  ```
  rgwtrace --import-json <dwarf.json> --dry-run --output json
  ```
- Live tracing (Linux + root):
  ```
  sudo rgwtrace --dwarf-source native --pid <pid> --preflight
  sudo rgwtrace --dwarf-source native --pid <pid> --timeout 30 --output json
  ```
- Logging: `--log-level info` or `RUST_LOG=rgwtrace=debug`. Logs go to **stderr** so stdout stays clean for JSON output. All CLI flags live in `src/cli.rs`; operational recipes in `RUNBOOK.md`.

## Layout

- `src/main.rs` — orchestration (parses CLI, dispatches `--dry-run`/`--preflight`/`--export-dwarf-json`, then output mode)
- `src/cli.rs` — clap `Cli` struct and enums; custom `value_parser` fns
- `src/collector.rs` — **core** correlation engine, `TraceDocument`, diagnostics
- `src/classify.rs` — RADOS role / request-class heuristics
- `src/events.rs` — BPF↔Rust ABI: `Raw*` on-wire structs decoded into owned Rust forms
- `src/dwarf_{input,json,native}.rs` — probe-metadata sources (`native` = gimli/object ELF+DWARF; `json` = cephtrace import); shared `DwarfInfo` model
- `src/targets.rs` — locate `librados`/`librbd`/`libceph-common`/`radosgw` (via `/proc/<pid>/root`)
- `src/preflight.rs` — pre-attach validation (functions, field counts, build IDs)
- `src/otel.rs` — OTLP/HTTP protobuf export (`ExportClient`: one reqwest client per exporter, no redirects, redacted logging)
- `src/otlp_headers.rs` — OTLP request-header sources (`--otlp-header-file` > `OTEL_EXPORTER_OTLP_HEADERS` > `--otlp-header`), merged by name; never logs a value
- `src/live.rs` → `src/live/linux.rs` — Linux-only BPF load/attach/ring-buffer poll
- `bpf/*.c`, `bpf/*.h` — eBPF program + C ABI mirror (`rgwtrace_events.h`, `ceph_abi.h`)
- `build.rs` — skeleton generation; `scripts/`, `tests/`, `docker/`

## Conventions

- Standard Rust naming (`snake_case` / `CamelCase` / `SCREAMING_SNAKE_CASE`), enforced by fmt + clippy.
- Errors: `anyhow` throughout (`Context`/`with_context`, `bail!`); no custom error enums.
- Logging: `tracing` to stderr with structured fields (e.g. `info!(pid, "starting live tracing")`).
- Serde: `#[serde(rename_all = "snake_case")]`; tagged enums for event types.
- `Raw*` `#[repr(C)]` types are the on-wire BPF form; decode them into owned Rust forms with `String`/`Vec`.
- Constants prefixed `RGWTRACE_*` (event types, `RGWTRACE_TRUNC_*`, `RGWTRACE_DIAG_*`) are mirrored **byte-for-byte** between `bpf/rgwtrace_events.h` and `src/events.rs` — keep them in sync.

## Gotchas — do not break

- **Do not re-add a `process_request` return probe, or any uretprobe** — live testing showed it can crash RGW (a uretprobe patches the return address on the stack while asio switches fiber stacks underneath it). Request context is seeded from the `RGWREST::get_handler` **entry** probe, and the request END is taken from the `req_state::~req_state` **entry** probe.
- **The request-END probe must bind to the complete/base destructor (D1/D2), never the deleting one (D0)** — all three demangle to `req_state::~req_state`, and g++ lists D0 first in both `.symtab` and DIE order. `dtor_variant_rank` (`src/dwarf_native.rs`) ranks candidates by *mangled* name and rejects D0. See `docs/design-request-end-probe.md`.
- **The request-END probe is optional and fails soft** — a build whose destructor symbol/descriptor/provenance does not resolve must keep working, with request ends derived from RADOS child bounds (`rgw.duration_quality = "marker"` instead of `"measured"`). Never make it a hard requirement. It must also never be skipped *silently*: warn at attach time, because a missing end probe changes what every request duration means.
- **An imported artifact's destructor address is refused without `func2linkage` provenance** — the D0/D1/D2 variants demangle identically, so an imported address that cannot prove it is D1/D2 does not get the end probe. Do not "fix" a missing-provenance warning by trusting the address; re-export the artifact.
- **`_send_op` must never stamp a `trans_id` from a context it has not proven live** (`request_ctx_is_live`) — `rgw_requests[tid]` holds *copies* of request context that outlive their request on every thread the destructor does not run on, and `req_state` addresses are recycled by later requests, so both bridge presence AND identity (`start_ns`, `tid`) are checked. A context with **no `req_state*`** (never bridged ⇒ never revocable) also fails closed when the END probe is attached. Mis-correlating an op is worse than not correlating it.
- **The liveness gate proves EXISTENCE, not "is running on this thread now"** — so a per-submit re-seed **miss** (`rgw_rados_operate` with a dpp we cannot key) must CLEAR a **SEEDED** `rgw_requests[tid]`. Otherwise request A's context, left on a pool thread A once ran an operate on, gets stamped onto request B's op after B resumes on that thread — and A being alive means the gate passes it. Do not "restore coverage" by keeping a seeded copy on a miss; that trades a coverage loss for a correctness loss.
- **...but that clear must NEVER touch a HOME context** (`ctx->tid == current tid`: one `get_handler` put on its own request's thread). Only a SEEDED copy (`ctx->tid != current tid`) is the re-seed's to destroy. An unscoped clear shipped a live regression: a sharded `rgw.bucket_list` is submitted through the cls_rgw AIO path, which **never reaches `rgw_rados_operate`**, so it correlates only off the HOME context — and one foreign-dpp operate on that thread stranded all 16 shard ops of a real ListObjects request. Clearing HOME buys no soundness either: a submit that never reaches this probe inherits the thread's context regardless (the accepted residual hazard, `docs/design-cross-thread-correlation.md` §11.3). Both outcomes are counted (`*_ctx_cleared` vs `*_home_ctx_preserved`). See `operate_drop_seeded_ctx`.
- **Never assert only "new ops get correlated" / "no op gets mis-correlated"** — those two shapes cannot see a LOSS of coverage that already worked, and that blind spot is what let the ListObjects regression reach a live cluster. A change to correlation needs a **coverage-regression** assertion too: *ops that were correlated before must STILL be correlated*. And model the **AIO submit path** (a `_send_op` with no preceding `rgw_rados_operate` on that thread), not just submits driven through the operate probe.
- **The cross-thread bridge is MULTI-KEYED and every key must be revoked at the destructor** — a request is findable by its `req_state*` (canonical) *and* by the `RGWOp*` executing it, because RGW passes the RGWOp — not the req_state — as the `dpp` at most call sites in an op's data path. Keying only on `req_state*` makes the whole feature inert. The alternate key lives inside the context value so the destructor (which only has `this`) can delete it; a key that outlives its request is a mis-correlation source (RGWOp addresses are recycled).
- **The per-submit re-seed must not attach without the request-END probe** — the END probe is the only thing that revokes bridge entries; without it, a recycled `req_state`/`RGWOp` address hits a dead request's entry and the (disabled) liveness gate fails open. Phase B degrades to Phase A, loudly.
- **The `dpp` is an opaque identity token — never dereference it, never apply an inheritance offset** — and the offset-0 claim it rests on (`req_state`/`RGWOp` inherit `DoutPrefixProvider` at 0) is **verified in DWARF per build** (`dpp_base_offset`, `src/dwarf_native.rs`), never assumed. A build that cannot prove it loses the key — or the whole per-submit re-seed — rather than keying on a guess.
- **A request must never be emitted twice under the same span id** — request-group expiry is open/closed aware (open = END still expected; never idle-expired, only lifetime-bounded), and every exported request key is remembered **for the whole session** in a never-reset Bloom filter so a straggler cannot resurrect it. Do not "bound" it with a FIFO: at production rates the memory turns over in seconds and a force-expired long request's late END then re-emits the same span id. A Bloom false positive is safe (it drops), a false negative is not (it duplicates) — and Bloom filters have none.
- Keep the BPF↔Rust ABI (constants, `#[repr(C)]` structs, `MAX_*` caps) mirrored between `bpf/rgwtrace_events.h` and `src/events.rs`.
- Fixed capture caps (`MAX_TRANS_ID=128`, `MAX_OBJECT_NAME=128`, `MAX_ACTING=16`, `MAX_RADOS_OPS=3`, …). Overflow is surfaced via `RGWTRACE_TRUNC_*` flags (→ `rgwtrace.truncated` attr + counters), never silently dropped.
- **Native DWARF input is untrusted** — every reference-following loop needs a hop cap or visited set, and a new DIE walker must be iterative (`next_dfs`) or depth-capped, never unbounded recursion. Whole-file reads go through `read_file_bounded` and decompression through `load_section`'s budget (`--max-debug-file-bytes`). Never fall back to the HOST package database for a target under another root's `/proc/<pid>/root`, and run host tools only through `host_tools::system_command`. See `docs/bugfix-dwarf-parser-limits.md`.
- `dwarf_native.rs` hardcodes libstdc++ `std::string`/`std::vector` member names (`_M_dataplus`, `_M_string_length`, `_M_impl._M_start`) — ABI-coupled; touch with care.
- Build-ID mismatch fails preflight/attach by default (`--allow-build-id-mismatch` overrides). Wrong DWARF yields silently wrong field offsets.
- Correlation is intentionally conservative: RADOS ops join a request only via same-thread `trans_id`. Inference (`--correlate-inferred`) joins only a *unique* candidate within `--inference-window`.
- Diagnostics counters (`TraceDiagnostics` and the BPF `diagnostics` map) are a first-class output contract, not just logs. Update them when you change event handling.

## Testing guidelines

Development is test-driven — write tests before or alongside implementation, not as an afterthought. Prefer inline `#[cfg(test)] mod tests` in the module under change (the established pattern, used in nearly every source file); use `tests/` for binary/integration behavior and `tests/fixtures/` golden JSON for output-shape assertions. For a **bug fix, first write a failing regression test** that reproduces it, then fix. Every change must leave `scripts/verify.sh` green.

## Documentation

Every feature or significant change updates docs in the **same PR**. Style is pragmatic and implementation-focused: code blocks, ASCII diagrams, shell/JSON examples. Map changes to the repo's root docs:

- `ARCHITECTURE.md` — design / pipeline changes
- `RUNBOOK.md` — operational or CLI-flag changes
- `README.md` — concise project overview and entry point to documentation
- `docs/README.md` — documentation index
- `docs/development.md` — build instructions and local/live test setup
- `docs/trace-examples.md` — annotated trace examples

For a bug fix, add a short `docs/bugfix-<descriptive-name>.md` (create `docs/` if it doesn't exist) explaining what happened, why, and the fix. Comments explain *why*, not *what*.

## Code review checklist (self-review before PR)

- Correctness and edge cases
- Error paths carry `anyhow` context; no swallowed errors
- BPF↔Rust ABI mirror stays in sync; truncation/caps handled
- No secrets or raw payloads logged; stdout stays clean (logs to stderr)
- Tests added/updated; docs updated
- Diagnostics counters updated if event handling changed

## Git, commits, PRs

- Short imperative subjects (e.g. `Add inferred correlation window`, `Fix stale trans_id retry`); first line < 72 chars; body explains *why*.
- Prefer smaller, focused commits over one bulky commit.
- Work on feature branches and PR into `main`; **never force-push `main`**.
- Do not commit generated or ignored paths: `target/`, `dist/`, `*.o`, `*.skel.rs`, `trace-data/`, local env files.
- Release automation: `.github/workflows/release.yml` publishes stable `vX.Y.Z` binary releases; `dwarf-release.yml` publishes validated, immutable DWARF catalogs from `release/dwarf-matrix.json`. See `docs/development.md#publishing-releases`.
- PRs include a concise summary, relevant design notes, linked issues if any, and the results of `cargo test`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings` (i.e. a clean `scripts/verify.sh`).
