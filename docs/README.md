# Documentation

[Back to rgwtrace](../README.md)

## Start here

| Guide | What it covers |
| --- | --- |
| [Release automation](development.md#publishing-releases) | Binary builds, DWARF catalogs, validation, and publishing |
| [Building and testing](development.md) | Native and container builds, local checks, and live end-to-end test setup |
| [Production runbook](../RUNBOOK.md) | Requirements, preflight, capture, export, diagnostics, and troubleshooting |
| [Reading a trace](trace-examples.md) | Annotated GET and DELETE captures |
| [Architecture](../ARCHITECTURE.md) | Probe metadata, event pipeline, correlation, span model, and export |

## Design notes

These documents explain implementation decisions and their history. For current
operating instructions, use the runbook above; some design sections are
superseded by later sections in the same document.

- [Request-END probe](design-request-end-probe.md): request duration, destructor
  selection, context liveness, and duplicate-span prevention.
- [Cross-thread correlation](design-cross-thread-correlation.md): pointer bridge,
  per-submit context recovery, coverage gaps, and accepted residual hazards.

## Performance and measurement

- [RGW A/B benchmark](bench-rgw-ab.md): compare live RGW workloads with and without tracing.
- [Per-probe microbenchmark](../bench/README.md): isolate probe and ring-buffer costs.
- [Overhead analysis](overhead-analysis.md): cost model, assumptions, and host-specific measurements.
- [Stage 0 measurement runbook](stage0-runbook.md): the diagnostic experiment used
  to investigate cross-thread correlation.

## Maintenance references

- [Dependency audit fixes](bugfix-dependency-audit.md): patched TLS/QUIC and compressed-DWARF dependencies.

- [Repository guidance](../AGENTS.md): development conventions and correctness constraints.
- [Versioned-soname module matching](bugfix-soname-symlink-module-match.md): why
  imported metadata must resolve symlinked libraries correctly.
- [DWARF parser limits](bugfix-dwarf-parser-limits.md): why native extraction
  bounds reference chains, nesting, file reads and decompression, and never
  guesses a container's Ceph version.
- [Removal of the dead request-lifecycle path](bugfix-remove-dead-request-lifecycle-path.md):
  historical context for the entry-probe request model.
- [Long-session data integrity](bugfix-long-session-data-integrity.md): bounded
  collector memory, the rotating no-duplicate tombstone, OTLP loss accounting,
  and the expiry clock.
