# rgwtrace

**See the RADOS work behind a Ceph RGW request.**

`rgwtrace` uses eBPF uprobes to trace Ceph RADOS Gateway (RGW) activity and
connect requests to their underlying RADOS operations. Inspect traces as JSON
or export them through OTLP/HTTP to a tracing backend such as Grafana Tempo.

## What you get

- RGW request spans with correlated RADOS operations as children.
- Operation timings, objects, pools, placement groups, target OSDs, and roles.
- Standalone spans for uncorrelated RADOS work, plus diagnostics for capture
  quality and correlation coverage.

```text
rgw.request
  ├─ rados.op   (metadata read)
  └─ rados.op   (object operation)
```

See [example traces](docs/trace-examples.md) for GET and DELETE requests.

## Get started

Live tracing requires **Linux**, root or equivalent BPF/perf privileges, and
Ceph/RGW debug information or matching probe metadata. macOS supports offline
workflows. Start with the [build guide](docs/development.md) and
[runtime requirements](RUNBOOK.md#requirements).

Once built, select the RGW process and validate it before capturing a short trace:

```sh
# Replace 12345 with the PID of the RGW process you want to trace.
RGW_PID=12345
sudo ./target/release/rgwtrace --dwarf-source native --pid "$RGW_PID" --preflight
sudo ./target/release/rgwtrace --dwarf-source native --pid "$RGW_PID" --timeout 30 --output json
```

Wait for `starting live tracing` before generating S3 traffic. JSON is written
to stdout when the capture finishes; logs go to stderr.

Continue in the runbook for [preflight and metadata setup](RUNBOOK.md#preflight),
[OTLP export](RUNBOOK.md#tempo-export), and
[troubleshooting](RUNBOOK.md#common-preflight-failures).

## Understand the results

Correlation coverage depends on the RGW build and execution path. Some async,
cross-thread, and background operations remain standalone spans. Request
durations can be measured or derived from child operations; the output records
that distinction.

See [correlation options and limitations](RUNBOOK.md#background-rados-spans)
and [capture quality](RUNBOOK.md#capture-quality) when interpreting a trace.

## Documentation

| I want to… | Start here |
| --- | --- |
| Build the CLI or run tests | [Building and testing](docs/development.md) |
| Capture and export traces | [Production runbook](RUNBOOK.md) |
| Understand the pipeline and trace model | [Architecture](ARCHITECTURE.md) |
| Explore design decisions and benchmarks | [Documentation index](docs/README.md) |

## License and acknowledgements

`rgwtrace` builds on [cephtrace](https://github.com/taodd/cephtrace) by Dongdong Tao
and contributors. Its BPF code and DWARF probe-extraction approach derive from
cephtrace's `radostrace` implementation.

Licensed **GPL-2.0-only**. See [NOTICE](NOTICE) for attribution and
[LICENSE.GPL-2.0](LICENSE.GPL-2.0) for the full license.
