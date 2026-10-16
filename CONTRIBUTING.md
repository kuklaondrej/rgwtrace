# Contributing

Open an issue to discuss substantial changes, then submit a focused PR into
`main`. Use Rust 1.90.0, follow [AGENTS.md](AGENTS.md), and run:

```sh
scripts/verify.sh
VERIFY_AUDIT=1 scripts/verify.sh
```

See [development setup](docs/development.md) for build and fixture dependencies.
Add a failing regression test before fixing a bug. Explain what changed, why,
and what you tested. Significant changes need documentation in the same PR.

Correlation changes must demonstrate both correct attachment and preservation
of existing coverage, including AIO submits without an operate probe. Changes
to BPF, DWARF, or correlation also need a maintainer-run private-lab validation
of the reviewed commit; unit/source-model tests cannot prove live behavior.
Record the tested SHA and link the sanitized lab results in the PR. A new push
invalidates that evidence until its effects are reviewed and tested.

Maintainers review changes to workflows, test assertions, thresholds, fixtures,
and dependencies as executable code. Do not weaken a check merely to make CI
pass. Public PR jobs must use hosted runners without repository secrets.
Never execute PR code through `pull_request_target` or privileged follow-up jobs.

Contributions are under GPL-2.0-only, the project's existing license. Preserve
upstream attribution and include only code you are entitled to contribute.
Report vulnerabilities using [SECURITY.md](SECURITY.md), not a public exploit.
