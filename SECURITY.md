# Security

rgwtrace is experimental privileged tracing software. Live tracing executes BPF
and reads RGW process memory; traces can contain object names and request IDs.
Keep raw traces and real credentials out of issues and CI artifacts.

For a vulnerability, use GitHub's private **Report a vulnerability** feature on
this repository's Security tab when enabled. If it is unavailable, contact the
maintainer through the contact information on their GitHub profile to arrange a
private channel. Do not post exploit details or secrets in public issues.
Include the affected revision, environment, impact, and a minimal reproducer.

Security fixes target `main`; there is no maintained older release series or
promised response SLA. Review fixes before deploying against production RGW.

Maintainers: complete [publication setup](docs/publication-checklist.md) before
opening the repository. Workflow YAML cannot enforce branch rules or isolate a
runner that remains registered with a public repository.
