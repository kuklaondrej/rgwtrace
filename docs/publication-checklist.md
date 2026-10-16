# Publication controls outside the repository

These require an administrator; editing repository files does not enable them.

- Remove persistent self-hosted runners from this repository. Register lab
  runners only with the private lab repository; see [lab setup](lab/README.md).
- Configure an active `main` ruleset: require PRs, the `rust` check from GitHub
  Actions, an up-to-date branch, and resolved discussions; block force pushes
  and deletion. Avoid routine bypass. Require CODEOWNERS approval and dismiss
  stale approvals when another maintainer is available. A sole maintainer
  cannot approve their own PR, so choose that requirement deliberately.
- Enable secret scanning, push protection, private vulnerability reporting,
  Dependabot alerts, and security updates. Scan **all branches and tags intended
  for publication**, not just the latest source tree. Investigate and rotate any
  exposed credential before history cleanup; a clean scanner is not proof that
  arbitrary private data is absent.
- Keep default Actions permissions read-only and disable Actions PR approval.
  Require approval for outside-contributor workflow runs. Review workflow
  changes before approval; this setting does not sandbox self-hosted runners.
- Review Git history, issues, PRs, logs, artifacts, and attribution for material
  that was only intended to be private. The included scanner checks Git content,
  not every GitHub surface.
- Require live-test evidence for the exact reviewed revision when changing BPF,
  DWARF, or correlation. A lab workflow in another repository does not
  automatically satisfy a source-repository required check. Until a trusted
  status publisher is configured, maintainers enforce this during review.

The workflow names and CODEOWNERS file provide inputs to these settings;
they do not activate them. Ruleset availability depends on visibility and plan.
See [GitHub rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
and [runner security](https://docs.github.com/en/actions/reference/security/secure-use).
