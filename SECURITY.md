# Security policy

## Supported release line

Security fixes are evaluated for the current v0.1 release line. This policy is not a service-level commitment or a guarantee that every vulnerability is known or fixed.

## Reporting a vulnerability

Do not disclose exploitable details, credentials, customer records, or unpatched vulnerability data in a public issue. If private vulnerability reporting is enabled on the hosting repository, use that facility. If it is not enabled, do not publish sensitive details; no separate security contact address is published for this project.

Ordinary product questions and non-sensitive defects belong in the issue tracker after the repository location is published.

## Product security boundaries

- Aegis is a local file-processing CLI. Provider API mock tests do not establish authentication, authorization, or live-service security for commercial platforms.
- Input files are untrusted. Aegis applies bounded parsing, semantic validation, quarantine/accounting, path containment, and XML entity/DOCTYPE protections described in [the security model](docs/SECURITY_MODEL.md).
- Reports are shareable/redacted by default. The `--include-raw` option is restricted to explicit internal exports; operators remain responsible for protecting local run directories and any deliberately lossless output.
- Aegis does not replace provider-side access controls, vulnerability validation, change management, backup, or human approval.
- Model-assisted analysis is optional and bounded. It may not assign final priority or turn unsupported claims into source evidence.

## Development and release controls

The repository CI and manually dispatched release workflow use read-only permissions by default, least privilege for release creation, and full-length action commit pins. The release workflow requires a release tag, full source commit, typed `PUBLISH` confirmation, version/source agreement, reviewed notes, package validation, clean-install smoke tests, SBOM, checksums, and a release manifest. Repository-level branch protection, environment reviewers, private reporting, and organization-wide action policy are hosting settings and must be reviewed by the repository owner before publication.

Security scan results are evidence for a point-in-time review, not proof of absence of vulnerabilities. See [Validation](docs/VALIDATION.md) and [the security model](docs/SECURITY_MODEL.md).
