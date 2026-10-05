# Security model

## Assets and trust boundaries

The principal sensitive assets are imported vulnerability records, provider-native metadata, asset identifiers, local source paths, run artifacts, optional configuration, and any explicitly lossless report. Aegis runs locally; it does not authenticate to commercial provider tenants in v0.1.0. Input files and AI-generated structured outputs are untrusted.

## Controls in the application

- Source files are snapshotted and hashed before parsing; the immutable snapshot is the source of truth for provenance.
- JSON/XML document size, record size, nesting, and structural nodes are bounded. Large data should use JSONL/CSV. XML processing removes a documented external Qualys DOCTYPE before parse and rejects entity declarations; targeted probes cover this boundary.
- Provider auto-detection uses contract structure and reports ambiguous formats; it does not rely on filename or loose key resemblance.
- Semantic identity requires valid vulnerability and target evidence. Malformed/ambiguous records are quarantined/rejected and accounted for.
- Selector paths are parsed as data; they are not evaluated as expressions.
- Stage outputs carry lineage. Upstream reruns invalidate downstream outputs; `run-all` stops on terminal failure/rejection.
- Default reports omit the complete raw source record and redact local path fields. `--include-raw` is a deliberate internal export and has no role-based permission enforcement.
- Triage is deterministic from typed structured evidence. Council outputs cannot assign final P0–P4.

## Operator responsibilities

Protect source snapshots and run directories using operating-system ACLs, apply retention and backup policy, review exports for residual PII/host context, keep dependencies updated, and validate every remediation with asset owners before execution. Windows file permission semantics depend on the host and are not a substitute for enterprise storage policy.

## Security review evidence

The release evidence records current-tree and Git-history secret scanning, Bandit, Semgrep, Ruff, compileall, dependency audit, package payload review, SBOM, and workflow analysis. Static scan matches are manually triaged against the guarded parser/data flow; a tool's exit code alone is not a security conclusion. Findings and their disposition are in the release-readiness result. No claim of zero vulnerabilities or live-service security is made.
