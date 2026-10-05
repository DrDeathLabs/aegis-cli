# Feature status

| Capability | v0.1 status | Boundary |
|---|---|---|
| File ingestion | Implemented | Finite file contracts in [Providers](PROVIDERS.md); unsupported variants may be rejected. |
| Canonical normalization | Implemented | Provider-independent finding schema; source-native fields remain separate. |
| Generic mapping | Implemented | Generic JSON/CSV only within declared shape/header contracts or explicit selector. |
| Evidence analysis | Implemented offline/mock | Structured observations/challenges; no final priority authority. |
| Public vulnerability intelligence | Implemented, explicit refresh | NVD CVE features, current EPSS CSV, and CISA KEV are cached locally with hashes and provenance; not a live commercial provider integration. |
| Aegis ML intelligence | Implemented, optional training extra | Temporal-holdout, evaluation-gated logistic model estimates the elevated EPSS band; local JSON inference, structured drivers, and fallback. It does not assign P0–P4. |
| Deterministic priority | Implemented | P0–P4 with recorded drivers/guards; not a provider SLA or automated remediation command. |
| Disposition and queue | Implemented | Disposition separate; inactive findings retain calculated risk and null effective queue priority. |
| Correlation | Implemented | Exact/strong identity, cross-provider relationships, conflicts, and optional baseline recurrence. No CVE-only cross-asset merge. |
| Remediation grouping | Implemented | Evidence precedence, not patch deployment; review actions before execution. |
| Reports/replay | Implemented | JSON/CSV/HTML/table, versioned replay validation/export, default raw-record omission. |
| Commercial provider APIs | Not implemented/live-tested | Fixtures and transport mocks do not establish live API support. |
| Scanner execution, PDF, SARIF, source-code reachability, OSV and public exploit feeds | Not in v0.1 | See [Limitations](LIMITATIONS.md). |

For test levels and exact evidence, see [Validation](VALIDATION.md). “Implemented” does not mean live-provider validated, production-ready for every deployment, or suitable for unattended patching.
