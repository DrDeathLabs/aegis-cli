# Provider and input support

## Scope

Aegis v0.1.0 imports files. It is not an API client for Tenable, Qualys, Rapid7, Microsoft Defender, or CrowdStrike. No API key, tenant, or commercial instance was exercised by this release-readiness work. The supported file variants below are finite contracts; other export versions can fail detection or require a future explicit mapping. File format recognition is schema/content based, not filename based.

## Supported variants

| Input family | Supported file shapes in v0.1 | Important preserved evidence |
|---|---|---|
| Tenable Vulnerability Management | Current nested vulnerability export records and supported flat finding/plugin export rows. | Finding `id`, `source`, severity/state, first/last seen, port/protocol/service, `asset` identity and observations, `definition` identity/CVEs/descriptions/solutions, supported CVSS/EPSS/VPR/exploit/patch data. Tenable-native values are not treated as one Aegis score. |
| Qualys VM | Host List Detection XML (`HOST` with one or more `DETECTION` records), plus the supported host-detection JSON/CSV row forms. | Host target context; QID and `UNIQUE_VULN_ID` as separate typed identifiers; CVE, Qualys severity and QDS as provider-native fields; status, diagnosis, solution, and provenance. Native severity is not CVSS. |
| Rapid7 InsightVM | Supported asset-vulnerability bulk/export resource rows and supported flat vulnerability export rows. | `assetId`/asset observations separately from `vulnId`, CVE, source occurrence ID, risk, exploit, solution, and other source metadata. An occurrence identifier is not target identity. |
| Microsoft Defender for Endpoint | `machinesVulnerabilities`/`value` response records and `SoftwareVulnerabilitiesByMachine` per-device assessment/export records; supported flat export rows. | Machine/device identity; occurrence and CVE identifiers; fixing KB/update, product/software, severity/exploitability, status, and available timestamps/OS context. These are separate format contracts. |
| CrowdStrike Spotlight | Supported nested Spotlight vulnerability resources and supported flat export rows. | `host_info` asset/exposure context; `cve` identity, CISA KEV, severity/base score, exploit evidence, status/timestamps, and remediation facets when present. `cve.remediation_level` is not exploit maturity. |
| Nessus | `.nessus` `NessusClientData_v2` XML with `ReportHost` and nested `ReportItem`. | `ReportHost` target context is inherited only where a finding-level value is absent; plugin/detection identity, CVSS/severity, port/protocol, solution, source pointer, and original XML-derived record are preserved. |
| Generic JSON | JSON object/array, JSONL/NDJSON, or a recognized semantic collection under supported envelope paths. Opaque nested collections require `--selector`. | Validated aliases for target and vulnerability identity; original source record and unknown fields; mapping warnings and confidence. Arbitrary recursive metadata inference is intentionally unsupported. |
| Generic CSV | CSV/TSV with unique supported canonical headers. | Header/row pointers, mapped columns, source-native identifiers, unknown columns and extra values. Duplicate headers are terminally accounted for rather than silently collapsed. |

The Tenable contract is informed by the [Vulnerability Management export API](https://developer.tenable.com/reference/exports-vulns-request-export) and [export field/key reference](https://docs.tenable.com/vulnerability-management/Content/Explore/export-findings-csv-keys.htm). Qualys field structure is documented in [Host Detection List](https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/host_detection.htm). Rapid7 references are the [InsightVM Bulk Export API](https://docs.rapid7.com/insightvm/bulk-export-api/) and [working with vulnerabilities](https://docs.rapid7.com/insightvm/working-with-vulnerabilities/). Defender references are [machines and vulnerabilities](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities-by-machines) and [software vulnerability assessment export](https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities). CrowdStrike’s [Spotlight Vulnerabilities API reference](https://developer.crowdstrike.com/api-reference/collections/spotlight-vulnerabilities/) documents nested `cve` and `host_info` fields. Tenable’s [Nessus file-format guide](https://docs.tenable.com/quick-reference/nessus-file-format/Nessus-File-Format.pdf) describes `ReportHost` and `ReportItem`.

These references describe vendor contracts; they do not imply that Aegis implements every field, API operation, version, or service behavior. The adapter/fixture matrix below defines Aegis’s narrower supported scope.

## Validation levels

| Provider | Automated fixture/unit | Clean installed-package file E2E in this release evidence | Blind corpus | Live commercial provider/API |
|---|---|---|---|---|
| Tenable | Yes | Checked with packaged Aegis CLI fixture run | Pack-level acceptance belongs to the supplied baseline; not repeated or scored here | No |
| Qualys | Yes | Checked with packaged Aegis CLI fixture run, including documented XML shape | Pack-level acceptance belongs to the supplied baseline; not repeated or scored here | No |
| Rapid7 | Yes | Checked with packaged Aegis CLI fixture run | Pack-level acceptance belongs to the supplied baseline; not repeated or scored here | No |
| Microsoft Defender | Yes | Checked with packaged Aegis CLI fixture run | Pack-level acceptance belongs to the supplied baseline; not repeated or scored here | No |
| CrowdStrike | Yes | Checked with packaged Aegis CLI fixture run | Pack-level acceptance belongs to the supplied baseline; not repeated or scored here | No |
| Nessus | Yes | Checked with packaged Aegis CLI fixture run | Pack-level acceptance belongs to the supplied baseline; not repeated or scored here | No |
| Generic JSON | Yes | Checked with packaged Aegis CLI fixture run | Pack-level acceptance belongs to the supplied baseline; not repeated or scored here | Not applicable |
| Generic CSV | Yes | Checked with packaged Aegis CLI fixture run | Pack-level acceptance belongs to the supplied baseline; not repeated or scored here | Not applicable |

“Blind corpus” is stated only at the pack level; there is no claim that each adapter passed an independent provider-specific blind score. Offline fixtures and mocks do not count as live validation. Every live-provider and live-provider end-to-end status is **NO**.

## Detection and unsupported inputs

Auto-detection evaluates complete path-aware contract predicates over bounded valid records. A filename or one vendor-like key is not enough. Ambiguous formats fail clearly. Generic input is selected only when its own contract is satisfied. For Generic JSON below an opaque parent, supply an explicit pointer, for example `/metadata/data/items`. Unknown arrays under metadata, audit, history, owners, contacts, and similar keys remain opaque.

Direct API authentication, tenant synchronization, scanner execution, provider-side pagination, or live rate-limit handling are not exposed by the CLI. Mock transport tests exercise only the provider-independent transport contract, not vendor API compatibility.
