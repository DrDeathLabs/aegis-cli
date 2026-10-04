# Canonical vulnerability schema

Every normalized record has `schema_version: aegis-finding-v1` and these top-level areas:

| Area | Contents |
|---|---|
| identity | immutable import-instance ID, optional source occurrence ID, typed provider vulnerability IDs, mutable target observations, pairwise semantic aliases, the observation-local signature, and the reconciled durable semantic entity ID/semantic finding key |
| vulnerability | identifiers, CVEs/CWEs, CVSS scores/vectors, normalized severity, exploitability, exploit maturity, exploited-in-wild, KEV, EPSS, vendor risk score/metadata, source signals |
| asset | source asset ID, hostname/FQDN, IPs, OS/application/package/version, exposure, criticality, sensitivity, owner, tags |
| state | first/last seen, recurrence, source status, patch/solution, explicit remediation action ID, vendor remediation/recommendation ID, controls |
| evidence | basis, field-level values and pointers, conflicts, missing context, warnings, mapping confidence |
| analysis | independent Council observations, confidence, missing evidence, challenge/conflict notes, model provenance |
| decision | separate `disposition`, deterministic `calculated_priority`, effective queue `effective_priority`, and the compatibility `priority` alias, with drivers and guards |

After triage, `calculated_priority` and `triage.calculated_priority` always retain the deterministic risk result. `effective_priority` and the top-level `priority` compatibility alias are the effective remediation-queue priority: they equal the calculated result only when `triage.active_queue` is true and are `null` for every non-active disposition, including accepted risk and mitigated findings. Disposition is never encoded as P4.
| correlation | group/canonical IDs, duplicate/related relations, recurrence and conflict summaries |
| remediation | deterministic action ID, action text, target |
| source_metadata | provider, source type, report SHA-256, record pointer, original record, provider metadata, unmapped fields, mapping versions, source identifiers |

Source-native values are never overwritten by normalized values. For example, a Tenable VPR or Qualys QDS value is kept under vendor risk and source signals while normalized severity is a separate field.

`source_record_id` identifies the imported occurrence when the source supplies one; it is nullable and is never manufactured from a CVE, provider vulnerability ID, pointer, title, filename, or scalar. Provider-native vulnerability IDs are typed and namespaced under `vulnerability.provider_identifiers`; they are never treated as targets. `asset.asset_id`, hostname/FQDN, and canonical IP observations are independently validated target identity. `import_instance_id` is immutable for one imported occurrence. `observation_signature` is a deterministic, observation-local hash of the aliases visible in that record and may change when identity evidence is enriched. `semantic_entity_id` is the reconciled durable semantic entity handle; it is inherited only when `correlate --baseline-run-dir` finds one unambiguous, non-conflicting prior entity and otherwise is an independent-run seed. `semantic_identity_aliases`/`identity.semantic_aliases` reconcile non-conflicting enrichment (hostname/IP/asset observation or native ID/CVE) without confusing import identity with mutable observations. Reconciliation records matched aliases, candidate/conflict state, and merged seed IDs. Correlation groups and fallback remediation actions use the reconciled handle, not the observation signature. XML text-only leaves are scalar-normalized before mapping, and unknown nested fields remain in the lossless internal source record. Default shareable reports retain only an original-record hash and omit machine-local paths; `--include-raw` is an explicitly restricted internal export.
