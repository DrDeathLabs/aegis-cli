# Prioritization

Aegis calculates P0–P4 deterministically from normalized structured evidence. It does not ask an LLM to choose the final tier and it does not reduce all source signals to one opaque score. Every decision preserves drivers, guard results, evidence provenance, conflicts, and missing context.

## Independent dimensions

The rule engine keeps technical impact, source severity, CVSS, provider risk, EPSS, KEV, active exploitation, exploit maturity, external exposure, target/business criticality, controls/isolation, disposition, and evidence confidence distinct. High CVSS describes technical impact; it does not alone create urgent priority. Provider-native severity uses that provider's semantics and is not automatically reinterpreted as CVSS.

`exploit_available=true` establishes existence of an exploit signal. When explicit maturity is PoC-only or otherwise not mature, generic availability does not promote the record to mature/functional/weaponized exploit evidence. KEV or genuine active exploitation establishes an urgency floor of at least P2, while context can distinguish P0/P1/P2. It does not automatically mean P0 or P1.

## Tier intent

| Tier | General intent |
|---|---|
| P0 | Critical consequence with strong, converging exploitation and internet-exposure evidence. |
| P1 | Urgent high-consequence cases with strong exploitation, exposure, or critical-asset context. |
| P2 | Significant risk with meaningful technical impact and contextual likelihood/exposure, including the active-exploitation/KEV floor. |
| P3 | Moderate consequence or material weakness lacking the evidence for higher urgency. |
| P4 | Lower current consequence and likelihood after validated context/mitigation; never a disposition. |

These are deterministic policy categories, not provider SLAs. Exact guard ordering and thresholds are documented in [Priority methodology](PRIORITY_METHODOLOGY.md); the engine output is the record of why a specific finding received its tier.

## Controls, uncertainty, and overrides

Only explicit affirmative, normalized, effective controls can reduce urgency. Failed, bypassed, misconfigured, expired, unavailable, monitor-only, audit-only, or unknown controls do not count as effective mitigation. Isolation and segmentation may influence the tier when strong exploitation, active/KEV evidence, mature exploit, meaningful exposure, or high-likelihood evidence do not override them. Missing context is shown as missing; it is not converted into a false-positive disposition or a low-risk assertion.

## Calculated and queue priority

`calculated_priority` is the risk result and is retained for history. `effective_priority` is the active queue priority; it is null when `active_queue=false`. Disposition is separate. See [Dispositions](DISPOSITIONS.md).
