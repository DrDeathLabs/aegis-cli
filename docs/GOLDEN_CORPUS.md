# Golden corpus

`fixtures/golden/golden.json` is the curated deterministic decision set used by the regression suite. Each case states the evidence inputs, expected calculated priority, disposition, and effective priority. The cases cover P0 through P4, false-positive suppression, accepted-risk retention, compensating-control effects, and missing context.

The provider fixture corpus separately exercises cross-provider identity, repeated exports, recurring findings, provider severity/risk signals, unknown fields, and shared remediation actions. Expected outcomes are checked from structured evidence, never from fixture identifiers.

The P0 case requires every incident guard: active exploitation/KEV, functional exploit, internet exposure, critical asset, critical technical impact, and no compensating control. The P1 case removes critical asset context but retains active exploitation, internet exposure, and high impact. P2 is driven by high impact plus EPSS without active exploitation. P3 is medium impact without higher context. P4 is low impact with uncertainty preserved.

False positive and accepted risk intentionally share the same calculated P0 evidence. Only the disposition changes the effective queue behavior; false positive receives no effective priority, while accepted risk retains P0. Mitigated retains calculated priority and records its control separately.
