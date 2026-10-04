# Remediation actions

Finding priority answers “how urgent is this risk?” A remediation action answers “which shared work item can resolve one or more findings?” They are related but not interchangeable.

## Evidence precedence

Action grouping uses strong, typed evidence in this order:

1. Explicit patch/action token.
2. Explicit cross-provider remediation identity.
3. Provider recommendation/remediation identifier.
4. Real package/product plus a fixed version.
5. Correlation-backed normalized solution.
6. Sufficiently specific solution text.

Weaker identifiers remain attached as secondary evidence. A generic free-text version, service name (`https`, `ssh`, `smb`, `rdp`, `http`, or `ftp`), or superficial text similarity is not proof that two findings share an action. Package/product inference must be explicit or supported by canonical evidence.

## Action records and queue semantics

Each action retains its deterministic identity, grouping evidence, finding references, target/asset observations, and priority summaries. Inactive accepted-risk or mitigated findings can retain historical associations, but they do not make an inactive action appear as urgent active queue work. Calculated finding priority remains available for history; effective queue priority remains separate.

## Operator review

Action grouping is a recommendation for coordinating work, not an approved change plan. Validate affected assets, package/version applicability, testing, maintenance windows, dependencies, and rollback before executing remediation. Aegis does not deploy patches or modify provider systems.
