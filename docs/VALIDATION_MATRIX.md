# Validation matrix

The matrix deliberately separates implementation from progressively stronger evidence. Fixture and mock results do not imply live validation.

| Provider | Implemented | Unit tested | Fixture tested | Mock API tested | End-to-end file import tested | Live provider tested | Live provider end-to-end validated |
|---|---:|---:|---:|---:|---:|---:|---:|
| Tenable | YES | YES | YES | NO | YES | NO | NO |
| Qualys | YES | YES | YES | NO | YES | NO | NO |
| Rapid7 | YES | YES | YES | NO | YES | NO | NO |
| Microsoft Defender | YES | YES | YES | NO | YES | NO | NO |
| CrowdStrike | YES | YES | YES | NO | YES | NO | NO |
| Nessus | YES | YES | YES | NO | YES | NO | NO |
| Generic JSON | YES | YES | YES | YES* | YES | NO | NO |
| Generic CSV | YES | YES | YES | YES* | YES | NO | NO |

`*` The mock API level covers the provider-independent paginated/retry transport contract, not a live vendor endpoint. There are no provider credentials or live instances in scope, so the final two columns remain NO by design.
