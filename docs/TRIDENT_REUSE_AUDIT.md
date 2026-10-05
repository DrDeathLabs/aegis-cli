# Trident Reuse Audit

## Scope and safety boundary

This audit is based only on the static snapshot at `_reference/trident-cli/`.
The snapshot was found workspace-locally as `_reference/Trident CLI`, normalized
to the required path, and had only its copied nested `.git` directory removed.
The pre-build recursive SHA-256 manifest is stored at
`artifacts/reference/trident_sha256_before.txt` and covers 487 files. No Trident
tests or commands were run against the snapshot because they can create caches,
temporary directories, databases, or other files inside the read-only tree.

Aegis is a separate repository. Reuse means independently maintained Aegis code
copied or reimplemented from a narrowly selected generic mechanism. Aegis must
not import from `_reference/trident-cli/`, use a live Trident path, create a
submodule, or preserve Trident's package/runtime dependency.

The source inventory, source symbols, architecture documentation, ingestion
documentation, triage documentation, and test names were inspected. Decisions
below are based on implementation behavior and test coverage, not filenames.

## Decision summary

| Area | Decision | Aegis treatment |
|---|---|---|
| Safe JSON pointers, bounded selectors, field provenance | REUSE DIRECTLY | Independently copy the small data-only algorithms into Aegis provenance utilities, with Aegis version identifiers and tests. |
| Record accounting and typed mapping-validation contracts | ADAPT / REFACTOR | Preserve the invariant that every selected record receives a terminal outcome; extend states for provider quarantine and CSV diagnostics. |
| Configuration resolution and secret-safe settings | ADAPT / REFACTOR | Keep CLI > environment > file > default precedence, but define Aegis settings and never inherit Trident names or defaults blindly. |
| LLM/model abstraction and mocks | ADAPT / REFACTOR | Reuse the interface, request metadata, bounded transport behavior, and deterministic mock ideas; Aegis analysis roles and provenance are different. |
| Typed structured-output boundary and replay ledger | ADAPT / REFACTOR | Keep fail-closed parsing, bounded repair, semantic validation, request identity, and replay; final P0-P4 remains deterministic code. |
| Evidence envelope and untrusted prompt packaging | ADAPT / REFACTOR | Build a canonical vulnerability evidence envelope that preserves provider records, signal independence, mapping confidence, and provenance. |
| Council phases, challenge, judge, and red team | ADAPT / REFACTOR | Use the Phase A / Phase B / judge / challenge mechanics only for evidence development and conflict analysis, not voting or final priority authority. |
| Deterministic triage and guard pipeline | ADAPT / REFACTOR | Replace source-code factors with enterprise exploitability, exposure, threat, asset/business criticality, remediation, and disposition-aware rules. |
| Correlation and remediation rollups | ADAPT / REFACTOR | Retain stable IDs, canonical members, duplicate/related distinction, and action rollups; replace file/CWE/line clustering with asset/CVE/provider/remediation keys. |
| CLI workflow, structured reports, events, logging | ADAPT / REFACTOR | Keep workflow clarity, stable machine output, evidence visibility, and progress/event patterns while implementing Aegis commands and schemas. |
| Scanner subprocesses, source reachability, source-specific tools | DO NOT REUSE | Aegis consumes vulnerability-management evidence; it is not a source scanner in v0.1.0. |
| Trident trained artifacts, source-specific calibration data, answer keys, VulnBank, scorecards, and source fixtures | DO NOT REUSE | These encode Trident-specific outcomes or source-scanning assumptions and are not evidence for Aegis vulnerability-management behavior. |
| General empirical corpus-calibration concepts for vulnerability findings | ADAPT / REFACTOR | The concept is technically applicable, but Aegis v0.1.0 intentionally has no corpus guard. Operational evidence must first demonstrate a repeatable calibration error; no guard should be added without measured evidence. |

## Detailed decisions

### Configuration and persistence

| Source path | Purpose | Domain assumptions | Dependencies / coverage | Decision | Reason | Aegis destination | Changes required |
|---|---|---|---|---|---|---|---|
| `backend/trident/config.py` | Environment-backed dataclass settings for LLM, loop, DB, task backend, workspaces, tools, and expert names. | Defaults are Trident/Ollama/scanner oriented; settings assume source workspaces and scanner tools. | `platformdirs`; covered indirectly by `test_desktop_config.py`, `test_hardening.py`, CLI tests. | ADAPT / REFACTOR | Precedence and explicit typed settings are useful, but Aegis needs provider/API, import, storage, triage, redaction, and offline settings. | `src/aegis/config.py` | Rename all settings; validate bounds and enums; separate credentials from persisted config; make offline behavior explicit. |
| `backend/trident/config_manager.py`, `docs/CONFIGURATION.md` | TOML config schema, CLI get/set/show/reset, source reporting. | Keys and environment names are Trident-specific; secret handling is partial and file-oriented. | `platformdirs`, `tomli_w`; tested through desktop/CLI coverage. | ADAPT / REFACTOR | The precedence and inspectable source model are directly valuable to a user-facing CLI. | `src/aegis/config.py`, `src/aegis/cli.py`, `docs/CLI.md` | Add safe provider profiles, no plaintext token persistence, redacted output, schema validation, and Aegis config migration/versioning. |
| `backend/trident/models.py`, `backend/trident/db.py` | SQLAlchemy ORM for jobs, findings, verdicts, LLM requests, events, chains, overrides, and SQLite/Postgres sessions. | `Finding` is a source finding: tool/rule/file/line/snippet/CWE; `Job` is a source scan; JSON columns carry additive metadata. | SQLAlchemy, Pydantic; broad tests in `test_exporters.py`, `test_orchestrator.py`, `test_triage.py`, `test_*.py`. | ADAPT / REFACTOR | Durable audit rows, append-only decision records, indexes, and session patterns are useful; the schema cannot be Aegis's canonical model. | `src/aegis/storage/models.py`, `src/aegis/storage/repository.py` | Create separate Finding/Vulnerability/Asset/Evidence/Disposition/Triage/Correlation/RemediationAction/ImportRun entities; version schemas and migrations; support streaming/batches and replay. |

### Ingestion, mapping, and provenance

| Source path | Purpose | Domain assumptions | Dependencies / coverage | Decision | Reason | Aegis destination | Changes required |
|---|---|---|---|---|---|---|---|
| `backend/trident/ingest/provenance.py` | RFC 6901 JSON pointers, pointer lookup, field-level original values, provenance envelope. | Assumes JSON input and report-level hash; no CSV cell coordinates or provider identity model. | Stdlib only; exercised through importer and universal-ingestion tests. | REUSE DIRECTLY | It is small, data-only, deterministic, bounded, and directly matches Aegis's lossless provenance need. | `src/aegis/provenance.py` | Copy independently; add CSV row/column provenance, file hash/import-run IDs, adapter/mapping versions, and redaction-safe metadata. |
| `backend/trident/ingest/contracts.py` | `RecordAccounting`, `MappingValidation`, `MappingProposal`, stable mapping hash. | Terminal states are generic JSON/report states; mapping version is `trident-json-mapping-v1`. | Stdlib only; covered by `test_importers.py`, `test_universal_ingestion.py`. | ADAPT / REFACTOR | The accounting invariant is essential, but Aegis needs accepted-with-warnings, rejected, quarantined, and field-loss checks. | `src/aegis/ingest/contracts.py` | Define Aegis mapping versions and accounting states; include malformed record details, warnings, unmapped fields, and confidence thresholds. |
| `backend/trident/ingest/mapping.py` | Safe token-by-token JSON selectors, deterministic normalization of severity/identifiers, mapping validation/application. | Canonical target fields are source file, line, CWE, package and source-scanner severity; generic records are JSON only. | Stdlib/Pydantic-adjacent `RawFinding`; 418 importer lines plus universal-ingestion tests. | ADAPT / REFACTOR | Safe selectors and fail-closed mapping are useful; target fields and severity handling must be enterprise-vulnerability-specific and provider metadata must remain independent. | `src/aegis/ingest/mapping.py`, `src/aegis/ingest/inference.py` | Add asset/vulnerability/evidence paths, multi-valued identifiers/scores, disposition/state mappings, unknown-field retention, deterministic type checks, and warnings. |
| `backend/trident/ingest/inference.py` | Bounded structural discovery and optional model-proposed JSON mappings. | Alias vocabulary is SAST/SCA-oriented; inference emits a Trident mapping and uses a model only for mapping proposals. | Stdlib plus LLM backend; covered by universal-ingestion tests and benchmark script. | ADAPT / REFACTOR | First-class generic import is a core Aegis requirement, and the bounded structural approach is a good safety baseline. | `src/aegis/ingest/inference.py` | Expand aliases for assets, providers, exploitability, exposure, EPSS, KEV, CVSS, remediation, ownership; make ambiguity/warnings first-class; never let model proposals bypass deterministic validation. |
| `backend/trident/ingest/importers.py`, `registry.py` | Detect report envelopes, parse known formats, hash inputs, attach legacy provenance, persist raw findings. | Supports SonarQube, Dependency-Check, SARIF, CycloneDX, generic JSON; no CSV and no enterprise providers. | JSON, SQLAlchemy, adapters, `RawFinding`; heavily covered by `test_importers.py` and `test_universal_ingestion.py`. | ADAPT / REFACTOR | The staged import flow, input hashing, accounting and import metadata are valuable. The supported format registry is not the Aegis day-one scope. | `src/aegis/ingest/pipeline.py`, `src/aegis/providers/` | Replace registry with provider-family adapters and generic JSON/CSV; support directories, pagination envelopes, retries, quarantine, idempotency, and import-run replay. |
| `backend/trident/ingest/adapters/sarif.py`, `cyclonedx.py` | Deterministic standard security-report adapters. | SARIF locations/rules and CycloneDX components are source/SBOM-centric; they do not model enterprise assets or provider-specific context. | Stdlib and `RawFinding`; adapter paths covered by importer tests. | DO NOT REUSE | Neither is required for Aegis v0.1.0 day-one ingestion, and carrying them forward would bias the canonical model toward source tooling. | None for v0.1.0 | If future standard imports are added, implement new adapters against the Aegis canonical contract with independent tests. |
| `backend/trident/ingest/pipeline.py` | Git/ZIP/mount/demo workspace ingestion and safe ZIP extraction. | Product scans source trees; `git clone`, scorecard blinding, language detection and workspace retention are central. | `zipfile`, subprocess, filesystem; covered by `test_ingest.py`, workspace-boundary tests. | ADAPT / REFACTOR | Safe path validation and bounded archive extraction are relevant for file imports; source checkout and scorecard behavior are not. | `src/aegis/ingest/files.py` | Support files/directories, archive traversal protection, size/record limits, safe temporary handling, no automatic content execution, and explicit network behavior. |
| `backend/trident/workspace.py` | Skip generated/vendor trees, enforce containment, walk regular files without following symlinks. | Assumes source workspaces and source-tool generated directories. | Stdlib; covered by `test_workspace_boundaries.py`, reachability and agent tests. | REUSE DIRECTLY | Containment and symlink-safe walking are broadly useful security primitives. | `src/aegis/security/paths.py` | Retain only the generic containment/walk portions; add provider-import path policy and archive extraction tests. |

### Analysis, Council, and deterministic decisions

| Source path | Purpose | Domain assumptions | Dependencies / coverage | Decision | Reason | Aegis destination | Changes required |
|---|---|---|---|---|---|---|---|
| `backend/trident/evidence.py` | Shared evidence basis, raw-record packaging, import metadata, untrusted prompt formatting, status-to-disposition labels. | Evidence is code or scanner report data; source file existence determines evidence basis. | JSON, filesystem, ORM; covered by importer/exporter tests. | ADAPT / REFACTOR | The explicit untrusted-data boundary and shared evidence contract are a strong pattern, but Aegis needs provider-independent canonical evidence and multiple independent signals. | `src/aegis/evidence.py`, `src/aegis/providers/common.py` | Preserve original records and field provenance; add provider/source type, import run, enrichment/analysis provenance, signal independence, conflicts, missing evidence, and redaction. |
| `backend/trident/llm/base.py`, `llm/openai_backend.py`, `llm/anthropic_backend.py` | Common chat/embed interface, transport errors, retries, model identity, deterministic mock backend. | Model calls review source snippets; Ollama is the default; embeddings support source dedupe. | `httpx`, `tenacity`; `test_ollama_cloud.py`, smoke and reliability tests. | ADAPT / REFACTOR | Aegis can use the same backend abstraction for optional analysis/challenge, but must not inherit provider/model defaults or treat embeddings as required. | `src/aegis/analysis/llm.py` | Add provider-neutral configuration, secret-safe transport, request identity, mock API fixtures, explicit offline mode, and metadata for model requested/actual. |
| `backend/trident/reliability/schemas.py`, `parse.py` | Pydantic schemas, alias coercion, strict-enough domain validation, fail-closed JSON parsing. | Schemas contain source review verdicts and source-code triage factors; unknown verdicts become disputed. | Pydantic; `test_reliability.py`, `test_ollama_cloud.py`. | ADAPT / REFACTOR | Typed contracts and “parse error is not a verdict” are essential to safe model-assisted evidence analysis. | `src/aegis/analysis/schemas.py` | Define expert evidence proposals, challenge findings, mapping proposals, and explanations; preserve unknowns as unresolved rather than silently coercing risk-critical values. |
| `backend/trident/reliability/structured.py`, `validation/replay.py` | Bounded repair, semantic validation, request ledger, parsed/raw decision replay, frozen corpus export. | Ledger is attached to Trident finding/job IDs and scanner corpus; model output can enrich source findings. | SQLAlchemy, Pydantic, JSON; tests in reliability, CLI, importer, and orchestrator suites. | ADAPT / REFACTOR | Durable request identity and replay are directly valuable for Aegis reproducibility, but payloads and accepted-decision semantics differ. | `src/aegis/analysis/structured.py`, `src/aegis/replay.py` | Replay canonical evidence and analysis decisions by version; never replay over changed input hashes; store model provenance without secrets; final priority recomputes deterministically from structured evidence. |
| `backend/trident/budget.py` | Thread-safe hard cap for model calls. | Budget counts Council/scanner triage calls; no provider API request budget model. | Stdlib only; used by deliberation/orchestrator tests. | REUSE DIRECTLY | Small, deterministic and useful for optional model-assisted analysis. | `src/aegis/analysis/budget.py` | Rename and extend with per-provider/API rate budget if needed; retain hard reservation semantics and tests. |
| `backend/trident/experts/base.py`, `experts/auth.py`, `crypto.py`, `dependency.py`, `injection.py`, `secrets_config.py` | Expert registry, relevance routing, DB-free LLM invocation, workspace-safe context, persistence helpers. | Expert domains are SAST categories and relevance is CWE/keyword/tool based. | Pydantic, LLM backend, source workspace; `test_deliberation.py`, `test_agent.py`, `test_orchestrator.py`. | ADAPT / REFACTOR | Registry and DB-free invocation patterns help; Aegis needs Exploitability, Exposure/Attack Path, Threat Intelligence, Asset/Business Criticality, Remediation and evidence-focused roles. | `src/aegis/analysis/council.py` | Route by canonical evidence dimensions/provider context; no voting; constrain model outputs to evidence proposals and conflicts; include provenance and confidence. |
| `backend/trident/deliberation.py` | Parallel independent review, conditional cross-examination, consensus shortcut, judge ruling, novel discovery, red-team chains. | Review asks whether source candidates are valid; novel discovery scans source sinks; chains are LLM hypotheses over source findings. | ThreadPoolExecutor, SQLAlchemy, LLM, filesystem; 133-line deliberation tests plus orchestrator/agent tests. | ADAPT / REFACTOR | Phase A independence, Phase B challenge and fail-closed persistence are useful. Consensus must not become priority voting, and novel source discovery is out of scope. | `src/aegis/analysis/council.py` | Analyze canonical evidence, conflicts, missing context and cross-finding relationships; persist every role result; use Judge and Red Team/Challenge as reviewers, while deterministic triage owns P0-P4. |
| `backend/trident/experts/judge.py`, `experts/redteam.py`, `prompts.py` | Adversarial judge, attack-chain reviewer, source-specific prompts and typed outputs. | Judge confirms/refutes source vulnerability claims; red team constructs source attack paths and can elevate tiers. | LLM/Pydantic; deliberation and reliability tests. | ADAPT / REFACTOR | The adversarial focus aligns with Aegis evidence challenge, but red-team outputs must remain bounded hypotheses and cannot assign final priority. | `src/aegis/analysis/roles/judge.py`, `challenge.py`, prompt templates | Add rules for conflict adjudication, asset attack paths and shared remediation; preserve report-derived vs verified evidence basis; never make LLM P0-P4 authoritative. |
| `backend/trident/triage.py`, `docs/TRIAGE.md`, `docs/GUARDS.md` | Maps model-assessed impact/vector/exploitability plus source reachability and chains to P0-P4; class/corpus/reachability guards. | Factors are source impact, network vector, code reachability, hardcoded-secret/hygiene classes, and a CWE corpus. | SQLAlchemy, filesystem, optional corpus DB, LLM; `test_triage.py`, `test_reachability.py`. | ADAPT / REFACTOR | The explicit factor → guard → tier pipeline and driver recording are highly reusable. Direct reuse would misclassify enterprise risk and source-context absence. | `src/aegis/triage/engine.py` | Define independent evidence dimensions and deterministic guard ordering; distinguish missing evidence from low risk; preserve drivers/guard results/conflicts; separate disposition and priority; test boundaries. |
| `backend/trident/reachability/` | Language-specific call graphs, entrypoint detection and source reachability guard. | HTTP/framework entrypoints and source function locations establish network reachability. | Stdlib/AST-ish parsing; 551-line reachability test suite. | DO NOT REUSE | Aegis exposure is asset/network/business evidence from providers, not source call-graph reachability. | None for v0.1.0 | Model exposure/attack-path evidence as canonical provider/context fields; a future code-context product may implement a separate feature. |
| `backend/trident/convergence.py` | Iterative loop stop conditions based on confirmed counts, entropy, unresolved work, budget and max iterations. | Iterations are source Council reviews and novel discovery. | SQLAlchemy/statistics; convergence/orchestrator tests. | ADAPT / REFACTOR | Bounded repeated analysis and explicit stop reasons may be useful for optional Council runs. | `src/aegis/analysis/convergence.py` | Make analysis stages replayable and idempotent; never let convergence promote an unresolved model result or change deterministic priority semantics. |

### Correlation, remediation, output, and operations

| Source path | Purpose | Domain assumptions | Dependencies / coverage | Decision | Reason | Aegis destination | Changes required |
|---|---|---|---|---|---|---|---|
| `backend/trident/correlate.py` | Stable finding identity, dependency collapse, file/CWE/line-proximity clusters, duplicate/related statuses, corroboration. | File path and line proximity are primary identity; dependency package/version is a remediation target. | SQLAlchemy, hashes/JSON; `test_correlate.py`, importer and exporter tests. | ADAPT / REFACTOR | Canonical-member selection, exact-record fingerprints, corroboration, and duplicate-vs-related accounting are useful. File/CWE clustering is insufficient for cross-provider asset identity, recurring findings and shared fixes. | `src/aegis/correlation/engine.py` | Add normalized asset identity, vulnerability identifiers, provider record identity, snapshot recurrence/staleness, conflict sets, shared remediation keys, deterministic cluster explanations, and scalable indexes. |
| `backend/trident/reporters/exporters.py` | JSON, table, SARIF, HTML, triage sidecar, disposition report, remediation action rollups. | Output is a source-scan report; remediation actions mostly group Dependency-Check package/version findings. | SQLAlchemy, JSON/HTML/SARIF/optional PDF; 284-line exporter tests. | ADAPT / REFACTOR | Evidence-preserving machine output, actionable-vs-disposition separation, stable action IDs and readable tables are directly relevant. | `src/aegis/reporting/` | Export canonical findings, dispositions, triage drivers, provenance, correlation, remediation actions, mapping warnings, validation matrix, and safe CSV/JSON/HTML reports. Do not claim provider validation in reports. |
| `backend/trident/events/`, `progress.py`, `tasks/` | Persisted events, in-process/Redis fan-out, progress snapshots and background task bodies. | Scan jobs run tools and Council iterations; Redis/Celery are deployment choices. | SQLAlchemy, asyncio, optional Redis; event/inprocess/orchestrator tests. | ADAPT / REFACTOR | Stage events and persisted replay improve long-running CLI observability. Aegis needs import/analyze/triage/correlation/remediation events and bounded progress. | `src/aegis/observability/` | Keep append-only structured events, no sensitive payload logging, deterministic event IDs/sequence, offline CLI behavior, and replayable run summaries. |
| `backend/trident/cli.py`, `help_texts.py` | Click CLI, import/inspect/scan/report options, exit codes, configuration/model/validation commands. | Commands are organized around source scanning and installed tools. | Click, Rich/JSON; 263-line CLI tests and importer/orchestrator tests. | ADAPT / REFACTOR | Coherent real-interface workflow and stable machine-readable behavior are valuable. | `src/aegis/cli.py` | Implement `ingest`, `normalize`, `analyze`, `triage`, `correlate`, `remediation`, `report`, `export`, `findings`; make errors/accounting visible and test actual subprocess CLI paths. |
| `backend/trident/tools/base.py`, `tools/*.py`, `tools/installer.py`, `scripts/install.*` | Scanner subprocess harnesses, stdout/stderr capture, 12 scanner adapters, tool downloads and installation. | Source repository scanning, external binaries, scanner-specific output and tool directories. | Subprocess/filesystem/network; `test_tools.py` and installer tests. | DO NOT REUSE | Aegis does not scan source code and must not import scanner behavior as a hidden dependency. | None | Implement provider file/API adapters under `src/aegis/providers/`; use documented contracts and mock APIs rather than scanner subprocesses. |
| `backend/trident/agent/loop.py`, `agent/tools.py` | Agentic source exploration through read/grep/definition/reference tools. | LLM explores source code and must remain inside a source workspace. | LLM, filesystem, regex; `test_agent.py`, workspace tests. | DO NOT REUSE | Unconstrained source exploration is not necessary for Aegis v0.1.0 and can blur evidence boundaries. | None for v0.1.0 | If later added, create a separate bounded evidence/query tool over canonical records, never over arbitrary host paths. |
| `backend/trident/calibration/`, `model_manager.py`, `eval/guard.py`, `eval/matcher.py` | Public-feed ingestion, statistical corpus profiles, model lifecycle, corpus guard and evaluation. | Trident uses source-review outcomes, source-specific features, calibration datasets and scorecards; its guard adjusts source triage. | HTTP, SQLite, scikit-learn/joblib; Trident hardening, NVD, matcher and smoke tests. | ADAPT / REFACTOR (concept only) | Corpus-based calibration is technically applicable to vulnerability management, but Trident's implementation/data are not transferable evidence. Aegis v0.1.0 deliberately does not implement a corpus guard. | None in v0.1.0 | Preserve provider-native evidence independently. Consider a future guard only after real operational testing demonstrates a repeatable calibration error and a separately reviewed Aegis dataset supports it. |
| Trident trained model/artifact, labels, source fixtures, scorecards and answer keys in `backend/trident/calibration/`, `eval/`, `vulnbank/` | Train/validate source-code triage and holdout behavior. | Labels, features, outcomes and fixture identifiers are specific to Trident's source scanning and evaluation. | Trained model and calibration artifacts plus Trident-only tests/data. | DO NOT REUSE | These artifacts and datasets do not measure Aegis vulnerability-management outcomes; reuse would import unsupported assumptions and contaminate acceptance. | None | Create independent Aegis operational evidence before considering any future calibration guard. |
| `backend/trident/vulnbank/`, `eval/`, `eval/universal_ingestion/` | Demo vulnerable applications, source fixtures, scorecards and Trident ingestion holdouts. | Contains source vulnerabilities and Trident answer keys; fixtures are not enterprise vulnerability records. | Go/Python/frontend/Terraform and test-only data. | DO NOT REUSE | Using these as Aegis acceptance evidence would mix products and could bias golden outputs. | None | Create Aegis-owned provider fixtures, synthetic corpora and golden cases with documented rationale. |
| `backend/trident/reporters/pdf_builder.py` | Optional PDF report rendering. | Source finding cards and Trident report schema. | ReportLab; no Aegis PDF requirement is specified for v0.1.0. | DO NOT REUSE | Avoid carrying a large presentation-specific module before the canonical/report contracts stabilize. | None for v0.1.0 | Add a separate renderer only if a tested Aegis PDF acceptance requirement appears. |

## Reuse constraints for implementation

1. No Aegis module may import `trident` or read `_reference/trident-cli/` at runtime.
2. Reused algorithms must be copied or reimplemented under Aegis with Aegis tests,
   version identifiers, and documentation of any semantic changes.
3. `Finding` is not a source-scanner row in Aegis. It must preserve provider,
   source record, vulnerability identifiers, asset identity, original record,
   field provenance, analysis provenance, disposition, and deterministic triage
   separately.
4. Provider severity, Tenable VPR, Qualys QDS, Rapid7 risk, Defender/CrowdStrike
   context, CVSS, EPSS and KEV remain distinct evidence fields. No Trident-style
   single `severity` field may erase source-native signals.
5. Trident's `confirmed`/`false_positive` workflow is a source-review pattern.
   Aegis will represent `Disposition` separately from `Priority`; accepted risk,
   mitigated, remediated and false-positive records retain their own evidence and
   calculated-risk context.
6. LLM output may propose mappings, analysis, challenges, explanations and
   relationships. Deterministic validation and the Aegis triage engine own final
   P0-P4 assignment.
7. Trident tests are audit evidence about the reference implementation only.
   Aegis acceptance requires its own provider fixtures, mock APIs, malformed
   inputs, large-corpus benchmark, golden corpus, real CLI workflows, and
   rendered artifact inspection.

## Audit conclusion

The highest-value reuse is the set of safety and reproducibility boundaries:
bounded structured parsing, exact source pointers and field provenance,
record-accounting invariants, typed/fail-closed model calls, durable request
identity/replay, thread-safe budgets, safe path containment, and explicit
stage/event reporting. The source-specific schema, scanners, reachability,
source-code Council prompts, and source-oriented correlation must be replaced
with Aegis-owned enterprise vulnerability semantics. Trident's trained model,
answer keys, source fixtures, labels, and source-specific calibration data are
not reused. The general corpus-calibration concept is technically applicable,
but Aegis v0.1.0 intentionally has no such guard. Real-world operational
testing must determine whether a repeatable Aegis calibration error exists;
no future corpus guard should be added without measured evidence.

## Implementation traceability after the strengthened reuse directive

The audit classifications are binding. The following source-level mechanisms
were inspected and are present in the Aegis execution path, with no runtime
import from Trident:

| Trident implementation inspected | Aegis implementation/use | Evidence of use |
|---|---|---|
| `backend/trident/workspace.py`: `is_within`, `prune_dirs`, `iter_workspace_files` | `src/aegis/security/paths.py`; used by `src/aegis/ingest/pipeline.py` input discovery | directory imports use symlink-safe, contained walking |
| `backend/trident/ingest/provenance.py`: RFC 6901 escaping/lookup, field provenance, report hashing | `src/aegis/provenance.py`; used by provider normalization | source report SHA, record pointers, CSV cell pointers, and original values are emitted |
| `backend/trident/ingest/contracts.py`: `RecordAccounting`, mapping hash, mapping validation shape | `src/aegis/ingest/contracts.py`; used in ingest and normalize stages | `record_accounting` and `normalize_record_accounting` invariants are stored in `run.json` |
| `backend/trident/ingest/mapping.py`: token-by-token selectors and bounded application | `src/aegis/ingest/mapping.py`; used by inferred generic mappings | generic mappings are validated/applied without expression evaluation and preserve pointers |
| `backend/trident/ingest/inference.py`: bounded structural inference | `src/aegis/ingest/inference.py`; called from the ingest mapping summary | every detected adapter records an inferred mapping, coverage, confidence, and warnings |
| `backend/trident/config.py` / `config_manager.py`: typed precedence and safe settings | `src/aegis/config.py`; used by provider-reader limits and Council budget/model configuration | `AEGIS_*` environment overrides and optional `aegis.toml` are reflected without secrets |
| `backend/trident/budget.py`: reserve-before-call hard budget | `src/aegis/analysis/budget.py`; used by mock Council analysis | model call count/limit is recorded and cannot exceed the shared budget across workers |
| `backend/trident/reliability/parse.py`: exact object/fenced JSON parsing | `src/aegis/analysis/structured.py`; used by `chat_structured` | garbage/prose responses fail closed and never become a verdict |
| `backend/trident/reliability/structured.py`: contract, bounded repair, request identity, typed result | `src/aegis/analysis/structured.py`; used by `analyze --backend mock` | model output remains an evidence observation; `priority_authority` is false |
| `backend/trident/validation/replay.py`: frozen artifact/replay validation | `src/aegis/replay.py` and `replay-export`/`replay-validate` CLI commands | canonical finding replay artifacts are hash checked before use |
| `backend/trident/deliberation.py`: ordered parallel phase execution | `_parallel` in `src/aegis/analysis/council.py`; used for bounded finding batches | Council observations are developed before deterministic triage; no vote assigns priority |
| `backend/trident/convergence.py`: explicit bounded stop reasons | `src/aegis/analysis/convergence.py`; recorded by analysis | analysis records `max_iterations`, budget, or no-unresolved stop reason |
| `backend/trident/evidence.py`: evidence basis and untrusted-data boundary | `src/aegis/evidence.py` and provider normalization | evidence basis, provenance, conflicts, missing context, and original records are separate |
| `backend/trident/correlate.py`: stable identity, fingerprint, canonical member, duplicate/related split | `src/aegis/correlation.py` | cross-provider asset/CVE groups, exact duplicate rows, canonical IDs, and conflict sets are emitted |
| `backend/trident/reporters/exporters.py`: actionable report and remediation rollups | `src/aegis/reporting.py` and `src/aegis/remediation.py` | JSON/CSV/HTML/table outputs expose priorities, reasons, dispositions, provenance, and actions |
| `backend/trident/events/inprocess_bus.py` / `publisher.py`: structured event lifecycle | `src/aegis/observability/events.py`; used by every pipeline stage | append-only `events.jsonl` records stage starts/completions and counts |
| `backend/trident/cli.py`: Click command organization and machine-readable output | `src/aegis/cli.py` | real `ingest` → `normalize` → `analyze` → `triage` → `correlate` → `remediation` → `report/export` path |

### Specific technical reasons for retained non-use or replacement

The audit does not silently downgrade any reusable item. Trident's SQLAlchemy
ORM and database session implementation are not copied because Aegis v0.1.0
uses atomic JSONL stage artifacts to stream the one-million-finding benchmark;
the canonical entities and audit fields are represented in versioned JSON
records instead. Trident's source-file/CWE/line clustering is replaced by
asset/vulnerability/remediation identity because file locations are not
present in vulnerability-management reports. Trident's LLM ledger is replaced
by versioned JSON replay records because importing SQLAlchemy would add a
runtime dependency and database write contention to the chosen scale path.
These are explicit domain/scale adaptations, not a re-creation of an existing
algorithm without inspection.

SARIF/CycloneDX, reachability analyzers, scanner subprocesses, agent source
exploration, trained Trident artifacts, answer keys, source fixtures, and PDF
rendering remain `DO NOT REUSE`. Trident's implementation-specific calibration
data is likewise not reused; only the general empirical calibration concept
is retained for possible future evaluation, not v0.1.0 behavior.

## v0.1.0 calibration boundary

Aegis v0.1.0 preserves imported CVSS, EPSS, KEV, exploit evidence, and
provider-native risk as independent evidence. It has no trained vulnerability
model and no corpus-calibration guard. Real-world operational testing will
determine whether any repeatable calibration error exists that justifies
future guard research. Any future guard requires measured Aegis-specific
evidence and a separately defined acceptance method; Trident labels, answer
keys, source fixtures, and calibration data are not acceptable substitutes.
