"""Import provider files into a lossless raw-record stage, then normalize."""

from __future__ import annotations

from collections import Counter, defaultdict
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from typing import Any, Iterable, Iterator

from aegis.models import json_safe
from aegis.config import settings
from aegis.provenance import report_sha256
from aegis.providers import adapter_for
from aegis.providers.base import available_adapters, iter_json_records
from aegis.ingest.contracts import RecordAccounting
from aegis.ingest.inference import infer_mapping
from aegis.observability.events import EventSink
from aegis.security.paths import is_within, iter_workspace_files
from aegis.storage import (
    ensure_run_dir, iter_jsonl, load_run, new_run_dir, save_run, stage_path,
    utc_now, record_stage_lineage, invalidate_downstream, enforce_run_limits,
    write_lineage_manifest,
)

_EXTENSIONS = {".json", ".jsonl", ".ndjson", ".csv", ".tsv", ".xml", ".nessus"}


def _snapshot_source(path: Path, run: Path, ordinal: int) -> tuple[Path, str]:
    """Copy and hash one immutable byte stream before adapter parsing."""
    target_dir = run / "source_blobs"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{ordinal:06d}-{path.name}"
    temporary = target.with_name(f".{target.name}.partial")
    digest = hashlib.sha256()
    with path.open("rb") as source, temporary.open("wb") as snapshot:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            snapshot.write(chunk)
        snapshot.flush()
        os.fsync(snapshot.fileno())
    os.replace(temporary, target)
    snapshot_digest = digest.hexdigest()
    # If the named source changed while it was being snapshotted, reject the
    # file before any records are committed. The adapter parses the snapshot,
    # so every accepted record's report hash identifies the parsed bytes.
    if report_sha256(path) != snapshot_digest:
        raise ValueError(f"input changed while being snapshotted (TOCTOU): {path}; no records committed")
    return target, snapshot_digest


def source_files(inputs: Iterable[str | Path]) -> Iterator[Path]:
    seen: set[Path] = set()
    for value in inputs:
        path = Path(value).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"input path not found: {value}")
        candidates = iter_workspace_files(path) if path.is_dir() else [path]
        for candidate in candidates:
            if candidate.is_file() and candidate.suffix.lower() in _EXTENSIONS:
                if is_within(path, candidate) and candidate not in seen:
                    seen.add(candidate)
                    yield candidate


def detect_provider(path: Path, requested: str = "auto", *, selectors: tuple[str, ...] = ()) -> str:
    if requested and requested.lower() != "auto":
        name = requested.lower().replace("-", "_")
        if name == "microsoft_defender":
            name = "defender"
        if name not in available_adapters():
            raise ValueError(f"unsupported provider: {requested}")
        return name
    suffix = path.suffix.lower()
    if suffix == ".nessus":
        return "nessus"
    # Detection is contract/path based.  Do not recursively flatten a record:
    # vendor-like keys in opaque metadata are common in enterprise exports and
    # must not turn a generic file into an ambiguous provider file.
    def compact_key(text: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", text.lower())

    def direct_keys(record: dict[str, Any]) -> set[str]:
        return {compact_key(str(key)) for key in record}

    def present(record: dict[str, Any], *names: str) -> bool:
        return any(record.get(name) not in (None, "", [], {}) for name in names)

    def contract_candidates(record: dict[str, Any]) -> set[str]:
        keys = direct_keys(record)
        candidates: set[str] = set()
        host_info = record.get("host_info") if isinstance(record.get("host_info"), dict) else None
        cve = record.get("cve") if isinstance(record.get("cve"), dict) else None
        host_contract_fields = {compact_key(field) for field in (
            "hostname", "fqdn", "platform_name", "asset_criticality",
            "internet_exposure", "local_ip", "os_version",
        )}
        cve_contract_fields = {compact_key(field) for field in (
            "is_cisa_kev", "severity", "base_score", "remediation_level",
            "exploit_status_to_include", "exploit_status",
        )}
        if (
            host_info is not None
            and cve is not None
            and present(record, "aid", "spotlight_id", "spotlightId")
            and cve.get("id")
            and (set(compact_key(field) for field in host_info) & host_contract_fields)
            and (set(compact_key(field) for field in cve) & cve_contract_fields
                 or isinstance(record.get("risk"), dict)
                 or isinstance(record.get("exposure"), dict)
                 or isinstance(record.get("exploit"), dict))
        ):
            candidates.add("crowdstrike")
        defender_identity = keys & {"machineid", "machinename", "deviceid", "devicename", "computerdnsname"}
        defender_evidence = keys & {
            "vulnerabilityseveritylevel", "productname", "softwarename",
            "recommendationid", "recommendationreference", "recommendedsecurityupdate",
            "recommendedsecurityupdateid", "fixingkbid", "securityupdateavailable",
            "exploitabilitylevel", "softwarevendor", "softwareversion",
        }
        defender_legacy_contract = (
            bool(keys & {"vulnerabilityid", "vulnid"}) and bool(keys & {"machineid", "machinename"})
            and (
                bool(defender_evidence)
                or ("machineid" in keys and "cveid" in keys and "riskscore" in keys)
                or ("vulnerabilityid" in keys and "machineid" in keys and "machinename" in keys)
            )
        )
        if defender_identity and (
            ((keys & {"cveid", "cve"}) and defender_evidence)
            or defender_legacy_contract
        ):
            candidates.add("defender")
        qualys_target = keys & {"assetid", "hostid", "hostname", "dns", "ip", "ipaddress"}
        if "qid" in keys and bool(keys & {"qds", "uniquevulnid", "cveid"}) and bool(keys & {"severity", "qds"}) and qualys_target:
            candidates.add("qualys")
        asset = record.get("asset") if isinstance(record.get("asset"), dict) else None
        definition = record.get("definition") if isinstance(record.get("definition"), dict) else None
        asset_fields = {compact_key(field) for field in (asset or {})}
        definition_fields = {compact_key(field) for field in (definition or {})}
        asset_identity = asset_fields & {"id", "uuid", "tenableid", "name", "hostname", "fqdns", "ipv4addresses", "ipv6addresses"}
        definition_evidence = definition_fields & {
            "cve", "name", "description", "solution", "severity", "cvss2", "cvss3",
            "cvss4", "vpr", "epss", "metasploit", "exploitabilityease",
        }
        tenable_export_anchor = keys & {"source", "state", "firstobserved", "lastseen", "severity", "port", "protocol", "service", "cvss3basescore", "vpr", "solution"}
        if asset is not None and definition is not None and asset_identity and definition_evidence and tenable_export_anchor and present(record, "id", "source"):
            candidates.add("tenable")
        elif "pluginid" in keys and bool(keys & {"pluginname", "vprscore", "cvss3basescore", "cve"}) and bool(keys & {"severity", "cve", "cvss3basescore", "vprscore"}):
            candidates.add("tenable")
        rapid7_identity = (
            ("assetid" in keys and bool(keys & {"vulnid", "vulnerabilityid"}))
            or ("vulnerabilityid" in keys and "riskscore" in keys)
        )
        rapid7_evidence = keys & {"cve", "cveid", "riskscore", "riskscoreoverride", "severity", "vulnerabilitytitle", "solution"}
        if rapid7_identity and rapid7_evidence:
            candidates.add("rapid7")
        crowdstrike_flat_evidence = keys & {"exploitstatus", "riskscore", "falconrating", "internetexposure", "hostinfo"}
        if (
            (("aid" in keys or "spotlightid" in keys) and bool(keys & {"cve", "cveid", "vulnerabilityid"}) and len(crowdstrike_flat_evidence) >= 2)
            or ("spotlightid" in keys and "falconrating" in keys and bool(keys & {"cve", "cveid"}))
        ):
            candidates.add("crowdstrike")
        return candidates

    def json_contract_candidates() -> set[str]:
        candidates: set[str] = set()
        try:
            inspected = 0
            # This is the same tolerant iterator used by ingest. Malformed
            # JSONL rows are skipped for detection but remain parser records
            # for quarantine/accounting during ingestion.
            for record, _pointer in iter_json_records(path, selectors=selectors):
                if isinstance(record, dict) and "_malformed" not in record:
                    candidates.update(contract_candidates(record))
                    inspected += 1
                if inspected >= 25:
                    break
            return candidates
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            return set()

    if suffix == ".xml":
        try:
            from aegis.providers.base import parse_xml_root
            root = parse_xml_root(path)
        except (OSError, UnicodeError, ET.ParseError, ValueError) as exc:
            raise ValueError("XML input could not be parsed for provider detection") from exc
        tags = {element.tag.rsplit("}", 1)[-1].lower() for element in root.iter() if isinstance(element.tag, str)}
        if "nessusclientdata_v2" in tags or "reportitem" in tags:
            return "nessus"
        if "host_list_vm_detection_output" in tags or "detection_list" in tags or "unique_vuln_id" in tags:
            return "qualys"
        raise ValueError("XML input requires an explicit provider adapter (for example --provider nessus or qualys)")
    if suffix in {".csv", ".tsv"}:
        try:
            with path.open(encoding="utf-8-sig", newline="") as handle:
                delimiter = "\t" if suffix == ".tsv" else ","
                header = next(csv.reader(handle, delimiter=delimiter), [])
        except (OSError, UnicodeError, StopIteration):
            header = []
        keys = {compact_key(value) for value in header}
        if "pluginid" in keys and bool(keys & {"pluginname", "vprscore", "cvss3basescore", "cve", "cveid"}) and bool(keys & {"severity", "vprscore", "cvss3basescore", "cve", "cveid"}):
            return "tenable"
        if "qid" in keys and bool(keys & {"qds", "uniquevulnid", "cveid"}) and bool(keys & {"severity", "qds"}) and bool(keys & {"assetid", "hostid", "hostname", "dns", "ip", "ipaddress"}):
            return "qualys"
        # Generic CSV commonly carries vulnerability_id and CVE/risk columns.
        # Those generic aliases do not identify a Rapid7 export.  Require the
        # provider-native assetId + vulnId identity pair before using the
        # Rapid7 CSV contract; set membership makes header order irrelevant.
        if {"assetid", "vulnid"}.issubset(keys) and bool(keys & {"riskscore", "cve", "cveid", "severity"}):
            return "rapid7"
        if (bool(keys & {"machineid", "machinename", "deviceid", "devicename"}) and bool(keys & {"cveid", "productname", "softwarename"}) and bool(keys & {"fixingkbid", "recommendedsecurityupdate", "recommendedsecurityupdateid", "vulnerabilityseveritylevel", "softwareversion"})) or ("vulnerabilityid" in keys and "machineid" in keys and "machinename" in keys):
            return "defender"
        if (bool(keys & {"spotlightid", "aid"}) and bool(keys & {"cve", "cveid", "vulnerabilityid"}) and len(keys & {"exploitstatus", "riskscore", "falconrating", "internetexposure", "hostinfo"}) >= 2) or ("spotlightid" in keys and "falconrating" in keys and bool(keys & {"cve", "cveid"})):
            return "crowdstrike"
        return "generic_csv"
    candidates = sorted(json_contract_candidates())
    if len(candidates) > 1:
        raise ValueError(f"ambiguous provider schema; candidates={','.join(candidates)}; pass --provider explicitly")
    if len(candidates) == 1:
        return candidates[0]
    return "generic_json"


def _mapping_summary(adapter, sample: list[dict[str, Any]]) -> dict[str, Any]:
    if not sample:
        return {"adapter": adapter.name, "confidence": 0.0, "fields": {}, "warnings": ["no records found"]}
    values, paths, warnings, unmapped, confidence, native = adapter.map_record(sample[0])
    warnings, confidence = adapter.finalize_mapping_diagnostics(values, warnings, confidence)
    unmapped = [field for field in unmapped if field not in set(paths.values())]
    inferred, validation = infer_mapping(sample, paths, name=f"{adapter.name}-inferred")
    from aegis.ingest.contracts import mapping_sha256
    return {
        "adapter": adapter.name, "mapping_version": adapter.mapping_version,
        "confidence": confidence, "fields": paths, "mapped_field_names": sorted(values),
        "unmapped_fields_sample": unmapped, "warnings": warnings,
        "native_signal_fields": sorted(native),
        "inferred_mapping": inferred, "mapping_validation": validation.as_dict(),
        "mapping_sha256": mapping_sha256(inferred),
    }


def ingest(inputs: list[str], *, run_dir: str | None = None, provider: str = "auto",
           selectors: tuple[str, ...] = ()) -> dict[str, Any]:
    """Create a raw-record run; good records survive file-level failures."""
    run = ensure_run_dir(run_dir) if run_dir else new_run_dir()
    run_id = run.name
    events = EventSink(run / "events.jsonl")
    events.emit("ingest.started", run_id=run_id, payload={"inputs": inputs, "provider": provider})
    raw_path = stage_path(run, "raw_records")
    metadata: dict[str, Any] = {
        "schema_version": "aegis-run-v1", "run_id": run_id, "run_dir": str(run), "created_at": utc_now(),
        "storage_policy": "private_run_directory_posix; host-managed ACLs on Windows",
        "status": "ingesting", "input_paths": [str(Path(value).expanduser().resolve()) for value in inputs],
        "selectors": list(selectors),
        "operational_budgets": {
            "max_run_disk_bytes": settings().max_run_disk_bytes,
            "max_stage_peak_rss_mb": settings().max_stage_peak_rss_mb,
            "max_run_seconds": settings().max_run_seconds,
            "max_record_bytes": settings().max_record_bytes,
            "rss_limit_mode": "advisory",
        },
        "retention_policy": {
            "source_snapshots": "retained_for_provenance",
            "stage_artifacts": "retained_until_operator_cleanup",
            "shareable_report_active_queue": "bounded_top_100; full findings remain in findings array",
        },
        "raw_records": 0, "files": [], "providers": {}, "errors": [], "warnings": [],
        "stages": {"ingest": {"status": "running"}},
    }
    save_run(run, metadata)
    samples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    providers: Counter[str] = Counter()
    errors: list[dict[str, Any]] = []
    accounting = RecordAccounting()
    records = 0

    def raw_records() -> Iterator[dict[str, Any]]:
        nonlocal records
        try:
            files = list(source_files(inputs))
        except Exception as exc:
            errors.append({"state": "rejected", "record": None, "reason": str(exc), "continued": False, "data_lost": False})
            return
        if not files:
            errors.append({"state": "rejected", "record": None, "reason": "no supported input files", "continued": False, "data_lost": False})
            return
        for ordinal, path in enumerate(files):
            try:
                snapshot_path, digest = _snapshot_source(path, run, ordinal)
                name = detect_provider(snapshot_path, provider, selectors=selectors)
                if selectors and name != "generic_json":
                    raise ValueError("--selector is supported only for Generic JSON input; pass --provider generic_json")
                adapter = adapter_for(name)
                file_count = 0
                for record, pointer in adapter.records(snapshot_path, selectors=selectors):
                    file_count += 1
                    records += 1
                    providers[name] += 1
                    if len(samples[name]) < 3:
                        samples[name].append(record)
                    accounting.add("mapped", pointer)
                    yield {
                        "provider": name, "source_format": path.suffix.lower().lstrip("."),
                        "source_path": str(path), "source_type": "file",
                        "source_snapshot_path": str(snapshot_path),
                        "report_sha256": digest, "record_pointer": pointer,
                        "original_record": json_safe(record),
                    }
                metadata["files"].append({"path": str(path), "provider": name, "sha256": digest, "records": file_count})
            except Exception as exc:
                accounting.add("malformed", "", reason=str(exc))
                errors.append({"state": "rejected", "file": str(path), "record": None, "reason": str(exc), "continued": True, "data_lost": False})

    from aegis.storage import write_jsonl
    mapping: dict[str, Any] = {}
    try:
        write_jsonl(raw_path, raw_records())
        record_stage_lineage(metadata, "ingest", None, raw_path)
        enforce_run_limits(run, metadata, "ingest")
        if records == 0 and not errors:
            errors.append({"state": "rejected", "file": None, "record": None,
                           "reason": "no records were parsed from the supported input files",
                           "continued": False, "data_lost": False})
        for name, sample in samples.items():
            adapter = adapter_for(name)
            summary = _mapping_summary(adapter, sample)
            mapping[name] = summary
            metadata["warnings"].extend(f"{name}: {warning}" for warning in summary.get("warnings", []))
        metadata.update({
            "status": "rejected" if records == 0 else "accepted_with_warnings" if errors or metadata["warnings"] else "accepted",
            "raw_records": records, "errors": errors, "mapping": mapping,
            "record_accounting": accounting.as_dict(),
            "data_lost": accounting.total_records != records,
            "providers": {name: {"records": count, "implemented": True} for name, count in providers.items()},
            "stages": {"ingest": {"status": "complete", "raw_records": records, "errors": len(errors), "warnings": len(metadata["warnings"])}},
            "updated_at": utc_now(),
        })
        save_run(run, metadata)
        write_lineage_manifest(run, metadata)
        events.emit("ingest.completed", run_id=run_id, payload={"records": records, "errors": len(errors)})
        return metadata
    except Exception as exc:
        reason = str(exc)
        errors.append({"state": "rejected", "file": None, "record": None,
                       "reason": reason, "continued": False, "data_lost": True})
        metadata.update({
            "status": "rejected", "raw_records": records, "errors": errors,
            "mapping": mapping, "record_accounting": accounting.as_dict(),
            "data_lost": True, "partial_artifacts": [str(raw_path)] if raw_path.exists() else [],
            "providers": {name: {"records": count, "implemented": True} for name, count in providers.items()},
            "stages": {"ingest": {"status": "failed", "raw_records": records, "errors": len(errors),
                                    "warnings": len(metadata["warnings"]), "partial": raw_path.exists()}},
            "updated_at": utc_now(),
        })
        save_run(run, metadata)
        events.emit("ingest.failed", run_id=run_id, payload={"records": records, "error": reason, "partial": raw_path.exists()})
        return metadata


def normalize(run_dir: str) -> dict[str, Any]:
    run = ensure_run_dir(run_dir)
    metadata = load_run(run)
    invalidate_downstream(run, metadata, "normalize")
    events = EventSink(run / "events.jsonl")
    events.emit("normalize.started", run_id=str(metadata.get("run_id") or run.name))
    raw_path = stage_path(run, "raw_records")
    if not raw_path.exists():
        raise FileNotFoundError(f"raw record stage not found: {raw_path}")
    output = stage_path(run, "findings")
    quarantine_path = stage_path(run, "quarantined")
    counts: Counter[str] = Counter()
    warnings: list[dict[str, Any]] = []
    quarantine_rows: list[dict[str, Any]] = []
    accounting = RecordAccounting()
    from aegis.storage import write_jsonl

    def record_terminal(raw: dict[str, Any], *, state: str, reason: str, user_intervention_required: bool) -> None:
        quarantine_rows.append({
            "state": state,
            "provider": str(raw.get("provider") or "generic_json"),
            "source_path": raw.get("source_path"),
            "record_pointer": raw.get("record_pointer"),
            "reason": reason,
            "continued": True,
            "data_lost": False,
            "user_intervention_required": user_intervention_required,
            "original_record": raw.get("original_record"),
        })

    def records() -> Iterator[dict[str, Any]]:
        for raw in iter_jsonl(raw_path):
            provider = str(raw.get("provider") or "generic_json")
            record = raw.get("original_record")
            if isinstance(record, dict) and "_malformed" in record:
                reason = str(record.get("_parse_error") or "record is not an object")
                accounting.add("malformed", str(raw.get("record_pointer") or ""), reason=reason)
                counts["quarantined"] += 1
                record_terminal(raw, state="quarantined", reason=reason, user_intervention_required=True)
                warnings.append({"state": "quarantined", "provider": provider, "record": raw.get("record_pointer"), "reason": reason, "continued": True})
                continue
            try:
                adapter = adapter_for(provider)
                finding = adapter.normalize(
                    record if isinstance(record, dict) else {"value": record},
                    pointer=str(raw.get("record_pointer") or ""),
                    report_sha256=str(raw.get("report_sha256") or ""),
                    source_type=str(raw.get("source_type") or "file"),
                )
                finding["source_metadata"]["source_path"] = raw.get("source_path")
                finding["source_metadata"]["source_snapshot_path"] = raw.get("source_snapshot_path")
                finding["source_metadata"]["source_format"] = raw.get("source_format")
                finding["source_metadata"]["import_run"] = metadata.get("run_id")
                finding["source_metadata"]["ingested_at"] = metadata.get("created_at")
                for item in finding.get("evidence", {}).get("items", []):
                    item["observed_at"] = item.get("observed_at") or metadata.get("created_at")
                if finding["evidence"].get("warnings"):
                    counts["accepted_with_warnings"] += 1
                    accounting.add("partially_mapped", str(raw.get("record_pointer") or ""), reason="normalization warnings")
                else:
                    counts["accepted"] += 1
                    accounting.add("mapped", str(raw.get("record_pointer") or ""))
                yield finding
            except (ValueError, TypeError) as exc:
                reason = str(exc)
                terminal_state = "quarantined" if any(token in reason for token in ("missing required vulnerability identity", "missing required target identity", "semantic validation failed")) else "rejected"
                accounting.add("malformed", str(raw.get("record_pointer") or ""), reason=reason)
                counts[terminal_state] += 1
                record_terminal(raw, state=terminal_state, reason=reason, user_intervention_required=terminal_state == "quarantined")
                warnings.append({"state": terminal_state, "provider": provider, "record": raw.get("record_pointer"), "reason": reason, "continued": True})

    normalized_count = write_jsonl(output, records())
    write_jsonl(quarantine_path, quarantine_rows)
    metadata["normalized_findings"] = normalized_count
    record_stage_lineage(metadata, "normalize", raw_path, output)
    enforce_run_limits(run, metadata, "normalize")
    metadata["quarantined_records"] = len(quarantine_rows)
    metadata["quarantine_path"] = str(quarantine_path)
    metadata["normalize_accounting"] = {key: counts.get(key, 0) for key in ("accepted", "accepted_with_warnings", "quarantined", "rejected")}
    metadata["normalize_record_accounting"] = accounting.as_dict()
    metadata["normalize_data_lost"] = accounting.total_records != normalized_count + len(quarantine_rows)
    metadata["normalization_warnings"] = warnings
    metadata["stages"]["normalize"] = {"status": "complete", "findings": normalized_count, "warnings": len(warnings),
                                          "quarantined": counts.get("quarantined", 0), "rejected": counts.get("rejected", 0)}
    if normalized_count == 0:
        metadata["status"] = "rejected"
        metadata["empty_usable_dataset"] = True
    else:
        metadata["status"] = "accepted_with_warnings" if warnings or counts.get("accepted_with_warnings") else metadata.get("status", "accepted")
    metadata["updated_at"] = utc_now()
    save_run(run, metadata)
    write_lineage_manifest(run, metadata)
    events.emit("normalize.completed", run_id=str(metadata.get("run_id") or run.name), payload={"findings": normalized_count, "warnings": len(warnings)})
    return metadata
