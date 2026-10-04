"""User-facing JSON, CSV, HTML and table reports."""

from __future__ import annotations

import csv
import html
import io
import json
import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Any

from aegis.models import DISPOSITIONS, PRIORITIES
from aegis.providers.base import available_adapters
from aegis.storage import ensure_run_dir, iter_jsonl, load_run, read_json, stage_path, file_sha256, fast_stage_fingerprint, write_lineage_manifest


def _findings_path(run: Path) -> Path:
    metadata = load_run(run)
    required = ("normalize", "analyze", "triage", "correlate", "remediation")
    if any((metadata.get("stages") or {}).get(stage, {}).get("status") != "complete" for stage in required):
        raise ValueError("report requires complete normalize, analyze, triage, correlate, and remediation stages")
    candidate = stage_path(run, "remediated")
    lineage = metadata.get("lineage") or {}
    chain = (("normalize", "raw_records", "findings"), ("analyze", "findings", "analyzed"),
             ("triage", "analyzed", "triaged"), ("correlate", "triaged", "correlated"),
             ("remediation", "correlated", "remediated"))
    cache_valid = True
    for stage, input_name, output_name in chain:
        item = lineage.get(stage) or {}
        input_path = stage_path(run, input_name)
        output_path = stage_path(run, output_name)
        input_fingerprint = fast_stage_fingerprint(run, input_name)
        output_fingerprint = fast_stage_fingerprint(run, output_name)
        if input_fingerprint is None or output_fingerprint is None:
            cache_valid = False
            input_fingerprint = file_sha256(input_path) if input_path.exists() else None
            output_fingerprint = file_sha256(output_path) if output_path.exists() else None
        if not input_path.exists() or not output_path.exists() or item.get("input_sha256") != input_fingerprint or item.get("output_sha256") != output_fingerprint:
            raise ValueError(f"{stage} stage is missing or stale; rerun the pipeline from the changed stage")
    if not cache_valid:
        write_lineage_manifest(run, metadata)
    return candidate


def load_findings(run_dir: str | Path) -> list[dict[str, Any]]:
    return list(iter_findings(run_dir))


def iter_findings(run_dir: str | Path):
    """Yield completed findings without materializing the corpus."""
    yield from iter_jsonl(_findings_path(ensure_run_dir(run_dir)))


def top_active_findings(run_dir: str | Path, limit: int = 100) -> list[dict[str, Any]]:
    """Return a bounded, deterministic top-N view of the active queue."""
    rank = {priority: index for index, priority in enumerate(PRIORITIES)}
    rows: list[dict[str, Any]] = []
    for finding in iter_findings(run_dir):
        if finding.get("disposition") != "confirmed":
            continue
        rows.append(finding)
        rows.sort(key=lambda item: (rank.get(item.get("priority"), 9), str(item.get("id"))))
        if len(rows) > limit:
            rows.pop()
    return rows


_SECRET_KEYS = {"token", "access_token", "api_key", "apikey", "password", "secret", "authorization", "client_secret"}
_PATH_KEYS = {"run_dir", "input_paths", "source_path", "source_snapshot_path", "quarantine_path", "path", "partial_artifacts"}
_RAW_RECORD_KEYS = {
    "original_record", "originalrecord", "original", "raw_record", "rawrecord",
    "raw_source_record", "rawsourcerecord", "source_record", "sourcerecord",
}


def _looks_absolute_path(value: str) -> bool:
    return bool(value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", value))


def _shareable(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            compact = str(key).lower().replace("-", "_")
            if compact in _SECRET_KEYS or any(part in compact for part in ("token", "password", "secret")):
                result[str(key)] = "[REDACTED]"
            elif compact in _PATH_KEYS or compact.endswith("_path"):
                # Shareable output carries logical provenance fields and
                # hashes, never machine-local paths or user-directory names.
                continue
            elif compact in _RAW_RECORD_KEYS and (
                compact in {"original_record", "originalrecord"} or isinstance(child, (dict, list))
            ):
                encoded = json.dumps(child, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
                digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
                result[str(key)] = f"[REDACTED_SOURCE_RECORD sha256:{digest}]"
            else:
                result[str(key)] = _shareable(child)
        return result
    if isinstance(value, list):
        return [_shareable(item) for item in value]
    if isinstance(value, str) and _looks_absolute_path(value):
        return "[REDACTED_PATH]"
    return value


def _provider_status(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    imported_providers = set(metadata.get("providers") or {})
    return {
        provider: {
            "implemented": True,
            "unit_tested": False,
            "fixture_tested": False,
            "mock_api_tested": False,
            "end_to_end_file_import_tested": provider in imported_providers,
            "live_provider_tested": False,
            "live_provider_end_to_end_validated": False,
        }
        for provider in available_adapters()
    }


def _report_validation(metadata: dict[str, Any]) -> dict[str, Any]:
    return {"reference_provider_live_validation": False, "provider_status": _provider_status(metadata)}


def _summary_from_stage(run: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    counts = Counter()
    calculated_counts = Counter()
    effective_counts = Counter()
    dispositions = Counter()
    total = 0
    active = 0
    for finding in iter_jsonl(_findings_path(run)):
        total += 1
        counts[finding.get("priority") or "unassigned"] += 1
        calculated_counts[finding.get("calculated_priority") or (finding.get("triage") or {}).get("calculated_priority") or "unassigned"] += 1
        effective_counts[finding.get("effective_priority") or "unassigned"] += 1
        disposition = finding.get("disposition") or "unconfirmed"
        dispositions[disposition] += 1
        active += disposition == "confirmed"
    actions_path = run / "remediation_actions.jsonl"
    action_count = sum(1 for _ in iter_jsonl(actions_path)) if actions_path.exists() else len(read_json(run / "remediation_actions.json")) if (run / "remediation_actions.json").exists() else 0
    quarantine_path = run / "quarantined.jsonl"
    quarantine_count = sum(1 for _ in iter_jsonl(quarantine_path)) if quarantine_path.exists() else 0
    return {
        "total_findings": total, "active_queue": active,
        "priority_counts": {priority: counts.get(priority, 0) for priority in PRIORITIES},
        "calculated_priority_counts": {priority: calculated_counts.get(priority, 0) for priority in PRIORITIES},
        "effective_priority_counts": {priority: effective_counts.get(priority, 0) for priority in PRIORITIES},
        "unassigned": counts.get("unassigned", 0),
        "disposition_counts": {disposition: dispositions.get(disposition, 0) for disposition in DISPOSITIONS},
        "remediation_actions": action_count, "quarantined_records": quarantine_count,
    }


def _stream_array(handle, records: Any, *, transform=lambda value: value) -> None:
    handle.write("[")
    first = True
    for record in records:
        if not first:
            handle.write(",")
        first = False
        handle.write(json.dumps(transform(record), ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str))
    handle.write("]")


def _stream_json_report(run: Path, output: Path, *, include_raw: bool) -> str:
    """Write JSON without materializing the complete finding corpus.

    The stage is reread for each report section.  This trades disk I/O for a
    bounded heap and keeps the shareable report boundary identical to the
    in-memory ``payload`` API used by smaller callers.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    metadata = load_run(run)
    findings_path = _findings_path(run)
    summary = _summary_from_stage(run, metadata)
    actions_path = run / "remediation_actions.jsonl"
    actions = iter_jsonl(actions_path) if actions_path.exists() else ()
    quarantine_path = run / "quarantined.jsonl"
    with output.open("w", encoding="utf-8", newline="") as handle:
        handle.write("{\"report_schema_version\":\"aegis-report-v1\",\"run\":")
        shareable_metadata = _shareable({key: value for key, value in metadata.items() if key not in {"mapping", "errors", "normalization_warnings"}})
        handle.write(json.dumps(shareable_metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str))
        handle.write(",\"summary\":")
        handle.write(json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str))
        handle.write(",\"findings\":")
        shareable = lambda item: item if include_raw else _shareable(item)
        _stream_array(handle, iter_jsonl(findings_path), transform=shareable)
        active_limit = 100
        handle.write(",\"active_queue_top_n\":")
        handle.write(str(active_limit))
        handle.write(",\"active_queue_truncated\":")
        handle.write("true" if summary["active_queue"] > active_limit else "false")
        handle.write(",\"active_queue\":")
        _stream_array(handle, top_active_findings(run, active_limit), transform=shareable)
        handle.write(",\"dispositions\":{\"counts\":")
        handle.write(json.dumps(summary["disposition_counts"], ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        handle.write(",\"records\":")
        def disposition_records():
            for finding in iter_jsonl(findings_path):
                if finding.get("disposition") == "confirmed":
                    continue
                yield {"id": finding["id"], "disposition": finding.get("disposition"),
                       "calculated_priority": (finding.get("triage") or {}).get("calculated_priority"),
                       "effective_priority": finding.get("effective_priority"), "priority": finding.get("priority"),
                       "title": finding.get("title"), "source": finding.get("source"),
                       "correlation": finding.get("correlation"), "evidence": finding.get("evidence"),
                       "reason": (finding.get("triage") or {}).get("explanation")}
        _stream_array(handle, disposition_records(), transform=shareable)
        handle.write("},\"remediation_actions\":")
        _stream_array(handle, actions, transform=shareable)
        handle.write(",\"quarantine\":")
        _stream_array(handle, iter_jsonl(quarantine_path) if quarantine_path.exists() else (), transform=shareable)
        handle.write(",\"validation\":")
        handle.write(json.dumps(_report_validation(metadata), ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str))
        handle.write("}\n")
    return str(output)


def payload(run_dir: str | Path, *, include_raw: bool = False) -> dict[str, Any]:
    run = ensure_run_dir(run_dir)
    metadata = load_run(run)
    findings = load_findings(run)
    counts = Counter(f.get("priority") or "unassigned" for f in findings)
    calculated_counts = Counter(
        (f.get("calculated_priority") or (f.get("triage") or {}).get("calculated_priority") or "unassigned")
        for f in findings
    )
    effective_counts = Counter(f.get("effective_priority") or "unassigned" for f in findings)
    dispositions = Counter(f.get("disposition") or "unconfirmed" for f in findings)
    actions_path = run / "remediation_actions.json"
    actions = read_json(actions_path) if actions_path.exists() else []
    quarantine_path = run / "quarantined.jsonl"
    quarantined = list(iter_jsonl(quarantine_path)) if quarantine_path.exists() else []
    rank = {priority: index for index, priority in enumerate(PRIORITIES)}
    active = sorted((f for f in findings if f.get("disposition") == "confirmed"), key=lambda f: (rank.get(f.get("priority"), 9), str(f.get("id"))))
    disposition_records = [
        {"id": f["id"], "disposition": f.get("disposition"), "calculated_priority": (f.get("triage") or {}).get("calculated_priority"), "effective_priority": f.get("effective_priority", f.get("priority")), "priority": f.get("priority"), "title": f.get("title"), "source": f.get("source"), "correlation": f.get("correlation"), "evidence": f.get("evidence"), "reason": (f.get("triage") or {}).get("explanation")}
        for f in findings if f.get("disposition") != "confirmed"
    ]
    imported_providers = set(metadata.get("providers") or {})
    provider_status = {
        provider: {
            "implemented": True,
            # Runtime output is not a test runner.  These claims must come
            # from retained validation evidence, never from a hardcoded
            # provider name or from successful parsing of one run.
            "unit_tested": False,
            "fixture_tested": False,
            "mock_api_tested": False,
            "end_to_end_file_import_tested": provider in imported_providers,
            "live_provider_tested": False,
            "live_provider_end_to_end_validated": False,
        }
        for provider in available_adapters()
    }
    result = {
        "report_schema_version": "aegis-report-v1",
        "run": {key: value for key, value in metadata.items() if key not in {"mapping", "errors", "normalization_warnings"}},
        "summary": {
            "total_findings": len(findings), "active_queue": len(active),
            # ``priority_counts`` remains the compatibility name for the
            # effective queue view.  The explicit fields prevent calculated
            # risk from being confused with queue eligibility.
            "priority_counts": {priority: counts.get(priority, 0) for priority in PRIORITIES},
            "calculated_priority_counts": {priority: calculated_counts.get(priority, 0) for priority in PRIORITIES},
            "effective_priority_counts": {priority: effective_counts.get(priority, 0) for priority in PRIORITIES},
            "unassigned": counts.get("unassigned", 0),
            "disposition_counts": {disposition: dispositions.get(disposition, 0) for disposition in DISPOSITIONS},
            "remediation_actions": len(actions), "quarantined_records": len(quarantined),
        },
        "findings": findings,
        "active_queue": active,
        "dispositions": {"counts": dict(dispositions), "records": disposition_records},
        "remediation_actions": actions,
        "quarantine": quarantined,
        "validation": {
            "reference_provider_live_validation": False,
            "provider_status": provider_status,
        },
    }
    return result if include_raw else _shareable(result)


def _csv_safe(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def csv_text(data: dict[str, Any]) -> str:
    output = io.StringIO(newline="")
    fields = ["id", "source", "source_finding_id", "title", "calculated_priority", "effective_priority", "priority", "disposition", "cve", "asset_id", "hostname", "internet_exposed", "business_criticality", "epss", "kev", "triage_explanation", "correlation_group_id", "remediation_action_id"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for original_finding in data.get("findings", []):
        finding = _shareable(original_finding)
        vuln = finding.get("vulnerability") or {}
        asset = finding.get("asset") or {}
        triage = finding.get("triage") or {}
        writer.writerow({
            "id": _csv_safe(finding.get("id")), "source": _csv_safe(finding.get("source")), "source_finding_id": _csv_safe(finding.get("source_finding_id")),
            "title": _csv_safe(finding.get("title")),
            "calculated_priority": _csv_safe(finding.get("calculated_priority") or triage.get("calculated_priority")),
            "effective_priority": _csv_safe(finding.get("effective_priority")),
            "priority": _csv_safe(finding.get("priority")), "disposition": _csv_safe(finding.get("disposition")),
            "cve": _csv_safe(vuln.get("cve")), "asset_id": _csv_safe(asset.get("asset_id")), "hostname": _csv_safe(asset.get("hostname")),
            "internet_exposed": _csv_safe(asset.get("internet_exposed")), "business_criticality": _csv_safe(asset.get("business_criticality")),
            "epss": _csv_safe(vuln.get("epss")), "kev": _csv_safe((vuln.get("kev") or {}).get("listed")), "triage_explanation": _csv_safe(triage.get("explanation")),
            "correlation_group_id": _csv_safe((finding.get("correlation") or {}).get("group_id")),
            "remediation_action_id": _csv_safe((finding.get("remediation") or {}).get("action_id")),
        })
    return output.getvalue()


def _csv_row(finding: dict[str, Any]) -> dict[str, str]:
    vuln = finding.get("vulnerability") or {}
    asset = finding.get("asset") or {}
    triage = finding.get("triage") or {}
    return {
        "id": _csv_safe(finding.get("id")), "source": _csv_safe(finding.get("source")),
        "source_finding_id": _csv_safe(finding.get("source_finding_id")), "title": _csv_safe(finding.get("title")),
        "calculated_priority": _csv_safe(finding.get("calculated_priority") or triage.get("calculated_priority")),
        "effective_priority": _csv_safe(finding.get("effective_priority")), "priority": _csv_safe(finding.get("priority")),
        "disposition": _csv_safe(finding.get("disposition")), "cve": _csv_safe(vuln.get("cve")),
        "asset_id": _csv_safe(asset.get("asset_id")), "hostname": _csv_safe(asset.get("hostname")),
        "internet_exposed": _csv_safe(asset.get("internet_exposed")),
        "business_criticality": _csv_safe(asset.get("business_criticality")), "epss": _csv_safe(vuln.get("epss")),
        "kev": _csv_safe((vuln.get("kev") or {}).get("listed")),
        "triage_explanation": _csv_safe(triage.get("explanation")),
        "correlation_group_id": _csv_safe((finding.get("correlation") or {}).get("group_id")),
        "remediation_action_id": _csv_safe((finding.get("remediation") or {}).get("action_id")),
    }


def _stream_csv_report(run: Path, output: Path) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = ["id", "source", "source_finding_id", "title", "calculated_priority", "effective_priority", "priority", "disposition", "cve", "asset_id", "hostname", "internet_exposed", "business_criticality", "epss", "kev", "triage_explanation", "correlation_group_id", "remediation_action_id"]
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for finding in iter_jsonl(_findings_path(run)):
            writer.writerow(_csv_row(_shareable(finding)))
    return str(output)


def _stream_html_report(run: Path, output: Path) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    metadata = load_run(run)
    summary = _summary_from_stage(run, metadata)
    with output.open("w", encoding="utf-8", newline="") as handle:
        handle.write("<!doctype html><html><head><meta charset='utf-8'><title>Aegis report</title><style>body{font:14px system-ui;margin:2rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:.45rem;text-align:left}th{background:#17324d;color:white}</style></head><body>")
        handle.write(f"<h1>Aegis vulnerability report</h1><p>Total findings: <b>{summary['total_findings']}</b>; active queue: <b>{summary['active_queue']}</b>; remediation actions: <b>{summary['remediation_actions']}</b></p><table><thead><tr><th>Finding ID</th><th>Calculated</th><th>Effective</th><th>Provider</th><th>Finding</th><th>Disposition</th><th>Why</th><th>Correlation</th><th>Action</th></tr></thead><tbody>")
        for raw_finding in iter_jsonl(_findings_path(run)):
            finding = _shareable(raw_finding)
            triage = finding.get("triage") or {}
            values = (finding.get("id"), finding.get("calculated_priority") or triage.get("calculated_priority"), finding.get("effective_priority"), finding.get("source"), finding.get("title"), finding.get("disposition"), triage.get("explanation"), (finding.get("correlation") or {}).get("group_id"), (finding.get("remediation") or {}).get("action_id"))
            handle.write("<tr>" + "".join(f"<td>{html.escape('' if value is None else str(value))}</td>" for value in values) + "</tr>")
        handle.write("</tbody></table></body></html>\n")
    return str(output)


def table_text(data: dict[str, Any]) -> str:
    summary = data["summary"]
    lines = ["Aegis vulnerability remediation queue", "", f"Total findings: {summary['total_findings']} | Active queue: {summary['active_queue']} | Remediation actions: {summary['remediation_actions']}", "Priority  Count"]
    for priority in PRIORITIES:
        lines.append(f"{priority:<8}{summary['priority_counts'].get(priority, 0)}")
    lines.append("\nActive findings:")
    for raw_finding in data.get("active_queue", [])[:100]:
        finding = _shareable(raw_finding)
        triage = finding.get("triage") or {}
        lines.append(f"{finding.get('priority') or '-':<3} {finding.get('source')} {finding.get('title')} | {triage.get('explanation', '')}")
    if len(data.get("active_queue", [])) > 100:
        lines.append(f"... {len(data['active_queue']) - 100} more active findings")
    return "\n".join(lines) + "\n"


def html_text(data: dict[str, Any]) -> str:
    summary = data["summary"]
    rows = []
    # HTML is a user-facing report, so it contains the complete finding set.
    # The active queue remains a separate field in the JSON payload; non-active
    # findings are rendered with a blank effective priority rather than being
    # silently dropped from the report.
    for raw_finding in data.get("findings", []):
        finding = _shareable(raw_finding)
        triage = finding.get("triage") or {}
        values = (
            finding.get("id"),
            finding.get("calculated_priority") or triage.get("calculated_priority"),
            finding.get("effective_priority"),
            finding.get("source"),
            finding.get("title"),
            finding.get("disposition"),
            triage.get("explanation"),
            (finding.get("correlation") or {}).get("group_id"),
            (finding.get("remediation") or {}).get("action_id"),
        )
        rows.append("<tr>" + "".join(f"<td>{html.escape('' if value is None else str(value))}</td>" for value in values) + "</tr>")
    template = "<!doctype html><html><head><meta charset='utf-8'><title>Aegis report</title><style>body{{font:14px system-ui;margin:2rem}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:.45rem;text-align:left}}th{{background:#17324d;color:white}}.p0{{color:#a00}}</style></head><body><h1>Aegis vulnerability report</h1><p>Total findings: <b>{total}</b>; active queue: <b>{active}</b>; remediation actions: <b>{actions}</b></p><table><thead><tr><th>Finding ID</th><th>Calculated</th><th>Effective</th><th>Provider</th><th>Finding</th><th>Disposition</th><th>Why</th><th>Correlation</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table></body></html>"
    return template.format(total=html.escape(str(summary["total_findings"])), active=html.escape(str(summary["active_queue"])), actions=html.escape(str(summary["remediation_actions"])), rows="".join(rows))


def report(run_dir: str, *, format_name: str = "json", output: str | None = None, include_raw: bool = False) -> str:
    run = ensure_run_dir(run_dir)
    if format_name == "json":
        path = Path(output) if output else run / "report.json"
        return _stream_json_report(run, path, include_raw=include_raw)
    if format_name == "csv":
        path = Path(output) if output else run / "report.csv"
        return _stream_csv_report(run, path)
    if format_name == "html":
        path = Path(output) if output else run / "report.html"
        return _stream_html_report(run, path)
    if format_name == "table":
        metadata = load_run(run)
        summary = _summary_from_stage(run, metadata)
        data = {"summary": summary, "active_queue": top_active_findings(run, 100)}
        text = table_text(data)
        if output:
            Path(output).write_text(text, encoding="utf-8")
            return output
        return text
    raise ValueError(f"unsupported report format: {format_name}")
