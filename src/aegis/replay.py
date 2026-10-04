"""Streaming, hash-checked canonical replay artifacts."""

from __future__ import annotations

import hashlib
import json
import ipaddress
import re
from pathlib import Path
from typing import Any

from aegis.models import SCHEMA_VERSION
from aegis.storage import iter_jsonl

REPLAY_FORMAT = "aegis-canonical-corpus-replay-jsonl"
REPLAY_VERSION = "aegis-replay-v2"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def _validate_canonical_finding(finding: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if finding.get("schema_version") != SCHEMA_VERSION:
        errors.append("canonical schema version mismatch")
    if not finding.get("id") or not finding.get("import_instance_id") or not finding.get("source"):
        errors.append("canonical finding identity is incomplete")
    vulnerability = finding.get("vulnerability")
    asset = finding.get("asset")
    if not isinstance(vulnerability, dict) or not isinstance(asset, dict):
        return [*errors, "canonical finding sections are missing"]
    cves = vulnerability.get("cve") or []
    if not isinstance(cves, list) or any(not isinstance(value, str) or not _CVE_RE.fullmatch(value) for value in cves):
        errors.append("canonical CVE list is invalid")
    natives = vulnerability.get("provider_identifiers") or []
    if not isinstance(natives, list) or any(not isinstance(item, dict) or not item.get("provider") or item.get("kind") != "vulnerability" or not item.get("value") for item in natives):
        errors.append("provider-native vulnerability identifiers are not typed")
    if not cves and not natives:
        errors.append("canonical vulnerability identity is missing")
    target_present = any(str(asset.get(field) or "").strip() for field in ("asset_id", "hostname", "fqdn"))
    ips = asset.get("ip_addresses") or []
    if not isinstance(ips, list):
        errors.append("canonical IP observations are not a list")
    else:
        for value in ips:
            try:
                ipaddress.ip_address(str(value))
                target_present = True
            except ValueError:
                errors.append("canonical asset contains an invalid IP")
    if not target_present:
        errors.append("canonical target identity is missing")
    return errors


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def export_corpus(findings_path: str | Path, output: str | Path) -> dict[str, Any]:
    """Write one bounded record at a time; the artifact is newline-delimited JSON."""
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    count = 0
    header = {"format": REPLAY_FORMAT, "replay_version": REPLAY_VERSION, "schema_version": SCHEMA_VERSION, "kind": "header"}
    with target.open("w", encoding="utf-8", newline="") as handle:
        handle.write(json.dumps(header, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        digest.update(_canonical(header))
        for finding in iter_jsonl(findings_path):
            if _validate_canonical_finding(finding):
                raise ValueError("canonical replay export encountered an invalid finding")
            row = {"kind": "finding", "finding": finding}
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str) + "\n")
            digest.update(_canonical(row))
            count += 1
        footer = {"kind": "footer", "sha256": digest.hexdigest(), "findings": count}
        handle.write(json.dumps(footer, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    return {"output": str(target), "findings": count, "sha256": footer["sha256"], "format": REPLAY_FORMAT}


def validate_corpus(path: str | Path) -> dict[str, Any]:
    """Validate replay structure, canonical semantics and the streaming digest."""
    digest = hashlib.sha256()
    header: dict[str, Any] | None = None
    footer: dict[str, Any] | None = None
    count = 0
    seen_ids: set[str] = set()
    with Path(path).open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            try:
                row = json.loads(line)
            except (json.JSONDecodeError, UnicodeError) as exc:
                raise ValueError(f"invalid replay JSON at line {number}: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"replay line {number} is not an object")
            kind = row.get("kind")
            if number == 1:
                if kind != "header" or row.get("format") != REPLAY_FORMAT or row.get("schema_version") != SCHEMA_VERSION or row.get("replay_version") != REPLAY_VERSION:
                    raise ValueError("invalid replay header, schema, or semantic version")
                header = row
                digest.update(_canonical(row))
                continue
            if kind == "finding":
                finding = row.get("finding")
                if not isinstance(finding, dict):
                    raise ValueError(f"invalid canonical finding at replay line {number}")
                errors = _validate_canonical_finding(finding)
                if errors:
                    raise ValueError(f"invalid canonical finding at replay line {number}: {'; '.join(errors)}")
                if finding["id"] in seen_ids:
                    raise ValueError(f"duplicate canonical finding id at replay line {number}")
                seen_ids.add(finding["id"])
                digest.update(_canonical(row))
                count += 1
                continue
            if kind == "footer":
                if footer is not None or not isinstance(row.get("findings"), int):
                    raise ValueError("invalid replay footer")
                footer = row
                continue
            raise ValueError(f"unexpected replay record kind at line {number}: {kind!r}")
    if header is None or footer is None:
        raise ValueError("replay requires header and footer")
    calculated = digest.hexdigest()
    return {"valid": footer.get("sha256") == calculated and footer.get("findings") == count,
            "findings": count, "expected_sha256": calculated, "supplied_sha256": footer.get("sha256"), "format": REPLAY_FORMAT}
