"""Shared deterministic provider-field normalization helpers."""

from __future__ import annotations

import re
import ipaddress
from datetime import datetime, timezone
from typing import Any, Iterable

from aegis.models import add_evidence, as_list, durable_semantic_entity_id, empty_finding, json_safe, normalize_text, put_signal, semantic_identity_aliases, set_semantic_entity_id
from aegis.provenance import field_provenance
from aegis.evidence import evidence_basis

_KEY_RE = re.compile(r"[^a-z0-9]+")
_ID_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[0-9A-Za-z-]+|OSV-[0-9A-Za-z-]+|CWE[-_: ]?\d+)\b", re.I)

ALIASES: dict[str, tuple[str, ...]] = {
    "source_record_id": ("source_finding_id", "sourcefindingid", "occurrence_id", "occurrenceid", "detection_id", "detectionid", "finding_id", "findingid", "issue_id", "issueid", "record_id", "recordid", "id", "uuid", "spotlight_id", "spotlightid"),
    "title": ("title", "name", "summary", "pluginname", "plugin_name", "vulnerability", "issue"),
    "description": ("description", "details", "detail", "synopsis", "message", "proof", "evidence"),
    "severity": ("severity", "risk", "risk_factor", "riskfactor", "rating", "level", "priority", "vulnerabilitySeverityLevel"),
    # Generic JSON commonly calls a CVE-bearing field ``vulnerability``.
    # It is a candidate CVE alias only; extract_identifiers validates it and
    # rejects arbitrary prose instead of manufacturing vulnerability identity.
    "cve": ("cve", "cve_id", "cveid", "cves", "vulnerability"),
    "cwe": ("cwe", "cwe_id", "cweid", "weakness"),
    "cvss_score": ("cvss", "cvss_score", "cvssscore", "cvss3_base_score", "cvssv3_basescore", "cvss3_base", "cvss3base", "cvssv3", "base_score", "basescore"),
    "cvss_version": ("cvss_version", "cvssversion", "cvss3_version", "cvss3version"),
    "cvss_vector": ("cvss_vector", "cvssvector", "cvss3_vector", "vector"),
    "exploit_available": ("exploit_available", "exploitavailable", "exploit", "exploit_exists", "public_exploit"),
    "exploit_maturity": ("exploit_maturity", "exploitmaturity", "exploit_code_maturity", "maturity"),
    "exploited_in_wild": ("exploited_in_wild", "exploitedinwild", "active_exploitation", "actively_exploited", "exploited"),
    "kev": ("kev", "known_exploited", "knownexploited", "known_exploited_vulnerability", "knownexploitedvulnerability", "is_kev", "iskev"),
    "epss": ("epss", "epss_score", "epssscore", "epss_probability", "epssprobability"),
    "vendor_risk_score": ("vpr", "qds", "risk_score", "riskscore", "vendor_risk_score", "vendorscore"),
    "asset_id": ("asset_id", "assetid", "asset_ref", "assetref", "target_id", "targetid", "machine_id", "machineid", "aid", "host_id", "hostid", "device_id", "deviceid", "resource_id", "resourceid", "resource_uid", "resourceuid", "instance_id", "instanceid", "endpoint_id", "endpointid", "node_id", "nodeid"),
    "hostname": ("hostname", "host_name", "host", "computer_name", "computername", "machine_name", "machinename"),
    "fqdn": ("fqdn", "fully_qualified_domain_name"),
    "ip": ("ip", "ip_address", "ipaddress", "address", "ipv4", "ipv6", "machine_ip", "machineip"),
    "operating_system": ("operating_system", "operatingsystem", "os", "os_name", "osPlatform", "osVersion"),
    "application": ("application", "app"),
    "package": ("package", "package_name", "packagename", "component", "artifact", "product", "softwareName"),
    "installed_version": ("installed_version", "installedversion", "version", "package_version", "packageversion", "softwareVersion"),
    "fixed_version": ("fixed_version", "fixedversion", "patched_version", "patchedversion", "solution_version"),
    "port": ("port", "port_number", "portnumber"),
    "protocol": ("protocol", "transport"),
    "service": ("service", "service_name", "servicename"),
    "environment": ("environment", "env", "asset_environment"),
    "network_zone": ("network_zone", "networkzone", "network_segment", "networksegment", "zone", "segment"),
    "isolation": ("network_isolation", "networkisolation", "network_isolated", "networkisolated", "isolation", "isolation_level", "isolationlevel", "isolated", "air_gapped", "airgapped"),
    "internet_exposed": ("internet_exposed", "internetexposed", "exposed_to_internet", "exposedtointernet", "internet_facing", "internetfacing", "publicly_exposed", "publicexposure"),
    "asset_criticality": ("asset_criticality", "assetcriticality", "criticality", "asset_priority"),
    "business_criticality": ("business_criticality", "businesscriticality", "business_impact", "business_priority"),
    "data_sensitivity": ("data_sensitivity", "datasensitivity", "data_classification", "classification"),
    "owner": ("owner", "asset_owner", "assetowner", "responsible_team", "team"),
    "tags": ("tags", "labels", "machine_tags", "machinetags"),
    "first_seen": ("first_seen", "firstseen", "first_found", "firstfound", "first_observed", "firstobserved", "firstSeenTimestamp", "discovered_at", "discoveredat"),
    "last_seen": ("last_seen", "lastseen", "last_found", "lastfound", "last_seen_timestamp", "lastSeenTimestamp", "updated_at", "updatedat", "updated_timestamp", "detected_at"),
    "status": ("status", "state", "finding_status", "findingstatus", "workflow_status", "disposition"),
    "patch_available": ("patch_available", "patchavailable", "has_patch", "haspatch", "fix_available", "fixavailable", "securityUpdateAvailable"),
    "solution": ("solution", "remediation", "recommended_fix", "recommendedfix", "recommended_security_update", "recommendedsecurityupdate", "recommendation", "fix", "suggested_fix", "suggestedfix"),
    # Explicit action identifiers are distinct from provider recommendation IDs.
    # Keeping the two fields separate lets remediation grouping preserve both
    # the cross-provider action identity and the weaker vendor evidence.
    "remediation_action_id": ("remediation_action_id", "remediationactionid", "action_id", "actionid", "cross_provider_remediation_id", "crossproviderremediationid", "shared_remediation_id", "sharedremediationid", "patch_action_id", "patchactionid", "fix_action_id", "fixactionid"),
    "remediation_id": ("remediation_id", "remediationid", "recommendation_id", "recommendationid", "recommendedSecurityUpdateId", "recommendationReference", "fix_id", "fixid", "patch_id", "patchid", "update_id", "updateid", "bulletin_id", "bulletinid"),
    "compensating_controls": ("compensating_controls", "compensating_control", "compensatingcontrols", "compensatingcontrol", "mitigations", "mitigation", "controls"),
    "technical_impact": ("technical_impact", "technicalimpact", "impact", "impact_type"),
    "prevalence": ("prevalence", "affected_assets", "affectedassets", "asset_count", "assetcount"),
}


def norm_key(value: Any) -> str:
    return _KEY_RE.sub("", str(value).lower())


def walk_fields(value: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield child_path, child
            yield from walk_fields(child, child_path)


def get_value(record: dict[str, Any], aliases: Iterable[str]) -> tuple[Any, str | None]:
    return get_indexed_value(index_fields(record), aliases)


def index_fields(record: dict[str, Any]) -> tuple[dict[str, tuple[Any, str]], dict[str, tuple[Any, str]]]:
    """Build exact-key and leaf-key indexes once per source record."""
    exact: dict[str, tuple[Any, str]] = {}
    leaves: dict[str, tuple[Any, str]] = {}
    for key, value in record.items():
        if value not in (None, "", [], {}):
            exact.setdefault(norm_key(key), (value, str(key)))
    for path, value in walk_fields(record):
        if value not in (None, "", [], {}) and not isinstance(value, (dict, list, tuple, set)):
            leaves.setdefault(norm_key(path.rsplit(".", 1)[-1]), (value, path))
    return exact, leaves


def get_indexed_value(index: tuple[dict[str, tuple[Any, str]], dict[str, tuple[Any, str]]], aliases: Iterable[str]) -> tuple[Any, str | None]:
    exact, leaves = index
    for alias in aliases:
        key = norm_key(alias)
        if key in exact:
            return exact[key]
    for alias in aliases:
        key = norm_key(alias.rsplit(".", 1)[-1])
        if key in leaves:
            return leaves[key]
    return None, None


def parse_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return None
    if isinstance(value, (dict, list, tuple, set)):
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value in (0, 1):
            return bool(value)
        return None
    text = normalize_text(value).lower()
    if text in {"true", "yes", "y", "1", "on", "active", "open", "listed", "exploited"}:
        return True
    if text in {"false", "no", "n", "0", "off", "inactive", "closed", "not listed", "none"}:
        return False
    return None


def parse_float(value: Any) -> float | None:
    """Parse a scalar numeric field without extracting numbers from prose."""
    if isinstance(value, bool) or value is None or isinstance(value, (dict, list, tuple, set)):
        return None
    try:
        text = normalize_text(value).replace(",", "")
        if not re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)", text):
            return None
        return float(text)
    except (TypeError, ValueError):
        return None


def parse_epss(value: Any) -> float | None:
    """Return canonical EPSS probability; explicit percent strings are converted."""
    if isinstance(value, str) and value.strip().endswith("%"):
        number = parse_float(value.strip()[:-1])
        return number / 100.0 if number is not None and 0 <= number <= 100 else None
    number = parse_float(value)
    return number if number is not None and 0 <= number <= 1 else None


def parse_cvss(value: Any) -> float | None:
    number = parse_float(value)
    return number if number is not None and 0 <= number <= 10 else None


def parse_port(value: Any) -> int | None:
    number = parse_float(value)
    if number is None or not number.is_integer() or not 1 <= number <= 65535:
        return None
    return int(number)


def parse_datetime(value: Any) -> str | None:
    if isinstance(value, (dict, list, tuple, set)):
        return None
    text = normalize_text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


def unique_text(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = normalize_text(value)
        if not text:
            continue
        if text.lower() not in seen:
            seen.add(text.lower())
            result.append(text)
    return result


_CONTROL_NEGATIVE_RE = re.compile(
    r"\b(?:failed?|failure|bypass(?:ed)?|misconfigured?|degraded|expired|unavailable|"
    r"monitor\s+only|audit\s+only|disabled|ineffective|unsegmented|unisolated|"
    r"not|without|no)\b",
    re.I,
)
_CONTROL_POSITIVE_RE = re.compile(
    r"\b(?:effective|strong|blocks?|den(?:y|ies|ied)|prevents?|contained|"
    r"segmented|isolated|air[- ]?gapped|virtual\s+patch(?:ed)?|mitigat(?:es?|ed|ion)|"
    r"compensat(?:es?|ed|ing))\b",
    re.I,
)


def normalize_control_evidence(value: Any) -> list[dict[str, Any]]:
    """Classify control text without treating control vocabulary as efficacy.

    A control word by itself is unknown.  Only an explicit affirmative efficacy
    phrase becomes effective; failure, bypass, degradation, expiration,
    unavailable, monitor-only and audit-only evidence is explicitly negative.
    """
    if isinstance(value, dict):
        raw_items = [value]
    else:
        raw_items = as_list(value)
    result: list[dict[str, Any]] = []
    for raw in raw_items:
        if isinstance(raw, dict):
            text = normalize_text(raw.get("text") or raw.get("name") or raw.get("control") or raw.get("value"))
            state = normalize_text(raw.get("state") or raw.get("effectiveness")).lower()
            explicit = parse_bool(raw.get("effective"))
            if explicit is True:
                state = "effective"
            elif explicit is False:
                state = "ineffective"
        else:
            text = normalize_text(raw)
            state = ""
        if not text:
            continue
        lowered = text.lower().strip()
        if lowered in {"none", "no", "false", "not applicable", "n/a", "na", "unknown"}:
            state = "unknown"
        elif _CONTROL_NEGATIVE_RE.search(lowered):
            state = "ineffective"
        elif state not in {"effective", "ineffective", "unknown"}:
            state = "effective" if _CONTROL_POSITIVE_RE.search(lowered) else "unknown"
        result.append({"text": text, "state": state, "effective": state == "effective"})
    return result


def normalize_controls(value: Any) -> list[str]:
    """Return normalized control text; triage uses the explicit state separately."""
    return [item["text"] for item in normalize_control_evidence(value)]


_IDENTITY_PLACEHOLDERS = {
    "", "none", "null", "unknown", "unk", "n/a", "na", "not available",
    "not_applicable", "not applicable", "placeholder", "record", "value",
    "empty", "nil", "false", "0", "-", "--",
}


def _usable_identity_value(value: Any) -> bool:
    if isinstance(value, (dict, list, tuple, set)):
        return False
    text = normalize_text(value).strip()
    return bool(text) and text.lower() not in _IDENTITY_PLACEHOLDERS


def has_target_identity(values: dict[str, Any]) -> bool:
    """Return whether a record identifies a real target without fabrication.

    Finding identifiers, titles, pointers, and source filenames are
    intentionally absent from this check.  Provider-native asset/device IDs
    are valid even when a hostname or IP is unavailable; an IP-like field must
    additionally parse as an IP address.
    """
    import ipaddress

    for field in ("asset_id", "hostname", "fqdn"):
        if _usable_identity_value(values.get(field)):
            return True
    raw_ips = values.get("ip")
    for item in as_list(raw_ips):
        if isinstance(item, (dict, list, tuple, set)):
            continue
        for candidate in re.split(r"[,;\s]+", normalize_text(item).strip()):
            if not candidate or candidate.lower() in _IDENTITY_PLACEHOLDERS:
                continue
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            return True
    return False


def extract_identifiers(*values: Any) -> tuple[list[str], list[str], list[str]]:
    identifiers: list[str] = []
    cves: list[str] = []
    cwes: list[str] = []
    for value in values:
        for item in as_list(value):
            text = normalize_text(item)
            for match in _ID_RE.findall(text):
                ident = match.upper()
                if ident.startswith("CVE-"):
                    cves.append(ident)
                elif ident.startswith("CWE"):
                    digits = re.search(r"\d+", ident)
                    if digits:
                        cwes.append(f"CWE-{digits.group(0)}")
                else:
                    identifiers.append(ident)
    return unique_text(identifiers), unique_text(cves), unique_text(cwes)


def normalize_severity(value: Any, cvss_score: Any = None, *, numeric_is_cvss: bool = False,
                       provider_scale: str | None = None) -> tuple[str, str]:
    original = value
    if isinstance(value, (dict, list, tuple, set)):
        value = None
    number = parse_float(value)
    numeric = not isinstance(value, str) or bool(re.fullmatch(r"\s*\d+(?:\.\d+)?\s*", str(value)))
    if number is not None and numeric and provider_scale == "qualys_1_5":
        if float(number).is_integer() and 1 <= number <= 5:
            return ("low" if number == 1 else "medium" if number == 2 else "high" if number in {3, 4} else "critical", "qualys_native_ordinal_1_5")
    if number is not None and numeric:
        if not numeric_is_cvss and 0 <= number <= 4 and float(number).is_integer():
            return ("none" if number == 0 else "low" if number == 1 else "medium" if number == 2 else "high" if number == 3 else "critical", "numeric_provider_severity")
        if 0 <= number <= 10:
            return ("critical" if number >= 9 else "high" if number >= 7 else "medium" if number >= 4 else "low" if number > 0 else "none", "numeric_cvss_like_score")
    text = normalize_text(original).lower()
    aliases = {"critical": "critical", "crit": "critical", "severe": "high", "high": "high", "medium": "medium", "moderate": "medium", "med": "medium", "low": "low", "info": "none", "informational": "none", "none": "none", "negligible": "none"}
    if text in aliases:
        return aliases[text], f"text_alias:{text}"
    score = parse_float(cvss_score)
    if score is not None:
        return normalize_severity(score, numeric_is_cvss=True)
    return "unknown", "unrecognized_or_missing"


def normalize_asset(values: dict[str, Any]) -> dict[str, Any]:
    ips: list[str] = []
    invalid_ips: list[str] = []
    for raw in as_list(values.get("ip")):
        if isinstance(raw, (dict, list, tuple, set)):
            continue
        for candidate in re.split(r"[,;\s]+", normalize_text(raw).strip()):
            if not candidate:
                continue
            try:
                canonical = str(ipaddress.ip_address(candidate))
            except ValueError:
                invalid_ips.append(candidate)
                continue
            if canonical.lower() not in {item.lower() for item in ips}:
                ips.append(canonical)
    tags = unique_text(as_list(values.get("tags")))
    return {
        "asset_id": normalize_text(values.get("asset_id")) if _usable_identity_value(values.get("asset_id")) else None,
        "hostname": normalize_text(values.get("hostname")) if _usable_identity_value(values.get("hostname")) else None,
        "fqdn": normalize_text(values.get("fqdn")) if _usable_identity_value(values.get("fqdn")) else None,
        "ip_addresses": ips,
        "operating_system": normalize_text(values.get("operating_system")) or None,
        "application": normalize_text(values.get("application")) or None,
        "package": normalize_text(values.get("package")) or None,
        "installed_version": normalize_text(values.get("installed_version")) or None,
        "fixed_version": normalize_text(values.get("fixed_version")) or None,
        "port": parse_port(values.get("port")),
        "protocol": normalize_text(values.get("protocol")) or None,
        "service": normalize_text(values.get("service")) or None,
        "environment": normalize_text(values.get("environment")) or None,
        "network_zone": normalize_text(values.get("network_zone")) or None,
        "isolation": normalize_text(values.get("isolation")).lower() or None,
        "isolated": parse_bool(values.get("isolation")),
        "internet_exposed": parse_bool(values.get("internet_exposed")),
        "asset_criticality": normalize_text(values.get("asset_criticality")).lower() or None,
        "business_criticality": normalize_text(values.get("business_criticality")).lower() or None,
        "data_sensitivity": normalize_text(values.get("data_sensitivity")).lower() or None,
        "owner": normalize_text(values.get("owner")) or None,
        "tags": tags,
        "invalid_ip_observations": invalid_ips,
    }


def normalize_status(value: Any) -> str | None:
    if isinstance(value, (dict, list, tuple, set)):
        return None
    text = normalize_text(value).lower().replace("-", "_").replace(" ", "_")
    if not text:
        return None
    aliases = {
        "fixed": "remediated", "resolved": "remediated", "closed": "remediated",
        "remediated": "remediated", "false_positive": "false_positive", "falsepositive": "false_positive",
        "accepted_risk": "accepted_risk", "risk_accepted": "accepted_risk", "accepted": "accepted_risk",
        "mitigated": "mitigated", "open": "confirmed", "active": "confirmed",
    }
    return aliases.get(text, text)


def make_finding(*, provider: str, source_type: str, source_record_id: str | None,
                 report_sha256: str, pointer: str, record: dict[str, Any],
                 values: dict[str, Any], paths: dict[str, str], mapping_confidence: float,
                 mapping_version: str, warnings: list[str], unmapped_fields: list[str],
                 provider_metadata: dict[str, Any], severity_scale: str | None = None) -> dict[str, Any]:
    title = normalize_text(values.get("title")) or normalize_text(values.get("cve")) or "Imported vulnerability finding"
    finding = empty_finding(
        provider=provider, source_type=source_type, source_record_id=source_record_id,
        report_sha256=report_sha256, record_pointer=pointer, original_record=record, title=title,
    )
    finding["description"] = normalize_text(values.get("description")) or title
    finding["finding_type"] = "vulnerability"
    identifiers, cves, cwes = extract_identifiers(values.get("cve"), values.get("cwe"))
    secondary = provider_metadata.get("source_identifiers") if isinstance(provider_metadata.get("source_identifiers"), dict) else {}
    native_ids = []
    if values.get("vulnerability_identifier") not in (None, ""):
        native_ids.append({"provider": provider, "kind": "vulnerability", "value": normalize_text(values["vulnerability_identifier"])})
    for key, value in secondary.items():
        if key.lower().endswith("vulnerability_id") or "vuln" in key.lower() or "plugin" in key.lower() or "qid" in key.lower():
            native_ids.append({"provider": provider, "kind": "vulnerability", "value": normalize_text(value), "source_path": key})
    finding["vulnerability"]["identifiers"] = unique_text([*identifiers])
    deduped_native: list[dict[str, Any]] = []
    seen_native: set[tuple[str, str, str]] = set()
    for item in native_ids:
        marker = (str(item.get("provider")), str(item.get("kind")), str(item.get("value")))
        if marker not in seen_native and item.get("value"):
            seen_native.add(marker)
            deduped_native.append(item)
    finding["vulnerability"]["provider_identifiers"] = deduped_native
    finding["vulnerability"]["cve"] = cves
    finding["vulnerability"]["cwe"] = cwes
    finding["vulnerability"]["technical_impact"] = normalize_text(values.get("technical_impact")) or None
    if values.get("source_record_id"):
        finding["source_metadata"]["provider_metadata"]["occurrence_identifier"] = json_safe(values["source_record_id"])
    score = parse_cvss(values.get("cvss_score"))
    severity, severity_basis = normalize_severity(
        values.get("severity"), score,
        numeric_is_cvss=values.get("severity") in (None, "") and score is not None,
        provider_scale=severity_scale,
    )
    finding["vulnerability"]["severity_original"] = json_safe(values.get("severity"))
    cvss_values = []
    for item in values.get("cvss_scores") or []:
        if not isinstance(item, dict):
            continue
        item_score = parse_cvss(item.get("score"))
        if item_score is not None:
            cvss_values.append({"version": item.get("version") or "unknown", "score": item_score, "source": item.get("source") or provider})
    if not cvss_values and score is not None:
        cvss_values = [{"version": values.get("cvss_version") or "unknown", "score": score, "source": provider}]
    finding["vulnerability"]["cvss_scores"] = cvss_values
    finding["vulnerability"]["cvss_versions"] = unique_text([item.get("version") for item in cvss_values])
    finding["vulnerability"]["cvss_vectors"] = unique_text([values.get("cvss_vector")])
    put_signal(finding, "severity_normalized", severity, provider, values.get("severity"))
    for key in ("exploit_available", "exploited_in_wild"):
        parsed = parse_bool(values.get(key))
        put_signal(finding, key, parsed, provider, values.get(key))
    finding["vulnerability"]["exploit_maturity"] = normalize_text(values.get("exploit_maturity")) or None
    kev_value = values.get("kev")
    kev_bool = parse_bool(kev_value)
    if isinstance(kev_value, dict):
        # Normalize the semantic boolean after copying source-native fields so
        # a string such as ``{"listed": "false"}`` cannot overwrite the
        # canonical boolean with a truthy string.
        kev = {**json_safe(kev_value), "listed": parse_bool(kev_value.get("listed")) is True, "source": provider}
    else:
        kev = {"listed": bool(kev_bool), "source": provider, "original": json_safe(kev_value)}
    put_signal(finding, "kev", kev, provider, kev_value)
    epss = parse_epss(values.get("epss"))
    if epss is not None:
        put_signal(finding, "epss", epss, provider, values.get("epss"))
    else:
        finding["vulnerability"]["epss"] = None
    vendor_score = parse_float(values.get("vendor_risk_score"))
    if vendor_score is not None:
        put_signal(finding, "vendor_risk_score", vendor_score, provider, values.get("vendor_risk_score"))
    else:
        finding["vulnerability"]["vendor_risk_score"] = None
    native_metadata = values.get("vendor_risk_metadata")
    finding["vulnerability"]["vendor_risk_metadata"] = (
        json_safe(native_metadata) if isinstance(native_metadata, dict)
        else {"value": json_safe(native_metadata)} if native_metadata not in (None, "") else {}
    )
    finding["vulnerability"]["source_signals"]["severity_normalization"] = {"value": severity, "source": provider, "basis": severity_basis, "original": json_safe(values.get("severity"))}
    finding["asset"] = normalize_asset(values)
    finding["state"].update({
        "first_seen": parse_datetime(values.get("first_seen")),
        "last_seen": parse_datetime(values.get("last_seen")),
        "status": normalize_status(values.get("status")),
        "patch_available": parse_bool(values.get("patch_available")),
        "solution": normalize_text(values.get("solution")) or None,
        "remediation_action_id": normalize_text(values.get("remediation_action_id")) or None,
        "remediation_id": normalize_text(values.get("remediation_id")) or None,
        "compensating_controls": normalize_controls(values.get("compensating_controls")),
        "control_evidence": normalize_control_evidence(values.get("compensating_controls")),
        "recurrence": max(1, int(parse_float(values.get("recurrence")) or 1)),
        "prevalence": max(0, int(parse_float(values.get("prevalence")) or 0)) or None,
    })
    provider_metadata = json_safe(provider_metadata)
    if source_record_id:
        provider_metadata.setdefault("occurrence_identifier", source_record_id)
    finding["source_metadata"]["provider_metadata"] = provider_metadata
    asset = finding["asset"]
    finding["identity"]["source_occurrence_id"] = source_record_id
    finding["identity"]["provider_vulnerability_ids"] = json_safe(deduped_native)
    finding["identity"]["target_observations"] = {
        "asset_id": asset.get("asset_id"), "hostname": asset.get("hostname"),
        "fqdn": asset.get("fqdn"), "ip_addresses": list(asset.get("ip_addresses") or []),
    }
    finding["semantic_identity_aliases"] = semantic_identity_aliases(finding)
    semantic_key = durable_semantic_entity_id(finding)
    set_semantic_entity_id(finding, semantic_key)
    finding["source_metadata"]["unmapped_fields"] = sorted(set(unmapped_fields))
    finding["source_metadata"]["mapping_version"] = mapping_version
    finding["evidence"]["mapping_confidence"] = max(0.0, min(1.0, float(mapping_confidence)))
    finding["evidence"]["basis"] = evidence_basis(has_original_record=True, has_field_provenance=bool(paths), source_type=source_type)
    finding["evidence"]["warnings"] = list(dict.fromkeys(warnings))
    if finding["asset"].get("invalid_ip_observations"):
        finding["evidence"]["warnings"].append("invalid IP observations were preserved but excluded from canonical asset identity")
    if values.get("port") not in (None, "") and finding["asset"].get("port") is None:
        finding["evidence"]["warnings"].append("port is outside the valid range 1-65535 or is not an integer")
    if values.get("cvss_score") not in (None, "") and score is None:
        finding["evidence"]["warnings"].append("CVSS score is outside the valid range 0-10 or is not numeric")
    missing = []
    if not cves and not identifiers and not deduped_native:
        missing.append("vulnerability_identifier")
    if not finding["asset"]["asset_id"] and not finding["asset"]["hostname"] and not finding["asset"]["ip_addresses"]:
        missing.append("asset_identity")
    if finding["vulnerability"]["severity_original"] is None:
        missing.append("source_severity")
    finding["evidence"]["missing"] = missing
    for field, value in values.items():
        if value not in (None, "", [], {}):
            add_evidence(finding, field=field, value=value, source=provider,
                         pointer=paths.get(field, f"{pointer}/{field}"), confidence=mapping_confidence)
    for item in finding["evidence"]["items"]:
        item.setdefault("observed_at", finding["state"].get("last_seen") or finding["state"].get("first_seen"))
    finding["evidence"]["items"].append({
        "field": "original_record", "value": "preserved_in_source_metadata",
        "source": provider, "confidence": 1.0, "provenance": pointer,
        "provenance_detail": field_provenance(pointer, record, source_kind=source_type),
    })
    return finding
