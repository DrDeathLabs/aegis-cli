from typing import Any

from aegis.models import json_safe, normalize_text
from aegis.providers.base import ProviderAdapter


_DIRECT_ASSET_KEYS = {"assetid", "assetuuid", "deviceid", "deviceuuid", "hostid", "resourceid", "resourceuid"}
_ASSET_CONTAINERS = {"asset", "assetinfo", "device", "deviceinfo", "resource", "resourceinfo"}


def _scalar_identity(value: Any) -> str | None:
    if isinstance(value, (dict, list, tuple, set)):
        return None
    text = normalize_text(value)
    return text or None


def _explicit_asset_id(record: dict[str, Any]) -> tuple[str, str] | None:
    """Resolve only path-aware Tenable asset/device/resource identity."""
    for key, value in record.items():
        if str(key).lower().replace("_", "") in _DIRECT_ASSET_KEYS:
            scalar = _scalar_identity(value)
            if scalar:
                return scalar, str(key)
    for container_key, container in record.items():
        if str(container_key).lower().replace("_", "") not in _ASSET_CONTAINERS:
            continue
        if not isinstance(container, dict):
            continue
        for key, value in container.items():
            compact = str(key).lower().replace("_", "")
            if compact in _DIRECT_ASSET_KEYS or compact in {"id", "uuid", "uid"}:
                scalar = _scalar_identity(value)
                if scalar:
                    return scalar, f"{container_key}.{key}"
    return None


class TenableAdapter(ProviderAdapter):
    name = "tenable"
    supported_variants = ("vulnerability_export_json", "vulnerability_export_csv", "api_vulnerability_record")
    contract_version = "tenable-vulnerability-export-2026"
    severity_scale = None
    aliases = {
        "source_record_id": ("source_finding_id", "sourceFindingId", "occurrence_id", "detection_id", "finding_id", "findingId", "id"),
        "title": ("pluginName", "plugin_name", "name", "title"),
        "cvss_score": ("cvss3BaseScore", "cvss3_base_score", "cvssBaseScore", "cvss_score"),
        "cvss_vector": ("cvss3Vector", "cvss3_vector", "cvss_vector"),
        "vendor_risk_score": ("vpr", "vprScore", "vpr_score"),
        # Bare top-level ``uuid`` can be a finding/occurrence identifier.
        # Resolve documented asset containers and direct asset fields with
        # path-aware logic in map_record instead of leaf fallback.
        "asset_id": (),
        "hostname": ("asset.hostname", "asset.hostName", "hostName", "host_name"),
        "ip": ("asset.ipv4", "asset.ip", "ipv4", "ip"),
        "solution": ("solution", "pluginText", "recommendation"),
        "exploit_available": ("exploitAvailable", "exploit_available", "exploitability"),
    }
    native_fields = ("vendor_risk_score", "cvss_score", "cvss_vector", "exploit_available")

    def map_record(self, record):
        values, paths, warnings, unmapped, confidence, provider_metadata = super().map_record(record)
        values.pop("asset_id", None)
        paths.pop("asset_id", None)
        provider_metadata.pop("asset_id", None)
        definition = record.get("definition") if isinstance(record.get("definition"), dict) else {}
        definition_id = definition.get("id") or record.get("pluginID") or record.get("plugin_id")
        if definition_id not in (None, ""):
            values["vulnerability_identifier"] = definition_id
            paths["vulnerability_identifier"] = "definition.id" if definition.get("id") not in (None, "") else "pluginID"
            provider_metadata["definition_id"] = definition_id
        if definition.get("name") not in (None, ""):
            values["title"] = definition["name"]
            paths["title"] = "definition.name"
        asset = record.get("asset") if isinstance(record.get("asset"), dict) else {}
        fqdns = asset.get("fqdns") if isinstance(asset.get("fqdns"), list) else []
        ipv4s = asset.get("ipv4_addresses") if isinstance(asset.get("ipv4_addresses"), list) else []
        ipv6s = asset.get("ipv6_addresses") if isinstance(asset.get("ipv6_addresses"), list) else []
        operating_systems = asset.get("operating_systems") if isinstance(asset.get("operating_systems"), list) else []
        if asset.get("name") not in (None, ""):
            values["hostname"], paths["hostname"] = asset["name"], "asset.name"
        elif fqdns:
            values["hostname"], paths["hostname"] = fqdns[0], "asset.fqdns[0]"
        if fqdns:
            values["fqdn"], paths["fqdn"] = fqdns[0], "asset.fqdns"
        if ipv4s or ipv6s:
            values["ip"], paths["ip"] = [*ipv4s, *ipv6s], "asset.ipv4_addresses" if ipv4s else "asset.ipv6_addresses"
        if operating_systems:
            values["operating_system"], paths["operating_system"] = "; ".join(map(str, operating_systems)), "asset.operating_systems"
        if asset.get("tenable_id") not in (None, ""):
            provider_metadata["tenable_asset_id"] = json_safe(asset["tenable_id"])
            provider_metadata["documented_paths"] = {"asset.tenable_id": "asset.tenable_id"}
        if record.get("first_observed") not in (None, ""):
            values["first_seen"], paths["first_seen"] = record["first_observed"], "first_observed"
        if record.get("last_seen") not in (None, ""):
            values["last_seen"], paths["last_seen"] = record["last_seen"], "last_seen"
        if record.get("severity") not in (None, ""):
            values["severity"], paths["severity"] = record["severity"], "severity"
        elif definition.get("severity") not in (None, ""):
            values["severity"], paths["severity"] = definition["severity"], "definition.severity"
        if definition.get("cve") not in (None, ""):
            values["cve"], paths["cve"] = definition["cve"], "definition.cve"
        if definition.get("description") not in (None, ""):
            values["description"], paths["description"] = definition["description"], "definition.description"
        if definition.get("solution") not in (None, ""):
            values["solution"], paths["solution"] = definition["solution"], "definition.solution"
        cvss_sections = [("2", definition.get("cvss2")), ("3", definition.get("cvss3")), ("4", definition.get("cvss4"))]
        cvss_scores = []
        for version, section in cvss_sections:
            if not isinstance(section, dict) or section.get("base_score") in (None, ""):
                continue
            cvss_scores.append({"version": version, "score": section.get("base_score"), "source": "tenable"})
            if section.get("base_vector") not in (None, ""):
                provider_metadata[f"cvss{version}_base_vector"] = json_safe(section["base_vector"])
        if cvss_scores:
            values["cvss_scores"], paths["cvss_scores"] = cvss_scores, "definition.cvss3.base_score"
            preferred = next((item for item in reversed(cvss_scores) if item.get("score") is not None), cvss_scores[-1])
            values["cvss_score"], paths["cvss_score"] = preferred["score"], f"definition.cvss{preferred['version']}.base_score"
            values["cvss_version"] = preferred["version"]
        vpr = definition.get("vpr") if isinstance(definition.get("vpr"), dict) else {}
        if vpr.get("score") is not None:
            values["vendor_risk_score"], paths["vendor_risk_score"] = vpr["score"], "definition.vpr.score"
        if vpr:
            provider_metadata["vpr"] = json_safe(vpr)
        epss = definition.get("epss") if isinstance(definition.get("epss"), dict) else {}
        if epss.get("score") is not None:
            values["epss"], paths["epss"] = epss["score"], "definition.epss.score"
        if definition.get("metasploit") not in (None, ""):
            values["exploit_available"], paths["exploit_available"] = definition["metasploit"], "definition.metasploit"
        if definition.get("exploitability_ease") not in (None, ""):
            provider_metadata["exploitability_ease"] = json_safe(definition["exploitability_ease"])
        drivers = vpr.get("drivers_exploit_code_maturity")
        if drivers not in (None, ""):
            values["exploit_maturity"], paths["exploit_maturity"] = drivers, "definition.vpr.drivers_exploit_code_maturity"
        if record.get("id") not in (None, ""):
            values["source_record_id"], paths["source_record_id"] = record["id"], "id"
            provider_metadata.setdefault("source_identifiers", {})["id"] = record["id"]
        if definition.get("id") not in (None, ""):
            provider_metadata.setdefault("source_identifiers", {})["definition.id"] = definition["id"]
        asset_identity = _explicit_asset_id(record)
        if asset_identity is not None:
            value, path = asset_identity
            values["asset_id"] = value
            paths["asset_id"] = path
            provider_metadata["asset_id"] = value
            root = path.split(".", 1)[0]
            unmapped = [field for field in unmapped if field != root]
        documented = {
            "asset.tenable_id", "asset.fqdns", "asset.ipv4_addresses", "asset.ipv6_addresses",
            "asset.operating_systems", "definition.cvss2.base_score", "definition.cvss2.base_vector",
            "definition.cvss3.base_score", "definition.cvss3.base_vector", "definition.cvss4.base_score",
            "definition.cvss4.base_vector", "definition.vpr.score", "definition.vpr.drivers_exploit_code_maturity",
            "definition.epss.score", "definition.metasploit", "definition.exploitability_ease",
            "definition.severity", "source",
        }
        unmapped = [field for field in unmapped if field not in set(paths.values()) and field not in documented]
        return values, paths, warnings, unmapped, confidence, provider_metadata
