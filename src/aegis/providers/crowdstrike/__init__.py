from aegis.models import json_safe
from aegis.providers.base import ProviderAdapter
from aegis.providers.common import parse_bool


class CrowdStrikeAdapter(ProviderAdapter):
    name = "crowdstrike"
    supported_variants = ("spotlight_vulnerabilities_api", "spotlight_export_json", "spotlight_export_csv")
    contract_version = "crowdstrike-spotlight-vulnerabilities-2026"
    aliases = {
        "source_record_id": ("source_finding_id", "sourceFindingId", "occurrence_id", "detection_id", "finding_id", "findingId", "id", "spotlight_id", "spotlightId"),
        "title": ("name", "title", "vulnerability_name"),
        "asset_id": ("aid", "asset_id", "device_id"),
        "hostname": ("hostname", "host_name", "device_name"),
        "ip": ("local_ip", "ip", "ip_address"),
        # These dimensions are intentionally independent.  Do not use the
        # shared business-criticality aliases here because they can select an
        # asset criticality value when both source fields are present.
        "asset_criticality": ("asset_criticality", "assetCriticality", "asset_priority"),
        "business_criticality": ("business_criticality", "businessCriticality", "business_impact", "business_priority", "device_value"),
        "exploit_available": ("exploit_status", "exploit_available", "exploitable"),
        "exploited_in_wild": ("exploited", "exploited_in_wild", "active_exploitation"),
        "solution": ("remediation", "recommendation", "solution"),
        "vendor_risk_metadata": ("falcon_rating", "falconRating"),
        "vendor_risk_score": ("risk_score", "riskScore", "exposure_score"),
        "cve": ("cve.id", "cveId"),
        "vulnerability_identifier": ("vulnerability_id", "vulnerabilityId"),
    }
    native_fields = ("vendor_risk_score", "exploit_available", "exploited_in_wild")

    def map_record(self, record):
        values, paths, warnings, unmapped, confidence, provider_metadata = super().map_record(record)
        host = record.get("host_info") if isinstance(record.get("host_info"), dict) else {}
        cve_raw = record.get("cve")
        cve = cve_raw if isinstance(cve_raw, dict) else {}
        risk = record.get("risk") if isinstance(record.get("risk"), dict) else {}
        exposure = record.get("exposure") if isinstance(record.get("exposure"), dict) else {}
        exploit = record.get("exploit") if isinstance(record.get("exploit"), dict) else {}
        exploit_status = cve.get("exploit_status_to_include") or exploit.get("status") or record.get("exploit_status")
        exploit_exists = None if exploit_status in (None, "") else str(exploit_status).lower() not in {"none", "no_exploit", "no exploit", "unknown", "false"}
        mappings = {
            "source_record_id": (record.get("id"), "id"),
            "asset_id": (record.get("aid") or host.get("aid"), "aid" if record.get("aid") else "host_info.aid"),
            "hostname": (host.get("hostname") or host.get("host_name"), "host_info.hostname"),
            "ip": (host.get("local_ip") or host.get("ip"), "host_info.local_ip"),
            "asset_criticality": (host.get("asset_criticality") or host.get("asset_priority"), "host_info.asset_criticality"),
            "business_criticality": (host.get("business_criticality") or host.get("business_priority"), "host_info.business_criticality"),
            "cve": (cve.get("id") or cve_raw if not isinstance(cve_raw, dict) else cve.get("id"), "cve.id" if isinstance(cve_raw, dict) else "cve"),
            "vendor_risk_score": (risk.get("score"), "risk.score"),
            "kev": (cve.get("is_cisa_kev"), "cve.is_cisa_kev"),
            "exploit_maturity": (cve.get("exploit_status_to_include") or exploit.get("maturity"), "cve.exploit_status_to_include"),
            "exploit_available": (exploit_exists, "cve.exploit_status_to_include"),
            "exploited_in_wild": (exploit.get("exploited"), "exploit.exploited"),
            "internet_exposed": (host.get("internet_exposure"), "host_info.internet_exposure"),
            "operating_system": (host.get("platform_name"), "host_info.platform_name"),
            "solution": (cve.get("remediation") or (record.get("remediation") if isinstance(record.get("remediation"), str) else None), "cve.remediation"),
            "cvss_score": (cve.get("base_score"), "cve.base_score"),
            "severity": (cve.get("severity") or risk.get("severity"), "cve.severity"),
            "last_seen": (record.get("updated_timestamp") or record.get("last_seen"), "updated_timestamp"),
            "status": (record.get("status"), "status"),
        }
        exposure_value = host.get("internet_exposure")
        if exposure_value not in (None, "") and parse_bool(exposure_value) is None:
            mappings["internet_exposed"] = (str(exposure_value).lower() in {"direct", "internet", "internet_exposed", "public", "exposed", "true", "yes"}, "host_info.internet_exposure")
        for field, (value, path) in mappings.items():
            if value not in (None, "", [], {}):
                values[field], paths[field] = value, path
        if cve.get("remediation_level") not in (None, ""):
            metadata = values.get("vendor_risk_metadata") if isinstance(values.get("vendor_risk_metadata"), dict) else {}
            metadata["remediation_level"] = json_safe(cve["remediation_level"])
            values["vendor_risk_metadata"], paths["vendor_risk_metadata"] = metadata, "cve.remediation_level"
        if cve.get("remediation") not in (None, ""):
            provider_metadata["remediation"] = json_safe(cve["remediation"])
        if record.get("remediation") not in (None, ""):
            provider_metadata["remediation_facet"] = json_safe(record["remediation"])
        # The shared mapper sees the nested ``cve`` object before this
        # contract mapper runs.  Replace only diagnostics made obsolete by
        # the documented nested mapping; retain all other warnings.
        if mappings["cve"][0] not in (None, "", [], {}):
            warnings = [warning for warning in warnings if "not a valid CVE" not in warning and "vulnerability identifier is missing" not in warning]
        if cve.get("id") and not values.get("title"):
            values["title"], paths["title"] = cve["id"], "cve.id"
        provider_metadata["documented_context"] = {
            "host_info": host, "cve": cve_raw, "risk": risk,
            "exposure": exposure, "exploit": exploit,
        }
        if record.get("id") not in (None, ""):
            provider_metadata.setdefault("source_identifiers", {})["id"] = record["id"]
        documented = {
            "host_info.aid", "host_info.hostname", "host_info.host_name", "host_info.local_ip",
            "host_info.ip", "host_info.asset_criticality", "host_info.business_criticality",
            "host_info.internet_exposure", "host_info.platform_name", "cve.id", "cve.is_cisa_kev",
            "cve.severity", "cve.base_score", "cve.exploit_status_to_include", "cve.remediation_level",
            "cve.remediation", "risk.score", "risk.severity", "exploit.status", "exploit.maturity",
            "exploit.exploited", "updated_timestamp", "last_seen", "status", "remediation",
        }
        unmapped = [field for field in unmapped if field not in set(paths.values()) and field not in documented]
        return values, paths, warnings, unmapped, confidence, provider_metadata
