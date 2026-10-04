from aegis.models import json_safe
from aegis.providers.base import ProviderAdapter


class DefenderAdapter(ProviderAdapter):
    name = "defender"
    supported_variants = ("machines_vulnerabilities_api", "software_vulnerabilities_api", "export_json")
    contract_version = "microsoft-defender-machines-vulnerabilities-2026"
    aliases = {
        "source_record_id": ("source_finding_id", "sourceFindingId", "occurrence_id", "detection_id", "finding_id", "findingId", "id"),
        "title": ("name", "title", "vulnerabilityName", "vulnerability_name", "productName"),
        "description": ("description", "descriptionUrl", "details"),
        "asset_id": ("machineId", "machine_id", "deviceId", "device_id"),
        "hostname": ("computerDnsName", "computer_dns_name", "computer_name", "machineName", "machine_name", "hostname", "deviceName", "device_name"),
        "ip": ("ipAddress", "ip_address", "machineIp", "machine_ip", "ip"),
        "internet_exposed": ("exposedToInternet", "exposed_to_internet", "internetFacing", "internet_facing", "internet_exposed"),
        "solution": ("recommendedSecurityUpdate", "recommendedFix", "recommendation", "remediation", "solution"),
        "remediation_id": ("recommendationId", "recommendation_id", "remediationId", "remediation_id"),
        "business_criticality": ("deviceValue", "business_criticality", "criticality"),
        "cvss_score": ("cvssV3", "cvss_v3", "cvss3Base", "cvss3_base", "cvss_score"),
        "kev": ("isKev", "is_kev", "kev", "known_exploited"),
        "vendor_risk_metadata": ("exposureLevel", "exposure_level"),
        "vendor_risk_score": ("exposureScore", "exposure_score", "riskScore"),
        "vulnerability_identifier": ("vulnerabilityId", "vulnerability_id"),
    }
    native_fields = ("vendor_risk_score", "internet_exposed", "business_criticality")

    def map_record(self, record):
        values, paths, warnings, unmapped, confidence, provider_metadata = super().map_record(record)
        software_variant = any(key in record for key in ("deviceId", "softwareName", "softwareVendor", "vulnerabilitySeverityLevel"))
        mappings = [
            ("cve", "cveId"), ("vulnerability_identifier", "vulnerabilityId"),
            ("source_record_id", "id"), ("asset_id", "deviceId" if software_variant else "machineId"),
            ("hostname", "deviceName" if software_variant else "computerDnsName"),
            ("severity", "vulnerabilitySeverityLevel"),
            ("package", "softwareName" if software_variant else "productName"),
            ("installed_version", "softwareVersion" if software_variant else "productVersion"),
            ("solution", "recommendedSecurityUpdate"),
            ("patch_available", "securityUpdateAvailable"),
            ("first_seen", "firstSeenTimestamp"), ("last_seen", "lastSeenTimestamp"),
            ("remediation_id", "recommendedSecurityUpdateId" if software_variant else "fixingKbId"),
            ("cvss_score", "cvssV3"),
        ]
        for field, key in mappings:
            if record.get(key) not in (None, ""):
                values[field] = record[key]
                paths[field] = key
                provider_metadata[key] = json_safe(record[key])
        if record.get("eventTimestamp") not in (None, ""):
            provider_metadata["eventTimestamp"] = json_safe(record["eventTimestamp"])
            if not values.get("last_seen"):
                values["last_seen"], paths["last_seen"] = record["eventTimestamp"], "eventTimestamp"
        if record.get("osPlatform") not in (None, "") or record.get("osVersion") not in (None, ""):
            platform = str(record.get("osPlatform") or "").strip()
            version = str(record.get("osVersion") or "").strip()
            values["operating_system"] = " ".join(part for part in (platform, version) if part)
            paths["operating_system"] = "osPlatform" if platform else "osVersion"
        if software_variant and record.get("softwareVendor") not in (None, ""):
            provider_metadata["softwareVendor"] = json_safe(record["softwareVendor"])
        if record.get("recommendationReference") not in (None, ""):
            provider_metadata["recommendationReference"] = json_safe(record["recommendationReference"])
            if not values.get("remediation_id"):
                values["remediation_id"], paths["remediation_id"] = record["recommendationReference"], "recommendationReference"
        if record.get("exploitabilityLevel") not in (None, ""):
            level = str(record["exploitabilityLevel"])
            values["exploit_maturity"], paths["exploit_maturity"] = level, "exploitabilityLevel"
            values["exploit_available"], paths["exploit_available"] = level.lower() not in {"noexploit", "none", "unknown"}, "exploitabilityLevel"
            provider_metadata["exploitabilityLevel"] = json_safe(record["exploitabilityLevel"])
        if record.get("productVendor") not in (None, ""):
            provider_metadata["product_vendor"] = json_safe(record["productVendor"])
            provider_metadata["productVendor"] = json_safe(record["productVendor"])
        if record.get("id") not in (None, ""):
            provider_metadata.setdefault("source_identifiers", {})["id"] = record["id"]
        provider_metadata["variant"] = "software_vulnerabilities_by_machine" if software_variant else "machines_vulnerabilities"
        documented = {
            "eventTimestamp", "osPlatform", "osVersion", "softwareVendor", "productVendor",
            "recommendationReference", "exploitabilityLevel", "deviceName", "deviceId",
            "vulnerabilitySeverityLevel", "recommendedSecurityUpdate", "recommendedSecurityUpdateId",
            "securityUpdateAvailable", "firstSeenTimestamp", "lastSeenTimestamp", "fixingKbId",
        }
        unmapped = [field for field in unmapped if field not in set(paths.values()) and field not in documented]
        return values, paths, warnings, unmapped, confidence, provider_metadata
