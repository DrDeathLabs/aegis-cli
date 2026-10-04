from __future__ import annotations

import re

from typing import Any

from aegis.providers.base import ProviderAdapter
from aegis.providers.common import extract_identifiers, get_indexed_value, normalize_text, norm_key


class GenericJSONAdapter(ProviderAdapter):
    name = "generic_json"
    supported_variants = ("json_object", "json_array", "jsonl", "nested_collections")
    contract_version = "aegis-generic-json-2026"
    _native_identifier = re.compile(r"^(?:[A-Za-z]{2,}[-_:][A-Za-z0-9][A-Za-z0-9_.:-]*|[1-9][0-9]{2,})$")
    mapping_version = "aegis-generic-json-mapping-v1"
    aliases = {
        "source_record_id": ("source_finding_id", "sourceFindingId", "occurrence_id", "occurrenceId", "detection_id", "detectionId", "finding_id", "findingId", "issue_id", "issueId", "record_key", "recordKey", "record_id", "recordId", "id"),
        "vulnerability_identifier": ("vulnerability_id", "vulnerabilityId", "vuln_id", "vulnId"),
        "title": ("finding_title", "issue_title", "finding_name", "title", "name", "summary", "issue"),
        "description": ("details", "detail_text", "description", "detail", "message", "evidence"),
        "cvss_score": ("base_score", "baseScore", "cvss", "cvss_score"),
        "epss": ("epss_probability", "epssProbability", "epss"),
        "solution": ("recommended_fix", "recommendedFix", "solution", "remediation"),
        "remediation_id": ("remediation_id", "remediationId", "recommendation_id", "recommendationId", "fix_id", "fixId", "patch_id", "patchId", "update_id", "updateId"),
    }

    @staticmethod
    def mapping_index(record: dict[str, Any]):
        """Index only direct generic fields.

        The Generic JSON contract permits explicit ``asset`` and
        ``vulnerability`` objects, which are mapped below by name. It does
        not permit arbitrary recursive leaf discovery through metadata,
        audit, history, owner, or other opaque ancestors.
        """
        def supported_direct(value: Any) -> bool:
            if value in (None, "", [], {}):
                return False
            if isinstance(value, (dict, tuple, set)):
                return False
            if isinstance(value, list):
                return all(not isinstance(item, (dict, list, tuple, set)) for item in value)
            return True

        exact = {
            norm_key(key): (value, str(key))
            for key, value in record.items()
            if supported_direct(value)
        }
        return exact, {}

    def map_record(self, record: dict[str, Any]):
        values, paths, warnings, unmapped, confidence, provider_metadata = super().map_record(record)
        field_index = self.mapping_index(record)
        vulnerability = record.get("vulnerability")
        vulnerability_path = "vulnerability" if vulnerability not in (None, "", {}, []) else None
        asset = record.get("asset") if isinstance(record.get("asset"), dict) else {}
        if isinstance(vulnerability, dict):
            if vulnerability.get("id") not in (None, ""):
                nested_id = normalize_text(vulnerability["id"])
                if self._native_identifier.fullmatch(nested_id):
                    values["vulnerability_identifier"], paths["vulnerability_identifier"] = vulnerability["id"], "vulnerability.id"
                else:
                    warnings.append("nested vulnerability.id is not a valid native identifier; preserved as source data")
            if vulnerability.get("cve") not in (None, "") or vulnerability.get("cveId") not in (None, ""):
                cve_key = "cve" if vulnerability.get("cve") not in (None, "") else "cveId"
                values["cve"], paths["cve"] = vulnerability[cve_key], f"vulnerability.{cve_key}"
        if asset:
            for field, keys in (("asset_id", ("id", "asset_id", "assetId")), ("hostname", ("hostname", "host")), ("fqdn", ("fqdn",)), ("ip", ("ip", "ip_address"))):
                key = next((candidate for candidate in keys if asset.get(candidate) not in (None, "")), None)
                if key:
                    values[field], paths[field] = asset[key], f"asset.{key}"
        explicit_source = next((key for key in ("source_finding_id", "sourceFindingId", "occurrence_id", "occurrenceId", "finding_id", "findingId", "record_id", "recordId", "id") if record.get(key) not in (None, "")), None)
        if explicit_source:
            values["source_record_id"], paths["source_record_id"] = record[explicit_source], explicit_source
            provider_metadata.setdefault("source_identifiers", {})[explicit_source] = record[explicit_source]
        vulnerability_id, vulnerability_id_path = get_indexed_value(field_index, ("vulnerability_id", "vulnerabilityId", "vuln_id", "vulnId"))
        if vulnerability_path is not None:
            cves = extract_identifiers(vulnerability)[1]
            if cves:
                values["cve"] = cves
                paths["cve"] = vulnerability_path
                root = vulnerability_path.split(".", 1)[0]
                unmapped = [field for field in unmapped if field != root]
                warnings = [warning for warning in warnings if warning not in {"required vulnerability identity is missing", "title and vulnerability identifier are missing"}]
            elif not values.get("cve"):
                native = normalize_text(vulnerability)
                if native and self._native_identifier.fullmatch(native) and native.lower() not in {"none", "null", "unknown", "n/a", "placeholder", "0", "-"}:
                    values["vulnerability_identifier"] = native
                    paths["vulnerability_identifier"] = vulnerability_path
                else:
                    warnings.append("generic vulnerability field is not a valid CVE or native identifier; preserved as source data")
        if vulnerability_id_path is not None:
            cves = extract_identifiers(vulnerability_id)[1]
            if cves:
                values["cve"] = cves
                paths["cve"] = vulnerability_id_path
                root = vulnerability_id_path.split(".", 1)[0]
                unmapped = [field for field in unmapped if field != root]
                values.pop("vulnerability_identifier", None)
                paths.pop("vulnerability_identifier", None)
            else:
                values["vulnerability_identifier"] = vulnerability_id
                paths["vulnerability_identifier"] = vulnerability_id_path
        return values, paths, warnings, unmapped, confidence, provider_metadata
