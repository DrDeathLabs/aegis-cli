from typing import Any

from aegis.models import normalize_text
from aegis.providers.base import ProviderAdapter


_RAPID7_DIRECT_ASSET_ID_KEYS = {
    "assetid", "deviceid", "resourceid", "assetuuid", "deviceuuid", "resourceuid",
}
_RAPID7_NESTED_ASSET_ID_KEYS = _RAPID7_DIRECT_ASSET_ID_KEYS | {"uuid", "uid"}
_RAPID7_ASSET_CONTAINERS = {"asset", "assetinfo", "device", "deviceinfo", "resource", "resourceinfo"}


def _scalar_identity(value: Any) -> str | None:
    if isinstance(value, (dict, list, tuple, set)):
        return None
    text = normalize_text(value)
    return text or None


def _explicit_asset_id(record: dict[str, Any]) -> tuple[str, str] | None:
    """Return only a provider-defined Rapid7 asset/device/resource identity.

    Rapid7's top-level ``id`` is an occurrence/finding identifier.  It is
    deliberately excluded here; generic leaf-alias lookup would otherwise
    match that value for the historical ``asset.id`` alias.
    """
    for key, value in record.items():
        if str(key).lower().replace("_", "") in _RAPID7_DIRECT_ASSET_ID_KEYS:
            scalar = _scalar_identity(value)
            if scalar:
                return scalar, str(key)
    for container_key, container in record.items():
        if str(container_key).lower().replace("_", "") not in _RAPID7_ASSET_CONTAINERS:
            continue
        if not isinstance(container, dict):
            continue
        for key, value in container.items():
            compact = str(key).lower().replace("_", "")
            if compact == "id" or compact in _RAPID7_NESTED_ASSET_ID_KEYS:
                scalar = _scalar_identity(value)
                if scalar:
                    return scalar, f"{container_key}.{key}"
    return None


class Rapid7Adapter(ProviderAdapter):
    name = "rapid7"
    supported_variants = ("asset_vulnerability_bulk", "insightvm_export_json", "insightvm_export_csv")
    contract_version = "rapid7-insightvm-vulnerability-2026"
    aliases = {
        "source_record_id": ("source_finding_id", "sourceFindingId", "occurrence_id", "detection_id", "finding_id", "findingId", "id"),
        "title": ("vulnerability_title", "vulnerabilityTitle", "title", "name"),
        "vendor_risk_score": ("riskScore", "risk_score", "riskScoreOverride"),
        # Do not use a dotted alias here.  The shared leaf lookup can resolve
        # ``asset.id`` to a top-level occurrence ``id``.  _explicit_asset_id
        # below handles documented target containers with path awareness.
        "asset_id": (),
        "hostname": ("asset.hostname", "hostname", "host_name"),
        "ip": ("asset.ip", "ip", "address"),
        "solution": ("solution", "fix", "remediation"),
        "exploit_available": ("exploits", "exploitAvailable", "exploit_available"),
    }
    native_fields = ("vendor_risk_score", "exploit_available")

    def map_record(self, record):
        values, paths, warnings, unmapped, confidence, provider_metadata = super().map_record(record)
        values.pop("asset_id", None)
        paths.pop("asset_id", None)
        provider_metadata.pop("asset_id", None)
        if record.get("vulnId") not in (None, "") or record.get("vulnerabilityId") not in (None, "") or record.get("vulnerability_id") not in (None, ""):
            value = record.get("vulnId", record.get("vulnerabilityId", record.get("vulnerability_id")))
            values["vulnerability_identifier"] = value
            paths["vulnerability_identifier"] = "vulnId" if record.get("vulnId") not in (None, "") else "vulnerabilityId" if record.get("vulnerabilityId") not in (None, "") else "vulnerability_id"
            provider_metadata["vulnerability_id"] = value
        if record.get("assetId") not in (None, ""):
            values["asset_id"], paths["asset_id"] = record["assetId"], "assetId"
            provider_metadata["asset_id"] = record["assetId"]
        if record.get("id") not in (None, ""):
            values["source_record_id"], paths["source_record_id"] = record["id"], "id"
            provider_metadata.setdefault("source_identifiers", {})["id"] = record["id"]
        asset_identity = _explicit_asset_id(record)
        if asset_identity is not None:
            value, path = asset_identity
            values["asset_id"] = value
            paths["asset_id"] = path
            provider_metadata["asset_id"] = value
            root = path.split(".", 1)[0]
            unmapped = [field for field in unmapped if field != root]
        return values, paths, warnings, unmapped, confidence, provider_metadata
