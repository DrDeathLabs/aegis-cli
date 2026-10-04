from __future__ import annotations

from aegis.providers.base import ProviderAdapter


class GenericCSVAdapter(ProviderAdapter):
    name = "generic_csv"
    mapping_version = "aegis-generic-csv-mapping-v1"
    aliases = {
        "source_record_id": ("source_finding_id", "sourceFindingId", "occurrence_id", "occurrenceId", "detection_id", "detectionId", "finding_id", "findingId", "issue_key", "issueKey", "issue_id", "issueId", "record_key", "recordKey", "record_id", "recordId", "id"),
        "vulnerability_identifier": ("vulnerability_id", "vulnerabilityId", "vuln_id", "vulnId"),
        "remediation_id": ("remediation_id", "remediationId", "recommendation_id", "recommendationId", "fix_id", "fixId", "patch_id", "patchId", "update_id", "updateId"),
        "title": ("finding_title", "issue_title", "title", "name", "summary", "issue"),
        "description": ("details", "detail_text", "description", "detail", "message", "evidence"),
    }
