"""Canonical remediation evidence accessors.

Provider adapters write fixed-version, solution, patch and action evidence into
the canonical finding model.  Consumers must use this module rather than
guessing whether a field belongs under ``asset`` or ``state``.
"""

from __future__ import annotations

from typing import Any


def remediation_evidence(finding: dict[str, Any]) -> dict[str, Any]:
    """Return one typed, read-only projection of remediation evidence."""
    asset = finding.get("asset") or {}
    state = finding.get("state") or {}
    return {
        "solution": state.get("solution"),
        "fixed_version": asset.get("fixed_version") or state.get("fixed_version"),
        "patch_available": state.get("patch_available"),
        "remediation_action_id": state.get("remediation_action_id"),
        "remediation_id": state.get("remediation_id"),
        "package": asset.get("package") or asset.get("application"),
        "installed_version": asset.get("installed_version"),
    }


def remediation_available(finding: dict[str, Any]) -> bool:
    evidence = remediation_evidence(finding)
    return bool(evidence["solution"] or evidence["fixed_version"] or evidence["patch_available"] is not None)
