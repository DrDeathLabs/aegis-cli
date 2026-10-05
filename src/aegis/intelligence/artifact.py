"""Safe JSON serialization and validation for local ML artifacts."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import tempfile
from pathlib import Path
from typing import Any

ARTIFACT_SCHEMA_VERSION = "aegis-ml-artifact-v1"
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def seal_artifact(payload: dict[str, Any]) -> dict[str, Any]:
    artifact = dict(payload)
    artifact.pop("model_hash", None)
    artifact["schema_version"] = ARTIFACT_SCHEMA_VERSION
    artifact["model_hash"] = hashlib.sha256(canonical_bytes(artifact)).hexdigest()
    return artifact


def validate_artifact(artifact: Any) -> tuple[bool, str]:
    if not isinstance(artifact, dict):
        return False, "model root must be an object"
    if artifact.get("schema_version") != ARTIFACT_SCHEMA_VERSION:
        return False, "unsupported model schema version"
    features = artifact.get("feature_names")
    coefficients = artifact.get("coefficients")
    means = artifact.get("means")
    scales = artifact.get("scales")
    if not isinstance(features, list) or not features or not all(isinstance(name, str) for name in features):
        return False, "invalid model feature schema"
    if not all(isinstance(values, list) and len(values) == len(features) for values in (coefficients, means, scales)):
        return False, "model coefficient dimensions do not match the feature schema"
    if not isinstance(artifact.get("intercept"), (int, float)):
        return False, "invalid model intercept"
    calibration = artifact.get("calibration", {})
    if not isinstance(calibration, dict):
        return False, "invalid calibration metadata"
    try:
        numbers = [float(artifact["intercept"]), *map(float, coefficients), *map(float, means), *map(float, scales)]
        numbers.extend(float(calibration.get(key, default)) for key, default in (("slope", 1.0), ("intercept", 0.0)))
    except (TypeError, ValueError):
        return False, "model contains non-numeric parameters"
    if not all(math.isfinite(value) for value in numbers):
        return False, "model contains non-finite parameters"
    if any(float(value) <= 0 for value in scales):
        return False, "model feature scales must be positive"
    expected_hash = artifact.get("model_hash")
    body = dict(artifact)
    body.pop("model_hash", None)
    actual_hash = hashlib.sha256(canonical_bytes(body)).hexdigest()
    if not isinstance(expected_hash, str) or not hmac.compare_digest(expected_hash, actual_hash):
        return False, "model integrity hash does not match"
    return True, "valid"


def read_artifact(path: Path) -> tuple[dict[str, Any] | None, str]:
    if not path.is_file():
        return None, "model is missing"
    try:
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            return None, "model exceeds the 32 MiB safety limit"
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"model cannot be read ({type(exc).__name__})"
    valid, reason = validate_artifact(artifact)
    return (artifact, reason) if valid else (None, reason)


def write_artifact(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    artifact = seal_artifact(payload)
    valid, reason = validate_artifact(artifact)
    if not valid:
        raise ValueError(f"refusing to write invalid model artifact: {reason}")
    encoded = json.dumps(artifact, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            path.chmod(0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return artifact
