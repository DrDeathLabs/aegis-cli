"""Create compact, independently checkable evidence for a large Aegis run.

The tool hashes every artifact without loading it into memory. JSONL artifacts
also receive deterministic record counts and sampled record/line hashes. The
result is intended for the evidence ZIP; it is not a replacement for the
private full run directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

TOOL_VERSION = "aegis-scale-evidence-v2"
CHUNK_BYTES = 4 * 1024 * 1024


def _sha256(path: Path) -> tuple[str, int, int, str]:
    digest = hashlib.sha256()
    size = 0
    chunk_hashes: list[bytes] = []
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_BYTES), b""):
            digest.update(chunk)
            size += len(chunk)
            chunk_hashes.append(hashlib.sha256(chunk).digest())
    # The root is deliberately defined as SHA-256 over the ordered chunk
    # digest stream. It is compact, deterministic, and independently
    # reproducible without loading the artifact into memory.
    merkle = hashlib.sha256(b"".join(chunk_hashes)).hexdigest() if chunk_hashes else hashlib.sha256(b"").hexdigest()
    return digest.hexdigest(), size, len(chunk_hashes), merkle


def _sample_record(value: dict[str, Any]) -> dict[str, Any]:
    vuln = value.get("vulnerability") or {}
    asset = value.get("asset") or {}
    state = value.get("state") or {}
    correlation = value.get("correlation") or {}
    remediation = value.get("remediation") or {}
    return {
        "id": value.get("id"),
        "source": value.get("source"),
        "source_finding_id": value.get("source_finding_id"),
        "semantic_finding_key": value.get("semantic_finding_key") or (value.get("source_metadata") or {}).get("semantic_finding_key"),
        "cve": vuln.get("cve"),
        "provider_identifiers": vuln.get("provider_identifiers"),
        "asset_id": asset.get("asset_id"),
        "hostname": asset.get("hostname"),
        "ip_addresses": asset.get("ip_addresses"),
        "disposition": value.get("disposition"),
        "calculated_priority": value.get("calculated_priority") or (value.get("triage") or {}).get("calculated_priority"),
        "effective_priority": value.get("effective_priority"),
        "active_queue": (value.get("triage") or {}).get("active_queue"),
        "status": state.get("status"),
        "correlation_group_id": correlation.get("group_id"),
        "remediation_action_id": remediation.get("action_id"),
    }


def _jsonl_evidence(path: Path, stride: int) -> tuple[int, list[dict[str, Any]]]:
    count = 0
    first: list[dict[str, Any]] = []
    periodic: list[dict[str, Any]] = []
    last: list[dict[str, Any]] = []
    with path.open("rb") as handle:
        while True:
            offset = handle.tell()
            line = handle.readline()
            if not line:
                break
            if not line.strip():
                continue
            count += 1
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                value = {"_invalid_jsonl": True}
            sample = {
                "record_number": count,
                "byte_offset": offset,
                "line_sha256": hashlib.sha256(line).hexdigest(),
                "record": _sample_record(value) if isinstance(value, dict) else {"type": type(value).__name__},
            }
            if count <= 3:
                first.append(sample)
            if count % stride == 0:
                periodic.append(sample)
            last.append(sample)
            if len(last) > 3:
                last.pop(0)
    samples = first + [item for item in periodic if item not in first and item not in last] + [item for item in last if item not in first]
    return count, samples


def _byte_samples(path: Path) -> list[dict[str, Any]]:
    size = path.stat().st_size
    if not size:
        return []
    offsets = sorted({0, max(0, size // 4), max(0, size // 2), max(0, size - min(size, 1024 * 1024))})
    samples = []
    with path.open("rb") as handle:
        for offset in offsets:
            handle.seek(offset)
            block = handle.read(min(1024 * 1024, size - offset))
            samples.append({"byte_offset": offset, "bytes": len(block), "sha256": hashlib.sha256(block).hexdigest()})
    return samples


def _lineage(run: Path, artifacts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    metadata_path = run / "run.json"
    if not metadata_path.exists():
        return []
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    names = {
        "ingest": (None, "raw_records.jsonl"),
        "normalize": ("raw_records.jsonl", "findings.jsonl"),
        "analyze": ("findings.jsonl", "analyzed.jsonl"),
        "triage": ("analyzed.jsonl", "triaged.jsonl"),
        "correlate": ("triaged.jsonl", "correlated.jsonl"),
        "remediation": ("correlated.jsonl", "remediated.jsonl"),
    }
    results = []
    for stage, item in sorted((metadata.get("lineage") or {}).items()):
        check: dict[str, Any] = {"stage": stage, "input_sha256_matches": None, "output_sha256_matches": None}
        for key, expected in (("input", item.get("input_sha256")), ("output", item.get("output_sha256"))):
            if not expected:
                continue
            index = 0 if key == "input" else 1
            artifact_name = names.get(stage, (None, None))[index]
            actual = artifacts.get(artifact_name, {}).get("sha256") if artifact_name else None
            check[f"{key}_artifact"] = artifact_name
            check[f"{key}_sha256_matches"] = actual == expected
        input_name, output_name = names.get(stage, (None, None))
        input_ids = {sample.get("record", {}).get("id") for sample in (artifacts.get(input_name, {}).get("record_samples") or []) if sample.get("record", {}).get("id")} if input_name else set()
        output_ids = {sample.get("record", {}).get("id") for sample in (artifacts.get(output_name, {}).get("record_samples") or []) if sample.get("record", {}).get("id")} if output_name else set()
        check["sampled_identity_overlap"] = len(input_ids & output_ids) if input_ids and output_ids else None
        results.append(check)
    return results


def build_evidence(run_dir: str | Path, output: str | Path, stride: int = 250_000) -> dict[str, Any]:
    run = Path(run_dir).expanduser().resolve()
    output_path = Path(output).expanduser().resolve()
    artifacts: dict[str, dict[str, Any]] = {}
    for path in sorted(item for item in run.rglob("*") if item.is_file() and item.resolve() != output_path):
        digest, size, chunk_count, merkle_root = _sha256(path)
        entry: dict[str, Any] = {"bytes": size, "sha256": digest, "chunk_bytes": CHUNK_BYTES,
                                 "chunk_count": chunk_count, "chunk_merkle_root": merkle_root}
        if path.suffix.lower() == ".jsonl":
            entry["record_count"], entry["record_samples"] = _jsonl_evidence(path, stride)
        else:
            entry["byte_samples"] = _byte_samples(path)
        artifacts[str(path.relative_to(run))] = entry
    evidence = {
        "schema_version": TOOL_VERSION,
        "tool_version": TOOL_VERSION,
        "run_dir": str(run),
        "sample_stride": stride,
        "artifact_count": len(artifacts),
        "total_bytes": sum(item["bytes"] for item in artifacts.values()),
        "artifacts": artifacts,
        "lineage_checks": _lineage(run, artifacts),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--sample-stride", type=int, default=250_000)
    args = parser.parse_args()
    if args.sample_stride < 1:
        parser.error("--sample-stride must be positive")
    print(json.dumps(build_evidence(args.run_dir, args.output, args.sample_stride), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
