"""Generate deterministic JSONL vulnerability corpora at 1k/100k/1m scale."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def record(index: int) -> dict:
    band = index % 10
    severity = "Critical" if band == 0 else "High" if band < 3 else "Medium" if band < 7 else "Low"
    return {
        "id": f"synthetic-{index:08d}", "title": f"Synthetic {severity.lower()} vulnerability {index}",
        "description": "Remote code execution" if band == 0 else "Synthetic vulnerability test record",
        "cve": f"CVE-2099-{(index % 9000) + 1000:04d}", "severity": severity,
        "cvss_score": 9.8 if band == 0 else 7.5 if band < 3 else 5.0 if band < 7 else 2.0,
        "epss": 0.9 if band == 0 else 0.5 if band == 1 else 0.1,
        "asset_id": f"asset-{index % 10000:05d}", "hostname": f"host-{index % 10000:05d}.example",
        "internet_exposed": band in {0, 1}, "business_criticality": "critical" if band == 0 else "medium",
        "exploit_available": band in {0, 1}, "exploited_in_wild": band == 0,
        "solution": "Apply the synthetic vendor update", "custom_field": {"batch": index // 10000},
    }


def generate(count: int, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        for index in range(count):
            handle.write(json.dumps(record(index), separators=(",", ":")) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.count, args.output)
