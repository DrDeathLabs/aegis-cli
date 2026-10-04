"""Small, secret-safe configuration layer adapted from Trident config precedence."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def env(name: str, default: Any = None) -> Any:
    """Read an environment override without exposing values in diagnostics."""
    return os.environ.get(name, default)


@dataclass(frozen=True)
class AegisSettings:
    # A million representative JSONL rows are ~435 MB in the acceptance
    # corpus; the bound protects memory while allowing the required scale.
    max_input_bytes: int = 1024 * 1024 * 1024
    # Whole-document JSON/XML parsing is intentionally much smaller than the
    # file safety limit; larger exports must use JSONL or a provider streaming
    # adapter so parser memory remains bounded.
    max_whole_document_bytes: int = 64 * 1024 * 1024
    max_json_depth: int = 64
    max_json_nodes: int = 2_000_000
    max_record_bytes: int = 8 * 1024 * 1024
    max_analysis_workers: int = 8
    max_model_calls: int = 0
    backend: str = "offline"
    model: str = "aegis-offline"
    repair_retries: int = 1
    max_run_disk_bytes: int = 128 * 1024 * 1024 * 1024
    max_stage_peak_rss_mb: int = 8192
    max_run_seconds: int = 6 * 60 * 60

    def __post_init__(self) -> None:
        bounds = {
            "max_input_bytes": (1, 10 * 1024 * 1024 * 1024),
            "max_whole_document_bytes": (1, 512 * 1024 * 1024),
            "max_json_depth": (1, 512), "max_json_nodes": (1, 20_000_000),
            "max_record_bytes": (1, 1024 * 1024 * 1024),
            "max_analysis_workers": (1, 256), "max_model_calls": (0, 10_000_000),
            "repair_retries": (0, 10),
            "max_run_disk_bytes": (1, 2 * 1024 * 1024 * 1024 * 1024),
            "max_stage_peak_rss_mb": (1, 131_072),
            "max_run_seconds": (1, 7 * 24 * 60 * 60),
        }
        for name, (minimum, maximum) in bounds.items():
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
                raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
        if self.backend not in {"offline", "mock"}:
            raise ValueError("backend must be offline or mock")
        if not self.model.strip():
            raise ValueError("model must be non-empty")

    @classmethod
    def from_file(cls, path: str | Path | None = None) -> "AegisSettings":
        values: dict[str, Any] = {}
        if path:
            candidate = Path(path).expanduser().resolve()
            if candidate.is_file():
                with candidate.open("rb") as handle:
                    raw = tomllib.load(handle)
                values = dict(raw.get("aegis", raw))
        converters = {"max_input_bytes": int, "max_whole_document_bytes": int, "max_json_depth": int, "max_json_nodes": int, "max_record_bytes": int,
                      "max_analysis_workers": int, "max_model_calls": int, "repair_retries": int,
                      "max_run_disk_bytes": int, "max_stage_peak_rss_mb": int, "max_run_seconds": int}
        for key, converter in converters.items():
            override = env("AEGIS_" + key.upper())
            if override is not None:
                values[key] = converter(override)
        for key in ("backend", "model"):
            override = env("AEGIS_" + key.upper())
            if override is not None:
                values[key] = str(override)
        return cls(**{key: values[key] for key in cls.__dataclass_fields__ if key in values})

    def public_dict(self) -> dict[str, Any]:
        """Return settings suitable for run metadata (no secrets)."""
        return {key: getattr(self, key) for key in self.__dataclass_fields__}


def locate_config(start: str | Path | None = None) -> Path | None:
    """Use an explicit file, then the current directory, then its parents."""
    if start:
        candidate = Path(start).expanduser().resolve()
        return candidate if candidate.is_file() else None
    current = Path.cwd().resolve()
    for parent in (current, *current.parents):
        candidate = parent / "aegis.toml"
        if candidate.is_file():
            return candidate
    return None


def settings(path: str | Path | None = None) -> AegisSettings:
    return AegisSettings.from_file(path or locate_config())
