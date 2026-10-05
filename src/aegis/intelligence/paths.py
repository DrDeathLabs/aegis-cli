"""Local, user-scoped storage paths for Aegis intelligence data."""

from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    explicit = os.environ.get("AEGIS_DATA_DIR")
    if explicit:
        return Path(explicit).expanduser().resolve()
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(root) / "Aegis" / "intelligence"
    root = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(root) / "aegis" / "intelligence"


def feed_dir() -> Path:
    return data_dir() / "feeds"


def corpus_path() -> Path:
    return data_dir() / "vulnerability-corpus.sqlite3"


def model_path() -> Path:
    return data_dir() / "vulnerability-model.json"
