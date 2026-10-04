"""Bounded filesystem walking adapted from Trident's workspace boundary rules.

Source implementation inspected: ``_reference/trident-cli/backend/trident/workspace.py``.
The Aegis walker is intentionally used for input discovery only; it never
walks the read-only Trident snapshot and never follows symlinks.
"""

from __future__ import annotations

import os
from collections.abc import MutableSequence
from pathlib import Path

_SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "virtualenv", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    "site-packages",
})
_SKIP_PREFIXES = (".venv", ".pytest", ".ruff", ".mypy", ".tox", ".release-", ".wsl-")


def should_skip_dir(name: str) -> bool:
    lowered = name.lower()
    return lowered in _SKIP_DIRS or lowered.startswith(_SKIP_PREFIXES)


def prune_dirs(dirs: MutableSequence[str], *, skip_tests: bool = False) -> None:
    dirs[:] = sorted([
        name for name in dirs
        if not should_skip_dir(name) and not (skip_tests and name.lower() in {"tests", "test"})
    ], key=str.casefold)


def is_within(root: str | os.PathLike[str], candidate: str | os.PathLike[str]) -> bool:
    """Return whether a resolved candidate stays inside a resolved root."""
    root_real = os.path.realpath(os.fspath(root))
    candidate_real = os.path.realpath(os.fspath(candidate))
    try:
        return os.path.commonpath((root_real, candidate_real)) == root_real
    except ValueError:
        return False


def iter_workspace_files(root: str | os.PathLike[str], *, skip_tests: bool = False):
    root_path = Path(root).resolve()
    for current_root, dirs, files in os.walk(root_path, followlinks=False):
        prune_dirs(dirs, skip_tests=skip_tests)
        dirs[:] = [name for name in dirs if not (Path(current_root) / name).is_symlink()]
        for name in sorted(files, key=lambda item: item.casefold()):
            path = Path(current_root) / name
            if path.is_symlink() or not path.is_file() or not is_within(root_path, path):
                continue
            yield path
