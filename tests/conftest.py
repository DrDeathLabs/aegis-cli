from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture
def local_tmp(request):
    """Use a workspace-local scratch area because this host's global temp ACL is restricted."""
    path = ROOT / "artifacts" / "test-tmp" / request.node.name
    path.mkdir(parents=True, exist_ok=True)
    return path
