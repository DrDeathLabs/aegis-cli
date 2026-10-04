from __future__ import annotations

from pathlib import Path

from aegis.analysis.budget import LLMBudget
from aegis.config import AegisSettings
from aegis.security.paths import is_within


def test_path_containment_and_hard_budget():
    root = Path("C:/workspace/aegis")
    assert is_within(root, root / "input.json")
    assert not is_within(root, Path("C:/workspace/aegis-other/input.json"))
    budget = LLMBudget(limit=2)
    assert budget.take() and budget.take() and not budget.take()
    assert budget.used == 2 and budget.exhausted


def test_config_environment_override_is_typed(monkeypatch):
    monkeypatch.setenv("AEGIS_MAX_JSON_NODES", "123")
    monkeypatch.setenv("AEGIS_BACKEND", "mock")
    settings = AegisSettings.from_file()
    assert settings.max_json_nodes == 123
    assert settings.backend == "mock"
    assert "token" not in str(settings.public_dict()).lower()
