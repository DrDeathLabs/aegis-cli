from __future__ import annotations

import json
import importlib.util
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_MANIFEST_SPEC = importlib.util.spec_from_file_location(
    "create_release_manifest", ROOT / "scripts" / "create_release_manifest.py"
)
assert _MANIFEST_SPEC is not None and _MANIFEST_SPEC.loader is not None
_MANIFEST_MODULE = importlib.util.module_from_spec(_MANIFEST_SPEC)
_MANIFEST_SPEC.loader.exec_module(_MANIFEST_MODULE)
ManifestError = _MANIFEST_MODULE.ManifestError
create_manifest = _MANIFEST_MODULE.create_manifest
verify_manifest = _MANIFEST_MODULE.verify_manifest
_SBOM_SPEC = importlib.util.spec_from_file_location(
    "enrich_release_sbom", ROOT / "scripts" / "enrich_release_sbom.py"
)
assert _SBOM_SPEC is not None and _SBOM_SPEC.loader is not None
_SBOM_MODULE = importlib.util.module_from_spec(_SBOM_SPEC)
_SBOM_SPEC.loader.exec_module(_SBOM_MODULE)
SbomError = _SBOM_MODULE.SbomError
enrich_sbom = _SBOM_MODULE.enrich_sbom


def test_release_verifier_success_and_failure_paths() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_release_candidate.py"), "--self-test"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert '"success_path": "passed"' in result.stdout
    for case in (
        "wrong_confirmation",
        "malformed_tag",
        "wrong_sha",
        "tag_source_mismatch",
        "version_mismatch",
        "notes_not_reviewed",
        "missing_notes",
    ):
        assert case in result.stdout


def test_release_manifest_binds_version_and_exact_asset_contract() -> None:
    with tempfile.TemporaryDirectory(prefix="aegis-release-manifest-test-", dir=ROOT) as directory:
        artifacts_dir = Path(directory)
        artifacts = {
            "aegis_vulnerability_triage-0.1.0-py3-none-any.whl": b"wheel",
            "aegis_vulnerability_triage-0.1.0.tar.gz": b"sdist",
            "aegis-v0.1.0-sbom.cdx.json": b"{}",
        }
        for name, content in artifacts.items():
            (artifacts_dir / name).write_bytes(content)

        source_sha = "a" * 40
        manifest = create_manifest(
            artifacts_dir,
            "v0.1.0",
            source_sha,
            "0.1.0",
            ["local:AEGIS_V01_RELEASE_READINESS_RESULT.md"],
        )
        verified = verify_manifest(artifacts_dir, "v0.1.0", source_sha)
        assert verified["verified"] is True
        assert verified["checksummed_file_count"] == 4
        assert manifest["python_version"]
        assert manifest["test_summary_references"] == ["local:AEGIS_V01_RELEASE_READINESS_RESULT.md"]
        sums = (artifacts_dir / "SHA256SUMS").read_text(encoding="ascii").splitlines()
        assert len(sums) == 4
        assert sums[-1].endswith("  release_manifest.json")

        manifest["version"] = "0.2.0"
        (artifacts_dir / "release_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with pytest.raises(ManifestError, match="version"):
            verify_manifest(artifacts_dir, "v0.1.0", source_sha)

        manifest["version"] = "0.1.0"
        manifest["artifacts"][0]["kind"] = "unknown"
        (artifacts_dir / "release_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with pytest.raises(ManifestError, match="asset names or kinds"):
            verify_manifest(artifacts_dir, "v0.1.0", source_sha)


def test_release_sbom_binds_wheel_and_runtime_license_inventory() -> None:
    with tempfile.TemporaryDirectory(prefix="aegis-release-sbom-test-", dir=ROOT) as directory:
        root = Path(directory)
        site = root / "site-packages"
        site.mkdir()
        (site / "aegis_vulnerability_triage-0.1.0.dist-info").mkdir()
        (site / "click-8.2.dist-info").mkdir()
        (site / "aegis_vulnerability_triage-0.1.0.dist-info" / "METADATA").write_text(
            "Metadata-Version: 2.4\nName: aegis-vulnerability-triage\nVersion: 0.1.0\n"
            "License-Expression: BUSL-1.1\nRequires-Dist: click>=8.1\n\n",
            encoding="utf-8",
        )
        (site / "click-8.2.dist-info" / "METADATA").write_text(
            "Metadata-Version: 2.4\nName: click\nVersion: 8.2\n"
            "License-Expression: BSD-3-Clause\n\n",
            encoding="utf-8",
        )
        wheel = root / "aegis_vulnerability_triage-0.1.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(
                "aegis_vulnerability_triage-0.1.0.dist-info/METADATA",
                "Metadata-Version: 2.4\nName: aegis-vulnerability-triage\n"
                "Version: 0.1.0\nLicense-Expression: BUSL-1.1\n"
                "Requires-Dist: click>=8.1\n"
                "Requires-Dist: pytest>=8; extra == \"dev\"\n\n",
            )
        sbom = root / "sbom.json"
        sbom.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "metadata": {},
                    "components": [
                        {"type": "library", "bom-ref": "click-ref", "name": "click", "version": "8.2"}
                    ],
                    "dependencies": [{"ref": "click-ref"}],
                }
            ),
            encoding="utf-8",
        )

        summary = enrich_sbom(sbom, wheel, site, "a" * 40)
        result = json.loads(sbom.read_text(encoding="utf-8"))

        assert summary["product"] == "aegis-vulnerability-triage"
        assert summary["dependency_components"] == 1
        assert result["metadata"]["component"]["licenses"] == [{"license": {"id": "BUSL-1.1"}}]
        assert result["metadata"]["component"]["properties"] == [
            {"name": "aegis:source-sha", "value": "a" * 40}
        ]
        assert result["components"][0]["licenses"] == [{"license": {"id": "BSD-3-Clause"}}]
        assert result["dependencies"][-1]["dependsOn"] == ["click-ref"]


def test_release_sbom_rejects_unaccounted_installed_component() -> None:
    with tempfile.TemporaryDirectory(prefix="aegis-release-sbom-invalid-", dir=ROOT) as directory:
        root = Path(directory)
        site = root / "site-packages"
        site.mkdir()
        (site / "aegis_vulnerability_triage-0.1.0.dist-info").mkdir()
        (site / "aegis_vulnerability_triage-0.1.0.dist-info" / "METADATA").write_text(
            "Metadata-Version: 2.4\nName: aegis-vulnerability-triage\nVersion: 0.1.0\n"
            "License-Expression: BUSL-1.1\n\n",
            encoding="utf-8",
        )
        (site / "click-8.2.dist-info").mkdir()
        (site / "click-8.2.dist-info" / "METADATA").write_text(
            "Metadata-Version: 2.4\nName: click\nVersion: 8.2\n"
            "License-Expression: BSD-3-Clause\n\n",
            encoding="utf-8",
        )
        wheel = root / "aegis_vulnerability_triage-0.1.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(
                "aegis_vulnerability_triage-0.1.0.dist-info/METADATA",
                "Metadata-Version: 2.4\nName: aegis-vulnerability-triage\n"
                "Version: 0.1.0\nLicense-Expression: BUSL-1.1\n\n",
            )
        sbom = root / "sbom.json"
        sbom.write_text(
            json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "metadata": {}, "components": []}),
            encoding="utf-8",
        )
        with pytest.raises(SbomError, match="absent from CycloneDX"):
            enrich_sbom(sbom, wheel, site, "a" * 40)
