#!/usr/bin/env python3
"""Bind a pip-audit CycloneDX dependency inventory to the Aegis wheel."""

from __future__ import annotations

import argparse
import email
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any


class SbomError(ValueError):
    """Raised when the dependency SBOM cannot be bound to the release wheel."""


def _canonical(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _license_choice(metadata: email.message.Message) -> list[dict[str, Any]]:
    expression = metadata.get("License-Expression")
    if expression:
        if re.fullmatch(r"[A-Za-z0-9.+-]+", expression.strip()):
            return [{"license": {"id": expression.strip()}}]
        return [{"expression": expression.strip()}]
    license_name = metadata.get("License")
    if license_name and license_name.strip() and license_name.strip().lower() not in {
        "unknown",
        "n/a",
    }:
        return [{"license": {"name": license_name.strip()}}]
    raise SbomError(f"distribution {metadata.get('Name', '<unknown>')} has no license metadata")


def _wheel_metadata(wheel: Path) -> email.message.Message:
    try:
        with zipfile.ZipFile(wheel) as archive:
            names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            if len(names) != 1:
                raise SbomError("wheel must contain exactly one dist-info/METADATA")
            return email.message_from_bytes(archive.read(names[0]))
    except (OSError, zipfile.BadZipFile) as exc:
        raise SbomError(f"cannot read wheel metadata: {exc}") from exc


def _installed_metadata(site_packages: Path) -> dict[str, email.message.Message]:
    result: dict[str, email.message.Message] = {}
    for metadata_path in site_packages.glob("*.dist-info/METADATA"):
        with metadata_path.open("r", encoding="utf-8", errors="replace") as stream:
            metadata = email.message_from_file(stream)
        name = metadata.get("Name")
        if name:
            key = _canonical(name)
            if key in result:
                raise SbomError(f"duplicate installed distribution metadata: {name}")
            result[key] = metadata
    if not result:
        raise SbomError(f"no installed distribution metadata found under {site_packages}")
    return result


def enrich_sbom(sbom_path: Path, wheel_path: Path, site_packages: Path, source_sha: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise SbomError("source SHA must be a full lowercase 40-character Git SHA")
    try:
        bom = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SbomError(f"cannot read CycloneDX JSON: {exc}") from exc
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") not in {"1.4", "1.5", "1.6"}:
        raise SbomError("input must be a supported CycloneDX JSON BOM")

    product = _wheel_metadata(wheel_path)
    product_name = product.get("Name")
    product_version = product.get("Version")
    if not product_name or not product_version:
        raise SbomError("wheel metadata is missing project name or version")
    product_key = _canonical(product_name)
    installed = _installed_metadata(site_packages)
    if product_key not in installed:
        raise SbomError("the clean wheel environment does not contain the release project")
    installed_product = installed[product_key]
    if installed_product.get("Version") != product_version:
        raise SbomError("wheel version does not match the clean installed environment")

    components = bom.get("components")
    if not isinstance(components, list):
        raise SbomError("CycloneDX BOM components must be a list")
    by_name: dict[str, dict[str, Any]] = {}
    for component in components:
        name = component.get("name")
        if not isinstance(name, str):
            raise SbomError("CycloneDX component is missing its name")
        key = _canonical(name)
        if key in by_name:
            raise SbomError(f"duplicate CycloneDX component: {name}")
        by_name[key] = component

    missing = sorted(set(by_name) - set(installed))
    if missing:
        raise SbomError(f"CycloneDX components are not present in the clean environment: {missing}")
    unexpected = sorted(set(installed) - set(by_name) - {product_key})
    if unexpected:
        raise SbomError(f"clean environment distributions are absent from CycloneDX: {unexpected}")

    for key, component in by_name.items():
        metadata = installed[key]
        if component.get("version") != metadata.get("Version"):
            raise SbomError(f"version mismatch for CycloneDX component {component['name']}")
        component["purl"] = f"pkg:pypi/{_canonical(metadata['Name'])}@{metadata['Version']}"
        component["licenses"] = _license_choice(metadata)

    product_ref = f"pkg:pypi/{_canonical(product_name)}@{product_version}"
    product_component: dict[str, Any] = {
        "type": "application",
        "bom-ref": product_ref,
        "name": product_name,
        "version": product_version,
        "purl": product_ref,
        "licenses": _license_choice(product),
        "hashes": [{"alg": "SHA-256", "content": _sha256(wheel_path)}],
        "properties": [{"name": "aegis:source-sha", "value": source_sha}],
    }
    metadata_section = bom.setdefault("metadata", {})
    if not isinstance(metadata_section, dict):
        raise SbomError("CycloneDX metadata must be an object")
    metadata_section["component"] = product_component

    direct_dependency_refs: list[str] = []
    for requirement in product.get_all("Requires-Dist", []):
        _, marker_separator, marker = requirement.partition(";")
        # The clean release environment installs the wheel without extras.
        # Optional-dependency requirements (for example the project's dev
        # extra) therefore are metadata, not members of this release SBOM.
        if marker_separator and re.search(r"\bextra\s*(?:==|!=)", marker):
            continue
        match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
        if not match:
            raise SbomError(f"cannot parse wheel runtime requirement: {requirement}")
        dependency_key = _canonical(match.group(1))
        if dependency_key not in by_name:
            raise SbomError(f"wheel runtime dependency missing from CycloneDX: {match.group(1)}")
        direct_dependency_refs.append(str(by_name[dependency_key].get("bom-ref", by_name[dependency_key]["purl"])))

    dependencies = bom.setdefault("dependencies", [])
    if not isinstance(dependencies, list):
        raise SbomError("CycloneDX dependencies must be a list")
    dependencies = [item for item in dependencies if item.get("ref") != product_ref]
    dependencies.append({"ref": product_ref, "dependsOn": sorted(set(direct_dependency_refs))})
    bom["dependencies"] = dependencies
    sbom_path.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "bomFormat": bom["bomFormat"],
        "specVersion": bom["specVersion"],
        "product": product_name,
        "version": product_version,
        "dependency_components": len(components),
        "direct_runtime_dependencies": len(set(direct_dependency_refs)),
        "source_sha": source_sha,
        "wheel_sha256": product_component["hashes"][0]["content"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--site-packages", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(enrich_sbom(args.sbom, args.wheel, args.site_packages, args.source_sha), indent=2))
    except (OSError, SbomError) as exc:
        print(f"release SBOM error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
