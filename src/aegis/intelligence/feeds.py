"""Explicit, bounded fetchers for public vulnerability intelligence feeds."""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from aegis.intelligence.paths import feed_dir

NVD_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_NVD_COMPRESSED_BYTES = 128 * 1024 * 1024
MAX_EPSS_COMPRESSED_BYTES = 64 * 1024 * 1024
MAX_KEV_BYTES = 24 * 1024 * 1024
MAX_FEED_AGE_SECONDS = 12 * 60 * 60
USER_AGENT = "Aegis-CLI/0.1.0 public-vulnerability-intelligence"


class FeedError(RuntimeError):
    """A public source could not be fetched or validated."""


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _download(url: str, target: Path, max_bytes: int, *, force: bool) -> dict[str, Any]:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_file() and not force and time.time() - target.stat().st_mtime < MAX_FEED_AGE_SECONDS:
        digest, size = _hash_file(target)
        return {
            "url": url, "retrieved_at": datetime.fromtimestamp(target.stat().st_mtime, timezone.utc).isoformat(),
            "sha256": digest, "bytes": size, "cache_hit": True,
        }

    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/csv, */*"})
    temporary: str | None = None
    digest = hashlib.sha256()
    size = 0
    try:
        with urlopen(request, timeout=90) as response:
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > max_bytes:
                raise FeedError(f"feed exceeds the configured compressed-size limit ({max_bytes} bytes)")
            fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
            with os.fdopen(fd, "wb") as output:
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > max_bytes:
                        raise FeedError(f"feed exceeds the configured compressed-size limit ({max_bytes} bytes)")
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, target)
            temporary = None
            if os.name != "nt":
                target.chmod(0o600)
            return {
                "url": url, "retrieved_at": datetime.now(timezone.utc).isoformat(),
                "sha256": digest.hexdigest(), "bytes": size, "cache_hit": False,
                "etag": response.headers.get("ETag"),
                "last_modified": response.headers.get("Last-Modified"),
            }
    except FeedError:
        raise
    except (OSError, URLError, ValueError) as exc:
        raise FeedError(f"could not retrieve public feed {url}: {type(exc).__name__}: {exc}") from exc
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def refresh_feeds(*, start_year: int, end_year: int, force: bool = False) -> dict[str, dict[str, Any]]:
    """Fetch NVD year feeds, the current EPSS CSV, and the CISA KEV catalog.

    Feed bytes are written to private user-local storage with atomic replacement.
    A failure leaves the previous file for that source intact.
    """
    current_year = datetime.now(timezone.utc).year
    if not (2002 <= start_year <= end_year <= current_year):
        raise ValueError(f"year range must be within 2002..{current_year}")
    if end_year - start_year > 10:
        raise ValueError("one refresh is limited to eleven NVD calendar-year feeds")

    root = feed_dir()
    root.mkdir(parents=True, exist_ok=True)
    results: dict[str, dict[str, Any]] = {}
    for year in range(start_year, end_year + 1):
        url = NVD_URL.format(year=year)
        results[f"nvd_{year}"] = _download(url, root / f"nvd-{year}.json.gz", MAX_NVD_COMPRESSED_BYTES, force=force)
    results["epss"] = _download(EPSS_URL, root / "epss-current.csv.gz", MAX_EPSS_COMPRESSED_BYTES, force=force)
    results["kev"] = _download(KEV_URL, root / "kev.json", MAX_KEV_BYTES, force=force)
    return results


def cached_feed_manifest() -> list[dict[str, Any]]:
    """Return hashes and local metadata for cached feeds, without network I/O."""
    root = feed_dir()
    if not root.exists():
        return []
    rows = []
    for path in sorted(root.iterdir()):
        if path.is_file() and path.suffix in {".gz", ".json"}:
            digest, size = _hash_file(path)
            rows.append({"file": path.name, "sha256": digest, "bytes": size})
    return rows
