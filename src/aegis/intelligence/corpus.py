"""Bounded NVD/EPSS/KEV ingestion and local SQLite vulnerability corpus."""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import math
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, TextIO

from aegis.intelligence.paths import corpus_path, feed_dir

MAX_UNCOMPRESSED_NVD_BYTES = 2 * 1024 * 1024 * 1024
MAX_UNCOMPRESSED_EPSS_BYTES = 1024 * 1024 * 1024
MAX_JSON_RECORD_BYTES = 8 * 1024 * 1024
MAX_CSV_ROW_BYTES = 1024 * 1024
CORPUS_SCHEMA_VERSION = "aegis-public-corpus-v1"


class CorpusError(RuntimeError):
    """A downloaded public corpus could not be safely parsed or built."""


class _JsonStream:
    def __init__(self, handle: TextIO, *, max_total_bytes: int) -> None:
        self.handle = handle
        self.max_total_bytes = max_total_bytes
        self.total_bytes = 0
        self.buffer = ""
        self.position = 0
        self.eof = False
        self.decoder = json.JSONDecoder()

    def _fill(self) -> None:
        if self.eof:
            return
        chunk = self.handle.read(64 * 1024)
        if not chunk:
            self.eof = True
            return
        self.total_bytes += len(chunk.encode("utf-8"))
        if self.total_bytes > self.max_total_bytes:
            raise CorpusError(f"NVD feed exceeds the {self.max_total_bytes}-byte uncompressed limit")
        self.buffer += chunk

    def _compact(self) -> None:
        if self.position > 0:
            self.buffer = self.buffer[self.position:]
            self.position = 0

    def _skip_space(self) -> None:
        while True:
            while self.position < len(self.buffer) and self.buffer[self.position].isspace():
                self.position += 1
            if self.position < len(self.buffer) or self.eof:
                return
            self._compact()
            self._fill()

    def _peek(self) -> str:
        self._skip_space()
        if self.position >= len(self.buffer):
            return ""
        return self.buffer[self.position]

    def _expect(self, token: str) -> None:
        actual = self._peek()
        if actual != token:
            raise CorpusError(f"unexpected NVD JSON structure near character {self.total_bytes}")
        self.position += 1

    def _value(self) -> Any:
        while True:
            self._skip_space()
            try:
                value, end = self.decoder.raw_decode(self.buffer, self.position)
                if end - self.position > MAX_JSON_RECORD_BYTES:
                    raise CorpusError("NVD JSON value exceeds the configured 8 MiB record limit")
                self.position = end
                return value
            except json.JSONDecodeError as exc:
                if self.eof:
                    raise CorpusError(f"malformed NVD JSON near character {self.total_bytes}") from exc
                if len(self.buffer) - self.position > MAX_JSON_RECORD_BYTES:
                    raise CorpusError("NVD JSON value exceeds the configured 8 MiB record limit") from exc
                self._compact()
                self._fill()

    def array(self, key: str) -> Iterator[Any]:
        self._expect("{")
        first = True
        while True:
            token = self._peek()
            if token == "}":
                if first:
                    raise CorpusError(f"NVD feed has no {key!r} array")
                self.position += 1
                return
            if not first:
                self._expect(",")
            name = self._value()
            if not isinstance(name, str):
                raise CorpusError("NVD top-level key is not a string")
            self._expect(":")
            if name == key:
                self._expect("[")
                item_first = True
                while self._peek() != "]":
                    if not item_first:
                        self._expect(",")
                    yield self._value()
                    item_first = False
                self._expect("]")
                # Validate the remainder of the root object as well.
                if self._peek() == ",":
                    self.position += 1
                    while True:
                        tail_key = self._value()
                        if not isinstance(tail_key, str):
                            raise CorpusError("NVD top-level key is not a string")
                        self._expect(":")
                        self._value()
                        separator = self._peek()
                        if separator == "}":
                            self.position += 1
                            break
                        self._expect(",")
                    return
                self._expect("}")
                return
            self._value()
            first = False
            if self._peek() == "}":
                self.position += 1
                raise CorpusError(f"NVD feed has no {key!r} array")


def _stream_nvd(path: Path) -> Iterator[dict[str, Any]]:
    try:
        if path.stat().st_size > 128 * 1024 * 1024:
            raise CorpusError("cached NVD feed exceeds the configured 128 MiB compressed limit")
        with gzip.open(path, "rt", encoding="utf-8", errors="strict", newline="") as handle:
            stream = _JsonStream(handle, max_total_bytes=MAX_UNCOMPRESSED_NVD_BYTES)
            for wrapper in stream.array("vulnerabilities"):
                if not isinstance(wrapper, dict) or not isinstance(wrapper.get("cve"), dict):
                    continue
                yield wrapper["cve"]
    except (OSError, EOFError, UnicodeError) as exc:
        raise CorpusError(f"could not read NVD feed {path.name}: {type(exc).__name__}") from exc


def _metric(cve: dict[str, Any]) -> tuple[float | None, str | None, dict[str, str]]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        entry = values[0]
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        try:
            number = float(score)
        except (TypeError, ValueError):
            number = None
        if number is not None and (not math.isfinite(number) or not 0 <= number <= 10):
            number = None
        vector = str(data.get("vectorString") or "")
        attributes = {
            name: str(data.get(source) or "").upper()
            for name, source in (
                ("attack_vector", "attackVector"), ("attack_complexity", "attackComplexity"),
                ("privileges_required", "privilegesRequired"), ("user_interaction", "userInteraction"),
                ("confidentiality_impact", "confidentialityImpact"),
                ("integrity_impact", "integrityImpact"), ("availability_impact", "availabilityImpact"),
            )
            if data.get(source)
        }
        if vector and not attributes:
            from aegis.intelligence.features import _VECTOR_RE
            attributes = {name.lower(): value for name, value in _VECTOR_RE.findall(vector)}
        return number, vector or None, attributes
    return None, None, {}


def _cwes(cve: dict[str, Any]) -> list[str]:
    found: set[str] = set()
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = str(description.get("value") or "").upper()
            if value.startswith("CWE-") and value[4:].isdigit() and value != "CWE-000":
                found.add(value)
    return sorted(found)


def _read_epss(conn: sqlite3.Connection, path: Path) -> int:
    count = 0
    if path.stat().st_size > 64 * 1024 * 1024:
        raise CorpusError("cached EPSS feed exceeds the configured 64 MiB compressed limit")
    with gzip.open(path, "rb") as handle:
        total_bytes = 0

        def bounded_lines():
            nonlocal total_bytes
            first_line = True
            while line := handle.readline(MAX_CSV_ROW_BYTES + 1):
                total_bytes += len(line)
                if len(line) > MAX_CSV_ROW_BYTES:
                    raise CorpusError("EPSS row exceeds the configured 1 MiB record limit")
                if total_bytes > MAX_UNCOMPRESSED_EPSS_BYTES:
                    raise CorpusError("EPSS feed exceeds the configured 1 GiB uncompressed limit")
                text = line.decode("utf-8-sig" if first_line else "utf-8", errors="strict")
                first_line = False
                yield text

        reader = csv.DictReader(line for line in bounded_lines() if not line.lstrip().startswith("#"))
        if not reader.fieldnames or not {"cve", "epss"}.issubset({name.strip().lower() for name in reader.fieldnames}):
            raise CorpusError("EPSS CSV must contain documented cve and epss columns")
        names = {name.strip().lower(): name for name in reader.fieldnames}
        for row in reader:
            if sum(len(value or "") for value in row.values()) > MAX_CSV_ROW_BYTES:
                raise CorpusError("EPSS row exceeds the configured 1 MiB record limit")
            cve = str(row.get(names["cve"]) or "").strip().upper()
            try:
                score = float(row.get(names["epss"]) or "")
            except ValueError:
                continue
            if not cve.startswith("CVE-") or not math.isfinite(score) or not 0 <= score <= 1:
                continue
            percentile_value = row.get(names.get("percentile", "")) if "percentile" in names else None
            try:
                percentile = float(percentile_value) if percentile_value else None
            except ValueError:
                percentile = None
            if percentile is not None and (not math.isfinite(percentile) or not 0 <= percentile <= 1):
                percentile = None
            conn.execute("INSERT OR REPLACE INTO epss_stage(cve_id, score, percentile) VALUES(?,?,?)", (cve, score, percentile))
            count += 1
    return count


def _read_kev(conn: sqlite3.Connection, path: Path) -> int:
    if path.stat().st_size > 24 * 1024 * 1024:
        raise CorpusError("cached CISA KEV catalog exceeds the configured 24 MiB limit")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusError(f"CISA KEV JSON is invalid: {type(exc).__name__}") from exc
    vulnerabilities = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulnerabilities, list):
        raise CorpusError("CISA KEV feed has no vulnerabilities array")
    for item in vulnerabilities:
        if isinstance(item, dict):
            cve = str(item.get("cveID") or "").strip().upper()
            if cve.startswith("CVE-"):
                conn.execute(
                    "INSERT OR REPLACE INTO kev_stage(cve_id, ransomware, date_added) VALUES(?,?,?)",
                    (cve, int(str(item.get("knownRansomwareCampaignUse") or "").lower() == "known"), str(item.get("dateAdded") or "")),
                )
    return len(vulnerabilities)


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE cve_record (
          cve_id TEXT PRIMARY KEY, published TEXT, last_modified TEXT, cvss_score REAL,
          cvss_vector TEXT, attributes_json TEXT NOT NULL, cwes_json TEXT NOT NULL,
          epss REAL, epss_percentile REAL, kev INTEGER NOT NULL, kev_ransomware INTEGER NOT NULL,
          source_feed TEXT NOT NULL
        );
        CREATE TABLE cwe_profile (
          cwe_id TEXT PRIMARY KEY, cve_count INTEGER NOT NULL, mean_cvss REAL,
          mean_epss REAL, kev_rate REAL, high_epss_rate REAL,
          first_published TEXT, last_published TEXT
        );
        CREATE TABLE feed_manifest (
          file TEXT PRIMARY KEY, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL
        );
        CREATE TABLE corpus_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TEMP TABLE epss_stage (cve_id TEXT PRIMARY KEY, score REAL, percentile REAL);
        CREATE TEMP TABLE kev_stage (cve_id TEXT PRIMARY KEY, ransomware INTEGER, date_added TEXT);
        """
    )


def _manifest_for_path(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return {"file": path.name, "sha256": digest.hexdigest(), "bytes": size}


def build_corpus() -> dict[str, Any]:
    """Build profiles from local feed snapshots and atomically replace SQLite."""
    root = feed_dir()
    nvd_files = sorted(root.glob("nvd-*.json.gz")) if root.exists() else []
    epss_path, kev_path = root / "epss-current.csv.gz", root / "kev.json"
    if not nvd_files or not epss_path.is_file() or not kev_path.is_file():
        raise CorpusError("local feeds are incomplete; run 'aegis model refresh' first")

    target = corpus_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".aegis-corpus-", suffix=".sqlite3", dir=target.parent)
    os.close(fd)
    temp = Path(temp_name)
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(temp)
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")
        _init_schema(conn)
        epss_count = _read_epss(conn, epss_path)
        kev_count = _read_kev(conn, kev_path)
        nvd_count = 0
        for feed in nvd_files:
            for cve in _stream_nvd(feed):
                cve_id = str(cve.get("id") or "").upper()
                if not cve_id.startswith("CVE-"):
                    continue
                score, vector, attributes = _metric(cve)
                cwes = _cwes(cve)
                conn.execute(
                    """INSERT OR REPLACE INTO cve_record(
                       cve_id,published,last_modified,cvss_score,cvss_vector,attributes_json,cwes_json,
                       epss,epss_percentile,kev,kev_ransomware,source_feed)
                       SELECT ?,?,?,?,?,?,?,e.score,e.percentile,CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END,
                       COALESCE(k.ransomware,0),? FROM (SELECT 1) LEFT JOIN epss_stage e ON e.cve_id=?
                       LEFT JOIN kev_stage k ON k.cve_id=?""",
                    (
                        cve_id, str(cve.get("published") or ""), str(cve.get("lastModified") or ""),
                        score, vector, json.dumps(attributes, sort_keys=True, separators=(",", ":")),
                        json.dumps(cwes, sort_keys=True, separators=(",", ":")), feed.name, cve_id, cve_id,
                    ),
                )
                nvd_count += 1
        conn.execute(
            """INSERT INTO cwe_profile(cwe_id,cve_count,mean_cvss,mean_epss,kev_rate,high_epss_rate,first_published,last_published)
               SELECT c.value,COUNT(*),AVG(r.cvss_score),AVG(r.epss),AVG(r.kev),AVG(CASE WHEN r.epss >= ? THEN 1.0 ELSE 0.0 END),
               MIN(r.published),MAX(r.published)
               FROM cve_record r JOIN json_each(r.cwes_json) c
               GROUP BY c.value""",
            (0.1,),
        )
        manifests = [_manifest_for_path(path) for path in [*nvd_files, epss_path, kev_path]]
        conn.executemany("INSERT INTO feed_manifest(file,sha256,bytes) VALUES(?,?,?)", ((row["file"], row["sha256"], row["bytes"]) for row in manifests))
        conn.execute("INSERT INTO corpus_meta(key,value) VALUES(?,?)", ("schema_version", CORPUS_SCHEMA_VERSION))
        conn.execute("INSERT INTO corpus_meta(key,value) VALUES(?,?)", ("built_at", datetime.now(timezone.utc).isoformat()))
        conn.execute("INSERT INTO corpus_meta(key,value) VALUES(?,?)", ("nvd_records_seen", str(nvd_count)))
        conn.execute("INSERT INTO corpus_meta(key,value) VALUES(?,?)", ("epss_records_seen", str(epss_count)))
        conn.execute("INSERT INTO corpus_meta(key,value) VALUES(?,?)", ("kev_records_seen", str(kev_count)))
        conn.execute("INSERT INTO corpus_meta(key,value) VALUES(?,?)", ("feed_manifest", json.dumps(manifests, sort_keys=True, separators=(",", ":"))))
        conn.commit()
        cve_count = conn.execute("SELECT COUNT(*) FROM cve_record").fetchone()[0]
        profile_count = conn.execute("SELECT COUNT(*) FROM cwe_profile").fetchone()[0]
        conn.close()
        conn = None
        os.replace(temp, target)
        if os.name != "nt":
            target.chmod(0o600)
        digest = corpus_digest(target)
        return {
            "status": "complete", "corpus_schema_version": CORPUS_SCHEMA_VERSION,
            "cve_records": cve_count, "nvd_records_seen": nvd_count,
            "epss_records_seen": epss_count, "kev_records_seen": kev_count,
            "cwe_profiles": profile_count, "feed_manifest": manifests,
            "corpus_sha256": digest, "corpus_path": str(target),
        }
    except Exception:
        if conn is not None:
            conn.close()
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def corpus_digest(path: Path | None = None) -> str:
    """Hash canonical rows rather than SQLite's mutable page layout."""
    db = path or corpus_path()
    digest = hashlib.sha256()
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        for row in conn.execute("SELECT * FROM cve_record ORDER BY cve_id"):
            encoded = json.dumps(dict(row), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            digest.update(encoded.encode("utf-8"))
            digest.update(b"\n")
    return digest.hexdigest()


def load_training_rows(path: Path | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    db = path or corpus_path()
    if not db.is_file():
        raise CorpusError("local public vulnerability corpus is missing; run 'aegis model build' or 'refresh'")
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        meta = {row["key"]: row["value"] for row in conn.execute("SELECT key,value FROM corpus_meta")}
        feed_manifest = json.loads(meta.get("feed_manifest", "[]"))
        rows = []
        for row in conn.execute("SELECT * FROM cve_record WHERE epss IS NOT NULL ORDER BY published,cve_id"):
            value = dict(row)
            value["cwes"] = json.loads(value.pop("cwes_json"))
            value["attributes"] = json.loads(value.pop("attributes_json"))
            rows.append(value)
    meta["feed_manifest"] = feed_manifest
    meta["corpus_sha256"] = corpus_digest(db)
    return rows, meta


def profile_for_cwe(cwe: str, path: Path | None = None) -> dict[str, Any] | None:
    db = path or corpus_path()
    if not db.is_file():
        return None
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM cwe_profile WHERE cwe_id=?", (cwe,)).fetchone()
        return dict(row) if row else None
