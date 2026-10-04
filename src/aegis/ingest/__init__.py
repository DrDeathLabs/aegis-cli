"""Ingestion package: lossless import, schema mapping, and normalization."""

from aegis.ingest.pipeline import detect_provider, ingest, normalize, source_files

__all__ = ["detect_provider", "ingest", "normalize", "source_files"]
