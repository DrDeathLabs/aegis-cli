"""Real Aegis command-line interface."""

from __future__ import annotations

import json

import click

from aegis import __version__
from aegis.ingest import ingest as ingest_stage, normalize as normalize_stage
from aegis.storage import ensure_run_dir, load_run, mark_stage_failed


def _emit(payload) -> None:
    click.echo(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str))


def _stage_error(run_dir: str, stage: str, error: Exception) -> click.ClickException:
    try:
        mark_stage_failed(run_dir, load_run(ensure_run_dir(run_dir)), stage, error)
    except Exception:
        # The original exception remains the actionable CLI failure even if
        # metadata persistence itself is unavailable.
        pass
    return click.ClickException(f"{stage} failed: {error}")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="aegis")
def main() -> None:
    """Aegis: explainable enterprise vulnerability prioritization."""


@main.command()
@click.argument("inputs", nargs=-1, type=click.Path(exists=True))
@click.option("--run-dir", type=click.Path(file_okay=False), default=None, help="Run artifact directory.")
@click.option("--provider", default="auto", show_default=True, help="Provider adapter or auto-detect.")
@click.option("--selector", "selectors", multiple=True, help="Explicit Generic JSON collection pointer, e.g. /metadata/data/items.")
def ingest(inputs: tuple[str, ...], run_dir: str | None, provider: str, selectors: tuple[str, ...]) -> None:
    """Ingest one or more provider files/directories into lossless raw records."""
    if not inputs:
        raise click.UsageError("at least one input file or directory is required")
    result = ingest_stage(list(inputs), run_dir=run_dir, provider=provider, selectors=selectors)
    _emit(result)
    if result.get("status") == "rejected":
        raise click.ClickException("ingest rejected the input: no records were accepted at the ingest boundary")


@main.command("normalize")
@click.option("--run-dir", required=True, type=click.Path(file_okay=False))
def normalize(run_dir: str) -> None:
    """Normalize raw provider records into the canonical Aegis finding model."""
    try:
        result = normalize_stage(run_dir)
    except Exception as exc:
        raise _stage_error(run_dir, "normalize", exc) from exc
    _emit(result)
    if result.get("status") == "rejected":
        raise click.ClickException("normalize rejected the input: no usable canonical findings were produced")


@main.command("analyze")
@click.option("--run-dir", required=True, type=click.Path(file_okay=False))
@click.option("--backend", type=click.Choice(["offline", "mock"]), default="offline", show_default=True)
def analyze(run_dir: str, backend: str) -> None:
    """Develop evidence observations and challenges without assigning priority."""
    from aegis.analysis.council import analyze as analyze_stage
    try:
        _emit(analyze_stage(run_dir, backend_name=backend))
    except Exception as exc:
        raise _stage_error(run_dir, "analyze", exc) from exc


@main.command("triage")
@click.option("--run-dir", required=True, type=click.Path(file_okay=False))
def triage(run_dir: str) -> None:
    """Assign deterministic P0-P4 priorities from structured evidence."""
    from aegis.triage.engine import triage as triage_stage
    try:
        _emit(triage_stage(run_dir))
    except Exception as exc:
        raise _stage_error(run_dir, "triage", exc) from exc


@main.command("correlate")
@click.option("--run-dir", required=True, type=click.Path(file_okay=False))
@click.option("--baseline-run-dir", type=click.Path(file_okay=False), default=None, help="Optional completed run to compare for recurrence/stale findings.")
def correlate(run_dir: str, baseline_run_dir: str | None) -> None:
    """Correlate duplicates, cross-provider records, recurrence, and conflicts."""
    from aegis.correlation import correlate as correlate_stage
    try:
        _emit(correlate_stage(run_dir, baseline_run_dir=baseline_run_dir))
    except Exception as exc:
        raise _stage_error(run_dir, "correlate", exc) from exc


@main.command("remediation")
@click.option("--run-dir", required=True, type=click.Path(file_okay=False))
def remediation(run_dir: str) -> None:
    """Group findings into deterministic remediation actions."""
    from aegis.remediation import remediation as remediation_stage
    try:
        _emit(remediation_stage(run_dir))
    except Exception as exc:
        raise _stage_error(run_dir, "remediation", exc) from exc


@main.command("report")
@click.option("--run-dir", required=True, type=click.Path(file_okay=False))
@click.option("--format", "format_name", type=click.Choice(["json", "csv", "html", "table"]), default="table", show_default=True)
@click.option("--output", type=click.Path(dir_okay=False), default=None)
@click.option("--include-raw", is_flag=True, help="Include lossless raw records; restricted internal export.")
def report(run_dir: str, format_name: str, output: str | None, include_raw: bool) -> None:
    """Generate a user-facing report with evidence, decisions and actions."""
    from aegis.reporting import report as report_stage
    result = report_stage(run_dir, format_name=format_name, output=output, include_raw=include_raw)
    if format_name == "table" and output is None:
        click.echo(result, nl=False)
    else:
        click.echo(json.dumps({"report": result}, indent=2))


@main.command("export")
@click.argument("format_name", type=click.Choice(["json", "csv", "html", "table"]))
@click.option("--run-dir", required=True, type=click.Path(file_okay=False))
@click.option("--output", type=click.Path(dir_okay=False), default=None)
@click.option("--include-raw", is_flag=True, help="Include lossless raw records; restricted internal export.")
def export(format_name: str, run_dir: str, output: str | None, include_raw: bool) -> None:
    """Export JSON, CSV, HTML or table output from the latest completed stage."""
    from aegis.reporting import report as report_stage
    result = report_stage(run_dir, format_name=format_name, output=output, include_raw=include_raw)
    if format_name == "table" and output is None:
        click.echo(result, nl=False)
    else:
        click.echo(json.dumps({"export": result}, indent=2))


@main.command("findings")
@click.option("--run-dir", required=True, type=click.Path(file_okay=False))
@click.option("--priority", type=click.Choice(["P0", "P1", "P2", "P3", "P4"]))
@click.option("--limit", type=click.IntRange(min=1), default=100, show_default=True)
def findings(run_dir: str, priority: str | None, limit: int) -> None:
    """List finding-level priority, disposition and explanation."""
    from aegis.reporting import iter_findings
    rows = []
    for row in iter_findings(run_dir):
        if priority and row.get("priority") != priority:
            continue
        rows.append(row)
        if len(rows) >= limit:
            break
    _emit(rows)


@main.command("status")
@click.option("--run-dir", required=True, type=click.Path(file_okay=False))
def status(run_dir: str) -> None:
    """Show run stage status and validation boundaries."""
    _emit(load_run(ensure_run_dir(run_dir)))


@main.command("run-all")
@click.argument("inputs", nargs=-1, type=click.Path(exists=True))
@click.option("--run-dir", type=click.Path(file_okay=False), default=None)
@click.option("--provider", default="auto", show_default=True)
@click.option("--selector", "selectors", multiple=True, help="Explicit Generic JSON collection pointer, e.g. /metadata/data/items.")
def run_all(inputs: tuple[str, ...], run_dir: str | None, provider: str, selectors: tuple[str, ...]) -> None:
    """Execute ingest through remediation as one deterministic local run."""
    if not inputs:
        raise click.UsageError("at least one input file or directory is required")
    from aegis.analysis.council import analyze as analyze_stage
    from aegis.correlation import correlate as correlate_stage
    from aegis.remediation import remediation as remediation_stage
    from aegis.triage.engine import triage as triage_stage
    metadata = ingest_stage(list(inputs), run_dir=run_dir, provider=provider, selectors=selectors)
    actual_run = str(metadata["run_dir"])
    if metadata.get("status") == "rejected":
        raise click.ClickException("ingest rejected the input: no records were accepted at the ingest boundary")
    stage_names = ("normalize", "analyze", "triage", "correlate", "remediation")
    for stage_name, stage in zip(stage_names, (normalize_stage, analyze_stage, triage_stage, correlate_stage, remediation_stage)):
        try:
            metadata = stage(actual_run)
        except Exception as exc:
            raise _stage_error(actual_run, stage_name, exc) from exc
        stage_status = (metadata.get("stages") or {}).get(stage_name, {}).get("status")
        if metadata.get("status") == "rejected" or stage_status not in {"complete", "complete_with_warnings"}:
            raise click.ClickException(f"run-all stopped after {stage_name}: terminal status={metadata.get('status')!r}, stage_status={stage_status!r}")
        if stage_name == "normalize" and int(metadata.get("normalized_findings") or 0) == 0:
            raise click.ClickException("run-all stopped after normalize: no usable findings were produced")
    _emit(metadata)


@main.command("replay-export")
@click.option("--findings", "findings_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", required=True, type=click.Path(dir_okay=False))
def replay_export(findings_path: str, output: str) -> None:
    """Export a canonical finding stage as a hash-checked replay artifact."""
    from aegis.replay import export_corpus
    _emit(export_corpus(findings_path, output))


@main.command("replay-validate")
@click.argument("artifact", type=click.Path(exists=True, dir_okay=False))
def replay_validate(artifact: str) -> None:
    """Validate a canonical replay artifact without recomputing priorities."""
    from aegis.replay import validate_corpus
    result = validate_corpus(artifact)
    _emit(result)
    if not result.get("valid"):
        raise click.ClickException("replay artifact failed validation")


if __name__ == "__main__":
    main()
