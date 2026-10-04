# Installation

## Requirements

- Python 3.11 or newer.
- A supported source archive, wheel, or checkout of Aegis v0.1.0.
- Network access to the Python package index, or a prepared wheelhouse, to resolve declared dependencies during installation. Aegis does not vendor dependencies.

This release candidate has been exercised with Python 3.11. Other versions allowed by the `requires-python` metadata are not separately claimed as tested in this readiness package.

## Install a downloaded wheel

Create an isolated environment and install the wheel file you obtained from the project’s release assets. The example filename is versioned; use the exact filename distributed with the release:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .\aegis_vulnerability_triage-0.1.0-py3-none-any.whl
python -m pip check
aegis --version
```

On POSIX shells, activate with `source .venv/bin/activate` and invoke `python -m pip install ./aegis_vulnerability_triage-0.1.0-py3-none-any.whl`.

## Install from a source archive or checkout

From the directory containing `pyproject.toml`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
python -m pip check
aegis --version
```

For development, install `python -m pip install -e ".[dev]"`; see [Development](DEVELOPMENT.md). A repository URL is not embedded in this documentation because no public remote URL is configured in the reviewed checkout.

## Verify installation

`aegis --version` should print the installed package version. `aegis --help` lists only commands available in that version. Do not assume a standalone `aegis replay` command exists; replay operations are `replay-export` and `replay-validate`.

## Uninstall

Deactivate the environment and remove the environment directory using your normal environment-management procedure. Do not delete a shared environment or a run directory containing evidence you need to retain.
