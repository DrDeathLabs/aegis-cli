# Third-party notices and dependency inventory

Aegis does not vendor or copy third-party Python packages into its source tree. The wheel declares dependencies by the constraints in `pyproject.toml`; installers resolve them separately, and their own license/notice files govern those distributions. This file records the dependency closure observed in the clean Windows/Python 3.11 release-validation environment; exact transitive versions can vary because runtime constraints are intentionally unchanged and are not a lock file.

| Distribution | Role | License reported by installed distribution |
|---|---|---|
| click | Direct runtime dependency | BSD-3-Clause |
| pydantic | Direct runtime dependency | MIT |
| annotated-types | pydantic runtime dependency | MIT |
| pydantic-core | pydantic runtime dependency | MIT |
| typing-extensions | pydantic runtime dependency | PSF-2.0 |
| typing-inspection | pydantic runtime dependency | MIT |

The release evidence includes the exact installed dependency versions, package metadata, and machine-generated SBOM. This inventory is not a substitute for each dependency's complete license text. Build and test tools are not runtime dependencies; their license inventory is retained separately in the release evidence. Any dependency whose installed metadata does not declare a license must be reviewed before publication.
