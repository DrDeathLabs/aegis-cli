# CI/CD and release process

## Continuous integration

The CI workflow runs on pushes to the default branch and pull requests with read-only repository permissions. It installs development dependencies, runs Ruff, `compileall`, pytest, dependency audit, builds wheel and sdist, runs Twine checks, installs the wheel into a fresh environment, verifies `aegis --version`/help, and executes the provider fixture path plus report/replay smoke. Untrusted pull requests do not receive publication credentials.

Dependabot checks Python dependencies and GitHub Actions weekly. Workflow actions are pinned to full commit SHAs; Dependabot can propose pin updates for review.

## Manually gated release workflow

The release workflow is only `workflow_dispatch`. It requires all of:

- exact `release_tag` (for v0.1.0, `v0.1.0`);
- exact 40-character `source_sha`;
- typed confirmation exactly `PUBLISH`;
- tag commit, checked-out HEAD, supplied source SHA, and project version agreement;
- versioned release notes present and reviewed by the release owner;
- wheel/sdist build and Twine validation;
- clean wheel and sdist installation, `pip check`, CLI smoke, and fixture E2E;
- CycloneDX SBOM, SHA256SUMS, and release manifest.

Only the final publish job receives `contents: write`; build/validation jobs stay read-only. The manual dispatch is a safeguard, not a substitute for protected branches, required reviewers, environment protection, release-owner review, or secret management. Configure and inspect those GitHub repository settings before publication.

This readiness task creates the automation but does not run its publish path, create a public v0.1.0 tag, create a GitHub Release, or publish to a package index. The release verifier’s success path is tested in an isolated local self-test without a real release tag.
