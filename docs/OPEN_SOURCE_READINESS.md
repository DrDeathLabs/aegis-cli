# Open-source and source-available readiness

## License status

Aegis v0.1.0 is licensed under Business Source License 1.1 with an Aegis-specific Additional Use Grant and a four-year change to MIT for each version, as specified in [LICENSE](../LICENSE). BSL 1.1 is **not** an open-source license. Aegis may be described as source-available; it must not be presented as OSI-approved open source. See [COMMERCIAL.md](../COMMERCIAL.md) for uses requiring separate permission. No commercial contact address is published.

## Release surface

The public documentation set, issue/PR templates, Dependabot, read-only CI, manually gated release workflow, versioned notes, release verifier, license notices, package artifacts, SBOM, checksums, and release manifest are prepared by the readiness work. Public release assets must not contain private blind corpora, private scorers, hidden answer keys, raw customer vulnerability exports, local run directories, or internal acceptance archives.

## Owner checks before distribution

1. Have an independent reviewer approve the release evidence and BSL 1.1 Additional Use Grant.
2. Confirm the public repository location and visibility; no repository remote URL is embedded in this candidate documentation.
3. Configure protected default branch, required CI, code-owner/reviewer policy, a protected release environment with required reviewers, least-privilege workflow permissions, and private vulnerability reporting where available.
4. Review the exact tag/source/version and the versioned release notes.
5. Verify the attached wheel/sdist/SBOM/SHA256SUMS/release manifest from the exact release candidate.
6. Decide whether historical acceptance/task documents remain accessible in repository history and which refs/tags will be published. Current release archives exclude local `artifacts/` and Trident reference material; this does not rewrite or purge Git history.
7. Only an authorized release owner may create the final tag and dispatch the workflow with typed `PUBLISH`.

This document does not claim that the release has been published, that hosting settings are configured, or that Aegis is production-ready for every environment.
