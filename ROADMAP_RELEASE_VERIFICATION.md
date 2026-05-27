# Release Verification Roadmap

This roadmap focuses on checking release artifacts after they have been built or copied, without installing or running them.

## Phase 1 - Manifest Verification

- Add a no-admin `--verify-manifest <file>` command.
- Verify artifact presence, file size, and SHA-256 hash.
- Report clear per-artifact pass/fail status.
- Treat missing required artifacts as failures.
- Keep existing absolute-path manifests verifiable for compatibility.

## Phase 2 - Package Verification

- Verify a release folder against a manifest after copy or transfer.
- Support relative paths rooted at the manifest folder.
- Add `--verify-manifest-report <file>` for optional JSON verification results.
- Add a concise summary suitable for CI logs.

Current manifest schema v2 records a portable `path` for verification and a
report-only `sourcePath` for local provenance.

## Phase 3 - Tamper Evidence

- Add manifest self-hash sidecar files.
- Add optional detached signature support using external signing tools.
- Document trusted signing and verification workflows.

## Phase 4 - CI Integration

- Add a build-and-manifest script.
- Add a verify-manifest CI step.
- Fail CI when required artifacts are missing or hashes drift.

## Guardrails

- Verification must be read-only.
- Verification must not install, load, start, stop, or sign drivers.
- Verification must not rewrite manifests or artifacts.
