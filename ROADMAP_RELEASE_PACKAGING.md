# Release Packaging Roadmap

This roadmap focuses on producing reviewable, verifiable release artifacts for lab or enterprise distribution.

## Phase 1 - Artifact Integrity

- Add a no-admin command to print SHA-256 hashes for built app and driver artifacts.
- Add a no-admin command to write a release manifest JSON.
- Include artifact presence, size, path, and hash in the manifest.
- Keep manifest generation read-only except for the manifest file itself.

## Phase 2 - Package Assembly

- Add a packaging command that copies approved artifacts into a timestamped release folder.
- Include documentation, sample profiles, app binaries, and driver packages.
- Generate hashes after copying, not before.
- Refuse to package missing required artifacts unless an explicit draft flag is used.

## Phase 3 - Verification

- Add a manifest verification command.
- Verify file presence, size, and SHA-256 hashes.
- Report clear differences between expected and actual artifacts.
- Add optional JSON output for verification results.

## Phase 4 - Versioning

- Add version metadata to the app and driver.
- Include build configuration, WDK version, app version, and driver version in the manifest.
- Add release notes generation from roadmap and history artifacts.

## Guardrails

- Do not sign, install, load, or start drivers as part of manifest generation.
- Do not hide missing artifacts.
- Do not mutate existing release artifacts during verification.
