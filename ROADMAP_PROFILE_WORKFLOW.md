# Profile Workflow Roadmap

This roadmap turns profile handling into a safer, reviewable workflow before any machine-changing operation runs.

## Phase 1 - Profile Utilities

- Add a no-admin command to list built-in and custom OEM profiles.
- Add a no-admin command to generate a valid custom `.profile` template.
- Add a no-admin command to validate custom profile files and explain issues.
- Show profile source and core identity fields in a compact table.

## Phase 2 - Selection and Planning

- Add CLI selection by profile name, not only interactive number.
- Add a `--plan <file>` command that writes the generated values and intended actions without applying them.
- Add an `--apply-plan <file>` command that applies only a previously generated plan.
- Require explicit confirmation when generated values come from an unvalidated custom profile.

## Phase 3 - Validation

- Validate generated serial lengths, UUID format, MAC format, and computer-name rules before writes.
- Validate config files before auto mode.
- Add resource checksums for embedded tooling.
- Add preflight summaries for privileges, writable paths, Windows build, and driver availability.

## Phase 4 - Driver Integration

- Add a user-mode driver client command for `IOCTL_AEGIS_GET_VERSION`.
- Add a user-mode driver client command for `IOCTL_AEGIS_PING`.
- Keep driver IOCTLs limited to health, versioning, and future approved lab-only control-plane operations.

## Phase 5 - Tests

- Move profile parsing into testable code.
- Add unit tests for valid, incomplete, and malformed profile files.
- Add command-line parser tests for no-admin utility commands.
- Add CI steps for app and driver builds.
