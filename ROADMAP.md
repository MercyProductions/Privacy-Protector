# DmiUpdater Roadmap

This roadmap keeps the project focused on legitimate provisioning, lab validation, and repair workflows. Features that weaken auditability, hide activity, or bypass third-party controls are out of scope.

## Phase 1 - Safety and Operability

- Add CLI help and predictable flags for unattended runs.
- Add dry-run mode that prints and records the exact planned actions without changing the machine.
- Add no-reboot mode for automation pipelines.
- Add a safe optional IOCTL driver scaffold for future lab-only control-plane features.
- Add preflight checks for administrator state, Windows version, architecture, resource availability, and writable output paths.
- Add config and profile validation before any write operation.
- Make cleanup actions explicit, auditable, and separated from identity changes.

## Phase 2 - Audit and Recovery

- Write structured JSON reports alongside the current text reports.
- Record a signed or hashed backup manifest for each run.
- Add restore previews before applying backup values.
- Add log rotation and a stable machine-readable history format.
- Add checksum validation for embedded resources before extraction.

## Phase 3 - Provisioning Workflow

- Add named profile selection from the CLI.
- Add commands to list built-in and custom profiles.
- Add profile template generation and validation.
- Add a single "plan" file that can be reviewed, approved, and then applied.
- Add import/export support for approved provisioning bundles.

## Phase 4 - Testability

- Extract pure generators, config parsing, and profile loading into testable modules.
- Add unit tests for serial, UUID, MAC, config, and profile behavior.
- Add a CI build script for Debug and Release x64.
- Add static analysis settings and treat selected warnings as errors.

## Phase 5 - Packaging

- Add version metadata and release notes.
- Add an installer or portable release package.
- Add code-signing support for trusted internal distribution.
- Add documentation for safe lab and enterprise use.
