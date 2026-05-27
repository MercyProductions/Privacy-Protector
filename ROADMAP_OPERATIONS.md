# Operations Roadmap

This roadmap focuses on making the tool easier to operate, audit, and support in lab or enterprise provisioning workflows.

## Phase 1 - Readiness Diagnostics

- Add a no-admin `--preflight` command for environment checks.
- Report admin state, OS build, native architecture, writable output path, embedded resources, profile count, and driver package status.
- Report whether the optional driver service is installed and whether it is currently running.
- Keep preflight read-only except for a temporary write/delete test in the output directory.

## Phase 2 - Audit Artifacts

- Add JSON reports next to text reports.
- Add stable run identifiers to reports, backups, and history entries.
- Add checksums for generated reports and backups.
- Add a summary command for recent history entries.

## Phase 3 - Release Health

- Add a release manifest listing app version, driver version, build time, and artifact hashes.
- Add a packaging script that collects the app, driver package, docs, and sample profiles.
- Add a command to verify a packaged release before distribution.

## Phase 4 - Driver Diagnostics

- Add a user-mode driver status command.
- Add a safe driver ping command using `IOCTL_AEGIS_PING`.
- Add a safe driver version command using `IOCTL_AEGIS_GET_VERSION`.
- Keep driver diagnostics limited to health and version checks.

## Phase 5 - Supportability

- Add troubleshooting guidance for missing WDK, unsigned drivers, UAC, and blocked writes.
- Add a machine-readable support bundle command that redacts sensitive values.
- Add static analysis and warning policy documentation.
