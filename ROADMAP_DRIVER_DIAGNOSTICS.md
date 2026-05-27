# Driver Diagnostics Roadmap

This roadmap keeps the optional driver integration limited to health checks, version checks, and approved lab-only control-plane diagnostics.

## Phase 1 - User-Mode Diagnostics

- Add a no-install `--driver-status` command that reports service, package, and device-open state.
- Add a safe `--driver-version` command that calls `IOCTL_AEGIS_GET_VERSION`.
- Add a safe `--driver-ping <value>` command that calls `IOCTL_AEGIS_PING`.
- Return clear error messages when the driver is not installed, not running, or access is denied.

## Phase 2 - Packaging Checks

- Add driver package checksum reporting.
- Add INF/catalog/sys presence checks for Debug and Release outputs.
- Add a package verification summary command.
- Add documentation for test-signing requirements on lab machines.

## Phase 3 - Lifecycle Helpers

- Add scripts or commands that print install/start/stop/remove instructions without running them.
- Add explicit lab-only guardrails around any future lifecycle command.
- Add service-state polling with timeouts for controlled test environments.

## Phase 4 - Test Harness

- Add a small user-mode diagnostic test executable or app subcommand test.
- Add negative tests for missing driver, access denied, invalid IOCTL buffers, and unsupported IOCTLs.
- Add CI build verification for the user-mode app and driver project.

## Guardrails

- No arbitrary memory access.
- No token, process, callback, handle-table, or object-manager manipulation.
- No stealth, anti-forensics, persistence, or bypass features.
