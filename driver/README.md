# Aegis IOCTL Driver

This folder contains an optional WDM kernel-driver scaffold for future legitimate control-plane work.

Current scope:

- Creates `\\Device\\AegisIoctl`.
- Creates the user-mode link `\\.\AegisIoctl`.
- Restricts the device object to LocalSystem and built-in Administrators.
- Supports only two buffered IOCTLs:
  - `IOCTL_AEGIS_GET_VERSION`
  - `IOCTL_AEGIS_PING`
- Supports transparent policy/session status IOCTLs:
  - `IOCTL_AEGIS_SESSION_BEGIN`
  - `IOCTL_AEGIS_SESSION_END`
  - `IOCTL_AEGIS_GET_POLICY_STATUS`
  - `IOCTL_AEGIS_GET_EVENT_COUNTS`

Intentionally out of scope:

- Arbitrary kernel memory read/write.
- Physical memory access.
- Process, token, callback, handle-table, or object-manager manipulation.
- Storage, network, filesystem, mount manager, SMBIOS, TPM, USB, or monitor stack attachment.
- Completion routine rewriting, inline hooks, dispatch patching, PDB offset parsing, mappers, or hardware identifier forgery.
- Security-product bypasses.
- Stealth, persistence, or anti-forensics behavior.

Build notes:

- Requires the Windows Driver Kit.
- The project is included in `DmiUpdater.sln`, but it is independent from the user-mode provisioning tool.
- Built binaries land under `bin\driver\<Configuration>`.
- Driver installation and loading should be done only on a test-signed lab machine or VM.
