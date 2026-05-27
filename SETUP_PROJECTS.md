# Privacy Protector Setup Projects

The solution contains exactly three focused setup helpers.

## System Reinstall Version

Generates a no-files-kept reinstall plan under `setup_artifacts\reinstall_<timestamp>`.
It does not wipe, delete, repartition, reset, or format disks by itself. The destructive step remains a manual Windows Setup decision after the target disk is verified.
It also writes `hardware_readiness.txt`/`.json` with read-only TPM, Secure Boot, BitLocker, RAID, VMD, Storage Spaces, controller, and disk findings, plus `fresh_pc_readiness.txt`/`.json` with a score, blockers, and next actions for making the machine feel like a new fresh PC.
The project now stages `device_inventory.txt`/`.json` for internal and peripheral visibility review, plus current-user and optional Administrator registry privacy baselines.

## Real Time Version

Generates standalone command templates for reversible runtime privacy workflows.
Supported modes are `user`, `sandbox`, and `policy`. The helper documents that host hardware identifiers remain visible to host processes and avoids hooks, spoofing, stealth, or bypass behavior.
It includes the same read-only hardware readiness report so runtime plans can record whether the host is on TPM/Secure Boot and RAID/VMD storage. It also emits a Fresh Session readiness score for browser/app profile isolation, host exposure documentation, saved Wi-Fi profiles, sync state, and Windows privacy toggles.
It creates a Windows Sandbox `.wsb` template with networking, clipboard, printer, audio input, and video input redirection disabled, per-session folder launch templates, optional firewall policy templates for a specified target, device inventory, and registry privacy baseline artifacts.

## UEFI Version

Reads firmware mode and Secure Boot state, then generates an EFI/UEFI boot privacy plan.
It does not write firmware variables, edit boot entries, clear Secure Boot keys, or touch partitions.
It includes TPM, BitLocker, RAID/VMD, Storage Spaces, controller, and disk readiness checks for boot and reinstall planning, plus a Fresh Boot readiness score for UEFI, Secure Boot, TPM, BitLocker recovery awareness, and storage-driver blockers.
It also records device inventory for boot-critical peripherals and stages the same registry privacy baseline for post-install review.

## Common Artifacts

- `hardware_readiness.txt/json`: TPM, Secure Boot, BitLocker, RAID/VMD, Storage Spaces, controller, and disk readiness.
- `fresh_pc_readiness.txt/json`: Fresh PC, Fresh Session, or Fresh Boot score depending on the project.
- `device_inventory.txt/json`: read-only present-device inventory for internal components, keyboard, mouse, HID, USB, Bluetooth, display, network, firmware, storage, and system devices where Windows reports them.
- `registry_privacy_baseline.txt`: human-readable registry privacy baseline guide.
- `registry_privacy_baseline.reg`: current-user registry privacy settings.
- `registry_admin_policy_baseline.reg`: optional Administrator machine-policy privacy settings.
- `apply_registry_user_baseline.cmd`: imports only the current-user registry baseline after review.

## Boundary

These setup projects are for privacy-preserving planning, clean reinstall preparation, runtime isolation, registry privacy baselines, device visibility reports, and boot-chain hardening. They intentionally do not implement anti-forensics, security-product bypasses, credential theft, unauthorized tracking avoidance, kernel tampering, hardware identifier forgery, or serial/UUID response spoofing.
