# Perm Setup Projects

The solution now contains three focused setup helpers alongside the existing tools.

## PermSetupReinstall

Generates a no-files-kept reinstall plan under `setup_artifacts\reinstall_<timestamp>`.
It does not wipe, delete, repartition, reset, or format disks by itself. The destructive step remains a manual Windows Setup decision after the target disk is verified.
It also writes `hardware_readiness.txt`/`.json` with read-only TPM, Secure Boot, BitLocker, RAID, VMD, Storage Spaces, controller, and disk findings, plus `fresh_pc_readiness.txt`/`.json` with a score, blockers, and next actions for making the machine feel like a new fresh PC.

## PermSetupRealtime

Generates command templates for reversible `DmiUpdater --privacy-session-*` workflows.
Supported modes are `user`, `sandbox`, and `policy`. The helper documents that host hardware identifiers remain visible to host processes and avoids hooks, spoofing, stealth, or bypass behavior.
It includes the same read-only hardware readiness report so runtime plans can record whether the host is on TPM/Secure Boot and RAID/VMD storage. It also emits a Fresh Session readiness score for browser/app profile isolation, host exposure documentation, saved Wi-Fi profiles, sync state, and Windows privacy toggles.

## PermSetupEfiBoot

Reads firmware mode and Secure Boot state, then generates an EFI/UEFI boot privacy plan.
It does not write firmware variables, edit boot entries, clear Secure Boot keys, or touch partitions.
It now includes TPM, BitLocker, RAID/VMD, Storage Spaces, controller, and disk readiness checks for boot and reinstall planning, plus a Fresh Boot readiness score for UEFI, Secure Boot, TPM, BitLocker recovery awareness, and storage-driver blockers.

## Boundary

These setup projects are for privacy-preserving planning, clean reinstall preparation, runtime isolation, and boot-chain hardening. They intentionally do not implement anti-forensics, security-product bypasses, credential theft, unauthorized tracking avoidance, kernel tampering, or hardware identifier forgery.
