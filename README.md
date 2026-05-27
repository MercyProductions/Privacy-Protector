# Privacy Protector

Privacy Protector is a Windows privacy and clean-reinstall workspace for planning a fresh-PC baseline, temporary isolated sessions, and EFI/UEFI boot readiness.

## Projects

`DmiUpdater.sln` contains exactly three setup projects:

- `System Reinstall Version`: permanent clean reinstall planning for a no-files-kept reset.
- `Real Time Version`: reversible runtime privacy session templates using Windows Sandbox, per-session folders, registry baselines, and optional firewall policy.
- `UEFI Version`: EFI/UEFI, Secure Boot, TPM, BitLocker, RAID/VMD, and storage boot-readiness planning.

## Fresh PC Readiness

The setup projects generate:

- `hardware_readiness.txt/json`: TPM, Secure Boot, BitLocker, RAID/VMD, Storage Spaces, controller, and disk findings.
- `fresh_pc_readiness.txt/json`: score, blockers, and next actions for making the OS/profile/network/app state feel like a new fresh PC.
- `device_inventory.txt/json`: read-only inventory for visible internal and peripheral devices, including keyboard, mouse, HID, USB, Bluetooth, display, network, firmware, storage, and system devices where Windows reports them.
- `registry_privacy_baseline.txt`: review guide for staged current-user and optional Administrator registry privacy baselines.
- `registry_privacy_baseline.reg`: current-user privacy settings for advertising ID, tailored experiences, app launch tracking, input personalization, and consumer suggestion surfaces.
- `registry_admin_policy_baseline.reg`: optional machine-policy privacy settings for Administrator review.

The readiness engine is read-only. It does not wipe files, change firmware, edit boot entries, alter TPM state, bypass controls, hide processes, spoof hardware identifiers, or tamper with kernel behavior.

## Build

Open `DmiUpdater.sln` in Visual Studio 2022/2026 with the C++ desktop workload.

Command-line build:

```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" DmiUpdater.sln /p:Configuration=Release /p:Platform=x64 /m
```

Third-party provisioning binaries are intentionally not embedded in this public source tree.

## Boundary

This project focuses on legitimate privacy preparation, clean reinstall workflows, runtime isolation, registry privacy baselines, device visibility reports, and boot-chain readiness. It intentionally excludes anti-forensics, credential theft, security-product bypasses, stealth persistence, kernel tampering, hardware response forgery, and serial/UUID response spoofing.
