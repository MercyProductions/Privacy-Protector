# Privacy Protector

Privacy Protector is a Windows privacy and clean-reinstall workspace for planning a fresh-PC baseline, temporary isolated sessions, and EFI/UEFI boot readiness.

## Projects

- `DmiUpdater`: legacy CLI utility plus privacy audit/session commands.
- `PermGuard`: GUI for system inventory, TPM/Secure Boot/BitLocker, Storage/RAID, reinstall prep, privacy cleanup, and reports.
- `PermSetupReinstall`: permanent clean reinstall planning for a no-files-kept reset.
- `PermSetupRealtime`: reversible real-time privacy session templates.
- `PermSetupEfiBoot`: EFI/UEFI, Secure Boot, TPM, and storage boot-readiness planning.
- `AegisIoctlDriver`: optional safe IOCTL driver scaffold for lab control-plane diagnostics only.

## Fresh PC Readiness

The setup projects generate:

- `hardware_readiness.txt/json`: TPM, Secure Boot, BitLocker, RAID/VMD, Storage Spaces, controller, and disk findings.
- `fresh_pc_readiness.txt/json`: score, blockers, and next actions for making the OS/profile/network/app state feel like a new fresh PC.

The readiness engine is read-only. It does not wipe files, change firmware, edit boot entries, alter TPM state, bypass controls, hide processes, spoof hardware identifiers, or tamper with kernel behavior.

## Build

Open `DmiUpdater.sln` in Visual Studio 2022/2026 with the C++ desktop workload. The optional driver project requires the Windows Driver Kit.

Command-line build:

```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" DmiUpdater.sln /p:Configuration=Release /p:Platform=x64 /m
```

Third-party provisioning binaries are intentionally not embedded in this public source tree. Legacy provisioning remains quarantined behind `--legacy-provisioning` and should use locally supplied, trusted tools only.

## Boundary

This project focuses on legitimate privacy preparation, clean reinstall workflows, runtime isolation, and boot-chain readiness. It intentionally excludes anti-forensics, credential theft, security-product bypasses, stealth persistence, kernel tampering, and hardware response forgery.
