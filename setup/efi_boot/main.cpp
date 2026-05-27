#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "../common/setup_common.h"
#include "../common/system_probe.h"
#include "../common/fresh_pc_readiness.h"

#include <windows.h>

#include <filesystem>
#include <iostream>
#include <string>

namespace {

struct Options {
    std::string outputDir;
    bool showHelp = false;
};

void PrintUsage() {
    std::cout
        << "PermSetupEfiBoot - EFI/UEFI boot privacy setup\n\n"
        << "Usage:\n"
        << "  PermSetupEfiBoot.exe [--output <directory>]\n\n"
        << "This helper audits UEFI/Secure Boot posture and writes a boot-time\n"
        << "privacy setup plan. It does not modify firmware variables or boot entries.\n";
}

bool ParseArgs(int argc, char** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h" || arg == "/?") {
            options.showHelp = true;
        } else if (arg == "--output" && i + 1 < argc) {
            options.outputDir = argv[++i];
        } else {
            std::cerr << "[!] Unknown or incomplete option: " << arg << "\n\n";
            PrintUsage();
            return false;
        }
    }
    return true;
}

SetupCommon::PlanDocument BuildPlan(const SetupProbe::SecurityProbe& security, const SetupProbe::StorageProbe& storage,
    const FreshPc::FreshReadiness& readiness) {
    SetupCommon::PlanDocument doc;
    doc.name = "EFI/UEFI Boot Privacy Setup";
    doc.purpose = "Prepare a trusted boot path for clean installs and privacy-sensitive maintenance without changing firmware from this tool.";
    doc.boundary = "Read-only audit and planning only. Firmware settings, boot entries, Secure Boot keys, and partitions must be changed manually in firmware UI or Windows Setup.";

    doc.steps = {
        {
            "Confirm firmware mode",
            "Detected firmware mode: " + security.secureBoot.firmwareType + ". Prefer UEFI mode for modern Windows installs and Secure Boot support.",
            security.secureBoot.firmwareType == "UEFI" ? "ok" : "review"
        },
        {
            "Confirm Secure Boot posture",
            "Detected Secure Boot state: " + security.secureBoot.state + ". Enable Secure Boot for normal use unless a trusted recovery tool requires it off temporarily.",
            security.secureBoot.state == "enabled" ? "ok" : "review"
        },
        {
            "Confirm TPM posture",
            "TPM present=" + security.tpm.present + ", ready=" + security.tpm.ready + ", enabled=" + security.tpm.enabled + ". Back up recovery keys before TPM or Secure Boot changes.",
            (SetupProbe::ContainsCi(security.tpm.present, "true") && SetupProbe::ContainsCi(security.tpm.ready, "true")) ? "ok" : "review"
        },
        {
            "Confirm boot storage driver readiness",
            "RAID=" + SetupProbe::YesNo(storage.raidDetected) + ", VMD=" + SetupProbe::YesNo(storage.vmdDetected) + ", Storage Spaces=" + SetupProbe::YesNo(storage.storageSpacesDetected) + ". Save controller drivers before reinstalling if any are detected.",
            (storage.raidDetected || storage.vmdDetected) ? "review-required" : "ok"
        },
        {
            "Review Fresh Boot readiness score",
            "Current score: " + std::to_string(readiness.percent) + "%. Resolve boot/storage blockers before deleting partitions.",
            readiness.blockers.empty() ? "ok" : "review-required"
        },
        {
            "Boot trusted install media",
            "Use a known-good Windows installer USB, choose the UEFI boot entry for that USB, and avoid unknown recovery images.",
            "required"
        },
        {
            "Keep network disconnected during setup",
            "Stay offline until the new install reaches privacy settings and account decisions.",
            "recommended"
        },
        {
            "Recreate EFI partition through Windows Setup",
            "For a no-files-kept install, delete partitions only on the chosen target disk inside Setup and allow Windows to recreate the EFI System Partition.",
            "destructive-manual"
        },
        {
            "Review boot order after install",
            "After Windows boots successfully, put Windows Boot Manager first and remove stale boot targets only if you can identify them safely.",
            "manual"
        },
        {
            "Enable BitLocker deliberately",
            "After updates and drivers are stable, enable BitLocker with recovery keys stored offline before adding sensitive files.",
            "recommended"
        },
    };

    doc.warnings = {
        {
            "Firmware changes can brick boot",
            "Do not delete boot entries, clear Secure Boot keys, or change storage controller mode unless you have recovery media and know the current values.",
            "critical"
        },
        {
            "EFI boot is not anonymity",
            "UEFI/Secure Boot improves trust in the boot chain, but it does not hide hardware identifiers from the installed OS.",
            "important"
        },
        {
            "Recovery tools must be trusted",
            "A privacy reinstall can be undone by booting untrusted images, importing old browser state, or signing into synced accounts too early.",
            "important"
        },
    };
    if (storage.raidDetected || storage.vmdDetected) {
        doc.warnings.push_back({
            "Storage controller driver required",
            "RAID/VMD boot storage can prevent Windows Setup from seeing disks until the vendor storage driver is loaded.",
            "critical"
        });
    }

    doc.outputs = {
        { "efi_boot_privacy_plan.txt", "Human-readable EFI/UEFI boot setup checklist.", "generated" },
        { "efi_boot_privacy_plan.json", "Machine-readable boot setup checklist.", "generated" },
        { "hardware_readiness.txt", "Read-only TPM, Secure Boot, BitLocker, RAID, VMD, and disk readiness report.", "generated" },
        { "hardware_readiness.json", "Machine-readable hardware readiness report.", "generated" },
        { "fresh_pc_readiness.txt", "Fresh boot readiness score, blockers, and next actions.", "generated" },
        { "fresh_pc_readiness.json", "Machine-readable Fresh boot readiness report.", "generated" },
    };

    return doc;
}

} // namespace

int main(int argc, char** argv) {
    Options options;
    if (!ParseArgs(argc, argv, options)) {
        return 1;
    }
    if (options.showHelp) {
        PrintUsage();
        return 0;
    }

    SetupProbe::SecurityProbe security = SetupProbe::ProbeSecurity();
    SetupProbe::StorageProbe storage = SetupProbe::ProbeStorage();
    FreshPc::FreshReadiness readiness = FreshPc::Build(FreshPc::ProjectKind::EfiBoot, security, storage);

    std::filesystem::path outputDir = SetupCommon::ResolveOutputDir(options.outputDir, "efi_boot");
    std::filesystem::path textPath;
    std::filesystem::path jsonPath;
    std::string error;

    if (!SetupCommon::WritePlanBundle(outputDir, "efi_boot_privacy_plan",
        BuildPlan(security, storage, readiness), textPath, jsonPath, error)) {
        std::cerr << "[!] Failed to write setup plan: " << error << "\n";
        return 1;
    }
    if (!SetupCommon::WriteTextFile(outputDir / "hardware_readiness.txt",
            SetupProbe::BuildReadinessText(security, storage), error) ||
        !SetupCommon::WriteTextFile(outputDir / "hardware_readiness.json",
            SetupProbe::BuildReadinessJson(security, storage), error)) {
        std::cerr << "[!] Failed to write hardware readiness report: " << error << "\n";
        return 1;
    }
    if (!SetupCommon::WriteTextFile(outputDir / "fresh_pc_readiness.txt",
            FreshPc::BuildText(readiness), error) ||
        !SetupCommon::WriteTextFile(outputDir / "fresh_pc_readiness.json",
            FreshPc::BuildJson(readiness), error)) {
        std::cerr << "[!] Failed to write Fresh boot readiness report: " << error << "\n";
        return 1;
    }

    SetupCommon::PrintGenerated(outputDir, textPath, jsonPath);
    std::cout << "  Hardware readiness: " << (outputDir / "hardware_readiness.txt").string() << "\n";
    std::cout << "  Fresh boot readiness: " << (outputDir / "fresh_pc_readiness.txt").string()
              << " (" << readiness.percent << "%)\n";
    std::cout << "  Firmware: " << security.secureBoot.firmwareType << "\n"
              << "  Secure Boot: " << security.secureBoot.state << "\n"
              << "  TPM present: " << security.tpm.present << "\n"
              << "  RAID detected: " << SetupProbe::YesNo(storage.raidDetected) << "\n";
    return 0;
}
