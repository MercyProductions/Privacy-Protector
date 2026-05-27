#include "../common/setup_common.h"
#include "../common/system_probe.h"
#include "../common/fresh_pc_readiness.h"
#include "../common/registry_privacy_baseline.h"

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
        << "PermSetupReinstall - clean reinstall privacy setup\n\n"
        << "Usage:\n"
        << "  PermSetupReinstall.exe [--output <directory>]\n\n"
        << "This helper generates a no-files-kept reinstall plan. It does not wipe,\n"
        << "delete, reset, repartition, or format any disk by itself.\n";
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

bool HasProtectedBitLockerVolume(const SetupProbe::SecurityProbe& security) {
    for (const auto& volume : security.bitLockerVolumes) {
        if (SetupProbe::ContainsCi(volume.protectionStatus, "on") ||
            volume.protectionStatus == "1" ||
            SetupProbe::ContainsCi(volume.protectionStatus, "true")) {
            return true;
        }
    }
    return false;
}

std::string HardwareSummary(const SetupProbe::SecurityProbe& security, const SetupProbe::StorageProbe& storage) {
    std::ostringstream out;
    out << "TPM present=" << security.tpm.present
        << ", TPM ready=" << security.tpm.ready
        << ", Secure Boot=" << security.secureBoot.state
        << ", RAID=" << SetupProbe::YesNo(storage.raidDetected)
        << ", VMD=" << SetupProbe::YesNo(storage.vmdDetected)
        << ", Storage Spaces=" << SetupProbe::YesNo(storage.storageSpacesDetected);
    return out.str();
}

SetupCommon::PlanDocument BuildPlan(const SetupProbe::SecurityProbe& security, const SetupProbe::StorageProbe& storage,
    const SetupProbe::DeviceInventoryProbe& inventory, const FreshPc::FreshReadiness& readiness) {
    SetupCommon::PlanDocument doc;
    doc.name = "Clean Reinstall Privacy Setup";
    doc.purpose = "Prepare a Windows reinstall where no old user files, app state, browser profiles, or account caches are carried forward.";
    doc.boundary = "Auditable planning only. Disk wiping and partition deletion must be performed intentionally in Windows Setup or a trusted recovery environment.";

    doc.steps = {
        {
            "Choose a clean-install path",
            "Boot from trusted Windows installation media in UEFI mode, choose Custom install, and use the no-files-kept path instead of an in-place reset.",
            "manual"
        },
        {
            "Back up only deliberate recovery material",
            "Export license keys, BitLocker recovery keys, firmware/RAID drivers, and account recovery codes to offline storage. Do not copy old browser profiles or user folders if the goal is a clean identity boundary.",
            "required"
        },
        {
            "Record hardware and storage readiness",
            "Read-only probe: " + HardwareSummary(security, storage) + ". Store hardware_readiness.txt with the reinstall records.",
            (storage.raidDetected || storage.vmdDetected || HasProtectedBitLockerVolume(security)) ? "review-required" : "ok"
        },
        {
            "Review Fresh PC readiness score",
            "Current score: " + std::to_string(readiness.percent) + "%. Resolve readiness blockers before treating this install as a new fresh PC.",
            readiness.blockers.empty() ? "ok" : "review-required"
        },
        {
            "Review device and peripheral inventory",
            "Read-only inventory captured " + std::to_string(inventory.devices.size()) + " present Plug and Play devices, including internal, USB, HID, keyboard, mouse, display, network, and system surfaces where Windows reports them.",
            inventory.error.empty() ? "informational" : "review"
        },
        {
            "Disconnect network for first boot",
            "Install Windows offline when possible, then connect only after local privacy settings and updates are staged.",
            "recommended"
        },
        {
            "Delete old OS partitions during setup",
            "Inside Windows Setup, verify the target disk, delete old Windows, recovery, MSR, and EFI partitions only on that target disk, then let Setup recreate partitions.",
            "destructive-manual"
        },
        {
            "Use a fresh local profile first",
            "Create the first user as a fresh local profile where supported, then add Microsoft or work accounts only after privacy settings are reviewed.",
            "recommended"
        },
        {
            "Post-install privacy baseline",
            "Review registry_privacy_baseline.txt, then optionally import registry_privacy_baseline.reg after the new local profile is created.",
            "required"
        },
    };

    doc.warnings = {
        {
            "No undo after partition deletion",
            "A no-files-kept reinstall is intentionally destructive. Verify the disk number, serial, and size before deleting partitions.",
            "critical"
        },
        {
            "Hardware identifiers still exist",
            "A clean reinstall removes old OS state, but it does not change firmware, TPM, disk, GPU, monitor, or network hardware identifiers.",
            "important"
        },
        {
            "Do not import old profile state",
            "Restoring browser profiles, app config folders, or full user directories can reintroduce old identifiers and tokens.",
            "important"
        },
    };
    if (HasProtectedBitLockerVolume(security)) {
        doc.warnings.push_back({
            "BitLocker protection detected",
            "Back up recovery keys offline and suspend protection only if firmware, TPM, Secure Boot, or storage-controller settings must change.",
            "critical"
        });
    }
    if (storage.raidDetected || storage.vmdDetected) {
        doc.warnings.push_back({
            "RAID or VMD storage detected",
            "Download the storage-controller driver before booting Windows Setup, or the installer may not see the target disk.",
            "critical"
        });
    }

    doc.outputs = {
        { "clean_reinstall_plan.txt", "Human-readable reinstall checklist.", "generated" },
        { "clean_reinstall_plan.json", "Machine-readable copy for release records or future UI import.", "generated" },
        { "hardware_readiness.txt", "Read-only TPM, Secure Boot, BitLocker, RAID, VMD, and disk readiness report.", "generated" },
        { "hardware_readiness.json", "Machine-readable hardware readiness report.", "generated" },
        { "fresh_pc_readiness.txt", "Fresh PC readiness score, blockers, and next actions.", "generated" },
        { "fresh_pc_readiness.json", "Machine-readable Fresh PC readiness report.", "generated" },
        { "device_inventory.txt", "Read-only inventory of present internal and peripheral device surfaces.", "generated" },
        { "device_inventory.json", "Machine-readable device inventory report.", "generated" },
        { "registry_privacy_baseline.txt", "Registry privacy settings guide for review before import.", "generated" },
        { "registry_privacy_baseline.reg", "Current-user registry privacy baseline.", "generated" },
        { "registry_admin_policy_baseline.reg", "Optional Administrator machine-policy privacy baseline.", "generated" },
        { "apply_registry_user_baseline.cmd", "Command template to import the current-user registry baseline.", "generated" },
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
    SetupProbe::DeviceInventoryProbe inventory = SetupProbe::ProbeDeviceInventory();
    FreshPc::FreshReadiness readiness = FreshPc::Build(FreshPc::ProjectKind::Perm, security, storage);

    std::filesystem::path outputDir = SetupCommon::ResolveOutputDir(options.outputDir, "reinstall");
    std::filesystem::path textPath;
    std::filesystem::path jsonPath;
    std::string error;

    if (!SetupCommon::WritePlanBundle(outputDir, "clean_reinstall_plan", BuildPlan(security, storage, inventory, readiness), textPath, jsonPath, error)) {
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
        std::cerr << "[!] Failed to write Fresh PC readiness report: " << error << "\n";
        return 1;
    }
    if (!SetupCommon::WriteTextFile(outputDir / "device_inventory.txt",
            SetupProbe::BuildDeviceInventoryText(inventory), error) ||
        !SetupCommon::WriteTextFile(outputDir / "device_inventory.json",
            SetupProbe::BuildDeviceInventoryJson(inventory), error)) {
        std::cerr << "[!] Failed to write device inventory report: " << error << "\n";
        return 1;
    }
    if (!SetupCommon::WriteTextFile(outputDir / "registry_privacy_baseline.txt",
            RegistryPrivacy::BuildGuideText(), error) ||
        !SetupCommon::WriteTextFile(outputDir / "registry_privacy_baseline.reg",
            RegistryPrivacy::BuildUserRegFile(), error) ||
        !SetupCommon::WriteTextFile(outputDir / "registry_admin_policy_baseline.reg",
            RegistryPrivacy::BuildAdminPolicyRegFile(), error) ||
        !SetupCommon::WriteTextFile(outputDir / "apply_registry_user_baseline.cmd",
            RegistryPrivacy::BuildApplyUserCommand(), error)) {
        std::cerr << "[!] Failed to write registry privacy baseline: " << error << "\n";
        return 1;
    }

    SetupCommon::PrintGenerated(outputDir, textPath, jsonPath);
    std::cout << "  Hardware readiness: " << (outputDir / "hardware_readiness.txt").string() << "\n";
    std::cout << "  Fresh PC readiness: " << (outputDir / "fresh_pc_readiness.txt").string()
              << " (" << readiness.percent << "%)\n";
    std::cout << "  Device inventory: " << (outputDir / "device_inventory.txt").string()
              << " (" << inventory.devices.size() << " devices)\n";
    std::cout << "  Registry baseline: " << (outputDir / "registry_privacy_baseline.txt").string() << "\n";
    std::cout << "  RAID detected: " << SetupProbe::YesNo(storage.raidDetected)
              << "  VMD detected: " << SetupProbe::YesNo(storage.vmdDetected)
              << "  TPM present: " << security.tpm.present << "\n";
    std::cout << "\nNext step: review the text plan before booting Windows Setup.\n";
    return 0;
}
