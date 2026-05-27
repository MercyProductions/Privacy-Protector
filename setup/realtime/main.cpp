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
    std::string mode = "sandbox";
    std::string target;
    bool showHelp = false;
};

void PrintUsage() {
    std::cout
        << "PermSetupRealtime - real-time privacy session setup\n\n"
        << "Usage:\n"
        << "  PermSetupRealtime.exe [--mode user|sandbox|policy] [--target <path>] [--output <directory>]\n\n"
        << "This helper writes launch plans and command templates for reversible\n"
        << "privacy sessions. It does not install hooks, hide processes, spoof\n"
        << "hardware responses, or bypass third-party controls.\n";
}

bool IsValidMode(const std::string& mode) {
    return mode == "user" || mode == "sandbox" || mode == "policy";
}

bool ParseArgs(int argc, char** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h" || arg == "/?") {
            options.showHelp = true;
        } else if (arg == "--mode" && i + 1 < argc) {
            options.mode = argv[++i];
        } else if (arg == "--target" && i + 1 < argc) {
            options.target = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            options.outputDir = argv[++i];
        } else {
            std::cerr << "[!] Unknown or incomplete option: " << arg << "\n\n";
            PrintUsage();
            return false;
        }
    }

    if (!IsValidMode(options.mode)) {
        std::cerr << "[!] Invalid mode: " << options.mode << "\n";
        return false;
    }

    return true;
}

SetupCommon::PlanDocument BuildPlan(const Options& options, const SetupProbe::SecurityProbe& security,
    const SetupProbe::StorageProbe& storage, const SetupProbe::DeviceInventoryProbe& inventory,
    const FreshPc::FreshReadiness& readiness) {
    SetupCommon::PlanDocument doc;
    doc.name = "Real-Time Privacy Session Setup";
    doc.purpose = "Prepare a reversible runtime privacy boundary for apps or browsers without changing firmware or hiding host activity.";
    doc.boundary = "Uses Windows privacy settings, Sandbox launch plans, per-session folders, and optional firewall policy. Host hardware identifiers remain visible to host processes.";

    doc.steps = {
        {
            "Start a privacy session",
            "Run start_realtime_session.cmd from the generated artifact directory. Sandbox mode opens realtime_sandbox.wsb when Windows Sandbox is available.",
            "command-template"
        },
        {
            "Use the right runtime boundary",
            "Use sandbox mode for strongest isolation, user mode for local browser profiles, and policy mode when outbound network blocking for a specific executable is the goal.",
            "required"
        },
        {
            "Record host hardware readiness",
            "Read-only probe: TPM present=" + security.tpm.present + ", Secure Boot=" + security.secureBoot.state + ", RAID=" + SetupProbe::YesNo(storage.raidDetected) + ", VMD=" + SetupProbe::YesNo(storage.vmdDetected) + ". Host apps still see host hardware.",
            "informational"
        },
        {
            "Review Fresh Session readiness score",
            "Current score: " + std::to_string(readiness.percent) + "%. Use Sandbox or a VM when a host app must not share browser/profile/network state.",
            readiness.blockers.empty() ? "ok" : "review"
        },
        {
            "Review device and peripheral inventory",
            "Read-only inventory captured " + std::to_string(inventory.devices.size()) + " present Plug and Play devices. Host-mode apps may still observe local keyboard, mouse, USB, HID, network, display, storage, and system surfaces.",
            inventory.error.empty() ? "informational" : "review"
        },
        {
            "Stage registry privacy baseline",
            "Review registry_privacy_baseline.txt, then optionally import registry_privacy_baseline.reg for the current user before starting privacy-sensitive browsing or app sessions.",
            "recommended"
        },
        {
            "Launch target through the session",
            options.target.empty()
                ? "Regenerate this plan with --target <path> for a launch template, or open the target manually inside Windows Sandbox."
                : "Run launch_realtime_target.cmd to start \"" + options.target + "\" with PERM_SESSION_DIR pointing at the generated session folder.",
            "command-template"
        },
        {
            "Restore the session",
            "Run restore_realtime_session.cmd. For policy mode with a target, it removes the generated outbound firewall block rule.",
            "required"
        },
        {
            "Review artifacts",
            "Inspect realtime_privacy_plan.txt, hardware_readiness.txt, fresh_pc_readiness.txt, device_inventory.txt, registry_privacy_baseline.txt, and generated command templates before use.",
            "recommended"
        },
    };

    doc.warnings = {
        {
            "No complete host invisibility",
            "Real-time protection cannot make a host process stop seeing host firmware, TPM, disk, GPU, monitor, USB, or MAC surfaces.",
            "important"
        },
        {
            "Policy mode needs Administrator",
            "Firewall policy mode writes reversible Windows Firewall rules and must be restored when finished.",
            "important"
        },
        {
            "Sandbox is not persistence",
            "Windows Sandbox intentionally discards guest state at close; store only the artifacts you deliberately need outside the sandbox.",
            "notice"
        },
    };

    doc.outputs = {
        { "realtime_privacy_plan.txt", "Human-readable runtime setup plan.", "generated" },
        { "realtime_privacy_plan.json", "Machine-readable runtime setup plan.", "generated" },
        { "hardware_readiness.txt", "Read-only TPM, Secure Boot, BitLocker, RAID, VMD, and disk readiness report.", "generated" },
        { "hardware_readiness.json", "Machine-readable hardware readiness report.", "generated" },
        { "fresh_pc_readiness.txt", "Fresh session readiness score, blockers, and next actions.", "generated" },
        { "fresh_pc_readiness.json", "Machine-readable Fresh session readiness report.", "generated" },
        { "device_inventory.txt", "Read-only inventory of present internal and peripheral device surfaces.", "generated" },
        { "device_inventory.json", "Machine-readable device inventory report.", "generated" },
        { "registry_privacy_baseline.txt", "Registry privacy settings guide for review before import.", "generated" },
        { "registry_privacy_baseline.reg", "Current-user registry privacy baseline.", "generated" },
        { "registry_admin_policy_baseline.reg", "Optional Administrator machine-policy privacy baseline.", "generated" },
        { "apply_registry_user_baseline.cmd", "Command template to import the current-user registry baseline.", "generated" },
        { "realtime_sandbox.wsb", "Windows Sandbox configuration with device and clipboard redirection disabled.", "generated" },
        { "start_realtime_session.cmd", "Command template for creating a session.", "generated" },
        { "restore_realtime_session.cmd", "Command template for restoring a session.", "generated" },
    };
    if (!options.target.empty()) {
        doc.outputs.push_back({ "launch_realtime_target.cmd", "Command template for launching the requested target.", "generated" });
    }

    return doc;
}

std::string BuildStartCommand(const Options& options) {
    return "@echo off\r\n"
        "setlocal\r\n"
        "set SESSION_OUTPUT=%~dp0session\r\n"
        "if not exist \"%SESSION_OUTPUT%\" mkdir \"%SESSION_OUTPUT%\"\r\n"
        "echo Created session folder: %SESSION_OUTPUT%\r\n"
        "echo Mode: " + options.mode + "\r\n"
        "if /I \"" + options.mode + "\"==\"sandbox\" (\r\n"
        "  echo Opening Windows Sandbox configuration...\r\n"
        "  start \"\" \"%~dp0realtime_sandbox.wsb\"\r\n"
        "  exit /b 0\r\n"
        ")\r\n"
        "if /I \"" + options.mode + "\"==\"policy\" (\r\n"
        "  echo Policy mode uses launch_realtime_target.cmd and restore_realtime_session.cmd when a target is configured.\r\n"
        ")\r\n"
        "echo Review registry_privacy_baseline.txt before importing registry settings.\r\n";
}

std::string BuildRestoreCommand(const Options& options) {
    std::string command = "@echo off\r\n"
        "setlocal\r\n"
        "echo Close any apps or Sandbox windows that were opened for this session.\r\n";
    if (options.mode == "policy" && !options.target.empty()) {
        command +=
            "netsh advfirewall firewall delete rule name=\"Perm Realtime Outbound Block\" program=\"" + options.target + "\" >nul 2>nul\r\n"
            "echo Removed generated firewall policy rule if it existed.\r\n";
    }
    command += "echo Session restore checklist complete.\r\n";
    return command;
}

std::string BuildLaunchCommand(const Options& options) {
    std::string command = "@echo off\r\n"
        "setlocal\r\n"
        "set SESSION_OUTPUT=%~dp0session\r\n"
        "if not exist \"%SESSION_OUTPUT%\" mkdir \"%SESSION_OUTPUT%\"\r\n"
        "set PERM_SESSION_DIR=%SESSION_OUTPUT%\r\n";
    if (options.mode == "policy") {
        command +=
            "netsh advfirewall firewall add rule name=\"Perm Realtime Outbound Block\" dir=out action=block program=\"" + options.target + "\" enable=yes profile=any\r\n";
    }
    command += "start \"\" \"" + options.target + "\"\r\n";
    return command;
}

std::string BuildSandboxConfig() {
    return "<Configuration>\r\n"
        "  <VGpu>Disable</VGpu>\r\n"
        "  <Networking>Disable</Networking>\r\n"
        "  <ClipboardRedirection>Disable</ClipboardRedirection>\r\n"
        "  <PrinterRedirection>Disable</PrinterRedirection>\r\n"
        "  <AudioInput>Disable</AudioInput>\r\n"
        "  <VideoInput>Disable</VideoInput>\r\n"
        "  <ProtectedClient>Enable</ProtectedClient>\r\n"
        "  <MemoryInMB>4096</MemoryInMB>\r\n"
        "</Configuration>\r\n";
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
    FreshPc::FreshReadiness readiness = FreshPc::Build(FreshPc::ProjectKind::RealTime, security, storage);

    std::filesystem::path outputDir = SetupCommon::ResolveOutputDir(options.outputDir, "realtime");
    std::filesystem::path textPath;
    std::filesystem::path jsonPath;
    std::string error;

    if (!SetupCommon::WritePlanBundle(outputDir, "realtime_privacy_plan", BuildPlan(options, security, storage, inventory, readiness), textPath, jsonPath, error)) {
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
        std::cerr << "[!] Failed to write Fresh session readiness report: " << error << "\n";
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

    if (!SetupCommon::WriteTextFile(outputDir / "realtime_sandbox.wsb", BuildSandboxConfig(), error) ||
        !SetupCommon::WriteTextFile(outputDir / "start_realtime_session.cmd", BuildStartCommand(options), error) ||
        !SetupCommon::WriteTextFile(outputDir / "restore_realtime_session.cmd", BuildRestoreCommand(options), error)) {
        std::cerr << "[!] Failed to write command template: " << error << "\n";
        return 1;
    }
    if (!options.target.empty() &&
        !SetupCommon::WriteTextFile(outputDir / "launch_realtime_target.cmd", BuildLaunchCommand(options), error)) {
        std::cerr << "[!] Failed to write launch template: " << error << "\n";
        return 1;
    }

    SetupCommon::PrintGenerated(outputDir, textPath, jsonPath);
    std::cout << "  Hardware readiness: " << (outputDir / "hardware_readiness.txt").string() << "\n";
    std::cout << "  Fresh session readiness: " << (outputDir / "fresh_pc_readiness.txt").string()
              << " (" << readiness.percent << "%)\n";
    std::cout << "  Device inventory: " << (outputDir / "device_inventory.txt").string()
              << " (" << inventory.devices.size() << " devices)\n";
    std::cout << "  Registry baseline: " << (outputDir / "registry_privacy_baseline.txt").string() << "\n";
    std::cout << "  Sandbox config: " << (outputDir / "realtime_sandbox.wsb").string() << "\n";
    std::cout << "  Start command: " << (outputDir / "start_realtime_session.cmd").string() << "\n"
              << "  Restore command: " << (outputDir / "restore_realtime_session.cmd").string() << "\n";
    if (!options.target.empty()) {
        std::cout << "  Launch command: " << (outputDir / "launch_realtime_target.cmd").string() << "\n";
    }
    return 0;
}
