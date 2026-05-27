#include "../common/setup_common.h"
#include "../common/system_probe.h"
#include "../common/fresh_pc_readiness.h"

#include <filesystem>
#include <iostream>
#include <string>

namespace {

struct Options {
    std::string outputDir;
    std::string mode = "sandbox";
    std::string target;
    std::string dmiUpdater = "DmiUpdater.exe";
    bool showHelp = false;
};

void PrintUsage() {
    std::cout
        << "PermSetupRealtime - real-time privacy session setup\n\n"
        << "Usage:\n"
        << "  PermSetupRealtime.exe [--mode user|sandbox|policy] [--target <path>] [--output <directory>] [--dmi-updater <path>]\n\n"
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
        } else if (arg == "--dmi-updater" && i + 1 < argc) {
            options.dmiUpdater = argv[++i];
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
    const SetupProbe::StorageProbe& storage, const FreshPc::FreshReadiness& readiness) {
    SetupCommon::PlanDocument doc;
    doc.name = "Real-Time Privacy Session Setup";
    doc.purpose = "Prepare a reversible runtime privacy boundary for apps or browsers without changing firmware or hiding host activity.";
    doc.boundary = "Uses Windows privacy settings, Sandbox launch plans, and optional firewall policy. Host hardware identifiers remain visible to host processes.";

    doc.steps = {
        {
            "Start a privacy session",
            options.dmiUpdater + " --privacy-session-start --mode " + options.mode + " --output <session-output-dir>",
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
            "Launch target through the session",
            options.target.empty()
                ? "After the session is created, run DmiUpdater --privacy-session-launch <session-id-or-path> <target>."
                : options.dmiUpdater + " --privacy-session-launch <session-id-or-path> \"" + options.target + "\"",
            "command-template"
        },
        {
            "Restore the session",
            options.dmiUpdater + " --privacy-session-restore <session-id-or-path>",
            "required"
        },
        {
            "Review artifacts",
            "Inspect snapshot.json, session_manifest.json, launch_plan.json, and any policy_rules.json before deleting the session folder.",
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
        "\"" + options.dmiUpdater + "\" --privacy-session-start --mode " + options.mode + " --output \"%SESSION_OUTPUT%\"\r\n";
}

std::string BuildRestoreCommand(const Options& options) {
    return "@echo off\r\n"
        "setlocal\r\n"
        "if \"%~1\"==\"\" (\r\n"
        "  echo Usage: restore_realtime_session.cmd ^<session-id-or-path^>\r\n"
        "  exit /b 1\r\n"
        ")\r\n"
        "\"" + options.dmiUpdater + "\" --privacy-session-restore \"%~1\"\r\n";
}

std::string BuildLaunchCommand(const Options& options) {
    return "@echo off\r\n"
        "setlocal\r\n"
        "if \"%~1\"==\"\" (\r\n"
        "  echo Usage: launch_realtime_target.cmd ^<session-id-or-path^>\r\n"
        "  exit /b 1\r\n"
        ")\r\n"
        "\"" + options.dmiUpdater + "\" --privacy-session-launch \"%~1\" \"" + options.target + "\"\r\n";
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
    FreshPc::FreshReadiness readiness = FreshPc::Build(FreshPc::ProjectKind::RealTime, security, storage);

    std::filesystem::path outputDir = SetupCommon::ResolveOutputDir(options.outputDir, "realtime");
    std::filesystem::path textPath;
    std::filesystem::path jsonPath;
    std::string error;

    if (!SetupCommon::WritePlanBundle(outputDir, "realtime_privacy_plan", BuildPlan(options, security, storage, readiness), textPath, jsonPath, error)) {
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

    if (!SetupCommon::WriteTextFile(outputDir / "start_realtime_session.cmd", BuildStartCommand(options), error) ||
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
    std::cout << "  Start command: " << (outputDir / "start_realtime_session.cmd").string() << "\n"
              << "  Restore command: " << (outputDir / "restore_realtime_session.cmd").string() << "\n";
    if (!options.target.empty()) {
        std::cout << "  Launch command: " << (outputDir / "launch_realtime_target.cmd").string() << "\n";
    }
    return 0;
}
