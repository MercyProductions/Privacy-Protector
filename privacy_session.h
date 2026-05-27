#pragma once

#include <filesystem>
#include <string>

struct PrivacySessionStartOptions {
    std::filesystem::path workDir;
    std::filesystem::path outputPath;
    std::string mode = "user";
};

struct PrivacySessionPathOptions {
    std::filesystem::path workDir;
    std::string sessionRef;
    std::string launchTarget;
    std::filesystem::path originalTargetPath;
    std::filesystem::path resolvedTargetPath;
    std::string targetKind;
    std::string launchMode;
    std::filesystem::path launchPath;
    std::filesystem::path launchPlanPath;
    std::filesystem::path launchCommandPath;
    std::filesystem::path launchSandboxPath;
    std::filesystem::path policyRulesPath;
};

struct PrivacySessionResult {
    bool ok = false;
    std::string errorMessage;
    std::string sessionId;
    std::string mode;
    std::filesystem::path sessionPath;
    std::filesystem::path snapshotPath;
    std::filesystem::path manifestPath;
    std::filesystem::path reportPath;
    std::filesystem::path sandboxPath;
    std::filesystem::path launchPath;
    std::filesystem::path launchPlanPath;
    std::filesystem::path launchCommandPath;
    std::filesystem::path launchSandboxPath;
    std::filesystem::path policyRulesPath;
    std::filesystem::path originalTargetPath;
    std::filesystem::path resolvedTargetPath;
    std::string targetKind;
    std::string launchMode;
    int changedCount = 0;
    int policyRuleCount = 0;
    bool restored = false;
    bool launched = false;
    bool sandboxUsed = false;
    bool hostLaunchWarning = false;
};

PrivacySessionResult StartPrivacySession(const PrivacySessionStartOptions& options);
PrivacySessionResult ShowPrivacySessionStatus(const PrivacySessionPathOptions& options);
PrivacySessionResult RestorePrivacySession(const PrivacySessionPathOptions& options);
PrivacySessionResult LaunchPrivacySessionTarget(const PrivacySessionPathOptions& options);
