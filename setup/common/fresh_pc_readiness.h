#pragma once

#include "setup_common.h"
#include "system_probe.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace FreshPc {

enum class ProjectKind {
    Perm,
    RealTime,
    EfiBoot,
};

struct FreshCheck {
    std::string area;
    std::string name;
    std::string detail;
    std::string status;
    int score = 0;
    int maxScore = 0;
    bool blocker = false;
};

struct FreshReadiness {
    std::string projectName;
    std::string projectPurpose;
    int score = 0;
    int maxScore = 0;
    int percent = 0;
    std::vector<FreshCheck> checks;
    std::vector<std::string> blockers;
    std::vector<std::string> nextActions;
};

inline std::string Env(const char* name) {
    char buffer[MAX_PATH]{};
    DWORD size = GetEnvironmentVariableA(name, buffer, static_cast<DWORD>(sizeof(buffer)));
    if (size == 0 || size >= sizeof(buffer)) {
        return {};
    }
    return buffer;
}

inline bool PathExists(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

inline int CountDirectories(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || !std::filesystem::is_directory(path, ec)) {
        return 0;
    }

    int count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(path, std::filesystem::directory_options::skip_permission_denied, ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        if (entry.is_directory(ec)) {
            ++count;
        }
    }
    return count;
}

inline std::string UserPath(const std::string& relative) {
    std::string profile = Env("USERPROFILE");
    if (profile.empty()) {
        return {};
    }
    return (std::filesystem::path(profile) / relative).string();
}

inline std::string LocalAppDataPath(const std::string& relative) {
    std::string base = Env("LOCALAPPDATA");
    if (base.empty()) {
        return {};
    }
    return (std::filesystem::path(base) / relative).string();
}

inline std::string AppDataPath(const std::string& relative) {
    std::string base = Env("APPDATA");
    if (base.empty()) {
        return {};
    }
    return (std::filesystem::path(base) / relative).string();
}

inline bool ReadCurrentUserDword(const std::wstring& subKey, const std::wstring& valueName, DWORD& value) {
    HKEY key = nullptr;
    LONG status = RegOpenKeyExW(HKEY_CURRENT_USER, subKey.c_str(), 0, KEY_READ, &key);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    DWORD type = REG_NONE;
    DWORD size = sizeof(value);
    status = RegQueryValueExW(key, valueName.c_str(), nullptr, &type, reinterpret_cast<BYTE*>(&value), &size);
    RegCloseKey(key);
    return status == ERROR_SUCCESS && type == REG_DWORD;
}

inline std::string DwordState(const std::wstring& subKey, const std::wstring& valueName) {
    DWORD value = 0;
    if (!ReadCurrentUserDword(subKey, valueName, value)) {
        return "unknown";
    }
    return value == 0 ? "disabled" : "enabled";
}

inline int BrowserProfileCount() {
    int count = 0;

    const std::string chromeDefault = LocalAppDataPath("Google\\Chrome\\User Data\\Default");
    if (!chromeDefault.empty() && PathExists(chromeDefault)) ++count;

    const std::string edgeDefault = LocalAppDataPath("Microsoft\\Edge\\User Data\\Default");
    if (!edgeDefault.empty() && PathExists(edgeDefault)) ++count;

    const std::string braveDefault = LocalAppDataPath("BraveSoftware\\Brave-Browser\\User Data\\Default");
    if (!braveDefault.empty() && PathExists(braveDefault)) ++count;

    const std::string firefoxProfiles = AppDataPath("Mozilla\\Firefox\\Profiles");
    if (!firefoxProfiles.empty()) {
        count += CountDirectories(firefoxProfiles);
    }

    return count;
}

inline int WifiProfileCount() {
    SetupProbe::CommandResult result = SetupProbe::CaptureCommand(L"netsh.exe wlan show profiles");
    if (!result.started || result.exitCode != 0) {
        return -1;
    }

    int count = 0;
    for (const auto& line : SetupProbe::Lines(result.output)) {
        if (SetupProbe::ContainsCi(line, "All User Profile") || SetupProbe::ContainsCi(line, "User Profile")) {
            ++count;
        }
    }
    return count;
}

inline bool OneDriveConfigured() {
    if (!Env("OneDrive").empty() || !Env("OneDriveConsumer").empty() || !Env("OneDriveCommercial").empty()) {
        return true;
    }
    return PathExists(UserPath("OneDrive"));
}

inline bool HasProtectedBitLockerVolume(const SetupProbe::SecurityProbe& security) {
    for (const auto& volume : security.bitLockerVolumes) {
        if (SetupProbe::ContainsCi(volume.protectionStatus, "on") ||
            volume.protectionStatus == "1" ||
            SetupProbe::ContainsCi(volume.protectionStatus, "true")) {
            return true;
        }
    }
    return false;
}

inline bool AllKnownDisksHealthy(const SetupProbe::StorageProbe& storage) {
    if (storage.disks.empty()) {
        return false;
    }
    for (const auto& disk : storage.disks) {
        if (!SetupProbe::ContainsCi(disk.healthStatus, "healthy") && !SetupProbe::ContainsCi(disk.healthStatus, "ok")) {
            return false;
        }
    }
    return true;
}

inline bool IsTrueState(const std::string& value) {
    return SetupProbe::ContainsCi(value, "true") || value == "1" || SetupProbe::ContainsCi(value, "yes");
}

inline void AddCheck(FreshReadiness& readiness, FreshCheck check) {
    readiness.score += check.score;
    readiness.maxScore += check.maxScore;
    if (check.blocker) {
        readiness.blockers.push_back(check.area + ": " + check.name + " - " + check.detail);
    }
    readiness.checks.push_back(std::move(check));
}

inline void AddBinaryCheck(FreshReadiness& readiness, const std::string& area, const std::string& name,
    bool ok, const std::string& okDetail, const std::string& reviewDetail, int weight, bool blockerOnReview = false) {
    AddCheck(readiness, {
        area,
        name,
        ok ? okDetail : reviewDetail,
        ok ? "ok" : "review",
        ok ? weight : 0,
        weight,
        !ok && blockerOnReview
    });
}

inline FreshReadiness Build(ProjectKind kind, const SetupProbe::SecurityProbe& security, const SetupProbe::StorageProbe& storage) {
    FreshReadiness readiness;
    switch (kind) {
        case ProjectKind::Perm:
            readiness.projectName = "Perm Fresh PC Readiness";
            readiness.projectPurpose = "Permanent clean-install baseline for a PC that should not inherit old files, profiles, sync state, or storage surprises.";
            break;
        case ProjectKind::RealTime:
            readiness.projectName = "RealTime Fresh Session Readiness";
            readiness.projectPurpose = "Runtime isolation readiness for browser/app sessions while documenting which host surfaces remain visible.";
            break;
        case ProjectKind::EfiBoot:
            readiness.projectName = "EFI Fresh Boot Readiness";
            readiness.projectPurpose = "Boot-chain and installer readiness for a trusted UEFI/Secure Boot reinstall path.";
            break;
    }

    const bool windowsOld = PathExists("C:\\Windows.old");
    const int browserProfiles = BrowserProfileCount();
    const int wifiProfiles = WifiProfileCount();
    const bool oneDrive = OneDriveConfigured();
    const std::string adId = DwordState(L"Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Enabled");
    const std::string tailored = DwordState(L"Software\\Microsoft\\Windows\\CurrentVersion\\Privacy", L"TailoredExperiencesWithDiagnosticDataEnabled");

    AddBinaryCheck(readiness, "Install State", "No Windows.old carryover",
        !windowsOld,
        "No C:\\Windows.old folder was found.",
        "C:\\Windows.old exists. Review or remove old OS data after deliberate backup decisions.",
        10);

    AddCheck(readiness, {
        "Profile State",
        "Browser profile carryover",
        browserProfiles == 0
            ? "No common browser profile folders were detected."
            : std::to_string(browserProfiles) + " common browser profile folder(s) were detected. Use fresh profiles for a clean-PC feel.",
        browserProfiles == 0 ? "ok" : "review",
        browserProfiles == 0 ? 10 : 3,
        10,
        false
    });

    AddCheck(readiness, {
        "Network State",
        "Known Wi-Fi profiles",
        wifiProfiles < 0
            ? "Wi-Fi profile count is unavailable on this system."
            : (wifiProfiles == 0 ? "No saved Wi-Fi profiles were detected." : std::to_string(wifiProfiles) + " saved Wi-Fi profile(s) detected."),
        wifiProfiles == 0 ? "ok" : "review",
        wifiProfiles == 0 ? 5 : (wifiProfiles < 0 ? 2 : 0),
        5,
        false
    });

    AddBinaryCheck(readiness, "Sync State", "OneDrive not already configured",
        !oneDrive,
        "No obvious OneDrive environment or profile folder was detected.",
        "OneDrive appears configured. A synced account can reintroduce old files/settings.",
        5);

    AddCheck(readiness, {
        "Windows Privacy",
        "Advertising ID",
        "Advertising ID is " + adId + ".",
        adId == "disabled" ? "ok" : "review",
        adId == "disabled" ? 5 : (adId == "unknown" ? 2 : 0),
        5,
        false
    });

    AddCheck(readiness, {
        "Windows Privacy",
        "Tailored experiences",
        "Tailored experiences are " + tailored + ".",
        tailored == "disabled" ? "ok" : "review",
        tailored == "disabled" ? 5 : (tailored == "unknown" ? 2 : 0),
        5,
        false
    });

    AddBinaryCheck(readiness, "Boot Trust", "UEFI firmware mode",
        security.secureBoot.firmwareType == "UEFI",
        "Firmware mode is UEFI.",
        "Firmware mode is " + security.secureBoot.firmwareType + ". Prefer UEFI for a modern clean install.",
        kind == ProjectKind::EfiBoot ? 15 : 8,
        kind == ProjectKind::EfiBoot);

    AddBinaryCheck(readiness, "Boot Trust", "Secure Boot enabled",
        security.secureBoot.state == "enabled",
        "Secure Boot is enabled.",
        "Secure Boot is " + security.secureBoot.state + ". Review firmware settings before final use.",
        kind == ProjectKind::EfiBoot ? 15 : 8,
        false);

    const bool tpmReady = IsTrueState(security.tpm.ready) || (IsTrueState(security.tpm.present) && security.tpm.ready == "unknown");
    AddCheck(readiness, {
        "TPM",
        "TPM readiness",
        "TPM present=" + security.tpm.present + ", ready=" + security.tpm.ready + ", enabled=" + security.tpm.enabled +
            (security.tpm.error.empty() ? "" : ", note=" + security.tpm.error),
        tpmReady ? "ok" : "review",
        tpmReady ? 10 : (security.tpm.present == "unknown" ? 4 : 0),
        10,
        false
    });

    const bool bitLockerActive = HasProtectedBitLockerVolume(security);
    AddCheck(readiness, {
        "Recovery",
        "BitLocker recovery awareness",
        bitLockerActive
            ? "BitLocker-protected volume(s) detected. Recovery keys must be backed up before firmware or partition work."
            : "No protected BitLocker volumes were reported.",
        bitLockerActive ? "review" : "ok",
        bitLockerActive ? 3 : 8,
        8,
        bitLockerActive && kind != ProjectKind::RealTime
    });

    const bool storageDriverReady = !(storage.raidDetected || storage.vmdDetected);
    AddCheck(readiness, {
        "Storage",
        "RAID/VMD installer readiness",
        storageDriverReady
            ? "No RAID or VMD storage mode was detected."
            : "RAID/VMD storage was detected. Save the vendor storage driver before reinstalling.",
        storageDriverReady ? "ok" : "review-required",
        storageDriverReady ? 12 : 0,
        12,
        !storageDriverReady && kind != ProjectKind::RealTime
    });

    AddBinaryCheck(readiness, "Storage", "Disk health reported healthy",
        AllKnownDisksHealthy(storage),
        "All reported physical disks are healthy.",
        storage.disks.empty() ? "No physical disk data was reported." : "One or more reported disks are not healthy.",
        7,
        false);

    if (kind == ProjectKind::RealTime) {
        AddCheck(readiness, {
            "Runtime Boundary",
            "Host hardware visibility documented",
            "Real-time host launches cannot hide TPM, firmware, disk, GPU, monitor, USB, or MAC surfaces. Use Sandbox or a VM for stronger separation.",
            "documented",
            10,
            10,
            false
        });
    }

    readiness.percent = readiness.maxScore > 0 ? (readiness.score * 100 / readiness.maxScore) : 0;

    if (readiness.blockers.empty()) {
        readiness.nextActions.push_back("Review the generated plan and keep the readiness report with your reinstall/session records.");
    } else {
        readiness.nextActions.push_back("Resolve blockers before treating the PC or session as fresh.");
    }
    if (browserProfiles > 0) {
        readiness.nextActions.push_back("Create fresh browser profiles instead of importing old cookies, extensions, and sync state.");
    }
    if (storage.raidDetected || storage.vmdDetected) {
        readiness.nextActions.push_back("Download RAID/VMD storage drivers before booting Windows Setup.");
    }
    if (bitLockerActive) {
        readiness.nextActions.push_back("Back up BitLocker recovery keys offline before changing boot, TPM, firmware, or partitions.");
    }

    return readiness;
}

inline std::string BuildText(const FreshReadiness& readiness) {
    std::ostringstream out;
    out << readiness.projectName << "\n";
    out << std::string(readiness.projectName.size(), '=') << "\n";
    out << "Created: " << SetupCommon::TimestampIso() << "\n";
    out << "Score: " << readiness.percent << "% (" << readiness.score << "/" << readiness.maxScore << ")\n\n";
    out << readiness.projectPurpose << "\n\n";

    out << "Checks\n";
    out << "------\n";
    for (const auto& check : readiness.checks) {
        out << "- [" << check.status << "] " << check.area << " / " << check.name
            << " (" << check.score << "/" << check.maxScore << "): " << check.detail << "\n";
    }

    out << "\nBlockers\n";
    out << "--------\n";
    if (readiness.blockers.empty()) {
        out << "None.\n";
    } else {
        for (const auto& blocker : readiness.blockers) {
            out << "- " << blocker << "\n";
        }
    }

    out << "\nNext Actions\n";
    out << "------------\n";
    for (const auto& action : readiness.nextActions) {
        out << "- " << action << "\n";
    }

    out << "\nBoundary\n";
    out << "--------\n";
    out << "This readiness report is read-only. It does not wipe files, change firmware, edit boot entries, alter TPM state, or spoof hardware identifiers.\n";
    return out.str();
}

inline std::string BuildJson(const FreshReadiness& readiness) {
    std::ostringstream out;
    out << "{\n";
    out << "  \"schemaVersion\": 1,\n";
    out << "  \"createdAt\": \"" << SetupCommon::JsonEscape(SetupCommon::TimestampIso()) << "\",\n";
    out << "  \"projectName\": \"" << SetupCommon::JsonEscape(readiness.projectName) << "\",\n";
    out << "  \"projectPurpose\": \"" << SetupCommon::JsonEscape(readiness.projectPurpose) << "\",\n";
    out << "  \"score\": " << readiness.score << ",\n";
    out << "  \"maxScore\": " << readiness.maxScore << ",\n";
    out << "  \"percent\": " << readiness.percent << ",\n";
    out << "  \"checks\": [\n";
    for (size_t i = 0; i < readiness.checks.size(); ++i) {
        const auto& check = readiness.checks[i];
        out << "    {\n";
        out << "      \"area\": \"" << SetupCommon::JsonEscape(check.area) << "\",\n";
        out << "      \"name\": \"" << SetupCommon::JsonEscape(check.name) << "\",\n";
        out << "      \"detail\": \"" << SetupCommon::JsonEscape(check.detail) << "\",\n";
        out << "      \"status\": \"" << SetupCommon::JsonEscape(check.status) << "\",\n";
        out << "      \"score\": " << check.score << ",\n";
        out << "      \"maxScore\": " << check.maxScore << ",\n";
        out << "      \"blocker\": " << (check.blocker ? "true" : "false") << "\n";
        out << "    }" << (i + 1 == readiness.checks.size() ? "\n" : ",\n");
    }
    out << "  ],\n";
    out << "  \"blockers\": [\n";
    for (size_t i = 0; i < readiness.blockers.size(); ++i) {
        out << "    \"" << SetupCommon::JsonEscape(readiness.blockers[i]) << "\""
            << (i + 1 == readiness.blockers.size() ? "\n" : ",\n");
    }
    out << "  ],\n";
    out << "  \"nextActions\": [\n";
    for (size_t i = 0; i < readiness.nextActions.size(); ++i) {
        out << "    \"" << SetupCommon::JsonEscape(readiness.nextActions[i]) << "\""
            << (i + 1 == readiness.nextActions.size() ? "\n" : ",\n");
    }
    out << "  ]\n";
    out << "}\n";
    return out.str();
}

} // namespace FreshPc
