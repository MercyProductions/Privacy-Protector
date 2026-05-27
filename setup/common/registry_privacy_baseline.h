#pragma once

#include "setup_common.h"

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace RegistryPrivacy {

struct RegistryDwordSetting {
    std::string key;
    std::string name;
    unsigned int value;
    std::string description;
};

inline std::vector<RegistryDwordSetting> UserSettings() {
    return {
        {
            "Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo",
            "Enabled",
            0,
            "Disable the per-user Windows advertising ID."
        },
        {
            "Software\\Microsoft\\Windows\\CurrentVersion\\Privacy",
            "TailoredExperiencesWithDiagnosticDataEnabled",
            0,
            "Disable tailored experiences that use diagnostic data."
        },
        {
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
            "Start_TrackProgs",
            0,
            "Disable app launch tracking for Start and search suggestions."
        },
        {
            "Software\\Microsoft\\InputPersonalization",
            "RestrictImplicitTextCollection",
            1,
            "Restrict implicit text collection for personalization."
        },
        {
            "Software\\Microsoft\\InputPersonalization",
            "RestrictImplicitInkCollection",
            1,
            "Restrict implicit ink collection for personalization."
        },
        {
            "Software\\Microsoft\\InputPersonalization\\TrainedDataStore",
            "HarvestContacts",
            0,
            "Disable contact harvesting for input personalization."
        },
        {
            "Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
            "ContentDeliveryAllowed",
            0,
            "Disable Windows content delivery suggestions."
        },
        {
            "Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
            "OemPreInstalledAppsEnabled",
            0,
            "Disable OEM promoted app reinstall suggestions."
        },
        {
            "Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
            "PreInstalledAppsEnabled",
            0,
            "Disable promoted preinstalled app suggestions."
        },
        {
            "Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
            "PreInstalledAppsEverEnabled",
            0,
            "Keep promoted preinstalled app suggestions disabled."
        },
        {
            "Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
            "SilentInstalledAppsEnabled",
            0,
            "Disable silent consumer app installation suggestions."
        },
        {
            "Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
            "SubscribedContent-338388Enabled",
            0,
            "Disable app suggestions in Windows surfaces."
        },
        {
            "Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
            "SubscribedContent-338389Enabled",
            0,
            "Disable Windows tips and suggestion content."
        },
        {
            "Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
            "SubscribedContent-353694Enabled",
            0,
            "Disable suggested content in Settings."
        },
        {
            "Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
            "SubscribedContent-353696Enabled",
            0,
            "Disable additional subscribed suggestion content."
        },
        {
            "Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
            "SystemPaneSuggestionsEnabled",
            0,
            "Disable Start menu system pane suggestions."
        },
    };
}

inline std::vector<RegistryDwordSetting> AdminPolicySettings() {
    return {
        {
            "SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo",
            "DisabledByGroupPolicy",
            1,
            "Disable Windows advertising ID by machine policy."
        },
        {
            "SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
            "DisableWindowsConsumerFeatures",
            1,
            "Disable Windows consumer feature recommendations by policy."
        },
        {
            "SOFTWARE\\Policies\\Microsoft\\Windows\\System",
            "EnableActivityFeed",
            0,
            "Disable Windows activity feed by policy."
        },
        {
            "SOFTWARE\\Policies\\Microsoft\\Windows\\System",
            "PublishUserActivities",
            0,
            "Disable publishing user activities by policy."
        },
        {
            "SOFTWARE\\Policies\\Microsoft\\Windows\\System",
            "UploadUserActivities",
            0,
            "Disable uploading user activities by policy."
        },
        {
            "SOFTWARE\\Policies\\Microsoft\\InputPersonalization",
            "AllowInputPersonalization",
            0,
            "Disable input personalization by policy."
        },
    };
}

inline void AppendRegFile(std::ostringstream& out, const std::string& hive,
    const std::vector<RegistryDwordSetting>& settings) {
    std::string currentKey;
    for (const auto& setting : settings) {
        if (setting.key != currentKey) {
            currentKey = setting.key;
            out << "\r\n[" << hive << "\\" << currentKey << "]\r\n";
        }

        out << "\"" << setting.name << "\"=dword:"
            << std::hex << std::setw(8) << std::setfill('0') << setting.value
            << std::dec << std::setfill(' ') << "\r\n";
    }
}

inline std::string BuildUserRegFile() {
    std::ostringstream out;
    out << "Windows Registry Editor Version 5.00\r\n";
    AppendRegFile(out, "HKEY_CURRENT_USER", UserSettings());
    return out.str();
}

inline std::string BuildAdminPolicyRegFile() {
    std::ostringstream out;
    out << "Windows Registry Editor Version 5.00\r\n";
    AppendRegFile(out, "HKEY_LOCAL_MACHINE", AdminPolicySettings());
    return out.str();
}

inline void AppendSettingsText(std::ostringstream& out, const std::string& title,
    const std::string& hive, const std::vector<RegistryDwordSetting>& settings) {
    out << "\n" << title << "\n";
    out << std::string(title.size(), '-') << "\n";
    for (const auto& setting : settings) {
        out << "- " << hive << "\\" << setting.key << "\\" << setting.name
            << " = " << setting.value << "\n";
        out << "  " << setting.description << "\n";
    }
}

inline std::string BuildGuideText() {
    std::ostringstream out;
    out << "Registry Privacy Baseline\n";
    out << "=========================\n";
    out << "Created: " << SetupCommon::TimestampIso() << "\n\n";
    out << "Scope\n";
    out << "-----\n";
    out << "These files stage registry privacy settings for review and optional import.\n";
    out << "They do not apply automatically, spoof hardware IDs, hide devices, bypass controls, or remove account tokens.\n\n";
    out << "Artifacts\n";
    out << "---------\n";
    out << "- registry_privacy_baseline.reg: current-user privacy settings that do not require elevation.\n";
    out << "- registry_admin_policy_baseline.reg: optional machine policy settings that require Administrator rights.\n";
    out << "- apply_registry_user_baseline.cmd: imports only the current-user baseline.\n";
    AppendSettingsText(out, "Current-user Settings", "HKCU", UserSettings());
    AppendSettingsText(out, "Administrator Policy Settings", "HKLM", AdminPolicySettings());
    out << "\nGuidance\n";
    out << "--------\n";
    out << "- Review every value before import, especially on managed work or school devices.\n";
    out << "- Create a restore point or export the affected registry keys before importing policy baselines.\n";
    out << "- Apply the current-user baseline after creating the fresh Windows profile, before signing into sync-heavy accounts.\n";
    return out.str();
}

inline std::string BuildApplyUserCommand() {
    return "@echo off\r\n"
        "setlocal\r\n"
        "reg import \"%~dp0registry_privacy_baseline.reg\"\r\n"
        "if errorlevel 1 (\r\n"
        "  echo Failed to import registry_privacy_baseline.reg\r\n"
        "  exit /b 1\r\n"
        ")\r\n"
        "echo Imported current-user registry privacy baseline.\r\n";
}

} // namespace RegistryPrivacy
