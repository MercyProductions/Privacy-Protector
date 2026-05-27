#include "modules/reinstall_prep.h"

#include "imgui/imgui.h"
#include "theme.h"

#include <algorithm>

namespace Modules {

namespace {

void RenderStepHeader(const char* title, const char* description) {
    ImGui::PushStyleColor(ImGuiCol_Text, Theme::kTeal);
    ImGui::TextUnformatted(title);
    ImGui::PopStyleColor();

    ImGui::PushStyleColor(ImGuiCol_Text, Theme::kTextSecondary);
    ImGui::TextWrapped("%s", description);
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();
}

} // namespace

void ReinstallPrep::Initialize() {
    if (m_initialized) {
        return;
    }

    m_backupFiles.title = "Recovery material only";
    m_backupFiles.items = {
        { "BitLocker recovery keys exported", "Store recovery keys offline before touching partitions.", false, false, Widgets::ChecklistRisk::Critical },
        { "Licenses and installers recorded", "Keep product keys, installer links, and vendor account recovery data.", false, false, Widgets::ChecklistRisk::High },
        { "Old user folders intentionally excluded", "For a no-files-kept privacy reset, do not copy old Desktop, Documents, browser profiles, or app data wholesale.", false, false, Widgets::ChecklistRisk::High },
    };

    m_browserData.title = "Browser and account reset";
    m_browserData.items = {
        { "Sync choices reviewed", "Know which accounts will sync extensions, history, passwords, or device state back onto the new install.", false, false, Widgets::ChecklistRisk::Medium },
        { "Fresh browser profile planned", "Use a new browser profile or a portable browser inside a privacy session for sensitive work.", false, false, Widgets::ChecklistRisk::Medium },
        { "Old cookies and tokens not restored", "Avoid importing session cookies or full profile folders from the old OS.", false, false, Widgets::ChecklistRisk::High },
    };

    m_appConfigs.title = "Application carry-over";
    m_appConfigs.items = {
        { "Essential apps listed", "Write down the apps you actually need rather than restoring everything from the old install.", false, false, Widgets::ChecklistRisk::Low },
        { "Secrets stored safely", "Move password manager exports, recovery codes, and SSH keys only through trusted encrypted storage.", false, false, Widgets::ChecklistRisk::High },
        { "Telemetry-heavy apps deferred", "Install account-heavy apps only after Windows privacy settings are reviewed.", false, false, Widgets::ChecklistRisk::Medium },
    };

    m_wifiProfiles.title = "Network profile reset";
    m_wifiProfiles.items = {
        { "Wi-Fi passwords available", "Keep only the network passwords you still trust.", false, false, Widgets::ChecklistRisk::Medium },
        { "Old known networks not imported", "Let the new install learn networks deliberately instead of importing all prior profiles.", false, false, Widgets::ChecklistRisk::Medium },
        { "Router admin access confirmed", "Confirm you can rotate Wi-Fi credentials if the old install was compromised.", false, false, Widgets::ChecklistRisk::High },
    };

    m_bitlockerKeys.title = "Disk encryption";
    m_bitlockerKeys.items = {
        { "Recovery keys backed up offline", "Do this before deleting partitions or changing Secure Boot, TPM, or firmware settings.", false, false, Widgets::ChecklistRisk::Critical },
        { "Protection suspended before firmware changes", "Suspend BitLocker only when needed and resume it after the system is stable.", false, false, Widgets::ChecklistRisk::High },
        { "New encryption plan selected", "Decide whether the new install will use BitLocker before placing sensitive files on it.", false, false, Widgets::ChecklistRisk::Medium },
    };

    m_windowsLicense.title = "Windows identity choices";
    m_windowsLicense.items = {
        { "Edition and activation known", "Confirm the intended Windows edition and activation path.", false, false, Widgets::ChecklistRisk::Low },
        { "Initial account type selected", "Use a fresh local profile first where supported, then add Microsoft or work accounts deliberately.", false, false, Widgets::ChecklistRisk::Medium },
        { "Device name planned", "Pick a neutral computer name before joining networks or accounts.", false, false, Widgets::ChecklistRisk::Low },
    };

    m_installMedia.title = "Install media";
    m_installMedia.items = {
        { "Trusted Windows USB created", "Use official or otherwise trusted media and verify it boots as UEFI.", false, false, Widgets::ChecklistRisk::High },
        { "Network kept offline for setup", "Stay offline until privacy choices are configured on first boot.", false, false, Widgets::ChecklistRisk::Medium },
        { "Recovery media tested", "Confirm you can boot back into setup or recovery before deleting partitions.", false, false, Widgets::ChecklistRisk::High },
    };

    m_driverPrep.title = "Drivers and firmware";
    m_driverPrep.items = {
        { "Storage or RAID driver saved", "If RAID/VMD is enabled, keep the storage driver available during Windows Setup.", false, false, Widgets::ChecklistRisk::High },
        { "Firmware settings recorded", "Photograph or write down boot mode, Secure Boot, TPM, and storage controller settings.", false, false, Widgets::ChecklistRisk::Medium },
        { "Vendor drivers staged", "Download chipset, network, GPU, and firmware tools from trusted vendor pages.", false, false, Widgets::ChecklistRisk::Medium },
    };

    m_finalConfirm.title = "Final no-files-kept confirmation";
    m_finalConfirm.items = {
        { "Target disk identified", "Match disk size, model, and serial before deleting partitions.", false, false, Widgets::ChecklistRisk::Critical },
        { "No old profile import planned", "Commit to reinstalling apps and signing into accounts deliberately.", false, false, Widgets::ChecklistRisk::High },
        { "Post-install privacy baseline ready", "Plan to disable advertising ID, tailored experiences, unnecessary diagnostics, and unwanted sync features.", false, false, Widgets::ChecklistRisk::Medium },
    };

    m_initialized = true;
}

void ReinstallPrep::Render() {
    Initialize();

    RenderStepHeader("Reinstall Preparation", "Prepare a clean Windows reinstall that keeps no old files or profile state. This page is a checklist; it does not delete files or change disks.");

    float progress = GetOverallProgress();
    ImGui::Text("Overall readiness: %d%%", static_cast<int>(progress * 100.0f));
    ImGui::ProgressBar(progress, ImVec2(-1.0f, 0.0f));
    ImGui::Spacing();

    RenderStepNav();
    ImGui::Spacing();
    RenderStep(m_currentStep);
}

float ReinstallPrep::GetOverallProgress() const {
    const Widgets::Checklist* lists[] = {
        &m_backupFiles,
        &m_browserData,
        &m_appConfigs,
        &m_wifiProfiles,
        &m_bitlockerKeys,
        &m_windowsLicense,
        &m_installMedia,
        &m_driverPrep,
        &m_finalConfirm,
    };

    int checked = 0;
    int total = 0;
    for (const auto* list : lists) {
        checked += list->GetCheckedCount();
        total += list->GetTotalCount();
    }

    if (total == 0) {
        return 0.0f;
    }
    return static_cast<float>(checked) / static_cast<float>(total);
}

bool ReinstallPrep::IsReady() const {
    return GetOverallProgress() >= 1.0f;
}

void ReinstallPrep::RenderStepNav() {
    if (ImGui::Button("<", ImVec2(32, 0))) {
        m_currentStep = (std::max)(0, m_currentStep - 1);
    }
    ImGui::SameLine();

    ImGui::Text("%d / %d", m_currentStep + 1, STEP_COUNT);
    ImGui::SameLine();

    if (ImGui::Button(">", ImVec2(32, 0))) {
        m_currentStep = (std::min)(STEP_COUNT - 1, m_currentStep + 1);
    }

    ImGui::Spacing();
    for (int i = 0; i < STEP_COUNT; ++i) {
        ImGui::PushID(i);
        bool selected = (m_currentStep == i);
        if (ImGui::Selectable(GetStepName(i), selected, 0, ImVec2(220, 0))) {
            m_currentStep = i;
        }
        ImGui::PopID();
        if ((i + 1) % 3 != 0) {
            ImGui::SameLine();
        }
    }
}

void ReinstallPrep::RenderStep(int step) {
    switch (step) {
        case 0: m_backupFiles.Render(); break;
        case 1: m_browserData.Render(); break;
        case 2: m_appConfigs.Render(); break;
        case 3: m_wifiProfiles.Render(); break;
        case 4: m_bitlockerKeys.Render(); break;
        case 5: m_windowsLicense.Render(); break;
        case 6: m_installMedia.Render(); break;
        case 7: m_driverPrep.Render(); break;
        case 8: m_finalConfirm.Render(); break;
        default: m_currentStep = 0; m_backupFiles.Render(); break;
    }
}

const char* ReinstallPrep::GetStepName(int step) {
    static const char* names[] = {
        "Recovery material",
        "Browser reset",
        "Apps",
        "Wi-Fi",
        "BitLocker",
        "Windows identity",
        "Install media",
        "Drivers",
        "Final confirm",
    };

    if (step < 0 || step >= STEP_COUNT) {
        return "Unknown";
    }
    return names[step];
}

} // namespace Modules
