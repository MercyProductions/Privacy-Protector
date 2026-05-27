#include "modules/tpm_security.h"
#include "imgui/imgui.h"
#include "core/wmi_query.h"
#include "core/powershell.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sstream>
#include <algorithm>

namespace Modules {

// ── Theme colors ──────────────────────────────────────────────────────
static const ImVec4 kTeal     = ImVec4(0.0f, 0.831f, 0.667f, 1.0f);
static const ImVec4 kAmber    = ImVec4(0.941f, 0.706f, 0.161f, 1.0f);
static const ImVec4 kRed      = ImVec4(0.906f, 0.298f, 0.235f, 1.0f);
static const ImVec4 kGreen    = ImVec4(0.180f, 0.800f, 0.443f, 1.0f);
static const ImVec4 kText     = ImVec4(0.902f, 0.929f, 0.953f, 1.0f);
static const ImVec4 kTextDim  = ImVec4(0.545f, 0.580f, 0.620f, 1.0f);
static const ImVec4 kSurface  = ImVec4(0.110f, 0.129f, 0.157f, 1.0f);

// ── InitChecklist ────────────────────────────────────────────────────
void TpmSecurity::InitChecklist() {
    m_recoveryChecklist = Widgets::Checklist("bitlocker_recovery");
    m_recoveryChecklist.AddItem("recovery_ms", "Recovery key saved to Microsoft Account");
    m_recoveryChecklist.AddItem("recovery_usb", "Recovery key saved to USB drive");
    m_recoveryChecklist.AddItem("recovery_print", "Recovery key printed on paper");
    m_recoveryChecklist.AddItem("recovery_written", "Recovery key written down / stored securely");
}

// ── Refresh ──────────────────────────────────────────────────────────
void TpmSecurity::Refresh() {
    m_state = SecurityState{};
    InitChecklist();

    // ── TPM ──────────────────────────────────────────────────────
    try {
        auto rows = Core::WmiQuery::Query(
            "ROOT\\CIMV2\\Security\\MicrosoftTpm",
            "SELECT IsEnabled_InitialValue, IsActivated_InitialValue, "
            "SpecVersion, ManufacturerId, ManufacturerVersion FROM Win32_Tpm");

        if (!rows.empty()) {
            auto& r = rows[0];
            m_state.tpm.present       = true;
            m_state.tpm.enabled       = (r["IsEnabled_InitialValue"] == "TRUE" ||
                                          r["IsEnabled_InitialValue"] == "True" ||
                                          r["IsEnabled_InitialValue"] == "1");
            m_state.tpm.activated     = (r["IsActivated_InitialValue"] == "TRUE" ||
                                          r["IsActivated_InitialValue"] == "True" ||
                                          r["IsActivated_InitialValue"] == "1");
            m_state.tpm.specVersion      = r["SpecVersion"];
            m_state.tpm.manufacturer     = r["ManufacturerId"];
            m_state.tpm.firmwareVersion  = r["ManufacturerVersion"];
        }
    }
    catch (...) {
        // WMI query to TPM namespace often needs admin
        m_state.requiresAdmin = true;
    }

    // ── Secure Boot ─────────────────────────────────────────────
    try {
        HKEY hKey = nullptr;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            m_state.secureBoot.supported = true;
            DWORD value = 0;
            DWORD size = sizeof(value);
            if (RegQueryValueExA(hKey, "UEFISecureBootEnabled", nullptr, nullptr,
                reinterpret_cast<LPBYTE>(&value), &size) == ERROR_SUCCESS) {
                m_state.secureBoot.enabled = (value == 1);
            }
            RegCloseKey(hKey);
        }
    }
    catch (...) {
        // Secure Boot registry key may not exist on legacy BIOS systems
    }

    // ── BitLocker ────────────────────────────────────────────────
    try {
        std::string psCmd =
            "Get-BitLockerVolume | ForEach-Object { "
            "$_.MountPoint + '|' + $_.ProtectionStatus + '|' + "
            "$_.EncryptionMethod + '|' + $_.VolumeStatus }";

        auto result = Core::PowerShell::Execute(psCmd);
        if (result.exitCode == 0 && !result.output.empty()) {
            std::istringstream stream(result.output);
            std::string line;
            while (std::getline(stream, line)) {
                // Trim whitespace
                while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
                    line.pop_back();
                if (line.empty()) continue;

                BitLockerVolume vol;
                size_t p1 = line.find('|');
                size_t p2 = line.find('|', p1 + 1);
                size_t p3 = line.find('|', p2 + 1);

                if (p1 != std::string::npos && p2 != std::string::npos && p3 != std::string::npos) {
                    vol.driveLetter      = line.substr(0, p1);
                    vol.protectionStatus = line.substr(p1 + 1, p2 - p1 - 1);
                    vol.encryptionMethod = line.substr(p2 + 1, p3 - p2 - 1);
                    vol.volumeStatus     = line.substr(p3 + 1);
                    vol.isProtected      = (vol.protectionStatus == "On" || vol.protectionStatus == "1");
                    m_state.bitlockerVolumes.push_back(std::move(vol));
                }
            }
        }
    }
    catch (...) {
        // BitLocker cmdlets may not be available or require admin
        m_state.requiresAdmin = true;
    }

    m_state.collected = true;
}

// ── GetOverallStatus ─────────────────────────────────────────────────
Widgets::CardStatus TpmSecurity::GetOverallStatus() const {
    if (!m_state.collected) return Widgets::CardStatus::Unknown;

    bool hasCritical = false;
    bool hasWarning  = false;

    // TPM not present is a warning for Windows 11
    if (!m_state.tpm.present) hasWarning = true;
    if (m_state.tpm.present && !m_state.tpm.enabled) hasWarning = true;

    // Secure Boot disabled is a warning
    if (m_state.secureBoot.supported && !m_state.secureBoot.enabled) hasWarning = true;

    // BitLocker protected volumes are critical (need recovery key backup)
    for (auto& v : m_state.bitlockerVolumes) {
        if (v.isProtected) hasCritical = true;
    }

    if (hasCritical) return Widgets::CardStatus::Critical;
    if (hasWarning)  return Widgets::CardStatus::Warning;
    return Widgets::CardStatus::Good;
}

// ── Render helpers ───────────────────────────────────────────────────
static void RenderInfoRow(const char* label, const std::string& value,
                          const ImVec4& valueColor = kText) {
    ImGui::TextColored(kTextDim, "%s", label);
    ImGui::SameLine(200.0f);
    ImGui::TextColored(valueColor, "%s", value.empty() ? "N/A" : value.c_str());
}

static void RenderStatusBadge(const char* text, const ImVec4& color) {
    ImVec2 textSize = ImGui::CalcTextSize(text);
    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float pad = 6.0f;
    dl->AddRectFilled(
        ImVec2(pos.x, pos.y),
        ImVec2(pos.x + textSize.x + pad * 2, pos.y + textSize.y + pad),
        ImGui::ColorConvertFloat4ToU32(ImVec4(color.x, color.y, color.z, 0.2f)),
        4.0f);
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + pad);
    ImGui::TextColored(color, "%s", text);
}

// ── Render ───────────────────────────────────────────────────────────
void TpmSecurity::Render() {
    ImGui::TextColored(kTeal, "TPM / Secure Boot / BitLocker");
    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 80.0f);
    if (ImGui::Button("Refresh##tpm", ImVec2(80, 0))) {
        Refresh();
    }
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (!m_state.collected) {
        ImGui::TextColored(kTextDim, "Click 'Refresh' to scan TPM and security state.");
        return;
    }

    // ── Admin warning ────────────────────────────────────────────
    if (m_state.requiresAdmin) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(kAmber.x, kAmber.y, kAmber.z, 0.1f));
        ImGui::BeginChild("##admin_warn", ImVec2(0, 40), ImGuiChildFlags_Borders);
        ImGui::TextColored(kAmber, "  Run as Administrator for full TPM/BitLocker data");
        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::Spacing();
    }

    ImGui::BeginChild("##tpm_scroll", ImVec2(0, 0), ImGuiChildFlags_None);

    // ════════════════════════════════════════════════════════════
    //  TPM Status
    // ════════════════════════════════════════════════════════════
    ImGui::TextColored(kTeal, "TPM Status");
    ImGui::Spacing();

    ImGui::PushStyleColor(ImGuiCol_ChildBg, kSurface);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
    ImGui::BeginChild("##tpm_card", ImVec2(0, 0), ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_Borders);
    ImGui::Spacing();
    ImGui::Indent(12.0f);

    if (m_state.tpm.present) {
        RenderInfoRow("Present:", "Yes", kGreen);
        RenderInfoRow("Enabled:", m_state.tpm.enabled ? "Yes" : "No",
                      m_state.tpm.enabled ? kGreen : kRed);
        RenderInfoRow("Activated:", m_state.tpm.activated ? "Yes" : "No",
                      m_state.tpm.activated ? kGreen : kRed);
        RenderInfoRow("Spec Version:", m_state.tpm.specVersion);
        RenderInfoRow("Manufacturer:", m_state.tpm.manufacturer);
        RenderInfoRow("Firmware:", m_state.tpm.firmwareVersion);
    } else {
        RenderInfoRow("Present:", "No", kRed);
        ImGui::Spacing();
        ImGui::TextColored(kAmber,
            "No TPM detected. Windows 11 requires TPM 2.0.");
    }

    ImGui::Spacing();

    // TPM clear warning
    if (m_state.tpm.present) {
        if (ImGui::CollapsingHeader("What does TPM clear affect?")) {
            ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(kAmber.x, kAmber.y, kAmber.z, 0.08f));
            ImGui::BeginChild("##tpm_clear_info", ImVec2(0, 0), ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_Borders);
            ImGui::Spacing();
            ImGui::Indent(8.0f);
            ImGui::TextColored(kAmber, "Clearing TPM will:");
            ImGui::BulletText("Invalidate BitLocker recovery keys (data loss risk!)");
            ImGui::BulletText("Reset Windows Hello (fingerprint, face, PIN)");
            ImGui::BulletText("Remove FIDO2 security keys stored in TPM");
            ImGui::BulletText("Reset device encryption keys");
            ImGui::BulletText("Invalidate any TPM-bound certificates");
            ImGui::Spacing();
            ImGui::TextColored(kRed, "Always back up BitLocker recovery keys BEFORE clearing TPM!");
            ImGui::Unindent(8.0f);
            ImGui::Spacing();
            ImGui::EndChild();
            ImGui::PopStyleColor();
        }
    }

    ImGui::Unindent(12.0f);
    ImGui::Spacing();
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    ImGui::Spacing();
    ImGui::Spacing();

    // ════════════════════════════════════════════════════════════
    //  Secure Boot
    // ════════════════════════════════════════════════════════════
    ImGui::TextColored(kTeal, "Secure Boot");
    ImGui::Spacing();

    ImGui::PushStyleColor(ImGuiCol_ChildBg, kSurface);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
    ImGui::BeginChild("##secboot_card", ImVec2(0, 0), ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_Borders);
    ImGui::Spacing();
    ImGui::Indent(12.0f);

    if (m_state.secureBoot.supported) {
        RenderInfoRow("Supported:", "Yes", kGreen);
        RenderInfoRow("Enabled:", m_state.secureBoot.enabled ? "Yes" : "No",
                      m_state.secureBoot.enabled ? kGreen : kAmber);
        if (!m_state.secureBoot.enabled) {
            ImGui::Spacing();
            ImGui::TextColored(kAmber,
                "Secure Boot is disabled. Enable it in BIOS for Windows 11 compatibility.");
        }
    } else {
        RenderInfoRow("Supported:", "Not detected", kTextDim);
        ImGui::TextColored(kTextDim, "System may use Legacy BIOS (non-UEFI).");
    }

    ImGui::Unindent(12.0f);
    ImGui::Spacing();
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    ImGui::Spacing();
    ImGui::Spacing();

    // ════════════════════════════════════════════════════════════
    //  BitLocker
    // ════════════════════════════════════════════════════════════
    ImGui::TextColored(kTeal, "BitLocker Encryption");
    ImGui::Spacing();

    bool anyProtected = false;
    for (auto& v : m_state.bitlockerVolumes) {
        if (v.isProtected) anyProtected = true;
    }

    // Critical warning if protected volumes exist
    if (anyProtected) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(kRed.x, kRed.y, kRed.z, 0.12f));
        ImGui::BeginChild("##bl_critical", ImVec2(0, 50), ImGuiChildFlags_Borders);
        ImGui::Spacing();
        ImGui::TextColored(kRed, "  CRITICAL: Back up your BitLocker recovery keys BEFORE reinstalling!");
        ImGui::TextColored(kRed, "  Without recovery keys, encrypted data will be permanently inaccessible.");
        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::Spacing();
    }

    ImGui::PushStyleColor(ImGuiCol_ChildBg, kSurface);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
    ImGui::BeginChild("##bl_card", ImVec2(0, 0), ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_Borders);
    ImGui::Spacing();
    ImGui::Indent(12.0f);

    if (m_state.bitlockerVolumes.empty()) {
        ImGui::TextColored(kTextDim, "No BitLocker volumes detected.");
        ImGui::TextColored(kTextDim, "(Requires Administrator privileges to query)");
    } else {
        // Volume table
        if (ImGui::BeginTable("##bl_table", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Drive");
            ImGui::TableSetupColumn("Protection");
            ImGui::TableSetupColumn("Encryption");
            ImGui::TableSetupColumn("Status");
            ImGui::TableHeadersRow();

            for (auto& vol : m_state.bitlockerVolumes) {
                ImGui::TableNextRow();

                ImGui::TableNextColumn();
                ImGui::TextColored(kText, "%s", vol.driveLetter.c_str());

                ImGui::TableNextColumn();
                ImVec4 protColor = vol.isProtected ? kGreen : kTextDim;
                ImGui::TextColored(protColor, "%s", vol.protectionStatus.c_str());

                ImGui::TableNextColumn();
                ImGui::TextColored(kText, "%s", vol.encryptionMethod.c_str());

                ImGui::TableNextColumn();
                ImGui::TextColored(kText, "%s", vol.volumeStatus.c_str());
            }
            ImGui::EndTable();
        }
    }

    ImGui::Unindent(12.0f);
    ImGui::Spacing();
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();

    // ── Recovery Key Checklist ───────────────────────────────────
    if (anyProtected) {
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::TextColored(kAmber, "Recovery Key Backup Checklist");
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_ChildBg, kSurface);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
        ImGui::BeginChild("##recovery_cl", ImVec2(0, 0), ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_Borders);
        ImGui::Spacing();
        ImGui::Indent(12.0f);

        m_recoveryChecklist.Render();

        ImGui::Unindent(12.0f);
        ImGui::Spacing();
        ImGui::EndChild();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();
    }

    ImGui::EndChild(); // tpm_scroll
}

} // namespace Modules
