#include "modules/storage_raid.h"
#include "imgui/imgui.h"
#include "core/wmi_query.h"
#include "core/powershell.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace Modules {

// ── Theme colors ──────────────────────────────────────────────────────
static const ImVec4 kTeal     = ImVec4(0.0f, 0.831f, 0.667f, 1.0f);
static const ImVec4 kAmber    = ImVec4(0.941f, 0.706f, 0.161f, 1.0f);
static const ImVec4 kRed      = ImVec4(0.906f, 0.298f, 0.235f, 1.0f);
static const ImVec4 kGreen    = ImVec4(0.180f, 0.800f, 0.443f, 1.0f);
static const ImVec4 kBlue     = ImVec4(0.204f, 0.596f, 0.859f, 1.0f);
static const ImVec4 kText     = ImVec4(0.902f, 0.929f, 0.953f, 1.0f);
static const ImVec4 kTextDim  = ImVec4(0.545f, 0.580f, 0.620f, 1.0f);
static const ImVec4 kSurface  = ImVec4(0.110f, 0.129f, 0.157f, 1.0f);

// ── Utility ──────────────────────────────────────────────────────────
static std::string FormatBytes(uint64_t bytes) {
    const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    int idx = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024.0 && idx < 4) {
        size /= 1024.0;
        idx++;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "%.1f %s", size, units[idx]);
    return buf;
}

static std::string ToUpper(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return out;
}

static bool ContainsCI(const std::string& haystack, const std::string& needle) {
    std::string h = ToUpper(haystack);
    std::string n = ToUpper(needle);
    return h.find(n) != std::string::npos;
}

static std::string BusTypeToString(int busType) {
    switch (busType) {
        case 1:  return "SCSI";
        case 2:  return "ATAPI";
        case 3:  return "ATA";
        case 4:  return "IEEE 1394";
        case 5:  return "SSA";
        case 6:  return "Fibre Channel";
        case 7:  return "USB";
        case 8:  return "RAID";
        case 9:  return "iSCSI";
        case 10: return "SAS";
        case 11: return "SATA";
        case 12: return "SD";
        case 13: return "MMC";
        case 14: return "Virtual";
        case 15: return "File Backed Virtual";
        case 16: return "Storage Spaces";
        case 17: return "NVMe";
        default: return "Unknown";
    }
}

static std::string MediaTypeToString(int mediaType) {
    switch (mediaType) {
        case 0:  return "Unspecified";
        case 3:  return "HDD";
        case 4:  return "SSD";
        case 5:  return "SCM";
        default: return "Unknown";
    }
}

// ── InitChecklist ────────────────────────────────────────────────────
void StorageRaid::InitChecklist() {
    m_preReinstallChecklist = Widgets::Checklist("storage_prereinstall");
    m_preReinstallChecklist.AddItem("data_backed", "All data backed up from RAID volumes?");
    m_preReinstallChecklist.AddItem("raid_driver", "RAID driver downloaded for Windows installer?");
    m_preReinstallChecklist.AddItem("raid_config", "RAID configuration documented?");
    m_preReinstallChecklist.AddItem("mode_risks", "Understand controller mode change risks?");
}

// ── DetectControllerModes ────────────────────────────────────────────
void StorageRaid::DetectControllerModes() {
    // Query SCSI controllers
    try {
        auto rows = Core::WmiQuery::QueryCimv2(
            "SELECT Name, Manufacturer, DriverName FROM Win32_SCSIController");
        for (auto& r : rows) {
            StorageController ctrl;
            ctrl.name         = r["Name"];
            ctrl.manufacturer = r["Manufacturer"];
            ctrl.driverName   = r["DriverName"];

            // Determine mode from name / driver
            std::string nameUpper = ToUpper(ctrl.name);
            if (ContainsCI(nameUpper, "NVME")) {
                ctrl.mode = "NVMe";
            } else if (ContainsCI(nameUpper, "RAID") || ContainsCI(ctrl.driverName, "iaStorA") ||
                       ContainsCI(ctrl.driverName, "iaStorV")) {
                ctrl.mode = "RAID";
            } else if (ContainsCI(nameUpper, "VMD")) {
                ctrl.mode = "VMD";
            } else if (ContainsCI(nameUpper, "AHCI") || ContainsCI(ctrl.driverName, "storahci")) {
                ctrl.mode = "AHCI";
            } else {
                ctrl.mode = "Unknown";
            }

            m_state.controllers.push_back(std::move(ctrl));
        }
    }
    catch (...) {}

    // Query IDE controllers (legacy)
    try {
        auto rows = Core::WmiQuery::QueryCimv2(
            "SELECT Name, Manufacturer FROM Win32_IDEController");
        for (auto& r : rows) {
            StorageController ctrl;
            ctrl.name         = r["Name"];
            ctrl.manufacturer = r["Manufacturer"];
            ctrl.driverName   = "";

            std::string nameUpper = ToUpper(ctrl.name);
            if (ContainsCI(nameUpper, "AHCI")) {
                ctrl.mode = "AHCI";
            } else if (ContainsCI(nameUpper, "RAID")) {
                ctrl.mode = "RAID";
            } else {
                ctrl.mode = "IDE";
            }

            m_state.controllers.push_back(std::move(ctrl));
        }
    }
    catch (...) {}

    // Check Intel RST registry key
    try {
        HKEY hKey = nullptr;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\iaStorV",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            // iaStorV service exists = Intel RST / RAID mode likely active
            bool alreadyHasRaid = false;
            for (auto& c : m_state.controllers) {
                if (c.mode == "RAID") { alreadyHasRaid = true; break; }
            }
            if (!alreadyHasRaid) {
                StorageController rstCtrl;
                rstCtrl.name = "Intel Rapid Storage Technology";
                rstCtrl.manufacturer = "Intel";
                rstCtrl.driverName = "iaStorV";
                rstCtrl.mode = "RAID";
                m_state.controllers.push_back(std::move(rstCtrl));
            }
            RegCloseKey(hKey);
        }
    }
    catch (...) {}
}

// ── DetectRaid ───────────────────────────────────────────────────────
void StorageRaid::DetectRaid() {
    // Check for Windows Storage Spaces
    try {
        std::string psCmd =
            "Get-StoragePool | Where-Object { $_.IsPrimordial -eq $false } | "
            "ForEach-Object { $_.FriendlyName + '|' + $_.OperationalStatus }";

        auto result = Core::PowerShell::Execute(psCmd);
        if (result.exitCode == 0 && !result.output.empty()) {
            std::istringstream stream(result.output);
            std::string line;
            while (std::getline(stream, line)) {
                while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                    line.pop_back();
                if (line.empty()) continue;

                size_t sep = line.find('|');
                RaidArray arr;
                arr.name   = (sep != std::string::npos) ? line.substr(0, sep) : line;
                arr.status = (sep != std::string::npos) ? line.substr(sep + 1) : "Unknown";
                arr.level  = "Storage Spaces";
                m_state.arrays.push_back(std::move(arr));
                m_state.raidDetected = true;
            }
        }
    }
    catch (...) {}

    // Check for Intel RST RAID arrays via registry
    try {
        HKEY hKey = nullptr;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\iaStorV\\Parameters\\Device",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            // Presence of this key with device entries indicates RAID arrays
            if (!m_state.raidDetected) {
                // Mark as detected even if we can't enumerate individual arrays
                for (auto& c : m_state.controllers) {
                    if (c.mode == "RAID") {
                        m_state.raidDetected = true;
                        break;
                    }
                }
            }
            RegCloseKey(hKey);
        }
    }
    catch (...) {}

    // Also check if any disk bus type is RAID
    for (auto& d : m_state.disks) {
        if (d.busType == "RAID") {
            m_state.raidDetected = true;
            break;
        }
    }
}

// ── Refresh ──────────────────────────────────────────────────────────
void StorageRaid::Refresh() {
    m_state = StorageState{};
    InitChecklist();

    // ── Detect controller modes ──────────────────────────────────
    DetectControllerModes();

    // ── Disks from Win32_DiskDrive ───────────────────────────────
    try {
        auto rows = Core::WmiQuery::QueryCimv2(
            "SELECT Model, SerialNumber, Size, InterfaceType, MediaType FROM Win32_DiskDrive");
        for (auto& r : rows) {
            DiskInfo disk;
            disk.model     = r["Model"];
            disk.serial    = r["SerialNumber"];
            disk.mediaType = r["MediaType"];
            disk.busType   = r["InterfaceType"];
            try { disk.sizeBytes = std::stoull(r["Size"]); } catch (...) {}
            m_state.disks.push_back(std::move(disk));
        }
    }
    catch (...) {}

    // ── Enhanced disk info from MSFT_PhysicalDisk ────────────────
    try {
        auto rows = Core::WmiQuery::Query(
            "ROOT\\Microsoft\\Windows\\Storage",
            "SELECT FriendlyName, SerialNumber, BusType, MediaType, HealthStatus, Size FROM MSFT_PhysicalDisk");
        for (auto& r : rows) {
            // Try to match by serial or model to existing disks
            std::string serial = r["SerialNumber"];
            std::string friendly = r["FriendlyName"];
            int busTypeInt = 0;
            int mediaTypeInt = 0;
            try { busTypeInt = std::stoi(r["BusType"]); }     catch (...) {}
            try { mediaTypeInt = std::stoi(r["MediaType"]); } catch (...) {}

            bool matched = false;
            for (auto& d : m_state.disks) {
                if ((!serial.empty() && d.serial == serial) ||
                    (!friendly.empty() && d.model.find(friendly) != std::string::npos)) {
                    d.busType      = BusTypeToString(busTypeInt);
                    d.mediaType    = MediaTypeToString(mediaTypeInt);
                    d.healthStatus = r["HealthStatus"];
                    if (d.sizeBytes == 0) {
                        try { d.sizeBytes = std::stoull(r["Size"]); } catch (...) {}
                    }
                    matched = true;
                    break;
                }
            }

            if (!matched) {
                DiskInfo disk;
                disk.model        = friendly;
                disk.serial       = serial;
                disk.busType      = BusTypeToString(busTypeInt);
                disk.mediaType    = MediaTypeToString(mediaTypeInt);
                disk.healthStatus = r["HealthStatus"];
                try { disk.sizeBytes = std::stoull(r["Size"]); } catch (...) {}
                m_state.disks.push_back(std::move(disk));
            }
        }
    }
    catch (...) {}

    // ── OS System Drive ──────────────────────────────────────────
    try {
        auto rows = Core::WmiQuery::QueryCimv2(
            "SELECT SystemDrive FROM Win32_OperatingSystem");
        if (!rows.empty()) {
            m_state.osSystemDrive = rows[0]["SystemDrive"];
        }
    }
    catch (...) {
        m_state.osSystemDrive = "C:";
    }

    // ── Detect RAID ──────────────────────────────────────────────
    DetectRaid();

    m_state.collected = true;
}

// ── Render helpers ───────────────────────────────────────────────────
static void RenderModeBadge(const std::string& mode) {
    ImVec4 color = kTextDim;
    if (mode == "AHCI")      color = kBlue;
    else if (mode == "RAID") color = kAmber;
    else if (mode == "NVMe") color = kGreen;
    else if (mode == "VMD")  color = kTeal;

    ImVec2 textSize = ImGui::CalcTextSize(mode.c_str());
    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float padX = 8.0f, padY = 3.0f;
    dl->AddRectFilled(
        ImVec2(pos.x, pos.y),
        ImVec2(pos.x + textSize.x + padX * 2, pos.y + textSize.y + padY * 2),
        ImGui::ColorConvertFloat4ToU32(ImVec4(color.x, color.y, color.z, 0.2f)),
        4.0f);
    dl->AddRect(
        ImVec2(pos.x, pos.y),
        ImVec2(pos.x + textSize.x + padX * 2, pos.y + textSize.y + padY * 2),
        ImGui::ColorConvertFloat4ToU32(ImVec4(color.x, color.y, color.z, 0.5f)),
        4.0f);
    ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPos().x + padX, ImGui::GetCursorPos().y + padY));
    ImGui::TextColored(color, "%s", mode.c_str());
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + padY);
}

// ── Render ───────────────────────────────────────────────────────────
void StorageRaid::Render() {
    ImGui::TextColored(kTeal, "Storage & RAID");
    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 80.0f);
    if (ImGui::Button("Refresh##stor", ImVec2(80, 0))) {
        Refresh();
    }
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (!m_state.collected) {
        ImGui::TextColored(kTextDim, "Click 'Refresh' to scan storage controllers and disks.");
        return;
    }

    ImGui::BeginChild("##stor_scroll", ImVec2(0, 0), ImGuiChildFlags_None);

    // ════════════════════════════════════════════════════════════
    //  Storage Controllers
    // ════════════════════════════════════════════════════════════
    ImGui::TextColored(kTeal, "Storage Controllers");
    ImGui::Spacing();

    if (m_state.controllers.empty()) {
        ImGui::TextColored(kTextDim, "No storage controllers detected.");
    } else {
        for (size_t i = 0; i < m_state.controllers.size(); i++) {
            auto& ctrl = m_state.controllers[i];
            ImGui::PushID(static_cast<int>(i));

            ImGui::PushStyleColor(ImGuiCol_ChildBg, kSurface);
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
            ImGui::BeginChild("##ctrl", ImVec2(0, 0), ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_Borders);
            ImGui::Spacing();
            ImGui::Indent(12.0f);

            ImGui::TextColored(kText, "%s", ctrl.name.c_str());
            ImGui::SameLine();
            RenderModeBadge(ctrl.mode);

            if (!ctrl.manufacturer.empty()) {
                ImGui::TextColored(kTextDim, "Manufacturer: %s", ctrl.manufacturer.c_str());
            }
            if (!ctrl.driverName.empty()) {
                ImGui::TextColored(kTextDim, "Driver: %s", ctrl.driverName.c_str());
            }

            ImGui::Unindent(12.0f);
            ImGui::Spacing();
            ImGui::EndChild();
            ImGui::PopStyleVar();
            ImGui::PopStyleColor();
            ImGui::Spacing();

            ImGui::PopID();
        }
    }
    ImGui::Spacing();

    // ════════════════════════════════════════════════════════════
    //  Physical Disks
    // ════════════════════════════════════════════════════════════
    ImGui::TextColored(kTeal, "Physical Disks");
    ImGui::Spacing();

    if (m_state.disks.empty()) {
        ImGui::TextColored(kTextDim, "No disks detected.");
    } else {
        if (ImGui::BeginTable("##disk_table", 6,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp |
            ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn("Model", ImGuiTableColumnFlags_WidthStretch, 2.0f);
            ImGui::TableSetupColumn("Size");
            ImGui::TableSetupColumn("Type");
            ImGui::TableSetupColumn("Bus");
            ImGui::TableSetupColumn("Health");
            ImGui::TableSetupColumn("Boot");
            ImGui::TableHeadersRow();

            for (auto& disk : m_state.disks) {
                ImGui::TableNextRow();

                ImGui::TableNextColumn();
                ImGui::TextColored(kText, "%s", disk.model.c_str());

                ImGui::TableNextColumn();
                ImGui::TextColored(kText, "%s", FormatBytes(disk.sizeBytes).c_str());

                ImGui::TableNextColumn();
                ImGui::TextColored(kText, "%s", disk.mediaType.c_str());

                ImGui::TableNextColumn();
                ImVec4 busColor = kText;
                if (disk.busType == "RAID") busColor = kAmber;
                else if (disk.busType == "NVMe") busColor = kGreen;
                ImGui::TextColored(busColor, "%s", disk.busType.c_str());

                ImGui::TableNextColumn();
                if (!disk.healthStatus.empty()) {
                    ImVec4 healthColor = kGreen;
                    if (ContainsCI(disk.healthStatus, "Warning")) healthColor = kAmber;
                    else if (ContainsCI(disk.healthStatus, "Unhealthy")) healthColor = kRed;
                    ImGui::TextColored(healthColor, "%s", disk.healthStatus.c_str());
                } else {
                    ImGui::TextColored(kTextDim, "N/A");
                }

                ImGui::TableNextColumn();
                if (disk.isBootDrive) {
                    ImGui::TextColored(kTeal, "Yes");
                } else {
                    ImGui::TextColored(kTextDim, "-");
                }
            }
            ImGui::EndTable();
        }
    }
    ImGui::Spacing();
    ImGui::Spacing();

    // ════════════════════════════════════════════════════════════
    //  RAID Arrays
    // ════════════════════════════════════════════════════════════
    if (m_state.raidDetected) {
        ImGui::TextColored(kAmber, "RAID Arrays Detected");
        ImGui::Spacing();

        if (m_state.arrays.empty()) {
            ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(kAmber.x, kAmber.y, kAmber.z, 0.08f));
            ImGui::BeginChild("##raid_warn_general", ImVec2(0, 0), ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_Borders);
            ImGui::Spacing();
            ImGui::Indent(12.0f);
            ImGui::TextColored(kAmber,
                "RAID mode detected on storage controller but could not enumerate arrays.");
            ImGui::TextColored(kAmber,
                "Check your BIOS/UEFI RAID configuration before reinstalling.");
            ImGui::Unindent(12.0f);
            ImGui::Spacing();
            ImGui::EndChild();
            ImGui::PopStyleColor();
        } else {
            for (size_t i = 0; i < m_state.arrays.size(); i++) {
                auto& arr = m_state.arrays[i];
                ImGui::PushID(static_cast<int>(1000 + i));

                ImGui::PushStyleColor(ImGuiCol_ChildBg, kSurface);
                ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
                ImGui::BeginChild("##raid_arr", ImVec2(0, 0), ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_Borders);
                ImGui::Spacing();
                ImGui::Indent(12.0f);

                ImGui::TextColored(kText, "%s", arr.name.c_str());
                ImGui::TextColored(kTextDim, "Level: ");
                ImGui::SameLine();
                ImGui::TextColored(kAmber, "%s", arr.level.c_str());
                ImGui::TextColored(kTextDim, "Status: ");
                ImGui::SameLine();
                ImGui::TextColored(kText, "%s", arr.status.c_str());

                if (!arr.memberDisks.empty()) {
                    ImGui::TextColored(kTextDim, "Member Disks:");
                    for (auto& md : arr.memberDisks) {
                        ImGui::BulletText("%s", md.c_str());
                    }
                }

                // RAID 0 specific warning
                if (ContainsCI(arr.level, "RAID0") || arr.level == "RAID 0") {
                    ImGui::Spacing();
                    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(kRed.x, kRed.y, kRed.z, 0.15f));
                    ImGui::BeginChild("##raid0_warn", ImVec2(0, 50), ImGuiChildFlags_Borders);
                    ImGui::Spacing();
                    ImGui::TextColored(kRed,
                        "  WARNING: RAID 0 has NO redundancy.");
                    ImGui::TextColored(kRed,
                        "  If one drive fails, ALL data is lost.");
                    ImGui::EndChild();
                    ImGui::PopStyleColor();
                }

                ImGui::Unindent(12.0f);
                ImGui::Spacing();
                ImGui::EndChild();
                ImGui::PopStyleVar();
                ImGui::PopStyleColor();
                ImGui::Spacing();

                ImGui::PopID();
            }
        }
        ImGui::Spacing();

        // ── Pre-Reinstall Checklist ──────────────────────────────
        ImGui::TextColored(kAmber, "Pre-Reinstall Storage Checklist");
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_ChildBg, kSurface);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
        ImGui::BeginChild("##raid_checklist", ImVec2(0, 0), ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_Borders);
        ImGui::Spacing();
        ImGui::Indent(12.0f);
        m_preReinstallChecklist.Render();
        ImGui::Unindent(12.0f);
        ImGui::Spacing();
        ImGui::EndChild();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();
        ImGui::Spacing();

        // ── Required Drivers Table ───────────────────────────────
        ImGui::TextColored(kTeal, "Required Drivers for Reinstall");
        ImGui::Spacing();

        if (ImGui::BeginTable("##driver_table", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Controller");
            ImGui::TableSetupColumn("Driver");
            ImGui::TableSetupColumn("Source Hint");
            ImGui::TableHeadersRow();

            for (auto& ctrl : m_state.controllers) {
                if (ctrl.mode == "RAID" || ctrl.mode == "VMD") {
                    ImGui::TableNextRow();

                    ImGui::TableNextColumn();
                    ImGui::TextColored(kText, "%s", ctrl.name.c_str());

                    ImGui::TableNextColumn();
                    ImGui::TextColored(kText, "%s",
                        ctrl.driverName.empty() ? "Check manufacturer" : ctrl.driverName.c_str());

                    ImGui::TableNextColumn();
                    if (ContainsCI(ctrl.manufacturer, "Intel") || ContainsCI(ctrl.name, "Intel")) {
                        ImGui::TextColored(kTextDim, "Intel RST / VMD driver from Intel.com");
                    } else if (ContainsCI(ctrl.manufacturer, "AMD")) {
                        ImGui::TextColored(kTextDim, "AMD RAID driver from AMD.com");
                    } else {
                        ImGui::TextColored(kTextDim, "Check motherboard manufacturer website");
                    }
                }
            }
            ImGui::EndTable();
        }
    } else {
        // No RAID — simple message
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(kGreen.x, kGreen.y, kGreen.z, 0.08f));
        ImGui::BeginChild("##no_raid", ImVec2(0, 40), ImGuiChildFlags_Borders);
        ImGui::Spacing();
        ImGui::TextColored(kGreen, "  No RAID arrays detected. Standard reinstall should work without special drivers.");
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    ImGui::EndChild(); // stor_scroll
}

} // namespace Modules
