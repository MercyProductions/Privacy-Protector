#include "modules/system_inventory.h"
#include "imgui/imgui.h"
#include "core/wmi_query.h"
#include "core/admin.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <algorithm>
#include <functional>
#include <sstream>
#include <cctype>

namespace Modules {

// ── Theme colors ──────────────────────────────────────────────────────
static const ImVec4 kTeal     = ImVec4(0.0f, 0.831f, 0.667f, 1.0f);
static const ImVec4 kAmber    = ImVec4(0.941f, 0.706f, 0.161f, 1.0f);
static const ImVec4 kRed      = ImVec4(0.906f, 0.298f, 0.235f, 1.0f);
static const ImVec4 kGreen    = ImVec4(0.180f, 0.800f, 0.443f, 1.0f);
static const ImVec4 kText     = ImVec4(0.902f, 0.929f, 0.953f, 1.0f);
static const ImVec4 kTextDim  = ImVec4(0.545f, 0.580f, 0.620f, 1.0f);
static const ImVec4 kSurface  = ImVec4(0.110f, 0.129f, 0.157f, 1.0f);

// ── Utility ──────────────────────────────────────────────────────────
static std::string ToLower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

static bool MatchesFilter(const std::string& text, const std::string& filter) {
    if (filter.empty()) return true;
    return ToLower(text).find(ToLower(filter)) != std::string::npos;
}

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

static std::string ReadRegistryString(HKEY rootKey, const char* subKey, const char* valueName) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(rootKey, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return "";
    }
    char buffer[512] = {};
    DWORD bufSize = sizeof(buffer);
    DWORD type = 0;
    std::string result;
    if (RegQueryValueExA(hKey, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(buffer), &bufSize) == ERROR_SUCCESS) {
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            result = buffer;
        }
    }
    RegCloseKey(hKey);
    return result;
}

static std::string GetRamTypeName(int smbiosType) {
    switch (smbiosType) {
        case 20: return "DDR";
        case 21: return "DDR2";
        case 22: return "DDR2 FB-DIMM";
        case 24: return "DDR3";
        case 26: return "DDR4";
        case 30: return "LPDDR4";
        case 34: return "DDR5";
        case 35: return "LPDDR5";
        default: return "Unknown";
    }
}

// ── Refresh ──────────────────────────────────────────────────────────
void SystemInventory::Refresh() {
    m_collecting = true;
    m_info = HardwareInfo{};

    try {
        // ── Motherboard ──────────────────────────────────────────
        {
            auto rows = Core::WmiQuery::QueryCimv2(
                "SELECT Manufacturer, Product, SerialNumber, Version FROM Win32_BaseBoard");
            if (!rows.empty()) {
                auto& r = rows[0];
                m_info.mbManufacturer = r["Manufacturer"];
                m_info.mbProduct      = r["Product"];
                m_info.mbSerial       = r["SerialNumber"];
                m_info.mbVersion      = r["Version"];
            }
        }
        // ── BIOS ─────────────────────────────────────────────────
        {
            auto rows = Core::WmiQuery::QueryCimv2(
                "SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate, Version FROM Win32_BIOS");
            if (!rows.empty()) {
                auto& r = rows[0];
                m_info.biosManufacturer = r["Manufacturer"];
                m_info.biosVersion      = r["SMBIOSBIOSVersion"];
                m_info.biosDate         = r["ReleaseDate"];
                m_info.smbiosVersion    = r["Version"];
            }
        }
        // ── CPU ──────────────────────────────────────────────────
        {
            auto rows = Core::WmiQuery::QueryCimv2(
                "SELECT Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor");
            if (!rows.empty()) {
                auto& r = rows[0];
                m_info.cpuName         = r["Name"];
                m_info.cpuManufacturer = r["Manufacturer"];
                try { m_info.cpuCores    = std::stoi(r["NumberOfCores"]); }            catch (...) {}
                try { m_info.cpuThreads  = std::stoi(r["NumberOfLogicalProcessors"]); } catch (...) {}
                try { m_info.cpuMaxClock = std::stoi(r["MaxClockSpeed"]); }             catch (...) {}
            }
        }
        // ── GPU ──────────────────────────────────────────────────
        {
            auto rows = Core::WmiQuery::QueryCimv2(
                "SELECT Name, DriverVersion, AdapterRAM FROM Win32_VideoController");
            if (!rows.empty()) {
                auto& r = rows[0];
                m_info.gpuName   = r["Name"];
                m_info.gpuDriver = r["DriverVersion"];
                try {
                    uint64_t vram = std::stoull(r["AdapterRAM"]);
                    m_info.gpuVram = FormatBytes(vram);
                } catch (...) {
                    m_info.gpuVram = r["AdapterRAM"];
                }
            }
        }
        // ── RAM ──────────────────────────────────────────────────
        {
            auto rows = Core::WmiQuery::QueryCimv2(
                "SELECT Capacity, Speed, SMBIOSMemoryType FROM Win32_PhysicalMemory");
            uint64_t totalBytes = 0;
            int stickCount = 0;
            int speed = 0;
            int memType = 0;
            for (auto& r : rows) {
                try { totalBytes += std::stoull(r["Capacity"]); } catch (...) {}
                try { speed = std::stoi(r["Speed"]); }           catch (...) {}
                try { memType = std::stoi(r["SMBIOSMemoryType"]); } catch (...) {}
                stickCount++;
            }
            m_info.ramTotalGB = static_cast<int>(totalBytes / (1024ULL * 1024ULL * 1024ULL));
            m_info.ramSpeed   = speed;
            m_info.ramSticks  = stickCount;
            m_info.ramType    = GetRamTypeName(memType);
        }
        // ── Storage ──────────────────────────────────────────────
        {
            auto rows = Core::WmiQuery::QueryCimv2(
                "SELECT Model, SerialNumber, Size, InterfaceType, MediaType FROM Win32_DiskDrive");
            for (auto& r : rows) {
                HardwareInfo::DriveInfo d;
                d.model         = r["Model"];
                d.serial        = r["SerialNumber"];
                d.interfaceType = r["InterfaceType"];
                d.mediaType     = r["MediaType"];
                try { d.sizeBytes = std::stoull(r["Size"]); } catch (...) {}
                m_info.drives.push_back(std::move(d));
            }
        }
        // ── Network ──────────────────────────────────────────────
        {
            auto rows = Core::WmiQuery::QueryCimv2(
                "SELECT Description, MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE");
            for (auto& r : rows) {
                HardwareInfo::NetworkAdapter a;
                a.name       = r["Description"];
                a.macAddress = r["MACAddress"];
                a.connected  = true;
                m_info.adapters.push_back(std::move(a));
            }
        }
        // ── Windows Info ─────────────────────────────────────────
        {
            const char* ntPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
            m_info.windowsEdition = ReadRegistryString(HKEY_LOCAL_MACHINE, ntPath, "ProductName");
            m_info.windowsVersion = ReadRegistryString(HKEY_LOCAL_MACHINE, ntPath, "DisplayVersion");
            m_info.windowsBuild   = ReadRegistryString(HKEY_LOCAL_MACHINE, ntPath, "CurrentBuildNumber");
            m_info.registeredOwner = ReadRegistryString(HKEY_LOCAL_MACHINE, ntPath, "RegisteredOwner");
        }
        // ── Computer Name ────────────────────────────────────────
        {
            m_info.computerName = Core::Admin::GetComputerName();
        }
        // ── Driver Count ─────────────────────────────────────────
        {
            auto rows = Core::WmiQuery::QueryCimv2(
                "SELECT DeviceName FROM Win32_PnPSignedDriver");
            m_info.driverCount = static_cast<int>(rows.size());
        }
        // ── Service Count ────────────────────────────────────────
        {
            auto rows = Core::WmiQuery::QueryCimv2(
                "SELECT Name, State FROM Win32_Service");
            m_info.serviceCount = static_cast<int>(rows.size());
            int running = 0;
            for (auto& r : rows) {
                if (r["State"] == "Running") running++;
            }
            m_info.runningServiceCount = running;
        }

        m_info.collected = true;
    }
    catch (...) {
        // partial data is OK – mark as collected anyway
        m_info.collected = true;
    }

    m_collecting = false;
}

// ── Render helpers ───────────────────────────────────────────────────
static void RenderInfoRow(const char* label, const std::string& value) {
    ImGui::TextColored(kTextDim, "%s", label);
    ImGui::SameLine(180.0f);
    if (value.empty()) {
        ImGui::TextColored(kTextDim, "N/A");
    } else {
        ImGui::TextColored(kText, "%s", value.c_str());
    }
}

static void RenderSectionCard(const char* title, const ImVec4& accentColor,
                               const std::function<void()>& contentFn) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, kSurface);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);

    float availWidth = ImGui::GetContentRegionAvail().x;
    ImGui::BeginChild(title, ImVec2(availWidth, 0), ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_Borders);

    // Accent bar
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::GetWindowDrawList()->AddRectFilled(
        ImVec2(p.x, p.y),
        ImVec2(p.x + 4.0f, p.y + ImGui::GetContentRegionAvail().y + 200.0f),
        ImGui::ColorConvertFloat4ToU32(accentColor), 2.0f);

    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 12.0f);
    ImGui::BeginGroup();
    ImGui::Spacing();
    ImGui::TextColored(accentColor, "%s", title);
    ImGui::Separator();
    ImGui::Spacing();

    contentFn();

    ImGui::Spacing();
    ImGui::EndGroup();

    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    ImGui::Spacing();
}

// ── Render ───────────────────────────────────────────────────────────
void SystemInventory::Render() {
    // Title + controls
    ImGui::TextColored(kTeal, "System Inventory");
    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 80.0f);
    if (ImGui::Button("Refresh", ImVec2(80, 0))) {
        Refresh();
    }

    ImGui::Spacing();

    // Search bar
    ImGui::SetNextItemWidth(300.0f);
    char filterBuf[256] = {};
    strncpy_s(filterBuf, m_searchFilter.c_str(), sizeof(filterBuf) - 1);
    if (ImGui::InputTextWithHint("##inv_search", "Search inventory...", filterBuf, sizeof(filterBuf))) {
        m_searchFilter = filterBuf;
    }
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Collecting spinner
    if (m_collecting) {
        float time = static_cast<float>(ImGui::GetTime());
        const char* spinner = "|/-\\";
        ImGui::TextColored(kAmber, "%c Scanning system...", spinner[static_cast<int>(time * 8.0f) % 4]);
        return;
    }

    if (!m_info.collected) {
        ImGui::TextColored(kTextDim, "Click 'Refresh' to scan your system.");
        return;
    }

    // Two-column layout
    float totalWidth = ImGui::GetContentRegionAvail().x;
    float colWidth = (totalWidth - 10.0f) * 0.5f;

    ImGui::BeginChild("##inv_scroll", ImVec2(0, 0), ImGuiChildFlags_None);

    ImGui::Columns(2, "##inv_cols", false);
    ImGui::SetColumnWidth(0, colWidth);
    ImGui::SetColumnWidth(1, colWidth);

    // ── Column 1 ─────────────────────────────────────────────
    // Motherboard
    if (MatchesFilter("motherboard " + m_info.mbManufacturer + " " + m_info.mbProduct, m_searchFilter)) {
        RenderSectionCard("Motherboard", kTeal, [&]() {
            RenderInfoRow("Manufacturer:", m_info.mbManufacturer);
            RenderInfoRow("Product:", m_info.mbProduct);
            RenderInfoRow("Serial:", m_info.mbSerial);
            RenderInfoRow("Version:", m_info.mbVersion);
        });
    }

    // CPU
    if (MatchesFilter("cpu processor " + m_info.cpuName, m_searchFilter)) {
        RenderSectionCard("Processor", kTeal, [&]() {
            RenderInfoRow("Name:", m_info.cpuName);
            RenderInfoRow("Manufacturer:", m_info.cpuManufacturer);
            RenderInfoRow("Cores:", std::to_string(m_info.cpuCores));
            RenderInfoRow("Threads:", std::to_string(m_info.cpuThreads));
            RenderInfoRow("Max Clock:", std::to_string(m_info.cpuMaxClock) + " MHz");
        });
    }

    // RAM
    if (MatchesFilter("ram memory " + m_info.ramType, m_searchFilter)) {
        RenderSectionCard("Memory", kTeal, [&]() {
            RenderInfoRow("Total:", std::to_string(m_info.ramTotalGB) + " GB");
            RenderInfoRow("Type:", m_info.ramType);
            RenderInfoRow("Speed:", std::to_string(m_info.ramSpeed) + " MHz");
            RenderInfoRow("Sticks:", std::to_string(m_info.ramSticks));
        });
    }

    // Storage
    if (MatchesFilter("storage disk drive", m_searchFilter)) {
        RenderSectionCard("Storage", kTeal, [&]() {
            if (m_info.drives.empty()) {
                ImGui::TextColored(kTextDim, "No drives detected");
            }
            for (size_t i = 0; i < m_info.drives.size(); i++) {
                auto& d = m_info.drives[i];
                if (i > 0) ImGui::Separator();
                ImGui::TextColored(kText, "Drive %zu", i);
                RenderInfoRow("  Model:", d.model);
                RenderInfoRow("  Serial:", d.serial);
                RenderInfoRow("  Size:", FormatBytes(d.sizeBytes));
                RenderInfoRow("  Interface:", d.interfaceType);
                RenderInfoRow("  Media:", d.mediaType);
            }
        });
    }

    // Services
    if (MatchesFilter("services drivers", m_searchFilter)) {
        RenderSectionCard("Services & Drivers", kTeal, [&]() {
            RenderInfoRow("Signed Drivers:", std::to_string(m_info.driverCount));
            RenderInfoRow("Total Services:", std::to_string(m_info.serviceCount));
            RenderInfoRow("Running:", std::to_string(m_info.runningServiceCount));
        });
    }

    ImGui::NextColumn();

    // ── Column 2 ─────────────────────────────────────────────
    // BIOS
    if (MatchesFilter("bios uefi " + m_info.biosManufacturer, m_searchFilter)) {
        RenderSectionCard("BIOS / UEFI", kTeal, [&]() {
            RenderInfoRow("Manufacturer:", m_info.biosManufacturer);
            RenderInfoRow("Version:", m_info.biosVersion);
            RenderInfoRow("Date:", m_info.biosDate);
            RenderInfoRow("SMBIOS:", m_info.smbiosVersion);
        });
    }

    // GPU
    if (MatchesFilter("gpu graphics video " + m_info.gpuName, m_searchFilter)) {
        RenderSectionCard("Graphics", kTeal, [&]() {
            RenderInfoRow("Name:", m_info.gpuName);
            RenderInfoRow("Driver:", m_info.gpuDriver);
            RenderInfoRow("VRAM:", m_info.gpuVram);
        });
    }

    // Network
    if (MatchesFilter("network adapter ethernet wifi", m_searchFilter)) {
        RenderSectionCard("Network", kTeal, [&]() {
            if (m_info.adapters.empty()) {
                ImGui::TextColored(kTextDim, "No active adapters detected");
            }
            for (size_t i = 0; i < m_info.adapters.size(); i++) {
                auto& a = m_info.adapters[i];
                if (i > 0) ImGui::Separator();
                ImGui::TextColored(kText, "%s", a.name.c_str());
                RenderInfoRow("  MAC:", a.macAddress);
                RenderInfoRow("  IP:", a.ipAddress.empty() ? "N/A" : a.ipAddress);
                ImGui::TextColored(a.connected ? kGreen : kRed, "  %s",
                    a.connected ? "Connected" : "Disconnected");
            }
        });
    }

    // Windows
    if (MatchesFilter("windows os operating system " + m_info.windowsEdition, m_searchFilter)) {
        RenderSectionCard("Windows", kTeal, [&]() {
            RenderInfoRow("Edition:", m_info.windowsEdition);
            RenderInfoRow("Version:", m_info.windowsVersion);
            RenderInfoRow("Build:", m_info.windowsBuild);
            RenderInfoRow("Computer:", m_info.computerName);
            RenderInfoRow("Owner:", m_info.registeredOwner);
        });
    }

    ImGui::Columns(1);
    ImGui::EndChild();
}

} // namespace Modules
