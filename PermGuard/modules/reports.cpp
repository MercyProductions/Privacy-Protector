#include "modules/reports.h"

#include "imgui/imgui.h"
#include "theme.h"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace Modules {

namespace fs = std::filesystem;

namespace {

bool WriteFile(const fs::path& path, const std::string& content) {
    try {
        fs::create_directories(path.parent_path());
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }
        file << content;
        return file.good();
    } catch (...) {
        return false;
    }
}

std::string ReadPreview(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return "Unable to open report.";
    }

    std::string content;
    content.resize(8192);
    file.read(content.data(), static_cast<std::streamsize>(content.size()));
    content.resize(static_cast<size_t>(file.gcount()));
    if (!file.eof()) {
        content += "\n\n[Preview truncated]";
    }
    return content;
}

} // namespace

void Reports::Render() {
    if (m_outputDir.empty()) {
        m_outputDir = GetOutputDir();
        ScanReports();
    }

    ImGui::PushStyleColor(ImGuiCol_Text, Theme::kTeal);
    ImGui::TextUnformatted("Reports");
    ImGui::PopStyleColor();

    ImGui::PushStyleColor(ImGuiCol_Text, Theme::kTextSecondary);
    ImGui::TextWrapped("Generate local reports for reinstall planning, privacy cleanup, storage readiness, and post-install review.");
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();

    char outputBuffer[MAX_PATH]{};
    strncpy_s(outputBuffer, m_outputDir.c_str(), sizeof(outputBuffer) - 1);
    ImGui::SetNextItemWidth(520.0f);
    if (ImGui::InputText("Output directory", outputBuffer, sizeof(outputBuffer))) {
        m_outputDir = outputBuffer;
    }

    if (ImGui::Button("Generate all", ImVec2(130, 0))) {
        GenerateAllReports(m_outputDir);
        ScanReports();
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh list", ImVec2(120, 0))) {
        ScanReports();
    }

    ImGui::Spacing();

    float width = ImGui::GetContentRegionAvail().x;
    float listWidth = (std::max)(280.0f, width * 0.35f);

    ImGui::BeginChild("##report_list", ImVec2(listWidth, 0), ImGuiChildFlags_Borders);
    for (int i = 0; i < static_cast<int>(m_reports.size()); ++i) {
        const auto& report = m_reports[i];
        bool selected = (m_selectedReport == i);
        if (ImGui::Selectable(report.name.c_str(), selected)) {
            m_selectedReport = i;
            LoadPreview(i);
        }
        ImGui::TextColored(Theme::kTextSecondary, "%s - %s", report.type.c_str(), report.timestamp.c_str());
        ImGui::TextColored(Theme::kTextSecondary, "%llu bytes", static_cast<unsigned long long>(report.sizeBytes));
        ImGui::Separator();
    }
    if (m_reports.empty()) {
        ImGui::TextColored(Theme::kTextSecondary, "No reports generated yet.");
    }
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##report_preview", ImVec2(0, 0), ImGuiChildFlags_Borders);
    if (m_previewContent.empty()) {
        ImGui::TextColored(Theme::kTextSecondary, "Select a report to preview it.");
    } else {
        ImGui::TextWrapped("%s", m_previewContent.c_str());
    }
    ImGui::EndChild();
}

std::string Reports::GenerateSystemReport(const std::string& outputDir) {
    fs::path path = fs::path(outputDir) / ("system_report_" + GetTimestamp() + ".txt");
    std::ostringstream out;
    out << "PermGuard System Report\n";
    out << "Created: " << GetTimestamp() << "\n\n";
    out << "Use the System Inventory page for live hardware details before reinstalling.\n";
    WriteFile(path, out.str());
    return path.string();
}

std::string Reports::GenerateBackupChecklist(const std::string& outputDir) {
    fs::path path = fs::path(outputDir) / ("backup_checklist_" + GetTimestamp() + ".txt");
    std::ostringstream out;
    out << "PermGuard Backup Checklist\n";
    out << "Created: " << GetTimestamp() << "\n\n";
    out << "- BitLocker recovery keys exported offline\n";
    out << "- License and installer records saved\n";
    out << "- Old browser profiles intentionally excluded for clean privacy reset\n";
    out << "- Account recovery codes stored securely\n";
    WriteFile(path, out.str());
    return path.string();
}

std::string Reports::GenerateSecurityReport(const std::string& outputDir) {
    fs::path path = fs::path(outputDir) / ("security_report_" + GetTimestamp() + ".txt");
    std::ostringstream out;
    out << "PermGuard Security Report\n";
    out << "Created: " << GetTimestamp() << "\n\n";
    out << "Review TPM, Secure Boot, BitLocker, and firmware settings before changing partitions.\n";
    WriteFile(path, out.str());
    return path.string();
}

std::string Reports::GenerateStorageReport(const std::string& outputDir) {
    fs::path path = fs::path(outputDir) / ("storage_report_" + GetTimestamp() + ".txt");
    std::ostringstream out;
    out << "PermGuard Storage Report\n";
    out << "Created: " << GetTimestamp() << "\n\n";
    out << "Record disk model, size, serial, storage controller mode, and RAID/VMD requirements.\n";
    WriteFile(path, out.str());
    return path.string();
}

std::string Reports::GenerateReadinessReport(const std::string& outputDir) {
    fs::path path = fs::path(outputDir) / ("readiness_report_" + GetTimestamp() + ".txt");
    std::ostringstream out;
    out << "PermGuard Reinstall Readiness Report\n";
    out << "Created: " << GetTimestamp() << "\n\n";
    out << "Complete every checklist item before choosing a no-files-kept reinstall path.\n";
    WriteFile(path, out.str());
    return path.string();
}

std::string Reports::GeneratePostInstallChecklist(const std::string& outputDir) {
    fs::path path = fs::path(outputDir) / ("postinstall_checklist_" + GetTimestamp() + ".txt");
    std::ostringstream out;
    out << "PermGuard Post-Install Privacy Checklist\n";
    out << "Created: " << GetTimestamp() << "\n\n";
    out << "- Disable advertising ID and tailored experiences\n";
    out << "- Review diagnostics and sync settings\n";
    out << "- Install drivers from trusted vendor sources\n";
    out << "- Enable BitLocker after updates and drivers settle\n";
    out << "- Add accounts and browsers deliberately\n";
    WriteFile(path, out.str());
    return path.string();
}

void Reports::GenerateAllReports(const std::string& outputDir) {
    GenerateSystemReport(outputDir);
    GenerateBackupChecklist(outputDir);
    GenerateSecurityReport(outputDir);
    GenerateStorageReport(outputDir);
    GenerateReadinessReport(outputDir);
    GeneratePostInstallChecklist(outputDir);
}

void Reports::ScanReports() {
    m_reports.clear();
    fs::path dir = m_outputDir.empty() ? fs::path(GetOutputDir()) : fs::path(m_outputDir);

    std::error_code ec;
    if (!fs::exists(dir, ec)) {
        return;
    }

    for (const auto& entry : fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        if (!entry.is_regular_file(ec)) {
            continue;
        }

        fs::path path = entry.path();
        std::string name = path.filename().string();
        std::string type = "report";
        if (name.find("system") != std::string::npos) type = "system";
        else if (name.find("backup") != std::string::npos) type = "backup";
        else if (name.find("security") != std::string::npos) type = "security";
        else if (name.find("storage") != std::string::npos) type = "storage";
        else if (name.find("readiness") != std::string::npos) type = "readiness";
        else if (name.find("postinstall") != std::string::npos) type = "postinstall";

        ReportEntry report;
        report.name = name;
        report.type = type;
        report.path = path;
        report.timestamp = GetTimestamp();
        report.sizeBytes = static_cast<uint64_t>(entry.file_size(ec));
        m_reports.push_back(std::move(report));
    }

    std::sort(m_reports.begin(), m_reports.end(), [](const ReportEntry& a, const ReportEntry& b) {
        return a.name > b.name;
    });
}

void Reports::LoadPreview(int index) {
    if (index < 0 || index >= static_cast<int>(m_reports.size())) {
        m_previewContent.clear();
        return;
    }
    m_previewContent = ReadPreview(m_reports[static_cast<size_t>(index)].path);
}

std::string Reports::GetTimestamp() {
    std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &now);

    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y%m%d_%H%M%S", &local);
    return buffer;
}

std::string Reports::GetOutputDir() {
    char profile[MAX_PATH]{};
    DWORD size = GetEnvironmentVariableA("USERPROFILE", profile, static_cast<DWORD>(sizeof(profile)));
    if (size > 0 && size < sizeof(profile)) {
        return (fs::path(profile) / "Documents" / "PermGuardReports").string();
    }
    return (fs::current_path() / "PermGuardReports").string();
}

} // namespace Modules
