#include "modules/privacy_cleanup.h"

#include "imgui/imgui.h"
#include "theme.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <sstream>
#include <string>
#include <utility>

namespace Modules {

namespace fs = std::filesystem;

namespace {

std::string EnvPath(const char* name) {
    char buffer[MAX_PATH]{};
    DWORD size = GetEnvironmentVariableA(name, buffer, static_cast<DWORD>(sizeof(buffer)));
    if (size == 0 || size >= sizeof(buffer)) {
        return {};
    }
    return buffer;
}

std::string JoinPath(const std::string& base, const std::string& child) {
    if (base.empty()) {
        return {};
    }
    return (fs::path(base) / child).string();
}

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool IsSafeCleanupRoot(const fs::path& path) {
    std::error_code ec;
    fs::path absolute = fs::absolute(path, ec);
    if (ec || absolute.empty() || !absolute.has_parent_path()) {
        return false;
    }

    std::string lower = Lower(absolute.string());
    return lower.find("\\temp") != std::string::npos ||
           lower.find("\\cache") != std::string::npos ||
           lower.find("\\inetcache") != std::string::npos ||
           lower.find("\\crashdumps") != std::string::npos ||
           lower.find("\\recent") != std::string::npos;
}

} // namespace

void PrivacyCleanup::Initialize() {
    if (m_initialized) {
        return;
    }

    const std::string temp = EnvPath("TEMP");
    const std::string localAppData = EnvPath("LOCALAPPDATA");
    const std::string appData = EnvPath("APPDATA");

    auto add = [&](CleanupCategory category) {
        bool hasPath = false;
        for (const auto& path : category.paths) {
            if (!path.empty()) {
                hasPath = true;
                break;
            }
        }
        if (hasPath) {
            m_categories.push_back(std::move(category));
        }
    };

    add({ "User temporary files", "Current user's temporary files and installer leftovers.", { temp }, 0, 0, true, false, false });
    add({ "Windows recent items", "Recent-file shortcut history for the current user.", { JoinPath(appData, "Microsoft\\Windows\\Recent") }, 0, 0, false, false, true });
    add({ "Crash dumps", "Local application crash dump files.", { JoinPath(localAppData, "CrashDumps") }, 0, 0, true, false, false });
    add({ "Edge cache", "Microsoft Edge cache for the current user.", { JoinPath(localAppData, "Microsoft\\Edge\\User Data\\Default\\Cache") }, 0, 0, true, false, false });
    add({ "Chrome cache", "Google Chrome cache for the current user.", { JoinPath(localAppData, "Google\\Chrome\\User Data\\Default\\Cache") }, 0, 0, true, false, false });
    add({ "Windows temp", "Machine-wide temporary files. Some entries may require Administrator.", { "C:\\Windows\\Temp" }, 0, 0, false, true, true });

    m_initialized = true;
}

void PrivacyCleanup::Scan() {
    Initialize();
    m_scanning = true;
    m_totalReclaimable = 0;

    for (auto& category : m_categories) {
        ScanCategory(category);
        m_totalReclaimable += category.totalSize;
    }

    m_scanning = false;
}

void PrivacyCleanup::Clean(bool dryRun) {
    Initialize();
    m_cleaning = true;
    m_lastCleanupReport.clear();

    std::ostringstream report;
    report << (dryRun ? "Dry-run cleanup preview" : "Cleanup result") << "\n";

    for (auto& category : m_categories) {
        if (!category.selected) {
            continue;
        }

        CleanCategory(category, dryRun);
        report << "- " << category.name << ": deleted=" << category.deletedCount
               << ", skipped=" << category.skippedCount << "\n";
    }

    m_lastCleanupReport = report.str();
    m_cleaning = false;
}

void PrivacyCleanup::Render() {
    Initialize();

    ImGui::PushStyleColor(ImGuiCol_Text, Theme::kTeal);
    ImGui::TextUnformatted("Privacy Cleanup");
    ImGui::PopStyleColor();

    ImGui::PushStyleColor(ImGuiCol_Text, Theme::kTextSecondary);
    ImGui::TextWrapped("Scan local cache and history locations before a reinstall or privacy session. Dry run is the default.");
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();

    if (ImGui::Button("Scan", ImVec2(120, 0))) {
        Scan();
    }
    ImGui::SameLine();
    ImGui::Checkbox("Dry run", &m_dryRun);
    ImGui::SameLine();
    if (ImGui::Button("Select scanned", ImVec2(140, 0))) {
        for (auto& category : m_categories) {
            category.selected = category.scanned && category.fileCount > 0;
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear selection", ImVec2(140, 0))) {
        for (auto& category : m_categories) {
            category.selected = false;
        }
    }

    ImGui::Spacing();
    ImGui::Text("Reclaimable: %s", FormatSize(m_totalReclaimable).c_str());
    if (m_scanning) {
        ImGui::TextColored(Theme::kAmber, "Scanning...");
    }
    if (m_cleaning) {
        ImGui::TextColored(Theme::kAmber, "Cleaning...");
    }

    ImGui::Spacing();
    if (ImGui::BeginTable("cleanup_categories", 6, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Use", ImGuiTableColumnFlags_WidthFixed, 48.0f);
        ImGui::TableSetupColumn("Category");
        ImGui::TableSetupColumn("Files", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Flags", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Description");
        ImGui::TableHeadersRow();

        for (size_t i = 0; i < m_categories.size(); ++i) {
            auto& category = m_categories[i];
            ImGui::PushID(static_cast<int>(i));
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            ImGui::Checkbox("##selected", &category.selected);

            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(category.name.c_str());

            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%d", category.fileCount);

            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(FormatSize(category.totalSize).c_str());

            ImGui::TableSetColumnIndex(4);
            std::string flags;
            if (category.requiresAdmin) {
                flags += "admin ";
            }
            if (category.isCaution) {
                flags += "review";
            }
            ImGui::TextColored(category.isCaution ? Theme::kAmber : Theme::kTextSecondary, "%s", flags.c_str());

            ImGui::TableSetColumnIndex(5);
            ImGui::TextWrapped("%s", category.description.c_str());

            ImGui::PopID();
        }

        ImGui::EndTable();
    }

    ImGui::Spacing();
    if (ImGui::Button(m_dryRun ? "Preview selected" : "Clean selected", ImVec2(160, 0))) {
        Clean(m_dryRun);
    }

    if (!m_lastCleanupReport.empty()) {
        ImGui::Spacing();
        ImGui::TextWrapped("%s", m_lastCleanupReport.c_str());
    }
}

void PrivacyCleanup::ScanCategory(CleanupCategory& category) {
    category.totalSize = 0;
    category.fileCount = 0;
    category.scanned = true;

    for (const auto& rawPath : category.paths) {
        if (rawPath.empty()) {
            continue;
        }

        std::error_code ec;
        fs::path path(rawPath);
        if (!fs::exists(path, ec)) {
            continue;
        }

        if (fs::is_regular_file(path, ec)) {
            category.totalSize += fs::file_size(path, ec);
            ++category.fileCount;
            continue;
        }

        if (!fs::is_directory(path, ec)) {
            continue;
        }

        for (const auto& entry : fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied, ec)) {
            if (ec) {
                ec.clear();
                continue;
            }
            if (entry.is_regular_file(ec)) {
                category.totalSize += entry.file_size(ec);
                ++category.fileCount;
            }
        }
    }
}

void PrivacyCleanup::CleanCategory(CleanupCategory& category, bool dryRun) {
    category.deletedCount = 0;
    category.skippedCount = 0;
    category.cleaned = false;

    for (const auto& rawPath : category.paths) {
        if (rawPath.empty()) {
            continue;
        }

        std::error_code ec;
        fs::path path(rawPath);
        if (!fs::exists(path, ec)) {
            continue;
        }
        if (!IsSafeCleanupRoot(path)) {
            ++category.skippedCount;
            continue;
        }

        if (dryRun) {
            CleanupCategory preview = category;
            preview.paths = { rawPath };
            ScanCategory(preview);
            category.deletedCount += preview.fileCount;
            continue;
        }

        if (fs::is_regular_file(path, ec)) {
            fs::remove(path, ec);
            ec ? ++category.skippedCount : ++category.deletedCount;
            continue;
        }

        for (const auto& entry : fs::directory_iterator(path, fs::directory_options::skip_permission_denied, ec)) {
            if (ec) {
                ++category.skippedCount;
                ec.clear();
                continue;
            }
            fs::remove_all(entry.path(), ec);
            ec ? ++category.skippedCount : ++category.deletedCount;
        }
    }

    category.cleaned = true;
    ScanCategory(category);
}

std::string PrivacyCleanup::FormatSize(uint64_t bytes) {
    const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }

    char buffer[64]{};
    std::snprintf(buffer, sizeof(buffer), "%.1f %s", value, units[unit]);
    return buffer;
}

} // namespace Modules
