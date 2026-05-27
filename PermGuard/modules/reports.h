#pragma once
#include <string>
#include <vector>
#include <filesystem>
#include <cstdint>

namespace Modules {

struct ReportEntry {
    std::string name;
    std::string type;  // system, backup, security, storage, readiness, postinstall
    std::filesystem::path path;
    std::string timestamp;
    uint64_t sizeBytes = 0;
};

class Reports {
public:
    void Render();

    // Generate specific reports
    std::string GenerateSystemReport(const std::string& outputDir);
    std::string GenerateBackupChecklist(const std::string& outputDir);
    std::string GenerateSecurityReport(const std::string& outputDir);
    std::string GenerateStorageReport(const std::string& outputDir);
    std::string GenerateReadinessReport(const std::string& outputDir);
    std::string GeneratePostInstallChecklist(const std::string& outputDir);
    void GenerateAllReports(const std::string& outputDir);

private:
    std::vector<ReportEntry> m_reports;
    int m_selectedReport = -1;
    std::string m_previewContent;
    std::string m_outputDir;

    void ScanReports();
    void LoadPreview(int index);
    static std::string GetTimestamp();
    static std::string GetOutputDir();
};

} // namespace Modules
