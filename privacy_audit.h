#pragma once

#include <filesystem>
#include <string>

struct PrivacyAuditOptions {
    std::filesystem::path workDir;
    std::filesystem::path outputPath;
    bool fullExport = false;
};

struct PrivacyAuditResult {
    bool ok = false;
    std::string errorMessage;
    std::filesystem::path textReportPath;
    std::filesystem::path jsonReportPath;
    std::filesystem::path fullExportPath;
    std::filesystem::path manifestPath;
    int lowCount = 0;
    int mediumCount = 0;
    int highCount = 0;
    int collectorOkCount = 0;
    int collectorPartialCount = 0;
    int collectorUnavailableCount = 0;
    int collectorErrorCount = 0;
};

PrivacyAuditResult RunPrivacyAudit(const PrivacyAuditOptions& options);
