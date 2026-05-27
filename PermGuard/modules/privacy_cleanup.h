#pragma once
#include <string>
#include <vector>
#include <filesystem>
#include <cstdint>

namespace Modules {

struct CleanupCategory {
    std::string name;
    std::string description;
    std::vector<std::string> paths;
    uint64_t totalSize = 0;
    int fileCount = 0;
    bool selected = false;
    bool scanned = false;
    bool requiresAdmin = false;
    bool isCaution = false;  // Show amber warning

    // Results after cleanup
    int deletedCount = 0;
    int skippedCount = 0;
    bool cleaned = false;
};

class PrivacyCleanup {
public:
    void Render();
    void Scan();    // Scan all categories for sizes
    void Clean(bool dryRun = true);   // Clean selected categories

private:
    std::vector<CleanupCategory> m_categories;
    bool m_initialized = false;
    bool m_scanning = false;
    bool m_cleaning = false;
    bool m_dryRun = true;
    uint64_t m_totalReclaimable = 0;
    std::string m_lastCleanupReport;

    void Initialize();
    void ScanCategory(CleanupCategory& cat);
    void CleanCategory(CleanupCategory& cat, bool dryRun);
    static std::string FormatSize(uint64_t bytes);
};

} // namespace Modules
