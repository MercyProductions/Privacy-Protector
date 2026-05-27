#pragma once
#include <string>
#include <vector>
#include <functional>

namespace Widgets {

enum class Page {
    Dashboard,
    SystemInventory,
    TpmSecurity,
    StorageRaid,
    ReinstallPrep,
    PrivacyCleanup,
    Reports,
    COUNT
};

struct SidebarItem {
    const char* icon;    // Unicode icon character
    const char* label;
    Page page;
};

class Sidebar {
public:
    void Render(Page& currentPage, bool isAdmin, float windowHeight);
    
private:
    float m_hoverAlpha[static_cast<int>(Page::COUNT)] = {};
};

} // namespace Widgets
