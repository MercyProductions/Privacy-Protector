#pragma once

#include "widgets/sidebar.h"
#include "modules/system_inventory.h"
#include "modules/tpm_security.h"
#include "modules/storage_raid.h"
#include "modules/reinstall_prep.h"
#include "modules/privacy_cleanup.h"
#include "modules/reports.h"

class App {
public:
    void Initialize();
    void Render();
    
    // Get overall readiness score (0-100)
    int GetReadinessScore() const;
    
private:
    Widgets::Page m_currentPage = Widgets::Page::Dashboard;
    Widgets::Sidebar m_sidebar;
    
    // Modules
    Modules::SystemInventory m_systemInventory;
    Modules::TpmSecurity     m_tpmSecurity;
    Modules::StorageRaid     m_storageRaid;
    Modules::ReinstallPrep   m_reinstallPrep;
    Modules::PrivacyCleanup  m_privacyCleanup;
    Modules::Reports         m_reports;
    
    bool m_initialized = false;
    bool m_isAdmin = false;
    float m_animTime = 0.0f;
    
    void RenderDashboard();
    void RenderTopBar();
};
