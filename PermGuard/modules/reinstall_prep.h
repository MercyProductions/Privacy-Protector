#pragma once
#include <string>
#include <vector>
#include "widgets/checklist.h"

namespace Modules {

class ReinstallPrep {
public:
    void Render();
    float GetOverallProgress() const;
    bool IsReady() const;

private:
    int m_currentStep = 0;
    static constexpr int STEP_COUNT = 9;

    // Step checklists
    Widgets::Checklist m_backupFiles;
    Widgets::Checklist m_browserData;
    Widgets::Checklist m_appConfigs;
    Widgets::Checklist m_wifiProfiles;
    Widgets::Checklist m_bitlockerKeys;
    Widgets::Checklist m_windowsLicense;
    Widgets::Checklist m_installMedia;
    Widgets::Checklist m_driverPrep;
    Widgets::Checklist m_finalConfirm;
    bool m_initialized = false;

    void Initialize();
    void RenderStepNav();
    void RenderStep(int step);

    // Step names
    static const char* GetStepName(int step);
};

} // namespace Modules
