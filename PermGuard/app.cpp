#include "app.h"
#include "theme.h"
#include "core/admin.h"
#include "core/wmi_query.h"
#include "widgets/status_card.h"
#include "widgets/progress_bar.h"
#include "widgets/risk_badge.h"
#include "imgui/imgui.h"

void App::Initialize() {
    if (m_initialized) return;
    
    m_isAdmin = Core::Admin::IsElevated();
    
    // Trigger initial data collection
    m_systemInventory.Refresh();
    m_tpmSecurity.Refresh();
    m_storageRaid.Refresh();
    
    m_initialized = true;
}

void App::Render() {
    if (!m_initialized) {
        Initialize();
    }
    
    m_animTime += ImGui::GetIO().DeltaTime;
    
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
                             ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus;
    
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    
    if (ImGui::Begin("##MainWindow", nullptr, flags)) {
        float windowHeight = ImGui::GetContentRegionAvail().y;
        
        // Sidebar
        m_sidebar.Render(m_currentPage, m_isAdmin, windowHeight);
        
        ImGui::SameLine();
        
        // Main content area
        ImGui::BeginGroup();
        {
            float contentWidth = ImGui::GetContentRegionAvail().x;
            float contentHeight = ImGui::GetContentRegionAvail().y;
            
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(Theme::kPadding, Theme::kPadding));
            ImGui::BeginChild("##Content", ImVec2(contentWidth, contentHeight), ImGuiChildFlags_AlwaysUseWindowPadding, 0);
            {
                switch (m_currentPage) {
                    case Widgets::Page::Dashboard:
                        RenderDashboard();
                        break;
                    case Widgets::Page::SystemInventory:
                        m_systemInventory.Render();
                        break;
                    case Widgets::Page::TpmSecurity:
                        m_tpmSecurity.Render();
                        break;
                    case Widgets::Page::StorageRaid:
                        m_storageRaid.Render();
                        break;
                    case Widgets::Page::ReinstallPrep:
                        m_reinstallPrep.Render();
                        break;
                    case Widgets::Page::PrivacyCleanup:
                        m_privacyCleanup.Render();
                        break;
                    case Widgets::Page::Reports:
                        m_reports.Render();
                        break;
                    default:
                        RenderDashboard();
                        break;
                }
            }
            ImGui::EndChild();
            ImGui::PopStyleVar();
        }
        ImGui::EndGroup();
    }
    ImGui::End();
    ImGui::PopStyleVar(2);
}

int App::GetReadinessScore() const {
    int score = 0;
    int factors = 0;
    
    // System inventory collected
    if (m_systemInventory.GetInfo().collected) {
        score += 15;
    }
    factors += 15;
    
    // Security state
    const auto& sec = m_tpmSecurity.GetState();
    if (sec.collected) {
        if (sec.tpm.present && sec.tpm.enabled) score += 10;
        if (sec.secureBoot.enabled) score += 10;
        // No BitLocker issues
        bool blOk = true;
        for (const auto& v : sec.bitlockerVolumes) {
            if (v.isProtected) blOk = false;
        }
        if (blOk || sec.bitlockerVolumes.empty()) score += 10;
    }
    factors += 30;
    
    // Storage state
    const auto& stor = m_storageRaid.GetState();
    if (stor.collected) {
        score += 10;
        if (!stor.raidDetected) score += 5;
    }
    factors += 15;
    
    // Reinstall prep progress
    float prepProgress = m_reinstallPrep.GetOverallProgress();
    score += static_cast<int>(prepProgress * 30.0f);
    factors += 30;
    
    // Privacy cleanup
    factors += 10;
    // Give partial credit just for being scanned
    score += 5;
    
    return factors > 0 ? (score * 100 / factors) : 0;
}

void App::RenderDashboard() {
    // ── Header ──────────────────────────────────────────────────
    ImGui::PushStyleColor(ImGuiCol_Text, Theme::kTeal);
    ImGui::SetWindowFontScale(1.4f);
    ImGui::Text("Dashboard");
    ImGui::SetWindowFontScale(1.0f);
    ImGui::PopStyleColor();
    
    ImGui::PushStyleColor(ImGuiCol_Text, Theme::kTextSecondary);
    ImGui::Text("System overview and reinstall readiness");
    ImGui::PopStyleColor();
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::Spacing();
    
    float contentWidth = ImGui::GetContentRegionAvail().x;
    
    // ── Readiness Score (centered) ──────────────────────────────
    {
        int score = GetReadinessScore();
        float scoreAreaWidth = 160.0f;
        ImGui::SetCursorPosX((contentWidth - scoreAreaWidth) * 0.5f);
        Widgets::ProgressBar::RenderCircularScore(score, 60.0f, "READINESS");
        ImGui::Spacing();
        ImGui::Spacing();
    }
    
    // ── Quick Status Cards Row ──────────────────────────────────
    {
        float cardWidth = (contentWidth - Theme::kPadding * 3) / 4.0f;
        if (cardWidth < 200.0f) cardWidth = (contentWidth - Theme::kPadding) / 2.0f;
        
        // Card 1: System Info
        {
            const auto& info = m_systemInventory.GetInfo();
            Widgets::StatusCard card;
            card.title = "System Info";
            card.icon = "[PC]";
            card.status = info.collected ? Widgets::CardStatus::OK : Widgets::CardStatus::Unknown;
            if (info.collected) {
                card.rows.push_back({"Computer", info.computerName});
                card.rows.push_back({"Windows", info.windowsEdition});
                card.rows.push_back({"CPU", info.cpuName.substr(0, 30)});
                card.rows.push_back({"Admin", m_isAdmin ? "Yes" : "No"});
            } else {
                card.rows.push_back({"Status", "Scanning..."});
            }
            card.Render(cardWidth);
        }
        
        ImGui::SameLine();
        
        // Card 2: Security Status
        {
            const auto& sec = m_tpmSecurity.GetState();
            Widgets::StatusCard card;
            card.title = "Security";
            card.icon = "[LOCK]";
            card.status = m_tpmSecurity.GetOverallStatus();
            if (sec.collected) {
                card.rows.push_back({"TPM", sec.tpm.present ? (sec.tpm.enabled ? "Enabled" : "Disabled") : "Not Found"});
                card.rows.push_back({"Secure Boot", sec.secureBoot.enabled ? "Enabled" : "Disabled"});
                card.rows.push_back({"BitLocker", sec.bitlockerVolumes.empty() ? "Not Active" : "Active"});
            } else {
                card.rows.push_back({"Status", sec.requiresAdmin ? "Needs Admin" : "Scanning..."});
            }
            card.Render(cardWidth);
        }
        
        ImGui::SameLine();
        
        // Card 3: Storage Status
        {
            const auto& stor = m_storageRaid.GetState();
            Widgets::StatusCard card;
            card.title = "Storage";
            card.icon = "[HDD]";
            card.status = stor.collected ? (stor.raidDetected ? Widgets::CardStatus::Warning : Widgets::CardStatus::OK) : Widgets::CardStatus::Unknown;
            if (stor.collected) {
                card.rows.push_back({"Drives", std::to_string(stor.disks.size())});
                card.rows.push_back({"RAID", stor.raidDetected ? "Detected" : "None"});
                card.rows.push_back({"OS Drive", stor.osSystemDrive});
            } else {
                card.rows.push_back({"Status", "Scanning..."});
            }
            card.Render(cardWidth);
        }
        
        ImGui::SameLine();
        
        // Card 4: Readiness
        {
            Widgets::StatusCard card;
            card.title = "Readiness";
            card.icon = "[CHK]";
            float progress = m_reinstallPrep.GetOverallProgress();
            card.status = progress >= 1.0f ? Widgets::CardStatus::OK :
                          progress >= 0.5f ? Widgets::CardStatus::Warning : Widgets::CardStatus::Info;
            card.rows.push_back({"Progress", std::to_string(static_cast<int>(progress * 100)) + "%"});
            card.rows.push_back({"Status", m_reinstallPrep.IsReady() ? "Ready" : "In Progress"});
            card.Render(cardWidth);
        }
    }
    
    ImGui::Spacing();
    ImGui::Spacing();
    
    // ── Action Items ────────────────────────────────────────────
    ImGui::PushStyleColor(ImGuiCol_Text, Theme::kTextPrimary);
    ImGui::Text("Action Items");
    ImGui::PopStyleColor();
    ImGui::Spacing();
    
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, Theme::kCardRounding);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, Theme::kBgSurface);
    ImGui::PushStyleColor(ImGuiCol_Border, Theme::kBorder);
    ImGui::BeginChild("##ActionItems", ImVec2(contentWidth, 200), ImGuiChildFlags_Borders);
    {
        ImGui::Spacing();
        
        const auto& sec = m_tpmSecurity.GetState();
        const auto& stor = m_storageRaid.GetState();
        
        auto actionItem = [](const char* icon, const ImVec4& color, const char* text) {
            ImGui::PushStyleColor(ImGuiCol_Text, color);
            ImGui::Text("  %s", icon);
            ImGui::PopStyleColor();
            ImGui::SameLine();
            ImGui::TextWrapped("%s", text);
        };
        
        if (!m_systemInventory.GetInfo().collected) {
            actionItem(">>", Theme::kBlue, "System inventory scan in progress...");
        }
        
        if (!m_isAdmin) {
            actionItem("!!", Theme::kAmber, "Run as Administrator for full TPM/BitLocker data and cleanup capabilities.");
        }
        
        if (sec.collected) {
            for (const auto& v : sec.bitlockerVolumes) {
                if (v.isProtected) {
                    actionItem("!!", Theme::kRed, ("BitLocker is active on " + v.driveLetter + " - back up recovery keys before reinstalling!").c_str());
                }
            }
        }
        
        if (stor.collected && stor.raidDetected) {
            actionItem("!!", Theme::kAmber, "RAID configuration detected - ensure you have RAID drivers ready for Windows Setup.");
        }
        
        if (m_reinstallPrep.GetOverallProgress() < 1.0f) {
            actionItem(">>", Theme::kTeal, "Complete the Reinstall Preparation checklist before proceeding.");
        }
        
        if (m_systemInventory.GetInfo().collected && sec.collected && !stor.raidDetected && m_reinstallPrep.IsReady()) {
            actionItem("OK", Theme::kGreen, "System is ready for a clean Windows reinstall!");
        }
    }
    ImGui::EndChild();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar();
}

void App::RenderTopBar() {
    // Reserved for future use (search, settings, etc.)
}
