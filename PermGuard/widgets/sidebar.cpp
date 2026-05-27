#include "widgets/sidebar.h"
#include "imgui/imgui.h"
#include <algorithm>
#include <cmath>

namespace Widgets {

// Theme color constants
static const ImVec4 kColorBackground  = ImVec4(0.051f, 0.067f, 0.090f, 1.0f);
static const ImVec4 kColorSurface     = ImVec4(0.110f, 0.129f, 0.157f, 1.0f);
static const ImVec4 kColorBorder      = ImVec4(0.188f, 0.212f, 0.239f, 1.0f);
static const ImVec4 kColorPrimary     = ImVec4(0.0f, 0.831f, 0.667f, 1.0f);
static const ImVec4 kColorWarning     = ImVec4(0.941f, 0.706f, 0.161f, 1.0f);
static const ImVec4 kColorDanger      = ImVec4(0.906f, 0.298f, 0.235f, 1.0f);
static const ImVec4 kColorSuccess     = ImVec4(0.180f, 0.800f, 0.443f, 1.0f);
static const ImVec4 kColorTextPrimary = ImVec4(0.902f, 0.929f, 0.953f, 1.0f);
static const ImVec4 kColorTextSecondary = ImVec4(0.545f, 0.580f, 0.620f, 1.0f);

static const SidebarItem kNavItems[] = {
    { "##",  "Dashboard",       Page::Dashboard },
    { "[]",  "System Inventory", Page::SystemInventory },
    { "<>",  "TPM / Security",  Page::TpmSecurity },
    { "HH",  "Storage / RAID",  Page::StorageRaid },
    { ">>",  "Reinstall Prep",  Page::ReinstallPrep },
    { "XX",  "Privacy Cleanup", Page::PrivacyCleanup },
    { "@@",  "Reports",         Page::Reports },
};

void Sidebar::Render(Page& currentPage, bool isAdmin, float windowHeight) {
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, kColorBackground);
    ImGui::PushStyleColor(ImGuiCol_Border, kColorBorder);

    ImGui::BeginChild("Sidebar", ImVec2(260, windowHeight), ImGuiChildFlags_Borders);

    float sidebarWidth = ImGui::GetContentRegionAvail().x;
    float dt = ImGui::GetIO().DeltaTime;

    // ── App Title ──────────────────────────────────────────────
    ImGui::Dummy(ImVec2(0, 16));
    {
        ImGui::PushStyleColor(ImGuiCol_Text, kColorPrimary);
        float titleWidth = ImGui::CalcTextSize("[+] PERMGUARD").x;
        ImGui::SetCursorPosX((sidebarWidth - titleWidth) * 0.5f);
        ImGui::Text("[+] PERMGUARD");
        ImGui::PopStyleColor();
    }
    {
        ImGui::PushStyleColor(ImGuiCol_Text, kColorTextSecondary);
        const char* subtitle = "Privacy & Reinstall Prep";
        float subtitleWidth = ImGui::CalcTextSize(subtitle).x;
        ImGui::SetCursorPosX((sidebarWidth - subtitleWidth) * 0.5f);
        ImGui::TextUnformatted(subtitle);
        ImGui::PopStyleColor();
    }

    ImGui::Dummy(ImVec2(0, 8));

    // ── Separator ──────────────────────────────────────────────
    {
        ImDrawList* drawList = ImGui::GetWindowDrawList();
        ImVec2 p = ImGui::GetCursorScreenPos();
        drawList->AddLine(
            ImVec2(p.x + 16, p.y),
            ImVec2(p.x + sidebarWidth - 16, p.y),
            ImGui::ColorConvertFloat4ToU32(kColorBorder), 1.0f);
        ImGui::Dummy(ImVec2(0, 12));
    }

    // ── Navigation Items ───────────────────────────────────────
    float itemHeight = 40.0f;
    float accentWidth = 3.0f;
    float iconColumnWidth = 36.0f;
    float padX = 12.0f;

    for (int i = 0; i < static_cast<int>(Page::COUNT); ++i) {
        const auto& item = kNavItems[i];
        bool isActive = (currentPage == item.page);

        ImVec2 cursorPos = ImGui::GetCursorScreenPos();
        ImVec2 itemMin = cursorPos;
        ImVec2 itemMax = ImVec2(cursorPos.x + sidebarWidth, cursorPos.y + itemHeight);

        // Invisible button for interaction
        ImGui::PushID(i);
        ImGui::SetCursorScreenPos(itemMin);
        bool clicked = ImGui::InvisibleButton("##nav", ImVec2(sidebarWidth, itemHeight));
        bool hovered = ImGui::IsItemHovered();
        ImGui::PopID();

        // Smooth hover animation
        float targetAlpha = hovered ? 1.0f : 0.0f;
        float speed = 8.0f;
        m_hoverAlpha[i] += (targetAlpha - m_hoverAlpha[i]) * std::min(1.0f, speed * dt);
        if (std::fabs(m_hoverAlpha[i]) < 0.001f) m_hoverAlpha[i] = 0.0f;
        if (std::fabs(m_hoverAlpha[i] - 1.0f) < 0.001f) m_hoverAlpha[i] = 1.0f;

        ImDrawList* drawList = ImGui::GetWindowDrawList();

        // Hover background highlight
        if (m_hoverAlpha[i] > 0.0f || isActive) {
            float alpha = isActive ? 0.12f : m_hoverAlpha[i] * 0.08f;
            ImVec4 bgColor = kColorPrimary;
            bgColor.w = alpha;
            drawList->AddRectFilled(itemMin, itemMax, ImGui::ColorConvertFloat4ToU32(bgColor));
        }

        // Active left accent bar
        if (isActive) {
            drawList->AddRectFilled(
                itemMin,
                ImVec2(itemMin.x + accentWidth, itemMax.y),
                ImGui::ColorConvertFloat4ToU32(kColorPrimary),
                2.0f);
        }

        // Icon text
        {
            ImVec4 iconColor = isActive ? kColorPrimary : kColorTextSecondary;
            if (!isActive && m_hoverAlpha[i] > 0.0f) {
                // Lerp icon color toward primary on hover
                iconColor.x += (kColorPrimary.x - iconColor.x) * m_hoverAlpha[i];
                iconColor.y += (kColorPrimary.y - iconColor.y) * m_hoverAlpha[i];
                iconColor.z += (kColorPrimary.z - iconColor.z) * m_hoverAlpha[i];
            }

            float textY = itemMin.y + (itemHeight - ImGui::GetTextLineHeight()) * 0.5f;

            drawList->AddText(
                ImVec2(itemMin.x + padX, textY),
                ImGui::ColorConvertFloat4ToU32(iconColor),
                item.icon);
        }

        // Label text
        {
            ImVec4 labelColor = isActive ? kColorTextPrimary : kColorTextSecondary;
            if (!isActive && m_hoverAlpha[i] > 0.0f) {
                labelColor.x += (kColorTextPrimary.x - labelColor.x) * m_hoverAlpha[i];
                labelColor.y += (kColorTextPrimary.y - labelColor.y) * m_hoverAlpha[i];
                labelColor.z += (kColorTextPrimary.z - labelColor.z) * m_hoverAlpha[i];
            }

            float textY = itemMin.y + (itemHeight - ImGui::GetTextLineHeight()) * 0.5f;

            drawList->AddText(
                ImVec2(itemMin.x + padX + iconColumnWidth, textY),
                ImGui::ColorConvertFloat4ToU32(labelColor),
                item.label);
        }

        if (clicked) {
            currentPage = item.page;
        }
    }

    // ── Bottom Admin Badge ─────────────────────────────────────
    {
        float badgeHeight = 28.0f;
        float bottomPadding = 20.0f;
        float badgeY = windowHeight - badgeHeight - bottomPadding;

        // Only draw if there's room (avoid overlap with nav items)
        float currentY = ImGui::GetCursorPosY();
        if (badgeY > currentY + 10.0f) {
            ImGui::SetCursorPosY(badgeY);
        }

        const char* badgeText = isAdmin ? "ADMIN" : "STANDARD";
        ImVec4 badgeColor = isAdmin ? kColorSuccess : kColorWarning;

        ImVec2 textSize = ImGui::CalcTextSize(badgeText);
        float pillWidth = textSize.x + 20.0f;
        float pillHeight = textSize.y + 8.0f;
        float pillX = (sidebarWidth - pillWidth) * 0.5f;

        ImVec2 screenPos = ImGui::GetCursorScreenPos();
        ImVec2 pillMin = ImVec2(screenPos.x + pillX, screenPos.y);
        ImVec2 pillMax = ImVec2(pillMin.x + pillWidth, pillMin.y + pillHeight);

        ImDrawList* drawList = ImGui::GetWindowDrawList();

        // Pill background (semi-transparent)
        ImVec4 bgColor = badgeColor;
        bgColor.w = 0.15f;
        drawList->AddRectFilled(pillMin, pillMax, ImGui::ColorConvertFloat4ToU32(bgColor), pillHeight * 0.5f);

        // Pill border
        ImVec4 borderColor = badgeColor;
        borderColor.w = 0.5f;
        drawList->AddRect(pillMin, pillMax, ImGui::ColorConvertFloat4ToU32(borderColor), pillHeight * 0.5f, 0, 1.0f);

        // Pill text
        drawList->AddText(
            ImVec2(pillMin.x + (pillWidth - textSize.x) * 0.5f, pillMin.y + (pillHeight - textSize.y) * 0.5f),
            ImGui::ColorConvertFloat4ToU32(badgeColor),
            badgeText);

        ImGui::Dummy(ImVec2(0, pillHeight));
    }

    ImGui::EndChild();

    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar();
}

} // namespace Widgets
