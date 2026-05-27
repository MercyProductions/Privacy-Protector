#include "widgets/risk_badge.h"
#include "imgui/imgui.h"

namespace Widgets {

// Theme color constants
static const ImVec4 kColorPrimary       = ImVec4(0.0f, 0.831f, 0.667f, 1.0f);
static const ImVec4 kColorWarning       = ImVec4(0.941f, 0.706f, 0.161f, 1.0f);
static const ImVec4 kColorDanger        = ImVec4(0.906f, 0.298f, 0.235f, 1.0f);
static const ImVec4 kColorSuccess       = ImVec4(0.180f, 0.800f, 0.443f, 1.0f);
static const ImVec4 kColorTextPrimary   = ImVec4(0.902f, 0.929f, 0.953f, 1.0f);
static const ImVec4 kColorGray          = ImVec4(0.400f, 0.420f, 0.450f, 1.0f);
static const ImVec4 kColorInfo          = ImVec4(0.231f, 0.596f, 0.851f, 1.0f);

ImVec4 RiskBadge::GetColor(RiskLevel level) {
    switch (level) {
        case RiskLevel::Safe:    return kColorSuccess;
        case RiskLevel::Caution: return kColorWarning;
        case RiskLevel::Danger:  return kColorDanger;
        case RiskLevel::Info:    return kColorInfo;
        case RiskLevel::Unknown:
        default:                 return kColorGray;
    }
}

const char* RiskBadge::GetText(RiskLevel level) {
    switch (level) {
        case RiskLevel::Safe:    return "SAFE";
        case RiskLevel::Caution: return "CAUTION";
        case RiskLevel::Danger:  return "DANGER";
        case RiskLevel::Info:    return "INFO";
        case RiskLevel::Unknown:
        default:                 return "UNKNOWN";
    }
}

void RiskBadge::Render(RiskLevel level, const char* customText) {
    const char* text = customText ? customText : GetText(level);
    ImVec4 color = GetColor(level);

    ImVec2 textSize = ImGui::CalcTextSize(text);
    float padX = 8.0f;
    float padY = 3.0f;
    float pillWidth = textSize.x + padX * 2.0f;
    float pillHeight = textSize.y + padY * 2.0f;
    float rounding = pillHeight * 0.5f;

    ImVec2 cursorPos = ImGui::GetCursorScreenPos();
    ImDrawList* drawList = ImGui::GetWindowDrawList();

    ImVec2 pillMin = cursorPos;
    ImVec2 pillMax(cursorPos.x + pillWidth, cursorPos.y + pillHeight);

    // Background (semi-transparent version of the color)
    ImVec4 bgColor = color;
    bgColor.w = 0.18f;
    drawList->AddRectFilled(pillMin, pillMax, ImGui::ColorConvertFloat4ToU32(bgColor), rounding);

    // Border (slightly more visible)
    ImVec4 borderColor = color;
    borderColor.w = 0.35f;
    drawList->AddRect(pillMin, pillMax, ImGui::ColorConvertFloat4ToU32(borderColor), rounding, 0, 1.0f);

    // Text centered in pill
    ImVec2 textPos(
        pillMin.x + (pillWidth - textSize.x) * 0.5f,
        pillMin.y + (pillHeight - textSize.y) * 0.5f);
    drawList->AddText(textPos, ImGui::ColorConvertFloat4ToU32(color), text);

    // Reserve space and make it interactable for tooltip detection
    ImGui::Dummy(ImVec2(pillWidth, pillHeight));
}

void RiskBadge::RenderWithTooltip(RiskLevel level, const char* tooltip, const char* customText) {
    const char* text = customText ? customText : GetText(level);
    ImVec4 color = GetColor(level);

    ImVec2 textSize = ImGui::CalcTextSize(text);
    float padX = 8.0f;
    float padY = 3.0f;
    float pillWidth = textSize.x + padX * 2.0f;
    float pillHeight = textSize.y + padY * 2.0f;
    float rounding = pillHeight * 0.5f;

    ImVec2 cursorPos = ImGui::GetCursorScreenPos();
    ImDrawList* drawList = ImGui::GetWindowDrawList();

    ImVec2 pillMin = cursorPos;
    ImVec2 pillMax(cursorPos.x + pillWidth, cursorPos.y + pillHeight);

    // Background
    ImVec4 bgColor = color;
    bgColor.w = 0.18f;
    drawList->AddRectFilled(pillMin, pillMax, ImGui::ColorConvertFloat4ToU32(bgColor), rounding);

    // Border
    ImVec4 borderColor = color;
    borderColor.w = 0.35f;
    drawList->AddRect(pillMin, pillMax, ImGui::ColorConvertFloat4ToU32(borderColor), rounding, 0, 1.0f);

    // Text
    ImVec2 textPos(
        pillMin.x + (pillWidth - textSize.x) * 0.5f,
        pillMin.y + (pillHeight - textSize.y) * 0.5f);
    drawList->AddText(textPos, ImGui::ColorConvertFloat4ToU32(color), text);

    // Invisible button for hover detection (overlaps the drawn pill)
    ImGui::InvisibleButton("##badge", ImVec2(pillWidth, pillHeight));
    if (ImGui::IsItemHovered() && tooltip && tooltip[0] != '\0') {
        ImGui::SetTooltip("%s", tooltip);
    }
}

} // namespace Widgets
