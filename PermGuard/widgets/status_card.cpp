#include "widgets/status_card.h"
#include "imgui/imgui.h"
#include <cstdio>

namespace Widgets {

// Theme color constants
static const ImVec4 kColorSurface       = ImVec4(0.110f, 0.129f, 0.157f, 1.0f);
static const ImVec4 kColorBorder        = ImVec4(0.188f, 0.212f, 0.239f, 1.0f);
static const ImVec4 kColorPrimary       = ImVec4(0.0f, 0.831f, 0.667f, 1.0f);
static const ImVec4 kColorWarning       = ImVec4(0.941f, 0.706f, 0.161f, 1.0f);
static const ImVec4 kColorDanger        = ImVec4(0.906f, 0.298f, 0.235f, 1.0f);
static const ImVec4 kColorSuccess       = ImVec4(0.180f, 0.800f, 0.443f, 1.0f);
static const ImVec4 kColorTextPrimary   = ImVec4(0.902f, 0.929f, 0.953f, 1.0f);
static const ImVec4 kColorTextSecondary = ImVec4(0.545f, 0.580f, 0.620f, 1.0f);
static const ImVec4 kColorInfo          = ImVec4(0.231f, 0.596f, 0.851f, 1.0f);
static const ImVec4 kColorUnknown       = ImVec4(0.400f, 0.420f, 0.450f, 1.0f);

static ImVec4 GetStatusColor(CardStatus status) {
    switch (status) {
        case CardStatus::OK:      return kColorSuccess;
        case CardStatus::Warning: return kColorWarning;
        case CardStatus::Error:   return kColorDanger;
        case CardStatus::Info:    return kColorInfo;
        case CardStatus::Unknown:
        default:                  return kColorUnknown;
    }
}

static const char* GetStatusText(CardStatus status) {
    switch (status) {
        case CardStatus::OK:      return "OK";
        case CardStatus::Warning: return "WARN";
        case CardStatus::Error:   return "ERROR";
        case CardStatus::Info:    return "INFO";
        case CardStatus::Unknown:
        default:                  return "N/A";
    }
}

void StatusCard::Render(float width) {
    if (width <= 0.0f)
        width = ImGui::GetContentRegionAvail().x;

    ImGui::PushID(title.c_str());
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16, 12));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, kColorSurface);
    ImGui::PushStyleColor(ImGuiCol_Border, kColorBorder);

    // Calculate card height based on content
    float headerHeight = ImGui::GetTextLineHeightWithSpacing() + 4.0f;
    float rowHeight = ImGui::GetTextLineHeightWithSpacing();
    int visibleRows = expanded ? static_cast<int>(rows.size()) : 0;
    float contentHeight = headerHeight + (visibleRows > 0 ? 8.0f : 0.0f) + (visibleRows * rowHeight) + 24.0f;

    ImGui::BeginChild("##card", ImVec2(width, contentHeight), ImGuiChildFlags_Borders);

    ImDrawList* drawList = ImGui::GetWindowDrawList();
    float availWidth = ImGui::GetContentRegionAvail().x;

    // ── Header: icon + title (clickable) + status badge ───────
    {
        ImVec2 startPos = ImGui::GetCursorScreenPos();

        // Icon
        if (!icon.empty()) {
            ImGui::PushStyleColor(ImGuiCol_Text, kColorPrimary);
            ImGui::TextUnformatted(icon.c_str());
            ImGui::PopStyleColor();
            ImGui::SameLine();
        }

        // Title (clickable to toggle expand)
        ImGui::PushStyleColor(ImGuiCol_Text, kColorTextPrimary);
        if (ImGui::Selectable(title.c_str(), false, ImGuiSelectableFlags_None, ImVec2(availWidth - 70.0f, 0))) {
            expanded = !expanded;
        }
        ImGui::PopStyleColor();

        // Status badge on the right
        {
            const char* statusText = GetStatusText(status);
            ImVec4 statusColor = GetStatusColor(status);
            ImVec2 textSize = ImGui::CalcTextSize(statusText);
            float pillW = textSize.x + 14.0f;
            float pillH = textSize.y + 4.0f;
            float pillX = startPos.x + availWidth - pillW;
            float pillY = startPos.y;

            ImVec2 pillMin(pillX, pillY);
            ImVec2 pillMax(pillX + pillW, pillY + pillH);

            ImVec4 bgColor = statusColor;
            bgColor.w = 0.18f;
            drawList->AddRectFilled(pillMin, pillMax, ImGui::ColorConvertFloat4ToU32(bgColor), pillH * 0.5f);
            drawList->AddText(
                ImVec2(pillMin.x + (pillW - textSize.x) * 0.5f, pillMin.y + (pillH - textSize.y) * 0.5f),
                ImGui::ColorConvertFloat4ToU32(statusColor),
                statusText);
        }
    }

    // ── Body: key-value rows ──────────────────────────────────
    if (expanded && !rows.empty()) {
        ImGui::Dummy(ImVec2(0, 4));

        // Thin separator
        {
            ImVec2 p = ImGui::GetCursorScreenPos();
            drawList->AddLine(
                ImVec2(p.x, p.y),
                ImVec2(p.x + availWidth, p.y),
                ImGui::ColorConvertFloat4ToU32(kColorBorder), 1.0f);
            ImGui::Dummy(ImVec2(0, 4));
        }

        float labelColumnWidth = availWidth * 0.4f;

        for (const auto& [label, value] : rows) {
            ImGui::PushStyleColor(ImGuiCol_Text, kColorTextSecondary);
            ImGui::TextUnformatted(label.c_str());
            ImGui::PopStyleColor();

            ImGui::SameLine(labelColumnWidth);

            ImGui::PushStyleColor(ImGuiCol_Text, kColorTextPrimary);
            ImGui::TextUnformatted(value.c_str());
            ImGui::PopStyleColor();
        }
    }

    ImGui::EndChild();

    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(2);
    ImGui::PopID();
}

void StatusCard::RenderCompact(const std::string& title, const std::string& value, CardStatus status, float width) {
    if (width <= 0.0f)
        width = ImGui::GetContentRegionAvail().x;

    ImGui::PushID(title.c_str());
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 6.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12, 10));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, kColorSurface);
    ImGui::PushStyleColor(ImGuiCol_Border, kColorBorder);

    float cardHeight = ImGui::GetTextLineHeightWithSpacing() * 2.0f + 20.0f;
    ImGui::BeginChild("##compact_card", ImVec2(width, cardHeight), ImGuiChildFlags_Borders);

    ImDrawList* drawList = ImGui::GetWindowDrawList();

    // Status color accent line at top
    {
        ImVec4 accentColor = GetStatusColor(status);
        ImVec2 winPos = ImGui::GetWindowPos();
        drawList->AddRectFilled(
            ImVec2(winPos.x, winPos.y),
            ImVec2(winPos.x + width, winPos.y + 2.0f),
            ImGui::ColorConvertFloat4ToU32(accentColor),
            6.0f, ImDrawFlags_RoundCornersTop);
    }

    // Title in secondary color
    ImGui::PushStyleColor(ImGuiCol_Text, kColorTextSecondary);
    ImGui::TextUnformatted(title.c_str());
    ImGui::PopStyleColor();

    // Value in primary color, large
    ImGui::PushStyleColor(ImGuiCol_Text, kColorTextPrimary);
    ImGui::TextUnformatted(value.c_str());
    ImGui::PopStyleColor();

    ImGui::EndChild();

    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(2);
    ImGui::PopID();
}

} // namespace Widgets
