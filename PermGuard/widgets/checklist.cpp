#include "widgets/checklist.h"
#include "imgui/imgui.h"
#include <cstdio>
#include <cmath>

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
static const ImVec4 kColorDarkBg        = ImVec4(0.086f, 0.106f, 0.133f, 1.0f);
static const ImVec4 kColorGray          = ImVec4(0.400f, 0.420f, 0.450f, 1.0f);

static ImVec4 GetRiskColor(ChecklistRisk risk) {
    switch (risk) {
        case ChecklistRisk::Low:      return kColorGray;
        case ChecklistRisk::Medium:   return kColorWarning;
        case ChecklistRisk::High:     return kColorDanger;
        case ChecklistRisk::Critical: return kColorDanger;
        case ChecklistRisk::None:
        default:                      return ImVec4(0, 0, 0, 0);
    }
}

static const char* GetRiskText(ChecklistRisk risk) {
    switch (risk) {
        case ChecklistRisk::Low:      return "LOW";
        case ChecklistRisk::Medium:   return "MEDIUM";
        case ChecklistRisk::High:     return "HIGH";
        case ChecklistRisk::Critical: return "CRITICAL";
        case ChecklistRisk::None:
        default:                      return "";
    }
}

int Checklist::GetCheckedCount() const {
    int count = 0;
    for (const auto& item : items) {
        if (item.checked || item.autoChecked) ++count;
    }
    return count;
}

int Checklist::GetTotalCount() const {
    return static_cast<int>(items.size());
}

bool Checklist::IsComplete() const {
    return GetCheckedCount() == GetTotalCount() && GetTotalCount() > 0;
}

float Checklist::GetProgress() const {
    int total = GetTotalCount();
    if (total == 0) return 0.0f;
    return static_cast<float>(GetCheckedCount()) / static_cast<float>(total);
}

void Checklist::Render() {
    if (items.empty()) return;

    ImGui::PushID(title.c_str());

    int checkedCount = GetCheckedCount();
    int totalCount = GetTotalCount();
    float progress = GetProgress();

    ImDrawList* drawList = ImGui::GetWindowDrawList();
    float availWidth = ImGui::GetContentRegionAvail().x;

    // ── Title + progress text ─────────────────────────────────
    {
        ImGui::PushStyleColor(ImGuiCol_Text, kColorTextPrimary);
        ImGui::TextUnformatted(title.c_str());
        ImGui::PopStyleColor();

        // Progress text on the right
        char progressText[64];
        std::snprintf(progressText, sizeof(progressText), "%d of %d completed", checkedCount, totalCount);
        ImVec2 progressTextSize = ImGui::CalcTextSize(progressText);
        ImGui::SameLine(availWidth - progressTextSize.x);
        ImGui::PushStyleColor(ImGuiCol_Text, kColorTextSecondary);
        ImGui::TextUnformatted(progressText);
        ImGui::PopStyleColor();
    }

    // ── Progress bar ──────────────────────────────────────────
    {
        ImGui::Dummy(ImVec2(0, 2));
        ImVec2 barPos = ImGui::GetCursorScreenPos();
        float barWidth = availWidth;
        float barHeight = 4.0f;

        // Background
        drawList->AddRectFilled(
            barPos,
            ImVec2(barPos.x + barWidth, barPos.y + barHeight),
            ImGui::ColorConvertFloat4ToU32(kColorDarkBg),
            barHeight * 0.5f);

        // Fill
        if (progress > 0.0f) {
            float fillWidth = barWidth * progress;
            drawList->AddRectFilled(
                barPos,
                ImVec2(barPos.x + fillWidth, barPos.y + barHeight),
                ImGui::ColorConvertFloat4ToU32(kColorPrimary),
                barHeight * 0.5f);
        }

        ImGui::Dummy(ImVec2(0, barHeight + 8.0f));
    }

    // ── Checklist items ───────────────────────────────────────
    for (int i = 0; i < static_cast<int>(items.size()); ++i) {
        auto& item = items[i];
        ImGui::PushID(i);

        bool isChecked = item.checked || item.autoChecked;

        // ── Checkbox ──────────────────────────────────────────
        if (item.autoChecked) {
            // Auto-checked: show a green checkmark, disabled checkbox feel
            ImGui::PushStyleColor(ImGuiCol_CheckMark, ImGui::ColorConvertFloat4ToU32(kColorSuccess));
            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertFloat4ToU32(ImVec4(kColorSuccess.x, kColorSuccess.y, kColorSuccess.z, 0.1f)));
            ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImGui::ColorConvertFloat4ToU32(ImVec4(kColorSuccess.x, kColorSuccess.y, kColorSuccess.z, 0.15f)));

            bool temp = true;
            ImGui::Checkbox("##auto", &temp); // Always shows checked; no user interaction needed

            ImGui::PopStyleColor(3);
        } else {
            // Manual checkbox with teal styling when checked
            if (item.checked) {
                ImGui::PushStyleColor(ImGuiCol_CheckMark, ImGui::ColorConvertFloat4ToU32(kColorPrimary));
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertFloat4ToU32(ImVec4(kColorPrimary.x, kColorPrimary.y, kColorPrimary.z, 0.1f)));
                ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImGui::ColorConvertFloat4ToU32(ImVec4(kColorPrimary.x, kColorPrimary.y, kColorPrimary.z, 0.2f)));
            } else {
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertFloat4ToU32(kColorDarkBg));
                ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImGui::ColorConvertFloat4ToU32(kColorBorder));
                ImGui::PushStyleColor(ImGuiCol_CheckMark, ImGui::ColorConvertFloat4ToU32(kColorPrimary));
            }

            ImGui::Checkbox("##check", &item.checked);

            ImGui::PopStyleColor(3);
        }

        ImGui::SameLine();

        // ── Label ─────────────────────────────────────────────
        {
            ImVec4 labelColor = isChecked ? kColorTextSecondary : kColorTextPrimary;
            ImGui::PushStyleColor(ImGuiCol_Text, labelColor);
            ImGui::TextUnformatted(item.label.c_str());
            ImGui::PopStyleColor();
        }

        // ── Risk badge on the right ───────────────────────────
        if (item.risk != ChecklistRisk::None) {
            const char* riskText = GetRiskText(item.risk);
            ImVec4 riskColor = GetRiskColor(item.risk);

            ImVec2 textSize = ImGui::CalcTextSize(riskText);
            float pillW = textSize.x + 12.0f;
            float pillH = textSize.y + 4.0f;

            float rightEdge = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
            // We need to position relative to the current line
            ImVec2 lineStart = ImGui::GetCursorScreenPos();
            float pillX = rightEdge - pillW;
            // Go back one line height to align with the label
            float pillY = lineStart.y - ImGui::GetTextLineHeightWithSpacing();

            // Pulsing effect for Critical
            float alpha = 1.0f;
            if (item.risk == ChecklistRisk::Critical) {
                alpha = 0.6f + 0.4f * (0.5f + 0.5f * std::sin(static_cast<float>(ImGui::GetTime()) * 4.0f));
            }

            ImVec4 bgColor = riskColor;
            bgColor.w = 0.18f * alpha;

            ImVec4 textColor = riskColor;
            textColor.w = alpha;

            ImVec2 pillMin(pillX, pillY);
            ImVec2 pillMax(pillX + pillW, pillY + pillH);

            drawList->AddRectFilled(pillMin, pillMax, ImGui::ColorConvertFloat4ToU32(bgColor), pillH * 0.5f);
            drawList->AddText(
                ImVec2(pillMin.x + (pillW - textSize.x) * 0.5f, pillMin.y + (pillH - textSize.y) * 0.5f),
                ImGui::ColorConvertFloat4ToU32(textColor),
                riskText);
        }

        // ── Auto-checked indicator ────────────────────────────
        if (item.autoChecked) {
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Text, kColorSuccess);
            ImGui::TextUnformatted("(auto)");
            ImGui::PopStyleColor();
        }

        // ── Description ───────────────────────────────────────
        if (!item.description.empty()) {
            // Indent to align with label (past checkbox)
            float indent = ImGui::GetFrameHeight() + ImGui::GetStyle().ItemInnerSpacing.x;
            ImGui::Dummy(ImVec2(0, 0));
            ImGui::SameLine(indent);
            ImGui::PushStyleColor(ImGuiCol_Text, kColorTextSecondary);
            ImGui::TextWrapped("%s", item.description.c_str());
            ImGui::PopStyleColor();
        }

        ImGui::Dummy(ImVec2(0, 2));
        ImGui::PopID();
    }

    ImGui::PopID();
}

} // namespace Widgets
