#include "widgets/progress_bar.h"
#include "imgui/imgui.h"
#include <cmath>
#include <cstdio>
#include <algorithm>

#ifndef IM_PI
#define IM_PI 3.14159265358979323846f
#endif

namespace Widgets {

// Theme color constants
static const ImVec4 kColorPrimary       = ImVec4(0.0f, 0.831f, 0.667f, 1.0f);
static const ImVec4 kColorWarning       = ImVec4(0.941f, 0.706f, 0.161f, 1.0f);
static const ImVec4 kColorDanger        = ImVec4(0.906f, 0.298f, 0.235f, 1.0f);
static const ImVec4 kColorSuccess       = ImVec4(0.180f, 0.800f, 0.443f, 1.0f);
static const ImVec4 kColorTextPrimary   = ImVec4(0.902f, 0.929f, 0.953f, 1.0f);
static const ImVec4 kColorTextSecondary = ImVec4(0.545f, 0.580f, 0.620f, 1.0f);
static const ImVec4 kColorDarkBg        = ImVec4(0.086f, 0.106f, 0.133f, 1.0f);

static ImVec4 LerpColor(const ImVec4& a, const ImVec4& b, float t) {
    return ImVec4(
        a.x + (b.x - a.x) * t,
        a.y + (b.y - a.y) * t,
        a.z + (b.z - a.z) * t,
        a.w + (b.w - a.w) * t);
}

void ProgressBar::RenderBar(float fraction, float width, float height, const char* overlay) {
    fraction = std::clamp(fraction, 0.0f, 1.0f);

    if (width < 0.0f)
        width = ImGui::GetContentRegionAvail().x;

    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    float rounding = height * 0.5f;

    ImVec2 barMin = pos;
    ImVec2 barMax = ImVec2(pos.x + width, pos.y + height);

    // Background
    drawList->AddRectFilled(barMin, barMax, ImGui::ColorConvertFloat4ToU32(kColorDarkBg), rounding);

    // Fill with gradient based on fraction
    if (fraction > 0.001f) {
        float fillWidth = width * fraction;
        ImVec2 fillMax = ImVec2(pos.x + fillWidth, pos.y + height);

        ImVec4 colorLeft, colorRight;
        if (fraction < 0.3f) {
            // Red to amber
            float t = fraction / 0.3f;
            colorLeft = kColorDanger;
            colorRight = LerpColor(kColorDanger, kColorWarning, t);
        } else if (fraction < 0.7f) {
            // Amber to teal
            float t = (fraction - 0.3f) / 0.4f;
            colorLeft = kColorWarning;
            colorRight = LerpColor(kColorWarning, kColorPrimary, t);
        } else {
            // Teal to green
            float t = (fraction - 0.7f) / 0.3f;
            colorLeft = kColorPrimary;
            colorRight = LerpColor(kColorPrimary, kColorSuccess, t);
        }

        ImU32 colLeft = ImGui::ColorConvertFloat4ToU32(colorLeft);
        ImU32 colRight = ImGui::ColorConvertFloat4ToU32(colorRight);

        // Draw gradient fill using the draw list
        // We clip to rounded rect by drawing the fill then overlaying
        drawList->PushClipRect(barMin, fillMax, true);
        drawList->AddRectFilledMultiColor(barMin, barMax, colLeft, colRight, colRight, colLeft);
        // Re-draw rounded background outline to clip corners properly
        // Actually, for proper rounding we draw a rounded filled rect and use it as a mask
        // ImGui doesn't have native masking, so we approximate by drawing rounded rect
        drawList->PopClipRect();

        // Simpler approach: draw filled rounded rect then gradient on top clipped
        // Let's just draw the rounded rect with the average color, then gradient overlay
        // Actually the simplest correct approach:
        drawList->AddRectFilled(barMin, fillMax, colLeft, rounding);
        // Overlay gradient
        if (fillWidth > rounding * 2.0f) {
            ImVec2 gradMin(barMin.x + rounding, barMin.y);
            ImVec2 gradMax(fillMax.x - rounding, fillMax.y);
            if (gradMax.x > gradMin.x) {
                drawList->AddRectFilledMultiColor(gradMin, gradMax, colLeft, colRight, colRight, colLeft);
            }
            // Right rounded cap
            drawList->AddRectFilled(
                ImVec2(fillMax.x - rounding * 2, barMin.y),
                fillMax,
                colRight, rounding, ImDrawFlags_RoundCornersRight);
        }
    }

    // Overlay text
    if (overlay && overlay[0] != '\0') {
        ImVec2 textSize = ImGui::CalcTextSize(overlay);
        ImVec2 textPos(
            pos.x + (width - textSize.x) * 0.5f,
            pos.y + (height - textSize.y) * 0.5f);
        drawList->AddText(textPos, ImGui::ColorConvertFloat4ToU32(kColorTextPrimary), overlay);
    }

    ImGui::Dummy(ImVec2(width, height));
}

void ProgressBar::RenderCircularScore(int score, float radius, const char* label) {
    score = std::clamp(score, 0, 100);
    float fraction = static_cast<float>(score) / 100.0f;

    ImDrawList* drawList = ImGui::GetWindowDrawList();
    ImVec2 pos = ImGui::GetCursorScreenPos();
    float diameter = radius * 2.0f;

    ImVec2 center(pos.x + radius, pos.y + radius);

    float thickness = radius * 0.12f;
    if (thickness < 3.0f) thickness = 3.0f;

    // Determine color based on score
    ImVec4 scoreColor;
    if (score < 30) {
        scoreColor = kColorDanger;
    } else if (score < 70) {
        scoreColor = kColorWarning;
    } else {
        scoreColor = kColorPrimary;
    }

    // Background ring
    drawList->AddCircle(center, radius - thickness * 0.5f,
        ImGui::ColorConvertFloat4ToU32(ImVec4(kColorDarkBg.x, kColorDarkBg.y, kColorDarkBg.z, 0.6f)),
        64, thickness);

    // Filled arc
    if (fraction > 0.001f) {
        float startAngle = -IM_PI * 0.5f;  // Top of circle (12 o'clock)
        float endAngle = startAngle + IM_PI * 2.0f * fraction;

        int numSegments = static_cast<int>(64.0f * fraction);
        if (numSegments < 4) numSegments = 4;

        float innerRadius = radius - thickness;
        float outerRadius = radius;

        // Draw arc as a thick polyline using path
        ImU32 arcColor = ImGui::ColorConvertFloat4ToU32(scoreColor);

        for (int i = 0; i < numSegments; ++i) {
            float a0 = startAngle + (endAngle - startAngle) * (static_cast<float>(i) / numSegments);
            float a1 = startAngle + (endAngle - startAngle) * (static_cast<float>(i + 1) / numSegments);

            ImVec2 p0_inner(center.x + innerRadius * std::cos(a0), center.y + innerRadius * std::sin(a0));
            ImVec2 p1_inner(center.x + innerRadius * std::cos(a1), center.y + innerRadius * std::sin(a1));
            ImVec2 p0_outer(center.x + outerRadius * std::cos(a0), center.y + outerRadius * std::sin(a0));
            ImVec2 p1_outer(center.x + outerRadius * std::cos(a1), center.y + outerRadius * std::sin(a1));

            drawList->AddQuadFilled(p0_inner, p1_inner, p1_outer, p0_outer, arcColor);
        }
    }

    // Score text in center
    {
        char scoreText[16];
        std::snprintf(scoreText, sizeof(scoreText), "%d", score);
        ImVec2 textSize = ImGui::CalcTextSize(scoreText);
        // We'd like a larger font but we don't have one, so just center it
        drawList->AddText(
            ImVec2(center.x - textSize.x * 0.5f, center.y - textSize.y * 0.5f - 4.0f),
            ImGui::ColorConvertFloat4ToU32(kColorTextPrimary),
            scoreText);
    }

    // Label below the number
    if (label && label[0] != '\0') {
        ImVec2 labelSize = ImGui::CalcTextSize(label);
        drawList->AddText(
            ImVec2(center.x - labelSize.x * 0.5f, center.y + 6.0f),
            ImGui::ColorConvertFloat4ToU32(kColorTextSecondary),
            label);
    }

    // Reserve space
    float totalHeight = diameter + ImGui::GetTextLineHeight();
    ImGui::Dummy(ImVec2(diameter, totalHeight));
}

void ProgressBar::RenderSpinner(float radius) {
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImVec2 center(pos.x + radius, pos.y + radius);

    float time = static_cast<float>(ImGui::GetTime());
    float thickness = radius * 0.25f;
    if (thickness < 2.0f) thickness = 2.0f;

    // Background faint circle
    drawList->AddCircle(center, radius,
        ImGui::ColorConvertFloat4ToU32(ImVec4(kColorDarkBg.x, kColorDarkBg.y, kColorDarkBg.z, 0.3f)),
        32, thickness);

    // Rotating arc (~120 degrees)
    float startAngle = time * 4.0f;  // Rotation speed
    float arcLength = IM_PI * 0.667f; // ~120 degrees
    float endAngle = startAngle + arcLength;

    int numSegments = 24;
    ImU32 arcColor = ImGui::ColorConvertFloat4ToU32(kColorPrimary);

    // Draw arc using path
    drawList->PathClear();
    for (int i = 0; i <= numSegments; ++i) {
        float angle = startAngle + (endAngle - startAngle) * (static_cast<float>(i) / numSegments);
        drawList->PathLineTo(ImVec2(
            center.x + radius * std::cos(angle),
            center.y + radius * std::sin(angle)));
    }
    drawList->PathStroke(arcColor, 0, thickness);

    // Reserve space
    ImGui::Dummy(ImVec2(radius * 2.0f, radius * 2.0f));
}

} // namespace Widgets
