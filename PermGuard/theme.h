#pragma once

#include "imgui/imgui.h"

namespace Theme {

// ─── Color Palette ──────────────────────────────────────────────
// Background layers
inline constexpr ImVec4 kBgDeep       = ImVec4(0.043f, 0.055f, 0.075f, 1.0f);  // #0B0E13
inline constexpr ImVec4 kBgBase       = ImVec4(0.051f, 0.067f, 0.090f, 1.0f);  // #0D1117
inline constexpr ImVec4 kBgSurface    = ImVec4(0.110f, 0.129f, 0.157f, 1.0f);  // #1C2128
inline constexpr ImVec4 kBgElevated   = ImVec4(0.137f, 0.161f, 0.192f, 1.0f);  // #232931

// Borders
inline constexpr ImVec4 kBorder       = ImVec4(0.188f, 0.212f, 0.239f, 1.0f);  // #30363D
inline constexpr ImVec4 kBorderLight  = ImVec4(0.188f, 0.212f, 0.239f, 0.5f);

// Accent colors
inline constexpr ImVec4 kTeal         = ImVec4(0.0f,   0.831f, 0.667f, 1.0f);  // #00D4AA
inline constexpr ImVec4 kTealDim      = ImVec4(0.0f,   0.722f, 0.580f, 1.0f);  // #00B894
inline constexpr ImVec4 kTealGlow     = ImVec4(0.0f,   0.831f, 0.667f, 0.15f);

// Status colors
inline constexpr ImVec4 kGreen        = ImVec4(0.180f, 0.800f, 0.443f, 1.0f);  // #2ECC71
inline constexpr ImVec4 kAmber        = ImVec4(0.941f, 0.706f, 0.161f, 1.0f);  // #F0B429
inline constexpr ImVec4 kRed          = ImVec4(0.906f, 0.298f, 0.235f, 1.0f);  // #E74C3C
inline constexpr ImVec4 kBlue         = ImVec4(0.318f, 0.569f, 0.890f, 1.0f);  // #5191E3

// Text
inline constexpr ImVec4 kTextPrimary  = ImVec4(0.902f, 0.929f, 0.953f, 1.0f);  // #E6EDF3
inline constexpr ImVec4 kTextSecondary= ImVec4(0.545f, 0.580f, 0.620f, 1.0f);  // #8B949E
inline constexpr ImVec4 kTextMuted    = ImVec4(0.380f, 0.412f, 0.450f, 1.0f);  // #616973

// ─── Spacing Constants ──────────────────────────────────────────
inline constexpr float kSidebarWidth   = 260.0f;
inline constexpr float kCardRounding   = 8.0f;
inline constexpr float kButtonRounding = 6.0f;
inline constexpr float kBadgeRounding  = 4.0f;
inline constexpr float kPadding        = 16.0f;
inline constexpr float kPaddingSmall   = 8.0f;

// ─── Functions ──────────────────────────────────────────────────
void ApplyPermGuardTheme();

// Helper: lerp between two colors
inline ImVec4 LerpColor(const ImVec4& a, const ImVec4& b, float t) {
    return ImVec4(
        a.x + (b.x - a.x) * t,
        a.y + (b.y - a.y) * t,
        a.z + (b.z - a.z) * t,
        a.w + (b.w - a.w) * t
    );
}

// Helper: color with modified alpha
inline ImVec4 WithAlpha(const ImVec4& c, float alpha) {
    return ImVec4(c.x, c.y, c.z, alpha);
}

// Helper: convert ImVec4 to ImU32 for draw list
inline ImU32 ToU32(const ImVec4& c) {
    return IM_COL32(
        (int)(c.x * 255.0f),
        (int)(c.y * 255.0f),
        (int)(c.z * 255.0f),
        (int)(c.w * 255.0f)
    );
}

} // namespace Theme
