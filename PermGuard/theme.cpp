#include "theme.h"

namespace Theme {

void ApplyPermGuardTheme() {
    ImGuiStyle& style = ImGui::GetStyle();

    // ── Sizing ──────────────────────────────────────────────────
    style.WindowPadding     = ImVec2(kPadding, kPadding);
    style.FramePadding      = ImVec2(12.0f, 8.0f);
    style.CellPadding       = ImVec2(8.0f, 4.0f);
    style.ItemSpacing       = ImVec2(10.0f, 8.0f);
    style.ItemInnerSpacing  = ImVec2(8.0f, 4.0f);
    style.IndentSpacing     = 20.0f;
    style.ScrollbarSize     = 12.0f;
    style.GrabMinSize       = 10.0f;

    // ── Rounding ────────────────────────────────────────────────
    style.WindowRounding    = 0.0f;    // Main window has no rounding
    style.ChildRounding     = kCardRounding;
    style.FrameRounding     = kButtonRounding;
    style.PopupRounding     = kCardRounding;
    style.ScrollbarRounding = 6.0f;
    style.GrabRounding      = 4.0f;
    style.TabRounding       = 6.0f;

    // ── Borders ─────────────────────────────────────────────────
    style.WindowBorderSize  = 0.0f;
    style.ChildBorderSize   = 1.0f;
    style.PopupBorderSize   = 1.0f;
    style.FrameBorderSize   = 0.0f;
    style.TabBorderSize     = 0.0f;

    // ── Alignment ───────────────────────────────────────────────
    style.WindowTitleAlign  = ImVec2(0.5f, 0.5f);
    style.ButtonTextAlign   = ImVec2(0.5f, 0.5f);

    // ── Anti-aliasing ───────────────────────────────────────────
    style.AntiAliasedLines  = true;
    style.AntiAliasedFill   = true;

    // ── Colors ──────────────────────────────────────────────────
    ImVec4* colors = style.Colors;

    // Text
    colors[ImGuiCol_Text]                  = kTextPrimary;
    colors[ImGuiCol_TextDisabled]          = kTextMuted;

    // Windows
    colors[ImGuiCol_WindowBg]              = kBgBase;
    colors[ImGuiCol_ChildBg]               = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    colors[ImGuiCol_PopupBg]               = kBgElevated;

    // Borders
    colors[ImGuiCol_Border]                = kBorder;
    colors[ImGuiCol_BorderShadow]          = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);

    // Frame BG (inputs, checkboxes, etc.)
    colors[ImGuiCol_FrameBg]               = kBgSurface;
    colors[ImGuiCol_FrameBgHovered]        = kBgElevated;
    colors[ImGuiCol_FrameBgActive]         = WithAlpha(kTeal, 0.25f);

    // Title bar
    colors[ImGuiCol_TitleBg]               = kBgDeep;
    colors[ImGuiCol_TitleBgActive]         = kBgDeep;
    colors[ImGuiCol_TitleBgCollapsed]      = kBgDeep;

    // Menu bar
    colors[ImGuiCol_MenuBarBg]             = kBgSurface;

    // Scrollbar
    colors[ImGuiCol_ScrollbarBg]           = kBgDeep;
    colors[ImGuiCol_ScrollbarGrab]         = kBorder;
    colors[ImGuiCol_ScrollbarGrabHovered]  = kTextMuted;
    colors[ImGuiCol_ScrollbarGrabActive]   = kTextSecondary;

    // Checkmark
    colors[ImGuiCol_CheckMark]             = kTeal;

    // Slider
    colors[ImGuiCol_SliderGrab]            = kTeal;
    colors[ImGuiCol_SliderGrabActive]      = kTealDim;

    // Buttons
    colors[ImGuiCol_Button]                = kBgSurface;
    colors[ImGuiCol_ButtonHovered]         = WithAlpha(kTeal, 0.20f);
    colors[ImGuiCol_ButtonActive]          = WithAlpha(kTeal, 0.35f);

    // Headers (collapsing headers, tree nodes, selectables)
    colors[ImGuiCol_Header]                = WithAlpha(kTeal, 0.12f);
    colors[ImGuiCol_HeaderHovered]         = WithAlpha(kTeal, 0.20f);
    colors[ImGuiCol_HeaderActive]          = WithAlpha(kTeal, 0.30f);

    // Separators
    colors[ImGuiCol_Separator]             = kBorder;
    colors[ImGuiCol_SeparatorHovered]      = kTeal;
    colors[ImGuiCol_SeparatorActive]       = kTealDim;

    // Resize grip
    colors[ImGuiCol_ResizeGrip]            = WithAlpha(kTeal, 0.10f);
    colors[ImGuiCol_ResizeGripHovered]     = WithAlpha(kTeal, 0.30f);
    colors[ImGuiCol_ResizeGripActive]      = WithAlpha(kTeal, 0.50f);

    // Tabs
    colors[ImGuiCol_Tab]                   = kBgSurface;
    colors[ImGuiCol_TabHovered]            = WithAlpha(kTeal, 0.30f);
    colors[ImGuiCol_TabSelected]           = WithAlpha(kTeal, 0.20f);
    colors[ImGuiCol_TabDimmed]             = kBgDeep;
    colors[ImGuiCol_TabDimmedSelected]     = kBgSurface;

    // Tables
    colors[ImGuiCol_TableHeaderBg]         = kBgElevated;
    colors[ImGuiCol_TableBorderStrong]     = kBorder;
    colors[ImGuiCol_TableBorderLight]      = kBorderLight;
    colors[ImGuiCol_TableRowBg]            = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    colors[ImGuiCol_TableRowBgAlt]         = WithAlpha(kBgSurface, 0.3f);

    // Nav highlight
    colors[ImGuiCol_NavHighlight]          = kTeal;

    // Modal dim
    colors[ImGuiCol_ModalWindowDimBg]      = ImVec4(0.0f, 0.0f, 0.0f, 0.6f);

    // Drag/drop target
    colors[ImGuiCol_DragDropTarget]        = kTeal;

    // Text selection
    colors[ImGuiCol_TextSelectedBg]        = WithAlpha(kTeal, 0.30f);
}

} // namespace Theme
