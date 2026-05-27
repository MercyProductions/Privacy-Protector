#pragma once
#include <string>
#include "imgui/imgui.h"

namespace Widgets {

enum class RiskLevel {
    Safe,
    Caution,
    Danger,
    Unknown,
    Info
};

class RiskBadge {
public:
    // Render an inline colored pill badge
    static void Render(RiskLevel level, const char* customText = nullptr);
    
    // Render with tooltip
    static void RenderWithTooltip(RiskLevel level, const char* tooltip, const char* customText = nullptr);
    
    // Get color for a risk level
    static ImVec4 GetColor(RiskLevel level);
    
    // Get default text for a risk level
    static const char* GetText(RiskLevel level);
};

} // namespace Widgets
