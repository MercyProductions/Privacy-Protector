#pragma once
#include <string>
#include <vector>
#include <utility>

namespace Widgets {

enum class CardStatus {
    OK,
    Good = OK,
    Warning,
    Error,
    Critical = Error,
    Unknown,
    Info
};

struct StatusCard {
    std::string title;
    std::string icon;
    CardStatus status = CardStatus::Unknown;
    std::vector<std::pair<std::string, std::string>> rows;  // label, value pairs
    bool expanded = true;
    
    void Render(float width = 0.0f);
    static void RenderCompact(const std::string& title, const std::string& value, CardStatus status, float width = 0.0f);
};

} // namespace Widgets
