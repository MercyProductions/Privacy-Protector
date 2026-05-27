#pragma once
#include <string>
#include <vector>
#include <utility>

namespace Widgets {

enum class ChecklistRisk {
    None,
    Low,
    Medium,
    High,
    Critical
};

struct ChecklistItem {
    std::string label;
    std::string description;
    bool checked = false;
    bool autoChecked = false;  // System verified this automatically
    ChecklistRisk risk = ChecklistRisk::None;
};

class Checklist {
public:
    std::string title;
    std::vector<ChecklistItem> items;

    Checklist() = default;
    explicit Checklist(std::string titleText) : title(std::move(titleText)) {}

    void AddItem(const std::string&, const std::string& label,
                 const std::string& description = {},
                 ChecklistRisk risk = ChecklistRisk::None) {
        items.push_back({ label, description, false, false, risk });
    }
    
    void Render();
    int GetCheckedCount() const;
    int GetTotalCount() const;
    bool IsComplete() const;
    float GetProgress() const;
};

} // namespace Widgets
