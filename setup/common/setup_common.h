#pragma once

#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace SetupCommon {

struct PlanItem {
    std::string title;
    std::string detail;
    std::string status;
};

struct PlanDocument {
    std::string name;
    std::string purpose;
    std::string boundary;
    std::vector<PlanItem> steps;
    std::vector<PlanItem> warnings;
    std::vector<PlanItem> outputs;
};

inline std::string TimestampForFile() {
    std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &now);

    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y%m%d_%H%M%S", &local);
    return buffer;
}

inline std::string TimestampIso() {
    std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &now);

    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &local);
    return buffer;
}

inline std::filesystem::path ResolveOutputDir(const std::string& outputArg, const std::string& areaName) {
    if (!outputArg.empty()) {
        return std::filesystem::absolute(std::filesystem::path(outputArg));
    }

    return std::filesystem::current_path() / "setup_artifacts" / (areaName + "_" + TimestampForFile());
}

inline bool EnsureDirectory(const std::filesystem::path& dir, std::string& error) {
    try {
        std::filesystem::create_directories(dir);
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

inline bool WriteTextFile(const std::filesystem::path& path, const std::string& text, std::string& error) {
    try {
        if (!path.parent_path().empty()) {
            std::filesystem::create_directories(path.parent_path());
        }

        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) {
            error = "could not open output file";
            return false;
        }

        file << text;
        if (!file.good()) {
            error = "write failed";
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

inline std::string JsonEscape(const std::string& value) {
    std::ostringstream escaped;
    for (unsigned char ch : value) {
        switch (ch) {
            case '\\': escaped << "\\\\"; break;
            case '"': escaped << "\\\""; break;
            case '\b': escaped << "\\b"; break;
            case '\f': escaped << "\\f"; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            default:
                if (ch < 0x20) {
                    escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                            << static_cast<int>(ch) << std::dec << std::setfill(' ');
                } else {
                    escaped << static_cast<char>(ch);
                }
                break;
        }
    }
    return escaped.str();
}

inline void AppendItemsText(std::ostringstream& out, const std::string& title, const std::vector<PlanItem>& items) {
    if (items.empty()) {
        return;
    }

    out << "\n" << title << "\n";
    out << std::string(title.size(), '-') << "\n";
    for (size_t i = 0; i < items.size(); ++i) {
        const auto& item = items[i];
        out << (i + 1) << ". " << item.title;
        if (!item.status.empty()) {
            out << " [" << item.status << "]";
        }
        out << "\n";
        if (!item.detail.empty()) {
            out << "   " << item.detail << "\n";
        }
    }
}

inline std::string BuildPlanText(const PlanDocument& doc) {
    std::ostringstream out;
    out << doc.name << "\n";
    out << std::string(doc.name.size(), '=') << "\n";
    out << "Created: " << TimestampIso() << "\n\n";
    out << "Purpose: " << doc.purpose << "\n\n";
    out << "Boundary: " << doc.boundary << "\n";

    AppendItemsText(out, "Steps", doc.steps);
    AppendItemsText(out, "Warnings", doc.warnings);
    AppendItemsText(out, "Artifacts", doc.outputs);
    out << "\n";
    return out.str();
}

inline void AppendItemsJson(std::ostringstream& out, const std::string& name, const std::vector<PlanItem>& items, bool trailingComma) {
    out << "  \"" << name << "\": [\n";
    for (size_t i = 0; i < items.size(); ++i) {
        const auto& item = items[i];
        out << "    {\n";
        out << "      \"title\": \"" << JsonEscape(item.title) << "\",\n";
        out << "      \"detail\": \"" << JsonEscape(item.detail) << "\",\n";
        out << "      \"status\": \"" << JsonEscape(item.status) << "\"\n";
        out << "    }" << (i + 1 == items.size() ? "\n" : ",\n");
    }
    out << "  ]" << (trailingComma ? "," : "") << "\n";
}

inline std::string BuildPlanJson(const PlanDocument& doc) {
    std::ostringstream out;
    out << "{\n";
    out << "  \"schemaVersion\": 1,\n";
    out << "  \"createdAt\": \"" << JsonEscape(TimestampIso()) << "\",\n";
    out << "  \"name\": \"" << JsonEscape(doc.name) << "\",\n";
    out << "  \"purpose\": \"" << JsonEscape(doc.purpose) << "\",\n";
    out << "  \"boundary\": \"" << JsonEscape(doc.boundary) << "\",\n";
    AppendItemsJson(out, "steps", doc.steps, true);
    AppendItemsJson(out, "warnings", doc.warnings, true);
    AppendItemsJson(out, "artifacts", doc.outputs, false);
    out << "}\n";
    return out.str();
}

inline bool WritePlanBundle(const std::filesystem::path& outputDir, const std::string& stem,
    const PlanDocument& doc, std::filesystem::path& textPath, std::filesystem::path& jsonPath, std::string& error) {
    if (!EnsureDirectory(outputDir, error)) {
        return false;
    }

    textPath = outputDir / (stem + ".txt");
    jsonPath = outputDir / (stem + ".json");

    if (!WriteTextFile(textPath, BuildPlanText(doc), error)) {
        return false;
    }

    return WriteTextFile(jsonPath, BuildPlanJson(doc), error);
}

inline void PrintGenerated(const std::filesystem::path& dir, const std::filesystem::path& textPath,
    const std::filesystem::path& jsonPath) {
    std::cout << "Generated setup artifacts.\n"
              << "  Directory: " << dir.string() << "\n"
              << "  Text plan: " << textPath.string() << "\n"
              << "  JSON plan: " << jsonPath.string() << "\n";
}

} // namespace SetupCommon
