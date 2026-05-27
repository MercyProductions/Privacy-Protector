#pragma once
#include <string>
#include <vector>
#include <map>
#include <optional>

namespace Core {

struct WmiResult {
    std::map<std::string, std::string> properties;

    std::string& operator[](const std::string& key) {
        return properties[key];
    }

    std::string operator[](const std::string& key) const {
        auto it = properties.find(key);
        return it == properties.end() ? std::string{} : it->second;
    }
};

class WmiQuery {
public:
    // Initialize COM for this thread (call once)
    static bool InitializeCom();
    static void UninitializeCom();

    // Query a WMI namespace. Returns vector of result rows.
    // namespace examples: "ROOT\\CIMV2", "ROOT\\CIMV2\\Security\\MicrosoftTpm"
    static std::vector<WmiResult> Query(
        const std::string& wmiNamespace,
        const std::string& query);

    // Convenience: query ROOT\CIMV2
    static std::vector<WmiResult> QueryCimv2(const std::string& query);

    // Get a single property value from first result
    static std::optional<std::string> QuerySingleValue(
        const std::string& wmiNamespace,
        const std::string& query,
        const std::string& propertyName);
};

} // namespace Core
