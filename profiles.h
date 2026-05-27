#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <exception>
#include <array>

struct OemProfile {
    std::string name;
    std::string systemManufacturer;
    std::string systemProduct;
    std::string boardManufacturer;
    std::string boardProduct;
    std::string chassisManufacturer;
    std::string serialPrefix;
    int serialLength;
    std::string boardSerialPrefix;
    int boardSerialLength;
    std::string chassisSerialPrefix;
    int chassisSerialLength;
    std::string familyName;
    std::string skuPrefix;
};

inline int ParseProfileLength(const std::string& value, int fallback) {
    if (value.empty()) {
        return fallback;
    }

    try {
        int parsed = std::stoi(value);
        return parsed > 0 ? parsed : fallback;
    } catch (const std::exception&) {
        return fallback;
    }
}

inline void AddProfileError(std::vector<std::string>* errors, const std::string& message) {
    if (errors != nullptr) {
        errors->push_back(message);
    }
}

inline bool TryParsePositiveInt(const std::string& value, int& parsed) {
    try {
        size_t consumed = 0;
        int candidate = std::stoi(value, &consumed);
        if (consumed != value.size() || candidate <= 0) {
            return false;
        }

        parsed = candidate;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

inline bool ValidateOemProfile(const OemProfile& profile, std::vector<std::string>* errors = nullptr) {
    auto requireText = [&](const std::string& field, const std::string& value) {
        if (value.empty()) {
            AddProfileError(errors, field + " is required.");
            return false;
        }
        return true;
    };

    bool ok = true;
    ok = requireText("Name", profile.name) && ok;
    ok = requireText("SystemManufacturer", profile.systemManufacturer) && ok;
    ok = requireText("SystemProduct", profile.systemProduct) && ok;
    ok = requireText("BoardManufacturer", profile.boardManufacturer) && ok;
    ok = requireText("BoardProduct", profile.boardProduct) && ok;
    ok = requireText("ChassisManufacturer", profile.chassisManufacturer) && ok;
    ok = requireText("SystemFamily", profile.familyName) && ok;
    ok = requireText("SystemSKU prefix", profile.skuPrefix) && ok;

    auto validateLength = [&](const std::string& field, const std::string& prefix, int length) {
        if (length <= 0) {
            AddProfileError(errors, field + " must be greater than zero.");
            return false;
        }
        if (length < static_cast<int>(prefix.size())) {
            AddProfileError(errors, field + " must be at least as long as its prefix.");
            return false;
        }
        if (length > 64) {
            AddProfileError(errors, field + " must be 64 characters or fewer.");
            return false;
        }
        return true;
    };

    ok = validateLength("SystemSerialLength", profile.serialPrefix, profile.serialLength) && ok;
    ok = validateLength("BoardSerialLength", profile.boardSerialPrefix, profile.boardSerialLength) && ok;
    ok = validateLength("ChassisSerialLength", profile.chassisSerialPrefix, profile.chassisSerialLength) && ok;

    return ok;
}

inline bool LoadOemProfileFile(const std::filesystem::path& path, OemProfile& profile, std::vector<std::string>* errors = nullptr) {
    std::ifstream f(path);
    if (!f.is_open()) {
        AddProfileError(errors, "Cannot open profile file: " + path.string());
        return false;
    }

    std::array<std::string, 14> fields;
    for (size_t i = 0; i < fields.size(); ++i) {
        if (!std::getline(f, fields[i])) {
            AddProfileError(errors, "Profile is incomplete. Expected 14 lines.");
            return false;
        }
    }

    int serialLength = 0;
    int boardSerialLength = 0;
    int chassisSerialLength = 0;
    bool ok = true;

    if (!TryParsePositiveInt(fields[7], serialLength)) {
        AddProfileError(errors, "SystemSerialLength must be a positive integer.");
        ok = false;
    }
    if (!TryParsePositiveInt(fields[9], boardSerialLength)) {
        AddProfileError(errors, "BoardSerialLength must be a positive integer.");
        ok = false;
    }
    if (!TryParsePositiveInt(fields[11], chassisSerialLength)) {
        AddProfileError(errors, "ChassisSerialLength must be a positive integer.");
        ok = false;
    }

    if (!ok) {
        return false;
    }

    profile = {
        fields[0],
        fields[1],
        fields[2],
        fields[3],
        fields[4],
        fields[5],
        fields[6],
        serialLength,
        fields[8],
        boardSerialLength,
        fields[10],
        chassisSerialLength,
        fields[12],
        fields[13],
    };

    return ValidateOemProfile(profile, errors);
}

inline std::vector<OemProfile> GetOemProfiles(const std::filesystem::path& workDir) {
    std::vector<OemProfile> profiles = {
        {
            "ASUS", "ASUSTeK COMPUTER INC.", "PRIME Z390-A", "ASUSTeK COMPUTER INC.", "PRIME Z390-A", "ASUSTeK COMPUTER INC.",
            "L1", 14, "MB", 14, "CHA", 14, "Desktop", "SKU"
        },
        {
            "MSI", "Micro-Star International Co., Ltd.", "MAG B550 TOMAHAWK (MS-7C91)", "Micro-Star International Co., Ltd.", "MAG B550 TOMAHAWK (MS-7C91)", "Micro-Star International Co., Ltd.",
            "A01", 16, "BSN", 16, "CSN", 16, "Desktop", "SKU"
        },
        {
            "Gigabyte", "Gigabyte Technology Co., Ltd.", "B450 AORUS PRO WIFI", "Gigabyte Technology Co., Ltd.", "B450 AORUS PRO WIFI-CF", "Gigabyte Technology Co., Ltd.",
            "SN", 14, "SN", 14, "SN", 14, "Desktop", "SKU"
        },
        {
            "Dell", "Dell Inc.", "OptiPlex 7090", "Dell Inc.", "0KWVT8", "Dell Inc.",
            "", 7, "", 7, "", 7, "OptiPlex", "SKU"
        },
        {
            "HP", "HP", "HP ProDesk 400 G7 Small Form Factor PC", "HP", "87D1", "HP",
            "", 10, "", 10, "", 10, "103C_53307F", "SKU"
        },
        {
            "Lenovo", "LENOVO", "ThinkCentre M920q 10RS", "LENOVO", "3136RR3", "LENOVO",
            "MP", 10, "MP", 10, "MP", 10, "ThinkCentre M920q", "SKU"
        },
        {
            "Random (Generic)", "System manufacturer", "System Product Name", "System manufacturer", "System Product Name", "System manufacturer",
            "SYS-", 16, "MB-", 16, "CHA-", 16, "Desktop-PRO-V2", "SKU-"
        }
    };

    // Load custom profiles
    try {
        if (std::filesystem::exists(workDir)) {
            for (const auto& entry : std::filesystem::directory_iterator(workDir)) {
                if (entry.path().extension() == ".profile") {
                    OemProfile p;
                    if (!LoadOemProfileFile(entry.path(), p)) continue;

                    p.name = "(Custom) " + p.name;
                    profiles.push_back(p);
                }
            }
        }
    } catch (const std::exception&) {
        // Ignore malformed or inaccessible custom profile directories.
    }

    return profiles;
}
