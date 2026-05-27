#include "registry.h"

namespace Core {

static std::string WideToUtf8(const wchar_t* wstr, int len) {
    if (!wstr || len == 0) return {};
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr, len, nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) return {};
    std::string result(sizeNeeded, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, len, result.data(), sizeNeeded, nullptr, nullptr);
    return result;
}

static std::string WideToUtf8(const std::wstring& wstr) {
    return WideToUtf8(wstr.c_str(), static_cast<int>(wstr.size()));
}

std::optional<std::string> Registry::ReadString(HKEY root, const std::wstring& subKey, const std::wstring& valueName) {
    HKEY hKey = nullptr;
    LONG status = RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (status != ERROR_SUCCESS) {
        return std::nullopt;
    }

    // First query to get the size
    DWORD type = 0;
    DWORD dataSize = 0;
    status = RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type, nullptr, &dataSize);
    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        RegCloseKey(hKey);
        return std::nullopt;
    }

    // Allocate buffer and read
    std::vector<BYTE> buffer(dataSize);
    status = RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type, buffer.data(), &dataSize);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS) {
        return std::nullopt;
    }

    // Convert wide string to narrow UTF-8
    const wchar_t* wideStr = reinterpret_cast<const wchar_t*>(buffer.data());
    int charCount = static_cast<int>(dataSize / sizeof(wchar_t));

    // Remove trailing null if present
    if (charCount > 0 && wideStr[charCount - 1] == L'\0') {
        charCount--;
    }

    return WideToUtf8(wideStr, charCount);
}

std::optional<DWORD> Registry::ReadDword(HKEY root, const std::wstring& subKey, const std::wstring& valueName) {
    HKEY hKey = nullptr;
    LONG status = RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (status != ERROR_SUCCESS) {
        return std::nullopt;
    }

    DWORD type = 0;
    DWORD data = 0;
    DWORD dataSize = sizeof(DWORD);
    status = RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type, reinterpret_cast<BYTE*>(&data), &dataSize);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS || type != REG_DWORD) {
        return std::nullopt;
    }

    return data;
}

std::vector<std::string> Registry::EnumSubkeys(HKEY root, const std::wstring& subKey) {
    std::vector<std::string> subkeys;

    HKEY hKey = nullptr;
    LONG status = RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (status != ERROR_SUCCESS) {
        return subkeys;
    }

    DWORD index = 0;
    wchar_t nameBuffer[256];

    while (true) {
        DWORD nameLen = static_cast<DWORD>(std::size(nameBuffer));
        status = RegEnumKeyExW(hKey, index, nameBuffer, &nameLen, nullptr, nullptr, nullptr, nullptr);

        if (status == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (status != ERROR_SUCCESS) {
            break;
        }

        subkeys.push_back(WideToUtf8(nameBuffer, static_cast<int>(nameLen)));
        index++;
    }

    RegCloseKey(hKey);
    return subkeys;
}

bool Registry::KeyExists(HKEY root, const std::wstring& subKey) {
    HKEY hKey = nullptr;
    LONG status = RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (status == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

} // namespace Core
