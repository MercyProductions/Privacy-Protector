#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <optional>

namespace Core {

class Registry {
public:
    static std::optional<std::string> ReadString(HKEY root, const std::wstring& subKey, const std::wstring& valueName);
    static std::optional<DWORD> ReadDword(HKEY root, const std::wstring& subKey, const std::wstring& valueName);
    static std::vector<std::string> EnumSubkeys(HKEY root, const std::wstring& subKey);
    static bool KeyExists(HKEY root, const std::wstring& subKey);
};

} // namespace Core
