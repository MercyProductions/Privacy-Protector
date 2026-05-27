#include "admin.h"

#include <shellapi.h>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")

namespace Core {

static std::string WideToUtf8(const wchar_t* wstr, int len) {
    if (!wstr || len == 0) return {};
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr, len, nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) return {};
    std::string result(sizeNeeded, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, len, result.data(), sizeNeeded, nullptr, nullptr);
    return result;
}

bool Admin::IsElevated() {
    BOOL elevated = FALSE;
    PSID adminGroup = nullptr;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
            &ntAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &adminGroup)) {
        return false;
    }

    if (!CheckTokenMembership(nullptr, adminGroup, &elevated)) {
        elevated = FALSE;
    }

    FreeSid(adminGroup);
    return elevated != FALSE;
}

void Admin::RequestElevation() {
    wchar_t exePath[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return;
    }

    // Get the command line arguments (skip the executable name)
    LPWSTR cmdLine = GetCommandLineW();
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(cmdLine, &argc);

    std::wstring params;
    if (argv) {
        for (int i = 1; i < argc; i++) {
            if (!params.empty()) params += L' ';
            // Quote arguments that contain spaces
            std::wstring arg = argv[i];
            if (arg.find(L' ') != std::wstring::npos) {
                params += L'"';
                params += arg;
                params += L'"';
            } else {
                params += arg;
            }
        }
        LocalFree(argv);
    }

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(SHELLEXECUTEINFOW);
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = params.empty() ? nullptr : params.c_str();
    sei.nShow = SW_SHOWNORMAL;
    sei.fMask = SEE_MASK_NOASYNC;

    if (ShellExecuteExW(&sei)) {
        ExitProcess(0);
    }
    // If ShellExecuteEx fails (user declined UAC), just return
}

std::string Admin::GetCurrentUser() {
    wchar_t buffer[256];
    DWORD size = static_cast<DWORD>(std::size(buffer));

    if (!GetUserNameW(buffer, &size)) {
        return "Unknown";
    }

    // size includes the null terminator
    return WideToUtf8(buffer, static_cast<int>(size - 1));
}

std::string Admin::GetComputerName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = static_cast<DWORD>(std::size(buffer));

    if (!::GetComputerNameW(buffer, &size)) {
        return "Unknown";
    }

    return WideToUtf8(buffer, static_cast<int>(size));
}

} // namespace Core
