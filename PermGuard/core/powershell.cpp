#include "powershell.h"

#include <algorithm>
#include <vector>

namespace Core {

static std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return {};
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), nullptr, 0);
    if (sizeNeeded <= 0) return {};
    std::wstring result(sizeNeeded, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), result.data(), sizeNeeded);
    return result;
}

static std::string WideToUtf8(const wchar_t* wstr, int len) {
    if (!wstr || len == 0) return {};
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr, len, nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) return {};
    std::string result(sizeNeeded, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, len, result.data(), sizeNeeded, nullptr, nullptr);
    return result;
}

static std::string ReadPipe(HANDLE hPipe) {
    std::string output;
    char buffer[4096];
    DWORD bytesRead = 0;

    while (true) {
        BOOL ok = ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, nullptr);
        if (!ok || bytesRead == 0) break;
        output.append(buffer, bytesRead);
    }

    return output;
}

static std::string TrimWhitespace(const std::string& str) {
    auto start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    auto end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

static std::wstring EscapeForCommandLine(const std::string& command) {
    // Escape double quotes in the command for the command line
    std::string escaped;
    escaped.reserve(command.size() + 16);
    for (char c : command) {
        if (c == '"') {
            escaped += "\\\"";
        } else {
            escaped += c;
        }
    }
    return Utf8ToWide(escaped);
}

PowerShellResult PowerShell::Execute(const std::string& command, DWORD timeoutMs) {
    PowerShellResult result;

    // Create pipes for stdout
    SECURITY_ATTRIBUTES saAttr{};
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = nullptr;

    HANDLE hStdOutRead = nullptr, hStdOutWrite = nullptr;
    HANDLE hStdErrRead = nullptr, hStdErrWrite = nullptr;

    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &saAttr, 0)) {
        return result;
    }
    if (!SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(hStdOutRead);
        CloseHandle(hStdOutWrite);
        return result;
    }

    if (!CreatePipe(&hStdErrRead, &hStdErrWrite, &saAttr, 0)) {
        CloseHandle(hStdOutRead);
        CloseHandle(hStdOutWrite);
        return result;
    }
    if (!SetHandleInformation(hStdErrRead, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(hStdOutRead);
        CloseHandle(hStdOutWrite);
        CloseHandle(hStdErrRead);
        CloseHandle(hStdErrWrite);
        return result;
    }

    // Build command line
    std::wstring escapedCmd = EscapeForCommandLine(command);
    std::wstring cmdLine = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"" + escapedCmd + L"\"";

    // Make a mutable copy for CreateProcessW
    std::vector<wchar_t> cmdLineBuf(cmdLine.begin(), cmdLine.end());
    cmdLineBuf.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(STARTUPINFOW);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdErrWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};

    BOOL created = CreateProcessW(
        nullptr,
        cmdLineBuf.data(),
        nullptr, nullptr,
        TRUE, // inherit handles
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi);

    // Close write ends in parent immediately
    CloseHandle(hStdOutWrite);
    CloseHandle(hStdErrWrite);

    if (!created) {
        CloseHandle(hStdOutRead);
        CloseHandle(hStdErrRead);
        return result;
    }

    // Read stdout and stderr
    // Note: reading sequentially — stdout first, then stderr.
    // For very large outputs this could deadlock, but for typical PS commands it's fine.
    result.output = ReadPipe(hStdOutRead);
    result.error = ReadPipe(hStdErrRead);

    CloseHandle(hStdOutRead);
    CloseHandle(hStdErrRead);

    // Wait for process
    DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);

    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 3000);
        result.timedOut = true;
        result.exitCode = -1;
    } else {
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        result.exitCode = static_cast<int>(exitCode);
        result.success = (exitCode == 0);
    }

    // Trim output
    result.output = TrimWhitespace(result.output);
    result.error = TrimWhitespace(result.error);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return result;
}

std::string PowerShell::ExecuteAndCapture(const std::string& command, DWORD timeoutMs) {
    auto result = Execute(command, timeoutMs);
    if (!result.success) return {};
    return result.output;
}

} // namespace Core
