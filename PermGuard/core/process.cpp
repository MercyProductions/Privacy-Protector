#include "process.h"

#include <vector>

namespace Core {

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

ProcessResult Process::CaptureOutput(const std::wstring& commandLine, DWORD timeoutMs) {
    ProcessResult result;

    // Create pipes for stdout/stderr (merged into one)
    SECURITY_ATTRIBUTES saAttr{};
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = nullptr;

    HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
        return result;
    }

    // Ensure the read handle is NOT inherited
    if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return result;
    }

    STARTUPINFOW si{};
    si.cb = sizeof(STARTUPINFOW);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};

    // CreateProcessW needs a mutable command line buffer
    std::vector<wchar_t> cmdBuf(commandLine.begin(), commandLine.end());
    cmdBuf.push_back(L'\0');

    BOOL created = CreateProcessW(
        nullptr,
        cmdBuf.data(),
        nullptr, nullptr,
        TRUE, // inherit handles
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi);

    // Close the write end in the parent so ReadFile will eventually return 0
    CloseHandle(hWritePipe);

    if (!created) {
        CloseHandle(hReadPipe);
        return result;
    }

    result.started = true;

    // Read all output from the pipe
    result.output = ReadPipe(hReadPipe);
    CloseHandle(hReadPipe);

    // Wait for the process to complete
    DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);

    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 3000);
        result.timedOut = true;
        result.exitCode = static_cast<DWORD>(-1);
    } else {
        GetExitCodeProcess(pi.hProcess, &result.exitCode);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return result;
}

bool Process::Execute(const std::wstring& commandLine, bool hidden) {
    STARTUPINFOW si{};
    si.cb = sizeof(STARTUPINFOW);

    if (hidden) {
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
    }

    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> cmdBuf(commandLine.begin(), commandLine.end());
    cmdBuf.push_back(L'\0');

    DWORD flags = hidden ? CREATE_NO_WINDOW : 0;

    BOOL created = CreateProcessW(
        nullptr,
        cmdBuf.data(),
        nullptr, nullptr,
        FALSE, // no handle inheritance
        flags,
        nullptr, nullptr,
        &si, &pi);

    if (!created) {
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}

} // namespace Core
