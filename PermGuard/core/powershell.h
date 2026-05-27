#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>

namespace Core {

struct PowerShellResult {
    bool success = false;
    int exitCode = -1;
    std::string output;
    std::string error;
    bool timedOut = false;
};

class PowerShell {
public:
    // Execute a PowerShell command and capture output
    // Command is passed as: powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "<command>"
    static PowerShellResult Execute(const std::string& command, DWORD timeoutMs = 15000);

    // Execute and return just the trimmed output (empty on failure)
    static std::string ExecuteAndCapture(const std::string& command, DWORD timeoutMs = 15000);
};

} // namespace Core
