#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>

namespace Core {

struct ProcessResult {
    bool started = false;
    bool timedOut = false;
    DWORD exitCode = 0;
    std::string output;
};

class Process {
public:
    // Capture output from a command line
    static ProcessResult CaptureOutput(const std::wstring& commandLine, DWORD timeoutMs = 15000);

    // Run a command without capturing output
    static bool Execute(const std::wstring& commandLine, bool hidden = true);
};

} // namespace Core
