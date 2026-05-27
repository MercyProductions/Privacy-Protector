#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <shellapi.h>

#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <ctime>
#include <iostream>
#include <utility>

namespace Utils {

// ---------------------------------------------------------------------------
// 1. Colored Console Output
// ---------------------------------------------------------------------------

enum class Color {
    SUCCESS,   // Green
    ERROR_,    // Red
    INFO,      // Yellow
    VERBOSE,   // Cyan
    RESET      // White
};

inline WORD ColorToAttribute(Color color) {
    switch (color) {
        case Color::SUCCESS: return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case Color::ERROR_:  return FOREGROUND_RED   | FOREGROUND_INTENSITY;
        case Color::INFO:    return FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case Color::VERBOSE: return FOREGROUND_GREEN | FOREGROUND_BLUE  | FOREGROUND_INTENSITY;
        case Color::RESET:   return FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_BLUE;
        default:             return FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_BLUE;
    }
}

inline void PrintColor(Color color, const std::string& message) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) {
        std::cout << message << std::endl;
        return;
    }

    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD originalAttrs = csbi.wAttributes;

    SetConsoleTextAttribute(hConsole, ColorToAttribute(color));
    std::cout << message << std::endl;
    SetConsoleTextAttribute(hConsole, originalAttrs);
}

inline void PrintSuccess(const std::string& message) { PrintColor(Color::SUCCESS, message); }
inline void PrintError(const std::string& message)   { PrintColor(Color::ERROR_,  message); }
inline void PrintInfo(const std::string& message)    { PrintColor(Color::INFO,    message); }
inline void PrintVerbose(const std::string& message) { PrintColor(Color::VERBOSE, message); }

// ---------------------------------------------------------------------------
// 2. Logger Class
// ---------------------------------------------------------------------------

class Logger {
public:
    bool silent = false;

    Logger() = default;

    explicit Logger(const std::string& filename)
        : m_filename(filename) {}

    void Init(const std::string& filename) {
        m_filename = filename;
    }

    void Log(Color level, const std::string& message) {
        std::string timestamp = GetIsoTimestamp();
        std::string levelStr  = LevelToString(level);
        std::string formatted = "[" + timestamp + "] [" + levelStr + "] " + message;

        if (!silent) {
            PrintColor(level, formatted);
        }

        if (!m_filename.empty()) {
            std::ofstream ofs(m_filename, std::ios::app);
            if (ofs.is_open()) {
                ofs << formatted << "\n";
            }
        }
    }

private:
    std::string m_filename;

    static std::string LevelToString(Color level) {
        switch (level) {
            case Color::SUCCESS: return "SUCCESS";
            case Color::ERROR_:  return "ERROR";
            case Color::INFO:    return "INFO";
            case Color::VERBOSE: return "VERBOSE";
            default:             return "LOG";
        }
    }
};

// ---------------------------------------------------------------------------
// 3. Admin Check
// ---------------------------------------------------------------------------

inline bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;

    if (AllocateAndInitializeSid(
            &ntAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin != FALSE;
}

// ---------------------------------------------------------------------------
// 4. Relaunch as Admin
// ---------------------------------------------------------------------------

inline void RelaunchAsAdmin() {
    wchar_t exePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    std::wstring cmdLine = GetCommandLineW();
    // Skip the executable name portion of the command line to get just the args.
    LPWSTR* argv = nullptr;
    int argc = 0;
    argv = CommandLineToArgvW(cmdLine.c_str(), &argc);

    std::wstring args;
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            if (!args.empty()) args += L" ";
            // Re-quote arguments that contain spaces.
            std::wstring arg = argv[i];
            if (arg.find(L' ') != std::wstring::npos) {
                args += L"\"" + arg + L"\"";
            } else {
                args += arg;
            }
        }
        LocalFree(argv);
    }

    ShellExecuteW(
        nullptr,
        L"runas",
        exePath,
        args.empty() ? nullptr : args.c_str(),
        nullptr,
        SW_SHOWNORMAL
    );

    ExitProcess(0);
}

// ---------------------------------------------------------------------------
// 5. Capture Process Output
// ---------------------------------------------------------------------------

inline std::string CaptureProcessOutput(const std::wstring& commandLine) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE hReadPipe  = nullptr;
    HANDLE hWritePipe = nullptr;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return {};
    }

    // Ensure the read end is not inherited by the child process.
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(STARTUPINFOW);
    si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};

    // CreateProcessW requires a mutable command line buffer.
    std::wstring cmdLineMut = commandLine;

    BOOL ok = CreateProcessW(
        nullptr,
        cmdLineMut.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    // Close the write end in the parent so ReadFile can detect EOF.
    CloseHandle(hWritePipe);

    if (!ok) {
        CloseHandle(hReadPipe);
        return {};
    }

    std::string output;
    char buffer[4096];
    DWORD bytesRead = 0;

    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output.append(buffer, bytesRead);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    return output;
}

// ---------------------------------------------------------------------------
// 6. Timestamp Helpers
// ---------------------------------------------------------------------------

inline std::string GetTimestamp() {
    std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &now);

    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(4) << (local.tm_year + 1900)
        << std::setw(2) << (local.tm_mon + 1)
        << std::setw(2) << local.tm_mday
        << "_"
        << std::setw(2) << local.tm_hour
        << std::setw(2) << local.tm_min
        << std::setw(2) << local.tm_sec;
    return oss.str();
}

inline std::string GetIsoTimestamp() {
    std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &now);

    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(4) << (local.tm_year + 1900) << "-"
        << std::setw(2) << (local.tm_mon + 1) << "-"
        << std::setw(2) << local.tm_mday << "T"
        << std::setw(2) << local.tm_hour << ":"
        << std::setw(2) << local.tm_min << ":"
        << std::setw(2) << local.tm_sec;
    return oss.str();
}

// ---------------------------------------------------------------------------
// 7. Box Drawing Helper
// ---------------------------------------------------------------------------

inline void PrintBox(const std::vector<std::pair<std::string, std::string>>& rows) {
    if (rows.empty()) return;

    // Determine column widths.
    size_t maxLabel = 0;
    size_t maxValue = 0;
    for (const auto& row : rows) {
        if (row.first.size()  > maxLabel) maxLabel = row.first.size();
        if (row.second.size() > maxValue) maxValue = row.second.size();
    }

    // Minimum padding inside cells.
    const size_t pad = 1;
    size_t labelW = maxLabel + pad * 2;
    size_t valueW = maxValue + pad * 2;

    // Build horizontal rules.
    // Top:    +==========+==========+
    // Middle: +==========+==========+
    // Bottom: +==========+==========+
    auto hRule = [&]() -> std::string {
        std::string line = "+";
        line.append(labelW, '-');
        line += "+";
        line.append(valueW, '-');
        line += "+";
        return line;
    };

    std::string rule = hRule();

    std::cout << rule << "\n";
    for (size_t i = 0; i < rows.size(); ++i) {
        const auto& [label, value] = rows[i];

        // Build the row: | label | value |
        std::ostringstream oss;
        oss << "|"
            << std::string(pad, ' ')
            << std::left << std::setw(static_cast<int>(maxLabel)) << label
            << std::string(pad, ' ')
            << "|"
            << std::string(pad, ' ')
            << std::left << std::setw(static_cast<int>(maxValue)) << value
            << std::string(pad, ' ')
            << "|";

        std::cout << oss.str() << "\n";
        std::cout << rule << "\n";
    }
}

} // namespace Utils
