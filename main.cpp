#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#pragma warning(disable: 4244) // Suppress wchar_t -> char narrowing (intentional for ASCII logging)

#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <ctime>
#include <algorithm>
#include <limits>
#include <map>
#include <functional>
#include <cctype>
#include <windows.h>
#include <shellapi.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <bcrypt.h>

#include "resource.h"
#include "profiles.h"
#include "privacy_audit.h"
#include "privacy_session.h"
#include "include/aegis_ioctl.h"

#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "Bcrypt.lib")

namespace fs = std::filesystem;

// ===========================================================================
// GLOBAL STATE
// ===========================================================================
static bool g_Silent = false;
static bool g_DryRun = false;
static bool g_NoReboot = false;
static std::ofstream g_LogFile;
static fs::path g_WorkDir;
static fs::path g_AmidewinPath;
static fs::path g_AmifldrvPath;

// Stored identity (before & after)
struct IdentitySnapshot {
    std::string computerName;
    std::string systemSerial;
    std::string systemUuid;
    std::string boardSerial;
    std::string chassisSerial;
    std::string machineGuid;
    std::string macAddress;
    std::string registeredOwner;
    std::string registeredOrg;
};

static IdentitySnapshot g_Before;
static IdentitySnapshot g_After;

// ===========================================================================
// CONSOLE COLORS
// ===========================================================================
enum class Color { SUCCESS, ERR, INFO, VERBOSE, RESET };

inline void SetColor(Color c) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    switch (c) {
        case Color::SUCCESS: SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_INTENSITY); break;
        case Color::ERR:     SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_INTENSITY); break;
        case Color::INFO:    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); break;
        case Color::VERBOSE: SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); break;
        case Color::RESET:   SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); break;
    }
}

inline std::string GetTimestamp() {
    time_t now = time(nullptr);
    struct tm t;
    localtime_s(&t, &now);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &t);
    return buf;
}

inline std::string GetIsoTimestamp() {
    time_t now = time(nullptr);
    struct tm t;
    localtime_s(&t, &now);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &t);
    return buf;
}

void LogWrite(Color c, const std::string& prefix, const std::string& msg) {
    std::string ts = GetIsoTimestamp();
    std::string full = ts + " " + prefix + " " + msg;

    if (g_LogFile.is_open()) {
        g_LogFile << full << std::endl;
    }

    if (!g_Silent) {
        SetColor(c);
        std::cout << prefix << " ";
        SetColor(Color::RESET);
        std::cout << msg << std::endl;
    }
}

void PrintSuccess(const std::string& msg) { LogWrite(Color::SUCCESS, "[+]", msg); }
void PrintError(const std::string& msg)   { LogWrite(Color::ERR,     "[!]", msg); }
void PrintInfo(const std::string& msg)    { LogWrite(Color::INFO,    "[*]", msg); }
void PrintVerbose(const std::string& msg) { LogWrite(Color::VERBOSE, "[i]", msg); }

void PrintUsage() {
    std::cout
        << "DmiUpdater - Enterprise System Provisioning & DMI Utility\n\n"
        << "Usage:\n"
        << "  DmiUpdater.exe [options]\n\n"
        << "Options:\n"
        << "  --help             Show this help text and exit.\n"
        << "  --privacy-audit    Run an offline hardware privacy exposure audit.\n"
        << "  --output <path>    Write privacy audit reports under this file or directory.\n"
        << "  --full-export      Also write a local full-value privacy audit JSON file.\n"
        << "  --privacy-session-start\n"
        << "                     Start a reversible privacy protection session.\n"
        << "  --mode <mode>      Session mode: user, sandbox, or policy (default user).\n"
        << "  --privacy-session-status <session>\n"
        << "                     Show a privacy session status by id or path.\n"
        << "  --privacy-session-restore <session>\n"
        << "                     Restore a privacy session snapshot by id or path.\n"
        << "  --privacy-session-launch <session> <target>\n"
        << "                     Launch a target through an existing privacy session.\n"
        << "  --verify           Display current system identity only.\n"
        << "  --legacy-provisioning\n"
        << "                     Unlock legacy machine provisioning and mutation flows.\n"
        << "  --auto             Run unattended with the generic profile.\n"
        << "  --silent           Run unattended without console output.\n"
        << "  --dry-run          Build and log the planned changes without applying them.\n"
        << "  --no-reboot        Do not prompt for or schedule a reboot.\n"
        << "  --preflight        Run read-only environment readiness checks.\n"
        << "  --driver-status    Report optional driver service and device status.\n"
        << "  --driver-version   Query the optional driver version IOCTL.\n"
        << "  --driver-ping <n>  Send a safe ping IOCTL to the optional driver.\n"
        << "  --show-history [n]\n"
        << "                     Show the most recent history entries (default 20).\n"
        << "  --artifact-hashes  Print SHA-256 hashes for built release artifacts.\n"
        << "  --release-manifest [file]\n"
        << "                     Write a release manifest JSON with artifact hashes.\n"
        << "  --verify-manifest <file>\n"
        << "                     Verify artifacts listed in a release manifest.\n"
        << "  --verify-manifest-report <file>\n"
        << "                     Write a JSON verification report (with --verify-manifest).\n"
        << "  --list-profiles    List built-in and custom OEM profiles.\n"
        << "  --create-profile-template <file>\n"
        << "                     Write a valid custom .profile template.\n"
        << "  --validate-profile <file>\n"
        << "                     Validate a custom .profile file.\n"
        << "  --smbios-only      Apply only SMBIOS/DMI updates in auto mode.\n"
        << "  --registry-only    Apply only registry/name updates in auto mode.\n"
        << "  --profile <file>   Load generated values from a config file.\n\n"
        << "Dry-run mode skips registry writes, network changes, log cleanup,\n"
        << "staging cleanup, SMBIOS tool execution, resource extraction, and reboot.\n";
}

fs::path ResolveWorkDirPath(const std::string& filename) {
    fs::path p(filename);
    if (p.is_relative()) {
        p = g_WorkDir / p;
    }
    return p;
}

void ListProfiles() {
    auto profiles = GetOemProfiles(g_WorkDir);

    std::cout << "Available OEM profiles (" << profiles.size() << "):\n\n";
    std::cout << std::left
              << std::setw(4) << "#"
              << std::setw(24) << "Name"
              << std::setw(34) << "System Product"
              << "Serial Format"
              << "\n";
    std::cout << std::string(86, '-') << "\n";

    for (size_t i = 0; i < profiles.size(); ++i) {
        const auto& p = profiles[i];
        std::string serialFormat = p.serialPrefix + std::to_string(p.serialLength);
        std::cout << std::left
                  << std::setw(4) << (i + 1)
                  << std::setw(24) << p.name.substr(0, 23)
                  << std::setw(34) << p.systemProduct.substr(0, 33)
                  << serialFormat
                  << "\n";
    }
}

bool CreateProfileTemplate(const std::string& filename) {
    fs::path p = ResolveWorkDirPath(filename);

    try {
        if (fs::exists(p)) {
            std::cerr << "[!] Profile template already exists: " << p.string() << "\n";
            return false;
        }

        if (!p.parent_path().empty()) {
            fs::create_directories(p.parent_path());
        }

        std::ofstream f(p);
        if (!f.is_open()) {
            std::cerr << "[!] Cannot create profile template: " << p.string() << "\n";
            return false;
        }

        f << "Custom Lab Workstation\n"
          << "Contoso Systems\n"
          << "Contoso Lab Workstation\n"
          << "Contoso Systems\n"
          << "Aegis Board 1\n"
          << "Contoso Systems\n"
          << "LAB-\n"
          << "16\n"
          << "MB-\n"
          << "16\n"
          << "CHA-\n"
          << "16\n"
          << "Lab Workstation\n"
          << "SKU-\n";

        std::cout << "Profile template created: " << p.string() << "\n";
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[!] Profile template error: " << e.what() << "\n";
        return false;
    }
}

bool ValidateProfileFile(const std::string& filename) {
    fs::path p = ResolveWorkDirPath(filename);
    if (!fs::exists(p)) {
        p = fs::path(filename);
    }

    OemProfile profile;
    std::vector<std::string> errors;
    if (!LoadOemProfileFile(p, profile, &errors)) {
        std::cerr << "[!] Profile validation failed: " << p.string() << "\n";
        for (const auto& error : errors) {
            std::cerr << "    - " << error << "\n";
        }
        return false;
    }

    std::cout << "Profile is valid: " << p.string() << "\n\n";
    std::cout << "Name: " << profile.name << "\n";
    std::cout << "System: " << profile.systemManufacturer << " / " << profile.systemProduct << "\n";
    std::cout << "Board: " << profile.boardManufacturer << " / " << profile.boardProduct << "\n";
    std::cout << "Serial lengths: system=" << profile.serialLength
              << ", board=" << profile.boardSerialLength
              << ", chassis=" << profile.chassisSerialLength << "\n";
    return true;
}

void PrintHeader() {
    if (g_Silent) return;
    SetColor(Color::VERBOSE);
    std::cout << R"(
  ____            _ _   _           _       _
 |  _ \ _ __ ___ | | | | |_ __   __| | __ _| |_ ___ _ __
 | | | | '_ ` _ \| | | | | '_ \ / _` |/ _` | __/ _ \ '__|
 | |_| | | | | | | | |_| | |_) | (_| | (_| | ||  __/ |
 |____/|_| |_| |_|_|\___/| .__/ \__,_|\__,_|\__\___|_|
                          |_|
)" << std::endl;
    SetColor(Color::INFO);
    std::cout << "  Enterprise System Provisioning & DMI Utility v2.0\n" << std::endl;
    SetColor(Color::RESET);
}

void PrintBox(const std::vector<std::pair<std::string, std::string>>& rows) {
    if (g_Silent) return;
    // Find max label width
    size_t maxLabel = 0;
    size_t maxValue = 0;
    for (auto& [l, v] : rows) {
        maxLabel = (std::max)(maxLabel, l.length());
        maxValue = (std::max)(maxValue, v.length());
    }
    size_t totalW = maxLabel + maxValue + 7; // "| label : value |"

    SetColor(Color::VERBOSE);
    std::cout << "+" << std::string(totalW - 2, '-') << "+" << std::endl;
    for (auto& [l, v] : rows) {
        std::cout << "| ";
        SetColor(Color::INFO);
        std::cout << std::left << std::setw(static_cast<int>(maxLabel)) << l;
        SetColor(Color::RESET);
        std::cout << " : ";
        SetColor(Color::SUCCESS);
        std::cout << std::left << std::setw(static_cast<int>(maxValue)) << v;
        SetColor(Color::VERBOSE);
        std::cout << " |" << std::endl;
    }
    std::cout << "+" << std::string(totalW - 2, '-') << "+" << std::endl;
    SetColor(Color::RESET);
}

bool ReadInt(int& value) {
    value = 0;
    if (std::cin >> value) {
        return true;
    }

    std::cin.clear();
    std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
    return false;
}

// ===========================================================================
// ADMIN CHECK & ELEVATION
// ===========================================================================
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;

    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

void RelaunchAsAdmin(int argc, char* argv[]) {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    // Reconstruct args
    std::wstring args;
    for (int i = 1; i < argc; i++) {
        if (i > 1) args += L" ";
        std::string a(argv[i]);
        std::wstring wa(a.begin(), a.end());
        if (wa.find_first_of(L" \t\"") != std::wstring::npos) {
            std::wstring quoted = L"\"";
            for (wchar_t ch : wa) {
                if (ch == L'\"') quoted += L'\\';
                quoted += ch;
            }
            quoted += L"\"";
            args += quoted;
        } else {
            args += wa;
        }
    }

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = args.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (ShellExecuteExW(&sei)) {
        ExitProcess(0);
    } else {
        std::cerr << "[!] Failed to elevate. Please run as Administrator manually.\n";
        ExitProcess(1);
    }
}

// ===========================================================================
// RESOURCE EXTRACTION
// ===========================================================================
bool ExtractResource(int resourceId, const std::wstring& outputPath) {
    HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
    if (!hRes) { PrintError("FindResource failed."); return false; }

    HGLOBAL hData = LoadResource(nullptr, hRes);
    if (!hData) { PrintError("LoadResource failed."); return false; }

    DWORD dataSize = SizeofResource(nullptr, hRes);
    void* pData = LockResource(hData);
    if (!pData || dataSize == 0) { PrintError("LockResource failed."); return false; }

    HANDLE hFile = CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) { PrintError("Cannot create output file."); return false; }

    DWORD written = 0;
    WriteFile(hFile, pData, dataSize, &written, nullptr);
    CloseHandle(hFile);

    return written == dataSize;
}

// ===========================================================================
// GENERATORS
// ===========================================================================
std::string GenerateRandomSerial(const std::string& prefix, int length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    std::string s = prefix;
    for (int i = static_cast<int>(prefix.length()); i < length; ++i)
        s += charset[dist(gen)];
    return s;
}

std::string GenerateRandomUuid() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> hd(0, 15);

    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 8; ++i)  ss << hd(gen);
    ss << "-";
    for (int i = 0; i < 4; ++i)  ss << hd(gen);
    ss << "-4";
    for (int i = 0; i < 3; ++i)  ss << hd(gen);
    ss << "-";
    ss << (8 + (hd(gen) % 4));
    for (int i = 0; i < 3; ++i)  ss << hd(gen);
    ss << "-";
    for (int i = 0; i < 12; ++i) ss << hd(gen);
    return ss.str();
}

std::string GenerateRandomMacAddress() {
    const char hex[] = "0123456789ABCDEF";
    const char laa[] = "26AE";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> hd(0, 15);
    std::uniform_int_distribution<> ld(0, 3);

    std::string mac;
    mac += hex[hd(gen)];
    mac += laa[ld(gen)];
    for (int i = 0; i < 10; ++i) mac += hex[hd(gen)];
    return mac;
}

// ===========================================================================
// PROCESS EXECUTION
// ===========================================================================
bool ExecuteProcess(const std::wstring& exe, const std::wstring& args) {
    std::wstring cmd = L"\"" + exe + L"\" " + args;
    PrintVerbose("Running: " + std::string(cmd.begin(), cmd.end())); // NOLINT: safe for ASCII command lines

    if (g_DryRun) {
        PrintInfo("Dry run: process execution skipped.");
        return true;
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(L'\0');

    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        PrintError("CreateProcess failed (Error: " + std::to_string(GetLastError()) + ")");
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exitCode == 0)
        PrintSuccess("Process exited successfully.");
    else
        PrintError("Process exited with code: " + std::to_string(exitCode));

    return exitCode == 0;
}

std::string CaptureProcessOutput(const std::wstring& commandLine) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hReadPipe = nullptr;
    HANDLE hWritePipe = nullptr;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return {};
    }
    if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return {};
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> buf(commandLine.begin(), commandLine.end());
    buf.push_back(L'\0');

    std::string output;
    if (CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hWritePipe);

        char readBuf[4096];
        DWORD bytesRead;
        while (ReadFile(hReadPipe, readBuf, sizeof(readBuf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            readBuf[bytesRead] = '\0';
            output += readBuf;
        }
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        CloseHandle(hWritePipe);
    }
    CloseHandle(hReadPipe);

    // Trim whitespace
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r' || output.back() == ' '))
        output.pop_back();
    return output;
}

// ===========================================================================
// REGISTRY HELPERS
// ===========================================================================
std::string ReadRegistryString(HKEY root, const std::wstring& subKey, const std::wstring& valueName) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return "(error)";

    wchar_t buf[512];
    DWORD sz = sizeof(buf);
    DWORD type = 0;
    if (RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type, reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        std::wstring ws(buf);
        return std::string(ws.begin(), ws.end());
    }
    RegCloseKey(hKey);
    return "(not set)";
}

bool WriteRegistryString(HKEY root, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& value) {
    if (g_DryRun) {
        PrintInfo("Dry run: registry write skipped.");
        return true;
    }

    HKEY hKey = nullptr;
    LSTATUS s = RegOpenKeyExW(root, subKey.c_str(), 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey);
    if (s != ERROR_SUCCESS) {
        PrintError("Cannot open registry key (Error: " + std::to_string(s) + ")");
        return false;
    }
    s = RegSetValueExW(hKey, valueName.c_str(), 0, REG_SZ,
        reinterpret_cast<const BYTE*>(value.c_str()),
        static_cast<DWORD>((value.length() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
    return s == ERROR_SUCCESS;
}

// ===========================================================================
// PREFLIGHT DIAGNOSTICS
// ===========================================================================
struct PreflightCheck {
    std::string name;
    std::string status;
    std::string detail;
    bool ok;
};

std::string BoolStatus(bool ok) {
    return ok ? "OK" : "WARN";
}

fs::path DetectProjectRoot() {
    fs::path p = g_WorkDir;
    for (int i = 0; i < 4 && !p.empty(); ++i) {
        if (fs::exists(p / "DmiUpdater.vcxproj")) {
            return p;
        }
        p = p.parent_path();
    }
    return g_WorkDir;
}

bool IsDirectoryWritable(const fs::path& dir) {
    try {
        if (!fs::exists(dir)) return false;
        fs::path probe = dir / ("preflight_write_test_" + GetTimestamp() + ".tmp");
        {
            std::ofstream f(probe);
            if (!f.is_open()) return false;
            f << "preflight";
        }
        fs::remove(probe);
        return true;
    } catch (...) {
        return false;
    }
}

std::string GetArchitectureName() {
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: return "x64";
        case PROCESSOR_ARCHITECTURE_ARM64: return "ARM64";
        case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
        default: return "unknown";
    }
}

std::string GetWindowsBuildSummary() {
    const std::wstring key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    std::string product = ReadRegistryString(HKEY_LOCAL_MACHINE, key, L"ProductName");
    std::string display = ReadRegistryString(HKEY_LOCAL_MACHINE, key, L"DisplayVersion");
    std::string build = ReadRegistryString(HKEY_LOCAL_MACHINE, key, L"CurrentBuildNumber");

    std::string summary = product;
    if (!display.empty() && display != "(not set)" && display != "(error)") {
        summary += " " + display;
    }
    if (!build.empty() && build != "(not set)" && build != "(error)") {
        summary += " (build " + build + ")";
    }
    return summary;
}

std::string GetDriverServiceStatus() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return "unknown (cannot open SCM)";
    }

    SC_HANDLE service = OpenServiceW(scm, L"AegisIoctlDriver", SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return "not installed";
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    std::string result = "installed";
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed)) {
        switch (status.dwCurrentState) {
            case SERVICE_RUNNING: result = "running"; break;
            case SERVICE_STOPPED: result = "stopped"; break;
            case SERVICE_START_PENDING: result = "start pending"; break;
            case SERVICE_STOP_PENDING: result = "stop pending"; break;
            default: result = "installed"; break;
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return result;
}

std::string GetLastErrorText(DWORD error) {
    char* buffer = nullptr;
    DWORD length = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buffer),
        0,
        nullptr);

    if (length == 0 || buffer == nullptr) {
        return "error " + std::to_string(error);
    }

    std::string message(buffer, length);
    LocalFree(buffer);
    while (!message.empty() && (message.back() == '\r' || message.back() == '\n' || message.back() == ' ')) {
        message.pop_back();
    }
    return message;
}

HANDLE OpenAegisDevice(DWORD desiredAccess, DWORD* error = nullptr) {
    HANDLE h = CreateFileA(
        AEGIS_IOCTL_DEVICE_NAME,
        desiredAccess,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (h == INVALID_HANDLE_VALUE && error != nullptr) {
        *error = GetLastError();
    }
    return h;
}

bool TryParseUlong(const std::string& value, unsigned long& parsed) {
    try {
        size_t consumed = 0;
        unsigned long candidate = std::stoul(value, &consumed, 0);
        if (consumed != value.size()) {
            return false;
        }
        parsed = candidate;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool PrintDriverStatus() {
    fs::path projectRoot = DetectProjectRoot();
    fs::path debugDriver = projectRoot / "bin" / "driver" / "Debug" / "AegisIoctlDriver.sys";
    fs::path releaseDriver = projectRoot / "bin" / "driver" / "Release" / "AegisIoctlDriver.sys";

    std::cout << "Driver diagnostics:\n\n";
    std::cout << "Service: " << GetDriverServiceStatus() << "\n";
    std::cout << "Debug package: " << (fs::exists(debugDriver) ? debugDriver.string() : "missing") << "\n";
    std::cout << "Release package: " << (fs::exists(releaseDriver) ? releaseDriver.string() : "missing") << "\n";

    DWORD error = ERROR_SUCCESS;
    HANDLE h = OpenAegisDevice(GENERIC_READ, &error);
    if (h == INVALID_HANDLE_VALUE) {
        std::cout << "Device: unavailable (" << GetLastErrorText(error) << ")\n";
        return true;
    }

    CloseHandle(h);
    std::cout << "Device: available (" << AEGIS_IOCTL_DEVICE_NAME << ")\n";
    return true;
}

bool QueryDriverVersion() {
    DWORD error = ERROR_SUCCESS;
    HANDLE h = OpenAegisDevice(GENERIC_READ, &error);
    if (h == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Cannot open " << AEGIS_IOCTL_DEVICE_NAME << ": " << GetLastErrorText(error) << "\n";
        return false;
    }

    AEGIS_IOCTL_VERSION version{};
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        h,
        IOCTL_AEGIS_GET_VERSION,
        nullptr,
        0,
        &version,
        sizeof(version),
        &bytesReturned,
        nullptr);

    if (!ok) {
        error = GetLastError();
        CloseHandle(h);
        std::cerr << "[!] IOCTL_AEGIS_GET_VERSION failed: " << GetLastErrorText(error) << "\n";
        return false;
    }

    CloseHandle(h);

    std::wstring wName(version.Name);
    std::string name(wName.begin(), wName.end());
    std::cout << "Driver version: " << name << " "
              << version.Major << "." << version.Minor << "." << version.Patch
              << " (" << bytesReturned << " bytes)\n";
    return true;
}

bool PingDriver(unsigned long input) {
    DWORD error = ERROR_SUCCESS;
    HANDLE h = OpenAegisDevice(GENERIC_READ | GENERIC_WRITE, &error);
    if (h == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Cannot open " << AEGIS_IOCTL_DEVICE_NAME << ": " << GetLastErrorText(error) << "\n";
        return false;
    }

    AEGIS_IOCTL_PING ping{};
    ping.Input = input;
    DWORD bytesReturned = 0;

    BOOL ok = DeviceIoControl(
        h,
        IOCTL_AEGIS_PING,
        &ping,
        sizeof(ping),
        &ping,
        sizeof(ping),
        &bytesReturned,
        nullptr);

    if (!ok) {
        error = GetLastError();
        CloseHandle(h);
        std::cerr << "[!] IOCTL_AEGIS_PING failed: " << GetLastErrorText(error) << "\n";
        return false;
    }

    CloseHandle(h);
    std::cout << "Driver ping: input=" << ping.Input
              << ", output=" << ping.Output
              << " (" << bytesReturned << " bytes)\n";
    return true;
}

bool RunPreflight() {
    fs::path projectRoot = DetectProjectRoot();
    fs::path debugDriver = projectRoot / "bin" / "driver" / "Debug" / "AegisIoctlDriver.sys";
    fs::path releaseDriver = projectRoot / "bin" / "driver" / "Release" / "AegisIoctlDriver.sys";

    std::vector<PreflightCheck> checks;
    auto add = [&](const std::string& name, bool ok, const std::string& detail) {
        checks.push_back({ name, BoolStatus(ok), detail, ok });
    };

    bool admin = IsRunningAsAdmin();
    checks.push_back({ "Administrator", admin ? "OK" : "INFO", admin ? "current process is elevated" : "not elevated; apply mode will request UAC", true });
    add("Windows", true, GetWindowsBuildSummary());
    add("Architecture", GetArchitectureName() == "x64", GetArchitectureName());
    add("Work directory", fs::exists(g_WorkDir), g_WorkDir.string());
    add("Work directory writable", IsDirectoryWritable(g_WorkDir), g_WorkDir.string());
    add("Project root", fs::exists(projectRoot / "DmiUpdater.vcxproj"), projectRoot.string());
    checks.push_back({ "Embedded provisioning resources", "INFO",
        "not embedded; legacy provisioning requires locally supplied trusted tools", true });

    auto profiles = GetOemProfiles(projectRoot);
    add("OEM profiles", !profiles.empty(), std::to_string(profiles.size()) + " profile(s) available");

    bool driverBuilt = fs::exists(debugDriver) || fs::exists(releaseDriver);
    std::string driverDetail = "Debug=" + std::string(fs::exists(debugDriver) ? "present" : "missing") +
        ", Release=" + std::string(fs::exists(releaseDriver) ? "present" : "missing");
    add("Driver build outputs", driverBuilt, driverDetail);
    add("Driver service", true, GetDriverServiceStatus());

    std::cout << "Preflight checks:\n\n";
    std::cout << std::left
              << std::setw(28) << "Check"
              << std::setw(8) << "Status"
              << "Detail\n";
    std::cout << std::string(86, '-') << "\n";

    bool ok = true;
    for (const auto& check : checks) {
        std::cout << std::left
                  << std::setw(28) << check.name
                  << std::setw(8) << check.status
                  << check.detail << "\n";
        ok = check.ok && ok;
    }

    std::cout << "\n";
    if (ok) {
        std::cout << "Preflight result: ready.\n";
    } else {
        std::cout << "Preflight result: review warnings before apply mode.\n";
    }
    return ok;
}

// ===========================================================================
// SYSTEM MODIFICATION FUNCTIONS
// ===========================================================================
bool UpdateMachineGuid(const std::string& guid) {
    std::wstring wGuid(guid.begin(), guid.end());
    return WriteRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", wGuid);
}

bool UpdateComputerName(const std::string& name) {
    if (g_DryRun) {
        PrintInfo("Dry run: computer name update skipped.");
        return true;
    }

    std::wstring wName(name.begin(), name.end());
    if (!SetComputerNameExW(ComputerNamePhysicalDnsHostname, wName.c_str())) {
        PrintError("SetComputerNameEx failed (Error: " + std::to_string(GetLastError()) + ")");
        return false;
    }
    return true;
}

bool UpdateRegisteredOwner(const std::wstring& owner, const std::wstring& org) {
    bool a = WriteRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"RegisteredOwner", owner);
    bool b = WriteRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"RegisteredOrganization", org);
    return a && b;
}

bool UpdateNetworkAdapterMacs(const std::string& mac) {
    if (g_DryRun) {
        PrintInfo("Dry run: network adapter MAC updates skipped.");
        return true;
    }

    std::wstring wMac(mac.begin(), mac.end());
    HKEY hClassKey = nullptr;
    LSTATUS s = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}",
        0, KEY_READ | KEY_WRITE, &hClassKey);
    if (s != ERROR_SUCCESS) { PrintError("Cannot open Network Class key."); return false; }

    wchar_t sub[256]; DWORD subSz = 256; DWORD idx = 0;
    while (RegEnumKeyExW(hClassKey, idx, sub, &subSz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        HKEY hAdapt = nullptr;
        if (RegOpenKeyExW(hClassKey, sub, 0, KEY_READ | KEY_WRITE, &hAdapt) == ERROR_SUCCESS) {
            wchar_t desc[512]; DWORD descSz = sizeof(desc);
            if (RegQueryValueExW(hAdapt, L"DriverDesc", nullptr, nullptr, reinterpret_cast<BYTE*>(desc), &descSz) == ERROR_SUCCESS) {
                if (RegSetValueExW(hAdapt, L"NetworkAddress", 0, REG_SZ,
                    reinterpret_cast<const BYTE*>(wMac.c_str()),
                    static_cast<DWORD>((wMac.length() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS) {
                    std::wstring d(desc);
                    PrintSuccess("MAC set on: " + std::string(d.begin(), d.end()));
                }
            }
            RegCloseKey(hAdapt);
        }
        subSz = 256; idx++;
    }
    RegCloseKey(hClassKey);
    return true;
}

bool ClearAdministrativeLogs() {
    if (g_DryRun) {
        PrintInfo("Dry run: event log clearing skipped.");
        return true;
    }

    std::vector<std::wstring> logs = { L"Application", L"System", L"Security" };
    bool ok = true;
    for (auto& ln : logs) {
        HANDLE h = OpenEventLogW(nullptr, ln.c_str());
        if (h) {
            if (ClearEventLogW(h, nullptr)) {
                std::wstring w(ln); PrintSuccess("Cleared log: " + std::string(w.begin(), w.end()));
            } else ok = false;
            CloseEventLog(h);
        }
    }
    return ok;
}

void CleanStagingDirectories() {
    if (g_DryRun) {
        PrintInfo("Dry run: staging directory cleanup skipped.");
        return;
    }

    std::vector<std::wstring> paths = { L"C:\\Windows\\Temp", L"C:\\Windows\\Prefetch" };
    for (auto& p : paths) {
        try {
            if (!fs::exists(p)) continue;
            std::wstring w(p); PrintInfo("Cleaning: " + std::string(w.begin(), w.end()));
            for (auto& e : fs::directory_iterator(p)) {
                try { fs::remove_all(e.path()); } catch (...) {}
            }
        } catch (...) {}
    }
}

void FlushDnsCache() {
    ExecuteProcess(L"ipconfig.exe", L"/flushdns");
}

void ResetNetworkAdapters() {
    if (g_DryRun) {
        PrintInfo("Dry run: network adapter reset skipped.");
        return;
    }

    PrintInfo("Resetting network adapters to apply MAC changes...");
    // Use netsh to cycle all interfaces
    std::string output = CaptureProcessOutput(L"netsh interface show interface");
    // Disable and re-enable using wmic (simpler and more reliable)
    ExecuteProcess(L"wmic.exe", L"path win32_networkadapter where netenabled=true call disable");
    Sleep(2000);
    ExecuteProcess(L"wmic.exe", L"path win32_networkadapter where netenabled=true call enable");
}

// ===========================================================================
// IDENTITY SNAPSHOT
// ===========================================================================
IdentitySnapshot CaptureCurrentIdentity() {
    IdentitySnapshot snap;

    // Computer name
    wchar_t compName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD compSz = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(compName, &compSz);
    std::wstring cn(compName);
    snap.computerName = std::string(cn.begin(), cn.end());

    // Registry values
    snap.machineGuid = ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
    snap.registeredOwner = ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"RegisteredOwner");
    snap.registeredOrg = ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"RegisteredOrganization");

    // SMBIOS via AMIDEWIN read mode (no argument = read)
    if (!g_DryRun && IsRunningAsAdmin() && fs::exists(g_AmidewinPath)) {
        std::wstring ami = g_AmidewinPath.wstring();
        snap.systemSerial = CaptureProcessOutput(L"\"" + ami + L"\" /SS");
        snap.systemUuid = CaptureProcessOutput(L"\"" + ami + L"\" /SU");
        snap.boardSerial = CaptureProcessOutput(L"\"" + ami + L"\" /BS");
        snap.chassisSerial = CaptureProcessOutput(L"\"" + ami + L"\" /CS");
    } else {
        // Fallback to wmic
        snap.systemSerial = CaptureProcessOutput(L"wmic bios get serialnumber /value");
        snap.systemUuid = CaptureProcessOutput(L"wmic csproduct get uuid /value");
        snap.boardSerial = CaptureProcessOutput(L"wmic baseboard get serialnumber /value");
        snap.chassisSerial = CaptureProcessOutput(L"wmic systemenclosure get serialnumber /value");
    }

    // MAC address
    snap.macAddress = CaptureProcessOutput(L"getmac /fo csv /nh");

    return snap;
}

void DisplayIdentity(const IdentitySnapshot& snap, const std::string& title) {
    PrintInfo(title);
    PrintBox({
        {"Computer Name",    snap.computerName},
        {"System Serial",    snap.systemSerial.substr(0, 40)},
        {"System UUID",      snap.systemUuid.substr(0, 40)},
        {"Board Serial",     snap.boardSerial.substr(0, 40)},
        {"Chassis Serial",   snap.chassisSerial.substr(0, 40)},
        {"MachineGuid",      snap.machineGuid},
        {"MAC Address",      snap.macAddress.substr(0, 40)},
        {"Registered Owner", snap.registeredOwner},
        {"Registered Org",   snap.registeredOrg},
    });
    std::cout << std::endl;
}

// ===========================================================================
// BACKUP & RESTORE
// ===========================================================================
void BackupCurrentValues(const IdentitySnapshot& snap) {
    if (g_DryRun) {
        PrintInfo("Dry run: backup file creation skipped.");
        return;
    }

    std::string filename = "backup_" + GetTimestamp() + ".txt";
    fs::path backupPath = g_WorkDir / filename;
    std::ofstream f(backupPath);
    if (!f.is_open()) { PrintError("Cannot create backup file."); return; }

    f << "[Backup] " << GetIsoTimestamp() << std::endl;
    f << "ComputerName=" << snap.computerName << std::endl;
    f << "SystemSerial=" << snap.systemSerial << std::endl;
    f << "SystemUUID=" << snap.systemUuid << std::endl;
    f << "BoardSerial=" << snap.boardSerial << std::endl;
    f << "ChassisSerial=" << snap.chassisSerial << std::endl;
    f << "MachineGuid=" << snap.machineGuid << std::endl;
    f << "MacAddress=" << snap.macAddress << std::endl;
    f << "RegisteredOwner=" << snap.registeredOwner << std::endl;
    f << "RegisteredOrg=" << snap.registeredOrg << std::endl;
    f.close();

    PrintSuccess("Backup saved to: " + filename);
}

void RestoreFromBackup() {
    // List backup files
    std::vector<fs::path> backups;
    for (auto& e : fs::directory_iterator(g_WorkDir)) {
        if (e.path().filename().string().find("backup_") == 0 &&
            e.path().extension() == ".txt") {
            backups.push_back(e.path());
        }
    }
    if (backups.empty()) {
        PrintError("No backup files found in working directory.");
        return;
    }

    PrintInfo("Available backups:");
    for (size_t i = 0; i < backups.size(); i++) {
        std::cout << "  [" << (i + 1) << "] " << backups[i].filename().string() << std::endl;
    }
    std::cout << "  [0] Cancel\n\nSelect: ";
    int sel = 0;
    if (!ReadInt(sel)) return;
    if (sel < 1 || sel > static_cast<int>(backups.size())) return;

    // Parse backup file
    std::ifstream f(backups[sel - 1]);
    std::string line;
    std::map<std::string, std::string> vals;
    while (std::getline(f, line)) {
        auto eq = line.find('=');
        if (eq != std::string::npos) {
            vals[line.substr(0, eq)] = line.substr(eq + 1);
        }
    }
    f.close();

    PrintInfo("Restoring values from " + backups[sel - 1].filename().string() + "...");

    if (vals.count("MachineGuid")) {
        PrintInfo("Restoring MachineGuid...");
        UpdateMachineGuid(vals["MachineGuid"]);
    }
    if (vals.count("ComputerName")) {
        PrintInfo("Restoring Computer Name...");
        UpdateComputerName(vals["ComputerName"]);
    }
    if (vals.count("RegisteredOwner") && vals.count("RegisteredOrg")) {
        PrintInfo("Restoring OS branding...");
        std::string o = vals["RegisteredOwner"], g = vals["RegisteredOrg"];
        UpdateRegisteredOwner(std::wstring(o.begin(), o.end()), std::wstring(g.begin(), g.end()));
    }

    PrintSuccess("Restore complete. SMBIOS values may require manual restore via AMIDEWIN.");
}

// ===========================================================================
// CONFIG FILE SAVE/LOAD
// ===========================================================================
struct GeneratedConfig {
    std::string sysSerial, uuid, mbSerial, chassisSerial;
    std::string machineGuid, systemSku, systemFamily;
    std::string computerName, macAddress;
    std::string sysMan, sysProd, boardMan, boardProd, chassisMan;
};

void SaveConfig(const GeneratedConfig& cfg, const std::string& filename) {
    fs::path p = g_WorkDir / filename;
    std::ofstream f(p);
    f << "[SMBIOS]\n";
    f << "SystemSerial=" << cfg.sysSerial << "\n";
    f << "SystemUUID=" << cfg.uuid << "\n";
    f << "BoardSerial=" << cfg.mbSerial << "\n";
    f << "ChassisSerial=" << cfg.chassisSerial << "\n";
    f << "SystemSKU=" << cfg.systemSku << "\n";
    f << "SystemFamily=" << cfg.systemFamily << "\n";
    f << "SystemManufacturer=" << cfg.sysMan << "\n";
    f << "SystemProduct=" << cfg.sysProd << "\n";
    f << "BoardManufacturer=" << cfg.boardMan << "\n";
    f << "BoardProduct=" << cfg.boardProd << "\n";
    f << "ChassisManufacturer=" << cfg.chassisMan << "\n";
    f << "\n[Registry]\n";
    f << "MachineGuid=" << cfg.machineGuid << "\n";
    f << "ComputerName=" << cfg.computerName << "\n";
    f << "\n[Network]\n";
    f << "MacAddress=" << cfg.macAddress << "\n";
    f.close();
    PrintSuccess("Config saved to: " + filename);
}

bool LoadConfig(const std::string& filename, GeneratedConfig& cfg) {
    fs::path p = g_WorkDir / filename;
    if (!fs::exists(p)) { p = fs::path(filename); }
    if (!fs::exists(p)) { PrintError("Config file not found: " + filename); return false; }

    std::ifstream f(p);
    if (!f.is_open()) {
        PrintError("Cannot open config file: " + p.string());
        return false;
    }

    std::string line;
    while (std::getline(f, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        if (key == "SystemSerial") cfg.sysSerial = val;
        else if (key == "SystemUUID") cfg.uuid = val;
        else if (key == "BoardSerial") cfg.mbSerial = val;
        else if (key == "ChassisSerial") cfg.chassisSerial = val;
        else if (key == "SystemSKU") cfg.systemSku = val;
        else if (key == "SystemFamily") cfg.systemFamily = val;
        else if (key == "SystemManufacturer") cfg.sysMan = val;
        else if (key == "SystemProduct") cfg.sysProd = val;
        else if (key == "BoardManufacturer") cfg.boardMan = val;
        else if (key == "BoardProduct") cfg.boardProd = val;
        else if (key == "ChassisManufacturer") cfg.chassisMan = val;
        else if (key == "MachineGuid") cfg.machineGuid = val;
        else if (key == "ComputerName") cfg.computerName = val;
        else if (key == "MacAddress") cfg.macAddress = val;
    }
    f.close();
    PrintSuccess("Config loaded from: " + filename);
    return true;
}

// ===========================================================================
// REPORT GENERATION
// ===========================================================================
std::string JsonEscape(const std::string& value) {
    std::ostringstream escaped;
    for (unsigned char ch : value) {
        switch (ch) {
            case '\\': escaped << "\\\\"; break;
            case '"': escaped << "\\\""; break;
            case '\b': escaped << "\\b"; break;
            case '\f': escaped << "\\f"; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            default:
                if (ch < 0x20) {
                    escaped << "\\u"
                            << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch)
                            << std::dec << std::setfill(' ');
                } else {
                    escaped << static_cast<char>(ch);
                }
                break;
        }
    }
    return escaped.str();
}

void WriteJsonField(std::ofstream& f, const std::string& key, const std::string& before, const std::string& after, bool last) {
    f << "    \"" << key << "\": {\n"
      << "      \"before\": \"" << JsonEscape(before) << "\",\n"
      << "      \"after\": \"" << JsonEscape(after) << "\"\n"
      << "    }" << (last ? "\n" : ",\n");
}

void GenerateJsonReport(const fs::path& path, const std::string& timestamp, const IdentitySnapshot& before, const GeneratedConfig& after) {
    std::ofstream f(path);
    if (!f.is_open()) {
        PrintError("Cannot create JSON report: " + path.filename().string());
        return;
    }

    f << "{\n";
    f << "  \"schemaVersion\": 1,\n";
    f << "  \"mode\": \"" << (g_DryRun ? "dry-run" : "apply") << "\",\n";
    f << "  \"createdAt\": \"" << JsonEscape(timestamp) << "\",\n";
    f << "  \"fields\": {\n";
    WriteJsonField(f, "systemSerial", before.systemSerial, after.sysSerial, false);
    WriteJsonField(f, "systemUuid", before.systemUuid, after.uuid, false);
    WriteJsonField(f, "boardSerial", before.boardSerial, after.mbSerial, false);
    WriteJsonField(f, "chassisSerial", before.chassisSerial, after.chassisSerial, false);
    WriteJsonField(f, "machineGuid", before.machineGuid, after.machineGuid, false);
    WriteJsonField(f, "computerName", before.computerName, after.computerName, false);
    WriteJsonField(f, "macAddress", before.macAddress, after.macAddress, true);
    f << "  }\n";
    f << "}\n";

    PrintSuccess("JSON report saved to: " + path.filename().string());
}

void GenerateReport(const IdentitySnapshot& before, const GeneratedConfig& after) {
    std::string reportStamp = GetTimestamp();
    std::string isoStamp = GetIsoTimestamp();
    std::string filename = "report_" + reportStamp + ".txt";
    fs::path p = g_WorkDir / filename;
    std::ofstream f(p);

    f << (g_DryRun ? "========= PROVISIONING DRY-RUN PLAN =========" : "========= PROVISIONING REPORT =========") << std::endl;
    f << "Date: " << isoStamp << std::endl;
    f << std::endl;
    f << std::left << std::setw(22) << "FIELD" << std::setw(30) << "OLD VALUE" << "NEW VALUE" << std::endl;
    f << std::string(80, '-') << std::endl;
    f << std::setw(22) << "System Serial" << std::setw(30) << before.systemSerial.substr(0,28) << after.sysSerial << std::endl;
    f << std::setw(22) << "System UUID" << std::setw(30) << before.systemUuid.substr(0,28) << after.uuid << std::endl;
    f << std::setw(22) << "Board Serial" << std::setw(30) << before.boardSerial.substr(0,28) << after.mbSerial << std::endl;
    f << std::setw(22) << "Chassis Serial" << std::setw(30) << before.chassisSerial.substr(0,28) << after.chassisSerial << std::endl;
    f << std::setw(22) << "MachineGuid" << std::setw(30) << before.machineGuid.substr(0,28) << after.machineGuid << std::endl;
    f << std::setw(22) << "Computer Name" << std::setw(30) << before.computerName << after.computerName << std::endl;
    f << std::setw(22) << "MAC Address" << std::setw(30) << before.macAddress.substr(0,28) << after.macAddress << std::endl;
    f.close();

    PrintSuccess("Report saved to: " + filename);
    GenerateJsonReport(g_WorkDir / ("report_" + reportStamp + ".json"), isoStamp, before, after);
}

void AppendHistory(const GeneratedConfig& cfg, bool success) {
    fs::path p = g_WorkDir / "history.log";
    std::ofstream f(p, std::ios::app);
    f << GetIsoTimestamp()
      << " | " << cfg.computerName
      << " | " << cfg.sysSerial
      << " | UUID:" << cfg.uuid.substr(0, 8) << "..."
      << " | MAC:" << cfg.macAddress
      << " | " << (g_DryRun ? "DRY-RUN" : (success ? "OK" : "PARTIAL"))
      << std::endl;
    f.close();
}

bool ShowHistory(size_t maxEntries) {
    fs::path p = g_WorkDir / "history.log";
    if (!fs::exists(p)) {
        fs::path projectHistory = DetectProjectRoot() / "history.log";
        if (fs::exists(projectHistory)) {
            p = projectHistory;
        }
    }

    std::ifstream f(p);
    if (!f.is_open()) {
        std::cerr << "[!] No history log found at: " << p.string() << "\n";
        return false;
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }

    if (lines.empty()) {
        std::cout << "History log is empty: " << p.string() << "\n";
        return true;
    }

    size_t start = lines.size() > maxEntries ? lines.size() - maxEntries : 0;
    std::cout << "Recent history entries (" << (lines.size() - start) << " of " << lines.size() << "):\n\n";
    for (size_t i = start; i < lines.size(); ++i) {
        std::cout << lines[i] << "\n";
    }
    return true;
}

// ===========================================================================
// RELEASE ARTIFACTS
// ===========================================================================
struct ReleaseArtifact {
    std::string name;
    fs::path path;
    bool required;
};

struct ManifestArtifact {
    std::string name;
    fs::path path;
    fs::path sourcePath;
    bool required = false;
    bool present = false;
    unsigned long long size = 0;
    std::string sha256;
    std::string note;
};

struct ReleaseManifest {
    int schemaVersion = 1;
    std::vector<ManifestArtifact> artifacts;
};

struct ManifestArtifactVerification {
    ManifestArtifact artifact;
    fs::path resolvedPath;
    bool ok = false;
    bool actualPresent = false;
    unsigned long long actualSize = 0;
    std::string actualSha256;
    std::string status;
    std::string detail;
};

std::vector<ReleaseArtifact> GetReleaseArtifacts() {
    fs::path root = DetectProjectRoot();
    return {
        { "app.debug.exe", root / "bin" / "Debug" / "DmiUpdater.exe", true },
        { "app.release.exe", root / "bin" / "Release" / "DmiUpdater.exe", true },
        { "driver.debug.sys", root / "bin" / "driver" / "Debug" / "AegisIoctlDriver" / "AegisIoctlDriver.sys", false },
        { "driver.debug.inf", root / "bin" / "driver" / "Debug" / "AegisIoctlDriver" / "AegisIoctlDriver.inf", false },
        { "driver.debug.cat", root / "bin" / "driver" / "Debug" / "AegisIoctlDriver" / "aegisioctldriver.cat", false },
        { "driver.release.sys", root / "bin" / "driver" / "Release" / "AegisIoctlDriver" / "AegisIoctlDriver.sys", false },
        { "driver.release.inf", root / "bin" / "driver" / "Release" / "AegisIoctlDriver" / "AegisIoctlDriver.inf", false },
        { "driver.release.cat", root / "bin" / "driver" / "Release" / "AegisIoctlDriver" / "aegisioctldriver.cat", false },
    };
}

std::string BytesToHex(const std::vector<unsigned char>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) {
        oss << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return oss.str();
}

bool ComputeSha256(const fs::path& path, std::string& hash, std::string& error) {
    if (!fs::exists(path)) {
        error = "missing";
        return false;
    }

    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        error = "cannot open";
        return false;
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;
    DWORD objectLength = 0;
    DWORD hashLength = 0;
    DWORD resultLength = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) {
        error = "BCryptOpenAlgorithmProvider failed";
        return false;
    }

    status = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &resultLength, 0);
    if (status >= 0) {
        status = BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &resultLength, 0);
    }
    if (status < 0 || objectLength == 0 || hashLength == 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        error = "BCryptGetProperty failed";
        return false;
    }

    std::vector<unsigned char> hashObject(objectLength);
    std::vector<unsigned char> digest(hashLength);
    status = BCryptCreateHash(alg, &hashHandle, hashObject.data(), objectLength, nullptr, 0, 0);
    if (status < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        error = "BCryptCreateHash failed";
        return false;
    }

    char buffer[64 * 1024];
    while (input.good()) {
        input.read(buffer, sizeof(buffer));
        std::streamsize bytesRead = input.gcount();
        if (bytesRead > 0) {
            status = BCryptHashData(hashHandle, reinterpret_cast<PUCHAR>(buffer), static_cast<ULONG>(bytesRead), 0);
            if (status < 0) {
                BCryptDestroyHash(hashHandle);
                BCryptCloseAlgorithmProvider(alg, 0);
                error = "BCryptHashData failed";
                return false;
            }
        }
    }

    status = BCryptFinishHash(hashHandle, digest.data(), hashLength, 0);
    BCryptDestroyHash(hashHandle);
    BCryptCloseAlgorithmProvider(alg, 0);

    if (status < 0) {
        error = "BCryptFinishHash failed";
        return false;
    }

    hash = BytesToHex(digest);
    return true;
}

bool PrintArtifactHashes() {
    auto artifacts = GetReleaseArtifacts();

    std::cout << "Release artifact hashes:\n\n";
    std::cout << std::left
              << std::setw(22) << "Artifact"
              << std::setw(10) << "Status"
              << std::setw(66) << "SHA-256"
              << "Path\n";
    std::cout << std::string(140, '-') << "\n";

    bool ok = true;
    for (const auto& artifact : artifacts) {
        std::string hash;
        std::string error;
        bool hashed = ComputeSha256(artifact.path, hash, error);
        if (!hashed && artifact.required) {
            ok = false;
        }

        std::cout << std::left
                  << std::setw(22) << artifact.name
                  << std::setw(10) << (hashed ? "OK" : (artifact.required ? "MISSING" : "SKIP"))
                  << std::setw(66) << (hashed ? hash : error)
                  << artifact.path.string() << "\n";
    }

    return ok;
}

bool WriteReleaseManifest(const std::string& requestedPath) {
    fs::path root = DetectProjectRoot();
    fs::path manifestPath = requestedPath.empty()
        ? (root / ("release_manifest_" + GetTimestamp() + ".json"))
        : fs::path(requestedPath);
    if (manifestPath.is_relative()) {
        manifestPath = root / manifestPath;
    }

    try {
        if (!manifestPath.parent_path().empty()) {
            fs::create_directories(manifestPath.parent_path());
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] Cannot create manifest directory: " << e.what() << "\n";
        return false;
    }

    std::ofstream f(manifestPath);
    if (!f.is_open()) {
        std::cerr << "[!] Cannot write release manifest: " << manifestPath.string() << "\n";
        return false;
    }

    auto artifacts = GetReleaseArtifacts();
    bool ok = true;

    f << "{\n";
    f << "  \"schemaVersion\": 2,\n";
    f << "  \"createdAt\": \"" << JsonEscape(GetIsoTimestamp()) << "\",\n";
    f << "  \"projectRoot\": \"" << JsonEscape(root.string()) << "\",\n";
    f << "  \"artifacts\": [\n";

    for (size_t i = 0; i < artifacts.size(); ++i) {
        const auto& artifact = artifacts[i];
        std::string hash;
        std::string error;
        bool hashed = ComputeSha256(artifact.path, hash, error);
        if (!hashed && artifact.required) {
            ok = false;
        }

        f << "    {\n";
        f << "      \"name\": \"" << JsonEscape(artifact.name) << "\",\n";
        fs::path manifestRelativePath = artifact.path;
        fs::path manifestDir = manifestPath.parent_path();
        if (!manifestDir.empty()) {
            fs::path relative = artifact.path.lexically_normal().lexically_relative(manifestDir.lexically_normal());
            if (!relative.empty()) {
                manifestRelativePath = relative;
            }
        }

        f << "      \"path\": \"" << JsonEscape(manifestRelativePath.string()) << "\",\n";
        f << "      \"sourcePath\": \"" << JsonEscape(artifact.path.string()) << "\",\n";
        f << "      \"required\": " << (artifact.required ? "true" : "false") << ",\n";
        f << "      \"present\": " << (hashed ? "true" : "false") << ",\n";
        f << "      \"size\": " << (hashed ? static_cast<unsigned long long>(fs::file_size(artifact.path)) : 0ULL) << ",\n";
        f << "      \"sha256\": \"" << (hashed ? hash : "") << "\",\n";
        f << "      \"note\": \"" << JsonEscape(hashed ? "" : error) << "\"\n";
        f << "    }" << (i + 1 == artifacts.size() ? "\n" : ",\n");
    }

    f << "  ]\n";
    f << "}\n";

    std::cout << "Release manifest written: " << manifestPath.string() << "\n";
    return ok;
}

std::string Trim(const std::string& value) {
    size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

struct JsonValue {
    enum class Type { Null, Bool, Number, String, Array, Object };
    Type type = Type::Null;
    bool boolValue = false;
    unsigned long long numberValue = 0;
    std::string stringValue;
    std::vector<JsonValue> arrayValue;
    std::map<std::string, JsonValue> objectValue;
};

class JsonParser {
public:
    explicit JsonParser(const std::string& input) : text(input) {}

    bool Parse(JsonValue& value, std::string& parseError) {
        SkipWhitespace();
        if (!ParseValue(value)) {
            parseError = error.empty() ? "invalid JSON" : error;
            return false;
        }
        SkipWhitespace();
        if (position != text.size()) {
            parseError = "unexpected trailing JSON content";
            return false;
        }
        return true;
    }

private:
    std::string text;
    size_t position = 0;
    std::string error;

    void SetError(const std::string& message) {
        if (error.empty()) {
            error = message;
        }
    }

    void SkipWhitespace() {
        while (position < text.size() && std::isspace(static_cast<unsigned char>(text[position]))) {
            ++position;
        }
    }

    bool Consume(char expected) {
        SkipWhitespace();
        if (position >= text.size() || text[position] != expected) {
            return false;
        }
        ++position;
        return true;
    }

    bool ParseLiteral(const std::string& literal) {
        if (text.compare(position, literal.size(), literal) != 0) {
            return false;
        }
        position += literal.size();
        return true;
    }

    bool ParseValue(JsonValue& value) {
        SkipWhitespace();
        if (position >= text.size()) {
            SetError("unexpected end of JSON");
            return false;
        }

        char ch = text[position];
        if (ch == '{') return ParseObject(value);
        if (ch == '[') return ParseArray(value);
        if (ch == '"') {
            value.type = JsonValue::Type::String;
            return ParseString(value.stringValue);
        }
        if (ch == 't') {
            if (!ParseLiteral("true")) {
                SetError("invalid true literal");
                return false;
            }
            value.type = JsonValue::Type::Bool;
            value.boolValue = true;
            return true;
        }
        if (ch == 'f') {
            if (!ParseLiteral("false")) {
                SetError("invalid false literal");
                return false;
            }
            value.type = JsonValue::Type::Bool;
            value.boolValue = false;
            return true;
        }
        if (ch == 'n') {
            if (!ParseLiteral("null")) {
                SetError("invalid null literal");
                return false;
            }
            value.type = JsonValue::Type::Null;
            return true;
        }
        if (std::isdigit(static_cast<unsigned char>(ch))) {
            value.type = JsonValue::Type::Number;
            return ParseNumber(value.numberValue);
        }

        SetError("unexpected JSON token");
        return false;
    }

    bool ParseString(std::string& value) {
        if (!Consume('"')) {
            SetError("expected JSON string");
            return false;
        }

        value.clear();
        while (position < text.size()) {
            char ch = text[position++];
            if (ch == '"') {
                return true;
            }
            if (static_cast<unsigned char>(ch) < 0x20) {
                SetError("unescaped control character in string");
                return false;
            }
            if (ch != '\\') {
                value.push_back(ch);
                continue;
            }
            if (position >= text.size()) {
                SetError("unterminated escape sequence");
                return false;
            }

            char esc = text[position++];
            switch (esc) {
                case '"': value.push_back('"'); break;
                case '\\': value.push_back('\\'); break;
                case '/': value.push_back('/'); break;
                case 'b': value.push_back('\b'); break;
                case 'f': value.push_back('\f'); break;
                case 'n': value.push_back('\n'); break;
                case 'r': value.push_back('\r'); break;
                case 't': value.push_back('\t'); break;
                case 'u': {
                    if (position + 4 > text.size()) {
                        SetError("short unicode escape");
                        return false;
                    }
                    unsigned int code = 0;
                    for (int i = 0; i < 4; ++i) {
                        char hex = text[position++];
                        code <<= 4;
                        if (hex >= '0' && hex <= '9') code += static_cast<unsigned int>(hex - '0');
                        else if (hex >= 'a' && hex <= 'f') code += static_cast<unsigned int>(hex - 'a' + 10);
                        else if (hex >= 'A' && hex <= 'F') code += static_cast<unsigned int>(hex - 'A' + 10);
                        else {
                            SetError("invalid unicode escape");
                            return false;
                        }
                    }
                    value.push_back(code <= 0x7F ? static_cast<char>(code) : '?');
                    break;
                }
                default:
                    SetError("invalid string escape");
                    return false;
            }
        }

        SetError("unterminated JSON string");
        return false;
    }

    bool ParseNumber(unsigned long long& value) {
        SkipWhitespace();
        size_t start = position;
        while (position < text.size() && std::isdigit(static_cast<unsigned char>(text[position]))) {
            ++position;
        }
        if (start == position) {
            SetError("expected non-negative integer");
            return false;
        }

        try {
            value = std::stoull(text.substr(start, position - start));
            return true;
        } catch (const std::exception&) {
            SetError("integer value is out of range");
            return false;
        }
    }

    bool ParseArray(JsonValue& value) {
        if (!Consume('[')) {
            SetError("expected array");
            return false;
        }
        value.type = JsonValue::Type::Array;
        SkipWhitespace();
        if (Consume(']')) {
            return true;
        }

        while (true) {
            JsonValue item;
            if (!ParseValue(item)) return false;
            value.arrayValue.push_back(item);

            SkipWhitespace();
            if (Consume(']')) return true;
            if (!Consume(',')) {
                SetError("expected comma or array end");
                return false;
            }
        }
    }

    bool ParseObject(JsonValue& value) {
        if (!Consume('{')) {
            SetError("expected object");
            return false;
        }
        value.type = JsonValue::Type::Object;
        SkipWhitespace();
        if (Consume('}')) {
            return true;
        }

        while (true) {
            std::string key;
            if (!ParseString(key)) return false;
            if (!Consume(':')) {
                SetError("expected object colon");
                return false;
            }

            JsonValue member;
            if (!ParseValue(member)) return false;
            value.objectValue[key] = member;

            SkipWhitespace();
            if (Consume('}')) return true;
            if (!Consume(',')) {
                SetError("expected comma or object end");
                return false;
            }
        }
    }
};

const JsonValue* FindJsonMember(const JsonValue& object, const std::string& key) {
    if (object.type != JsonValue::Type::Object) return nullptr;
    auto it = object.objectValue.find(key);
    return it == object.objectValue.end() ? nullptr : &it->second;
}

bool ReadOptionalJsonString(const JsonValue& object, const std::string& key, std::string& value, std::string& error) {
    const JsonValue* member = FindJsonMember(object, key);
    if (member == nullptr) return true;
    if (member->type != JsonValue::Type::String) {
        error = "manifest field '" + key + "' must be a string";
        return false;
    }
    value = member->stringValue;
    return true;
}

bool ReadOptionalJsonBool(const JsonValue& object, const std::string& key, bool& value, std::string& error) {
    const JsonValue* member = FindJsonMember(object, key);
    if (member == nullptr) return true;
    if (member->type != JsonValue::Type::Bool) {
        error = "manifest field '" + key + "' must be a boolean";
        return false;
    }
    value = member->boolValue;
    return true;
}

bool ReadOptionalJsonNumber(const JsonValue& object, const std::string& key, unsigned long long& value, std::string& error) {
    const JsonValue* member = FindJsonMember(object, key);
    if (member == nullptr) return true;
    if (member->type != JsonValue::Type::Number) {
        error = "manifest field '" + key + "' must be a non-negative integer";
        return false;
    }
    value = member->numberValue;
    return true;
}

bool LoadReleaseManifest(const fs::path& manifestPath, ReleaseManifest& manifest, std::string& error) {
    std::ifstream f(manifestPath);
    if (!f.is_open()) {
        error = "cannot open manifest";
        return false;
    }

    std::ostringstream buffer;
    buffer << f.rdbuf();

    JsonValue root;
    JsonParser parser(buffer.str());
    if (!parser.Parse(root, error)) {
        return false;
    }
    if (root.type != JsonValue::Type::Object) {
        error = "manifest root must be a JSON object";
        return false;
    }

    unsigned long long schemaVersion = 1;
    if (!ReadOptionalJsonNumber(root, "schemaVersion", schemaVersion, error)) {
        return false;
    }
    if (schemaVersion > static_cast<unsigned long long>((std::numeric_limits<int>::max)())) {
        error = "manifest schemaVersion is out of range";
        return false;
    }
    manifest.schemaVersion = static_cast<int>(schemaVersion);
    manifest.artifacts.clear();

    const JsonValue* artifacts = FindJsonMember(root, "artifacts");
    if (artifacts == nullptr || artifacts->type != JsonValue::Type::Array) {
        error = "manifest artifacts must be an array";
        return false;
    }

    for (size_t i = 0; i < artifacts->arrayValue.size(); ++i) {
        const JsonValue& item = artifacts->arrayValue[i];
        if (item.type != JsonValue::Type::Object) {
            error = "manifest artifact entry must be an object";
            return false;
        }

        ManifestArtifact current;
        std::string pathText;
        std::string sourcePathText;
        if (!ReadOptionalJsonString(item, "name", current.name, error) ||
            !ReadOptionalJsonString(item, "path", pathText, error) ||
            !ReadOptionalJsonString(item, "sourcePath", sourcePathText, error) ||
            !ReadOptionalJsonString(item, "sha256", current.sha256, error) ||
            !ReadOptionalJsonString(item, "note", current.note, error) ||
            !ReadOptionalJsonBool(item, "required", current.required, error) ||
            !ReadOptionalJsonBool(item, "present", current.present, error) ||
            !ReadOptionalJsonNumber(item, "size", current.size, error)) {
            return false;
        }

        if (current.name.empty()) {
            error = "manifest artifact is missing name";
            return false;
        }
        if (pathText.empty()) {
            error = "manifest artifact '" + current.name + "' is missing path";
            return false;
        }

        current.path = fs::path(pathText);
        if (!sourcePathText.empty()) {
            current.sourcePath = fs::path(sourcePathText);
        }
        manifest.artifacts.push_back(current);
    }

    if (manifest.artifacts.empty()) {
        error = "no artifacts found";
        return false;
    }

    return true;
}

fs::path ResolveManifestArtifactPath(const fs::path& manifestPath, const ManifestArtifact& artifact) {
    if (artifact.path.is_absolute()) {
        return artifact.path;
    }
    return manifestPath.parent_path() / artifact.path;
}

fs::path ResolveVerificationReportPath(const fs::path& manifestPath, const std::string& reportFilename) {
    fs::path reportPath(reportFilename);
    if (reportPath.is_relative()) {
        reportPath = manifestPath.parent_path() / reportPath;
    }
    return reportPath;
}

ManifestArtifactVerification VerifyManifestArtifact(const fs::path& manifestPath, const ManifestArtifact& artifact) {
    ManifestArtifactVerification result;
    result.artifact = artifact;
    result.resolvedPath = ResolveManifestArtifactPath(manifestPath, artifact);

    try {
        result.actualPresent = fs::exists(result.resolvedPath);

        if (!artifact.present) {
            if (artifact.required) {
                result.status = "FAIL";
                result.detail = "required artifact was missing when manifest was created";
                return result;
            }
            if (result.actualPresent) {
                result.status = "FAIL";
                result.detail = "presence mismatch expected=missing actual=present";
                return result;
            }
            result.ok = true;
            result.status = "OK";
            result.detail = "optional artifact not present";
            return result;
        }

        if (!result.actualPresent) {
            result.status = "FAIL";
            result.detail = "missing: " + result.resolvedPath.string();
            return result;
        }
        if (!fs::is_regular_file(result.resolvedPath)) {
            result.status = "FAIL";
            result.detail = "not a regular file: " + result.resolvedPath.string();
            return result;
        }

        result.actualSize = static_cast<unsigned long long>(fs::file_size(result.resolvedPath));
        if (result.actualSize != artifact.size) {
            result.status = "FAIL";
            result.detail = "size mismatch expected=" + std::to_string(artifact.size) +
                " actual=" + std::to_string(result.actualSize);
            return result;
        }
        if (artifact.sha256.empty()) {
            result.status = "FAIL";
            result.detail = "missing expected SHA-256 in manifest";
            return result;
        }

        std::string hashError;
        if (!ComputeSha256(result.resolvedPath, result.actualSha256, hashError)) {
            result.status = "FAIL";
            result.detail = "hash error: " + hashError;
            return result;
        }
        if (result.actualSha256 != artifact.sha256) {
            result.status = "FAIL";
            result.detail = "hash mismatch";
            return result;
        }

        result.ok = true;
        result.status = "OK";
        result.detail = "verified";
        return result;
    } catch (const std::exception& e) {
        result.status = "FAIL";
        result.detail = e.what();
        return result;
    }
}

bool WriteVerificationReport(const fs::path& reportPath, const fs::path& manifestPath, int manifestSchemaVersion,
    const std::vector<ManifestArtifactVerification>& results, bool ok, const std::string& error) {
    try {
        if (!reportPath.parent_path().empty()) {
            fs::create_directories(reportPath.parent_path());
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] Cannot create verification report directory: " << e.what() << "\n";
        return false;
    }

    std::ofstream f(reportPath);
    if (!f.is_open()) {
        std::cerr << "[!] Cannot write verification report: " << reportPath.string() << "\n";
        return false;
    }

    size_t passed = 0;
    for (const auto& result : results) {
        if (result.ok) {
            ++passed;
        }
    }
    size_t failed = results.size() - passed;

    f << "{\n";
    f << "  \"schemaVersion\": 1,\n";
    f << "  \"createdAt\": \"" << JsonEscape(GetIsoTimestamp()) << "\",\n";
    f << "  \"manifestPath\": \"" << JsonEscape(manifestPath.string()) << "\",\n";
    f << "  \"manifestSchemaVersion\": " << manifestSchemaVersion << ",\n";
    f << "  \"result\": \"" << (ok ? "passed" : "failed") << "\",\n";
    f << "  \"error\": \"" << JsonEscape(error) << "\",\n";
    f << "  \"summary\": {\n";
    f << "    \"total\": " << results.size() << ",\n";
    f << "    \"passed\": " << passed << ",\n";
    f << "    \"failed\": " << failed << "\n";
    f << "  },\n";
    f << "  \"artifacts\": [\n";

    for (size_t i = 0; i < results.size(); ++i) {
        const auto& result = results[i];
        const auto& artifact = result.artifact;
        f << "    {\n";
        f << "      \"name\": \"" << JsonEscape(artifact.name) << "\",\n";
        f << "      \"path\": \"" << JsonEscape(artifact.path.string()) << "\",\n";
        f << "      \"resolvedPath\": \"" << JsonEscape(result.resolvedPath.string()) << "\",\n";
        f << "      \"sourcePath\": \"" << JsonEscape(artifact.sourcePath.string()) << "\",\n";
        f << "      \"required\": " << (artifact.required ? "true" : "false") << ",\n";
        f << "      \"expectedPresent\": " << (artifact.present ? "true" : "false") << ",\n";
        f << "      \"actualPresent\": " << (result.actualPresent ? "true" : "false") << ",\n";
        f << "      \"expectedSize\": " << artifact.size << ",\n";
        f << "      \"actualSize\": " << result.actualSize << ",\n";
        f << "      \"expectedSha256\": \"" << JsonEscape(artifact.sha256) << "\",\n";
        f << "      \"actualSha256\": \"" << JsonEscape(result.actualSha256) << "\",\n";
        f << "      \"status\": \"" << JsonEscape(result.status) << "\",\n";
        f << "      \"detail\": \"" << JsonEscape(result.detail) << "\"\n";
        f << "    }" << (i + 1 == results.size() ? "\n" : ",\n");
    }

    f << "  ]\n";
    f << "}\n";
    return true;
}

bool VerifyReleaseManifest(const std::string& filename, const std::string& reportFilename) {
    fs::path manifestPath = fs::path(filename);
    if (manifestPath.is_relative()) {
        manifestPath = DetectProjectRoot() / manifestPath;
    }

    fs::path reportPath;
    if (!reportFilename.empty()) {
        reportPath = ResolveVerificationReportPath(manifestPath, reportFilename);
    }

    ReleaseManifest manifest;
    std::string error;
    if (!LoadReleaseManifest(manifestPath, manifest, error)) {
        std::cerr << "[!] Cannot verify manifest: " << error << " (" << manifestPath.string() << ")\n";
        if (!reportPath.empty()) {
            if (WriteVerificationReport(reportPath, manifestPath, 0, {}, false, error)) {
                std::cout << "Verification report: " << reportPath.string() << "\n";
            }
        }
        return false;
    }

    std::cout << "Manifest verification: " << manifestPath.string() << "\n\n";
    std::cout << std::left
              << std::setw(22) << "Artifact"
              << std::setw(10) << "Status"
              << "Detail\n";
    std::cout << std::string(100, '-') << "\n";

    bool ok = true;
    std::vector<ManifestArtifactVerification> results;
    for (const auto& artifact : manifest.artifacts) {
        ManifestArtifactVerification result = VerifyManifestArtifact(manifestPath, artifact);
        ok = result.ok && ok;
        std::cout << std::left
                  << std::setw(22) << artifact.name
                  << std::setw(10) << result.status
                  << result.detail << "\n";
        results.push_back(result);
    }

    size_t passed = 0;
    for (const auto& result : results) {
        if (result.ok) {
            ++passed;
        }
    }
    size_t failed = results.size() - passed;

    std::cout << "\nVerification result: " << (ok ? "passed" : "failed")
              << " (" << passed << " passed, " << failed << " failed).\n";

    bool reportOk = true;
    if (!reportPath.empty()) {
        reportOk = WriteVerificationReport(reportPath, manifestPath, manifest.schemaVersion, results, ok, "");
        if (reportOk) {
            std::cout << "Verification report: " << reportPath.string() << "\n";
        }
    }

    return ok && reportOk;
}

// ===========================================================================
// SELF-CLEANUP
// ===========================================================================
void SelfCleanup() {
    if (g_DryRun) {
        PrintInfo("Dry run: extracted tool cleanup skipped.");
        return;
    }

    PrintInfo("Cleaning up extracted tool artifacts...");
    try {
        if (fs::exists(g_AmidewinPath)) { fs::remove(g_AmidewinPath); PrintSuccess("Removed AMIDEWINx64.EXE"); }
        if (fs::exists(g_AmifldrvPath)) { fs::remove(g_AmifldrvPath); PrintSuccess("Removed amifldrv64.sys"); }
    } catch (const std::exception& e) {
        PrintError(std::string("Cleanup error: ") + e.what());
    }
}

// ===========================================================================
// APPLY ALL MODIFICATIONS
// ===========================================================================
GeneratedConfig GenerateNewConfig(const OemProfile& profile) {
    GeneratedConfig cfg;
    cfg.sysSerial = GenerateRandomSerial(profile.serialPrefix, profile.serialLength);
    cfg.uuid = GenerateRandomUuid();
    cfg.mbSerial = GenerateRandomSerial(profile.boardSerialPrefix, profile.boardSerialLength);
    cfg.chassisSerial = GenerateRandomSerial(profile.chassisSerialPrefix, profile.chassisSerialLength);
    cfg.machineGuid = GenerateRandomUuid();
    cfg.systemSku = GenerateRandomSerial(profile.skuPrefix, 12);
    cfg.systemFamily = profile.familyName;
    cfg.computerName = GenerateRandomSerial("DESKTOP-", 15);
    cfg.macAddress = GenerateRandomMacAddress();
    cfg.sysMan = profile.systemManufacturer;
    cfg.sysProd = profile.systemProduct;
    cfg.boardMan = profile.boardManufacturer;
    cfg.boardProd = profile.boardProduct;
    cfg.chassisMan = profile.chassisManufacturer;
    return cfg;
}

bool ApplySmbiosUpdates(const GeneratedConfig& cfg) {
    if (!fs::exists(g_AmidewinPath)) {
        if (g_DryRun) {
            PrintInfo("Dry run: SMBIOS tool is not extracted; commands will be planned only.");
        } else {
            PrintError("AMIDEWINx64.EXE not found - SMBIOS updates skipped.");
            return false;
        }
    }

    std::wstring ami = g_AmidewinPath.wstring();
    auto toW = [](const std::string& s) { return std::wstring(s.begin(), s.end()); };

    bool ok = true;
    ok = ExecuteProcess(ami, L"/SS \"" + toW(cfg.sysSerial) + L"\"") && ok;
    ok = ExecuteProcess(ami, L"/SU \"" + toW(cfg.uuid) + L"\"") && ok;
    ok = ExecuteProcess(ami, L"/BS \"" + toW(cfg.mbSerial) + L"\"") && ok;
    ok = ExecuteProcess(ami, L"/CS \"" + toW(cfg.chassisSerial) + L"\"") && ok;
    ok = ExecuteProcess(ami, L"/SK \"" + toW(cfg.systemSku) + L"\"") && ok;
    ok = ExecuteProcess(ami, L"/SF \"" + toW(cfg.systemFamily) + L"\"") && ok;
    ok = ExecuteProcess(ami, L"/SM \"" + toW(cfg.sysMan) + L"\"") && ok;
    ok = ExecuteProcess(ami, L"/SP \"" + toW(cfg.sysProd) + L"\"") && ok;
    ok = ExecuteProcess(ami, L"/BM \"" + toW(cfg.boardMan) + L"\"") && ok;
    ok = ExecuteProcess(ami, L"/BP \"" + toW(cfg.boardProd) + L"\"") && ok;
    ok = ExecuteProcess(ami, L"/CM \"" + toW(cfg.chassisMan) + L"\"") && ok;
    return ok;
}

bool ApplyAll(GeneratedConfig& cfg) {
    bool ok = true;

    // Registry modifications
    PrintInfo("Updating MachineGuid...");
    if (!UpdateMachineGuid(cfg.machineGuid)) ok = false;
    else PrintSuccess("MachineGuid updated.");

    PrintInfo("Updating Computer Name...");
    if (!UpdateComputerName(cfg.computerName)) ok = false;
    else PrintSuccess("Computer Name scheduled: " + cfg.computerName);

    PrintInfo("Updating MAC Addresses (LAA)...");
    if (!UpdateNetworkAdapterMacs(cfg.macAddress)) ok = false;

    PrintInfo("Updating OS branding...");
    if (!UpdateRegisteredOwner(L"Enterprise Professional User", L"Staging Organization Corp")) ok = false;
    else PrintSuccess("OS branding updated.");

    PrintInfo("Clearing event logs...");
    ClearAdministrativeLogs();

    PrintInfo("Cleaning staging directories...");
    CleanStagingDirectories();

    PrintInfo("Flushing DNS cache...");
    FlushDnsCache();

    // SMBIOS via AMIDEWIN
    if (g_DryRun || fs::exists(g_AmidewinPath)) {
        std::wstring ami = g_AmidewinPath.wstring();
        auto toW = [](const std::string& s) { return std::wstring(s.begin(), s.end()); };

        PrintInfo("Running AMIDEWIN SMBIOS updates...");
        ok = ExecuteProcess(ami, L"/SS \"" + toW(cfg.sysSerial) + L"\"") && ok;
        ok = ExecuteProcess(ami, L"/SU \"" + toW(cfg.uuid) + L"\"") && ok;
        ok = ExecuteProcess(ami, L"/BS \"" + toW(cfg.mbSerial) + L"\"") && ok;
        ok = ExecuteProcess(ami, L"/CS \"" + toW(cfg.chassisSerial) + L"\"") && ok;
        ok = ExecuteProcess(ami, L"/SK \"" + toW(cfg.systemSku) + L"\"") && ok;
        ok = ExecuteProcess(ami, L"/SF \"" + toW(cfg.systemFamily) + L"\"") && ok;
        ok = ExecuteProcess(ami, L"/SM \"" + toW(cfg.sysMan) + L"\"") && ok;
        ok = ExecuteProcess(ami, L"/SP \"" + toW(cfg.sysProd) + L"\"") && ok;
        ok = ExecuteProcess(ami, L"/BM \"" + toW(cfg.boardMan) + L"\"") && ok;
        ok = ExecuteProcess(ami, L"/BP \"" + toW(cfg.boardProd) + L"\"") && ok;
        ok = ExecuteProcess(ami, L"/CM \"" + toW(cfg.chassisMan) + L"\"") && ok;
    } else {
        PrintError("AMIDEWINx64.EXE not found — SMBIOS updates skipped.");
        ok = false;
    }

    return ok;
}

// ===========================================================================
// OEM PROFILE SELECTION
// ===========================================================================
int SelectOemProfile() {
    auto profiles = GetOemProfiles(g_WorkDir);
    PrintInfo("Select OEM Manufacturer Profile:");
    std::cout << std::endl;
    for (size_t i = 0; i < profiles.size(); i++) {
        SetColor(Color::VERBOSE);
        std::cout << "  [" << (i + 1) << "] ";
        SetColor(Color::RESET);
        std::cout << profiles[i].name;
        SetColor(Color::INFO);
        std::cout << "  (" << profiles[i].systemProduct << ")" << std::endl;
    }
    SetColor(Color::RESET);
    std::cout << "\nSelect [1-" << profiles.size() << "]: ";
    int sel = 0;
    if (!ReadInt(sel)) return static_cast<int>(profiles.size()) - 1;
    if (sel < 1 || sel > static_cast<int>(profiles.size())) return static_cast<int>(profiles.size()) - 1;
    return sel - 1;
}

// ===========================================================================
// REBOOT PROMPT
// ===========================================================================
void RebootPrompt() {
    if (g_DryRun || g_NoReboot) {
        PrintInfo("Reboot skipped.");
        return;
    }

    std::cout << std::endl;
    PrintInfo("Changes require a restart to take effect.");
    std::cout << "  [1] Reboot now\n";
    std::cout << "  [2] Reboot in 60 seconds\n";
    std::cout << "  [3] Skip (manual reboot later)\n";
    std::cout << "\nSelect: ";
    int sel = 0;
    if (!ReadInt(sel)) {
        PrintInfo("Skipped. Please reboot manually.");
        return;
    }

    switch (sel) {
        case 1:
            PrintInfo("Rebooting now...");
            ExecuteProcess(L"shutdown.exe", L"/r /t 0");
            break;
        case 2:
            PrintInfo("Reboot scheduled in 60 seconds...");
            ExecuteProcess(L"shutdown.exe", L"/r /t 60");
            break;
        default:
            PrintInfo("Skipped. Please reboot manually.");
            break;
    }
}

// ===========================================================================
// INTERACTIVE MENU
// ===========================================================================
void ShowMenu() {
    std::cout << std::endl;
    SetColor(Color::VERBOSE);
    std::cout << "+---------------------------------------------+" << std::endl;
    std::cout << "|              MAIN MENU                      |" << std::endl;
    std::cout << "+---------------------------------------------+" << std::endl;
    SetColor(Color::RESET);
    std::cout << "  [1] Run ALL modifications (recommended)\n";
    std::cout << "  [2] SMBIOS / DMI only\n";
    std::cout << "  [3] Registry only (GUID, Name, Owner)\n";
    std::cout << "  [4] Network MAC only\n";
    std::cout << "  [5] Cleanup only (logs, temp files)\n";
    std::cout << "  [6] View current system identity\n";
    std::cout << "  [7] Restore from backup\n";
    std::cout << "  [8] Save current config to file\n";
    std::cout << "  [9] Load config from file\n";
    std::cout << "  [0] Exit\n";
    std::cout << "\nSelect: ";
}

// ===========================================================================
// MAIN
// ===========================================================================
int main(int argc, char* argv[]) {
    // Determine working directory
    wchar_t exePathBuf[MAX_PATH];
    GetModuleFileNameW(nullptr, exePathBuf, MAX_PATH);
    g_WorkDir = fs::path(exePathBuf).parent_path();
    g_AmidewinPath = g_WorkDir / L"AMIDEWINx64.EXE";
    g_AmifldrvPath = g_WorkDir / L"amifldrv64.sys";

    // Parse CLI arguments
    bool autoMode = false;
    bool smbiosOnly = false;
    bool registryOnly = false;
    bool verifyOnly = false;
    bool showHelp = false;
    bool privacyAudit = false;
    bool privacyFullExport = false;
    bool privacySessionStart = false;
    bool legacyProvisioning = false;
    bool explicitAutoFlag = false;
    bool silentRequested = false;
    bool preflightOnly = false;
    bool driverStatusOnly = false;
    bool driverVersionOnly = false;
    bool listProfiles = false;
    bool showHistory = false;
    bool artifactHashesOnly = false;
    bool releaseManifest = false;
    size_t historyCount = 20;
    std::string profileFile;
    std::string createProfileTemplateFile;
    std::string validateProfileFile;
    std::string driverPingValue;
    std::string releaseManifestPath;
    std::string verifyManifestPath;
    std::string verifyManifestReportPath;
    std::string privacyOutputPath;
    std::string privacySessionMode = "user";
    std::string privacySessionStatusRef;
    std::string privacySessionRestoreRef;
    std::string privacySessionLaunchRef;
    std::string privacySessionLaunchTarget;

    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg == "--help" || arg == "-h" || arg == "/?") showHelp = true;
        else if (arg == "--privacy-audit") privacyAudit = true;
        else if (arg == "--output" && i + 1 < argc) privacyOutputPath = argv[++i];
        else if (arg == "--full-export") privacyFullExport = true;
        else if (arg == "--privacy-session-start") privacySessionStart = true;
        else if (arg == "--mode" && i + 1 < argc) privacySessionMode = argv[++i];
        else if (arg == "--privacy-session-status" && i + 1 < argc) privacySessionStatusRef = argv[++i];
        else if (arg == "--privacy-session-restore" && i + 1 < argc) privacySessionRestoreRef = argv[++i];
        else if (arg == "--privacy-session-launch" && i + 2 < argc) {
            privacySessionLaunchRef = argv[++i];
            privacySessionLaunchTarget = argv[++i];
        }
        else if (arg == "--legacy-provisioning") legacyProvisioning = true;
        else if (arg == "--auto") { autoMode = true; explicitAutoFlag = true; }
        else if (arg == "--silent") { g_Silent = true; silentRequested = true; }
        else if (arg == "--dry-run") { g_DryRun = true; autoMode = true; g_NoReboot = true; }
        else if (arg == "--no-reboot") g_NoReboot = true;
        else if (arg == "--preflight") preflightOnly = true;
        else if (arg == "--driver-status") driverStatusOnly = true;
        else if (arg == "--driver-version") driverVersionOnly = true;
        else if (arg == "--driver-ping" && i + 1 < argc) driverPingValue = argv[++i];
        else if (arg == "--show-history") {
            showHistory = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                unsigned long parsed = 0;
                if (!TryParseUlong(argv[i + 1], parsed) || parsed == 0) {
                    std::cerr << "[!] Invalid --show-history count: " << argv[i + 1] << "\n";
                    return 1;
                }
                historyCount = static_cast<size_t>(parsed);
                ++i;
            }
        }
        else if (arg == "--artifact-hashes") artifactHashesOnly = true;
        else if (arg == "--release-manifest") {
            releaseManifest = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                releaseManifestPath = argv[++i];
            }
        }
        else if (arg == "--verify-manifest" && i + 1 < argc) verifyManifestPath = argv[++i];
        else if (arg == "--verify-manifest-report" && i + 1 < argc) verifyManifestReportPath = argv[++i];
        else if (arg == "--smbios-only") { smbiosOnly = true; autoMode = true; }
        else if (arg == "--registry-only") { registryOnly = true; autoMode = true; }
        else if (arg == "--verify") verifyOnly = true;
        else if (arg == "--list-profiles") listProfiles = true;
        else if (arg == "--create-profile-template" && i + 1 < argc) createProfileTemplateFile = argv[++i];
        else if (arg == "--validate-profile" && i + 1 < argc) validateProfileFile = argv[++i];
        else if (arg == "--profile" && i + 1 < argc) profileFile = argv[++i];
        else {
            std::cerr << "[!] Unknown or incomplete option: " << arg << "\n\n";
            PrintUsage();
            return 1;
        }
    }

    if (silentRequested && !privacyAudit) {
        autoMode = true;
    }

    if (showHelp) {
        PrintUsage();
        return 0;
    }

    const bool privacySessionCommand = privacySessionStart || !privacySessionStatusRef.empty() ||
        !privacySessionRestoreRef.empty() || !privacySessionLaunchRef.empty();
    if (privacyAudit && privacySessionCommand) {
        std::cerr << "[!] Privacy audit and privacy session commands cannot be combined.\n";
        return 1;
    }
    if (!privacyAudit && privacyFullExport) {
        std::cerr << "[!] --full-export is only valid with --privacy-audit.\n";
        return 1;
    }
    if (!privacyAudit && !privacySessionStart && !privacyOutputPath.empty()) {
        std::cerr << "[!] --output is only valid with --privacy-audit or --privacy-session-start.\n";
        return 1;
    }
    if (!privacySessionStart && privacySessionMode != "user") {
        std::cerr << "[!] --mode is only valid with --privacy-session-start.\n";
        return 1;
    }
    if (verifyManifestPath.empty() && !verifyManifestReportPath.empty()) {
        std::cerr << "[!] --verify-manifest-report is only valid with --verify-manifest.\n";
        return 1;
    }
    if (privacyAudit && (explicitAutoFlag || smbiosOnly || registryOnly || !profileFile.empty() || g_DryRun)) {
        std::cerr << "[!] --privacy-audit cannot be combined with legacy provisioning options.\n";
        return 1;
    }

    if (privacyAudit) {
        PrivacyAuditOptions options;
        options.workDir = g_WorkDir;
        options.fullExport = privacyFullExport;
        if (!privacyOutputPath.empty()) {
            options.outputPath = fs::path(privacyOutputPath);
        }

        PrivacyAuditResult result = RunPrivacyAudit(options);
        if (!result.ok) {
            std::cerr << "[!] Privacy audit failed while writing report files.\n";
            if (!result.errorMessage.empty()) {
                std::cerr << "    " << result.errorMessage << "\n";
            }
            return 1;
        }

        if (!g_Silent) {
            std::cout << "Privacy audit complete.\n"
                      << "  High: " << result.highCount
                      << "  Medium: " << result.mediumCount
                      << "  Low: " << result.lowCount << "\n"
                      << "  Collectors: ok=" << result.collectorOkCount
                      << " partial=" << result.collectorPartialCount
                      << " unavailable=" << result.collectorUnavailableCount
                      << " error=" << result.collectorErrorCount << "\n"
                      << "  Text report: " << result.textReportPath.string() << "\n"
                      << "  JSON report: " << result.jsonReportPath.string() << "\n"
                      << "  Manifest: " << result.manifestPath.string() << "\n";
            if (!result.fullExportPath.empty()) {
                std::cout << "  Warning: full export contains local plaintext identifiers. Keep it private and local.\n";
                std::cout << "  Full local export: " << result.fullExportPath.string() << "\n";
            }
        }
        return 0;
    }

    if (privacySessionCommand) {
        if (explicitAutoFlag || smbiosOnly || registryOnly || !profileFile.empty() || g_DryRun || privacyFullExport) {
            std::cerr << "[!] Privacy session commands cannot be combined with legacy provisioning, dry-run, or full-export options.\n";
            return 1;
        }

        PrivacySessionResult result;
        if (privacySessionStart) {
            PrivacySessionStartOptions options;
            options.workDir = g_WorkDir;
            options.mode = privacySessionMode;
            if (!privacyOutputPath.empty()) {
                options.outputPath = fs::path(privacyOutputPath);
            }
            result = StartPrivacySession(options);
        } else if (!privacySessionStatusRef.empty()) {
            result = ShowPrivacySessionStatus({ g_WorkDir, privacySessionStatusRef, {} });
        } else if (!privacySessionRestoreRef.empty()) {
            result = RestorePrivacySession({ g_WorkDir, privacySessionRestoreRef, {} });
        } else {
            result = LaunchPrivacySessionTarget({ g_WorkDir, privacySessionLaunchRef, privacySessionLaunchTarget });
        }

        if (!result.ok) {
            std::cerr << "[!] Privacy session command failed.\n";
            if (!result.errorMessage.empty()) {
                std::cerr << "    " << result.errorMessage << "\n";
            }
            if (!result.launchPlanPath.empty()) {
                std::cerr << "    Launch plan: " << result.launchPlanPath.string() << "\n";
            }
            if (!result.launchCommandPath.empty()) {
                std::cerr << "    Launch command: " << result.launchCommandPath.string() << "\n";
            }
            if (!result.policyRulesPath.empty()) {
                std::cerr << "    Policy rules: " << result.policyRulesPath.string() << "\n";
            }
            return 1;
        }

        if (!g_Silent) {
            std::cout << "Privacy session " << (privacySessionStart ? "started" :
                (!privacySessionStatusRef.empty() ? "status" :
                (!privacySessionRestoreRef.empty() ? "restored" : "launched"))) << ".\n"
                      << "  Session: " << result.sessionId << "\n"
                      << "  Mode: " << result.mode << "\n"
                      << "  Path: " << result.sessionPath.string() << "\n";
            if (privacySessionStart) {
                std::cout << "  Changed settings: " << result.changedCount << "\n"
                          << "  Snapshot: " << result.snapshotPath.string() << "\n"
                          << "  Manifest: " << result.manifestPath.string() << "\n";
                if (!result.sandboxPath.empty()) {
                    std::cout << "  Sandbox config: " << result.sandboxPath.string() << "\n"
                              << "  Sandbox launch attempted: " << (result.launched ? "yes" : "no") << "\n";
                }
            } else if (!privacySessionStatusRef.empty()) {
                std::cout << "  Restore state: " << (result.restored ? "restored" : "active") << "\n"
                          << "  Manifest: " << result.manifestPath.string() << "\n";
            } else if (!privacySessionRestoreRef.empty()) {
                std::cout << "  Restored settings: " << result.changedCount << "\n"
                          << "  Restored policy rules: " << result.policyRuleCount << "\n"
                          << "  Restore state: restored\n";
            } else {
                std::cout << "  Launch mode: " << result.launchMode << "\n"
                          << "  Target kind: " << result.targetKind << "\n"
                          << "  Sandbox used: " << (result.sandboxUsed ? "yes" : "no") << "\n"
                          << "  Launch attempted: " << (result.launched ? "yes" : "no") << "\n";
                if (result.hostLaunchWarning) {
                    std::cout << "  Host launch warning: yes\n";
                }
                if (!result.launchPlanPath.empty()) {
                    std::cout << "  Launch plan: " << result.launchPlanPath.string() << "\n";
                }
                if (!result.launchCommandPath.empty()) {
                    std::cout << "  Launch command: " << result.launchCommandPath.string() << "\n";
                }
                if (!result.launchSandboxPath.empty()) {
                    std::cout << "  Sandbox config: " << result.launchSandboxPath.string() << "\n";
                }
                if (!result.policyRulesPath.empty()) {
                    std::cout << "  Policy rules: " << result.policyRulesPath.string() << "\n";
                }
            }
        }
        return 0;
    }

    if (preflightOnly) {
        return RunPreflight() ? 0 : 1;
    }

    const bool driverUtilityMode = driverStatusOnly || driverVersionOnly || !driverPingValue.empty();
    if (driverUtilityMode) {
        bool ok = true;
        if (driverStatusOnly) {
            ok = PrintDriverStatus() && ok;
        }
        if (driverVersionOnly) {
            ok = QueryDriverVersion() && ok;
        }
        if (!driverPingValue.empty()) {
            unsigned long pingInput = 0;
            if (!TryParseUlong(driverPingValue, pingInput)) {
                std::cerr << "[!] Invalid --driver-ping value: " << driverPingValue << "\n";
                return 1;
            }
            ok = PingDriver(pingInput) && ok;
        }
        return ok ? 0 : 1;
    }

    const bool localUtilityMode = showHistory || artifactHashesOnly || releaseManifest || !verifyManifestPath.empty() ||
        listProfiles || !createProfileTemplateFile.empty() || !validateProfileFile.empty();
    if (localUtilityMode) {
        bool ok = true;
        if (showHistory) {
            ok = ShowHistory(historyCount) && ok;
        }
        if (artifactHashesOnly) {
            ok = PrintArtifactHashes() && ok;
        }
        if (releaseManifest) {
            ok = WriteReleaseManifest(releaseManifestPath) && ok;
        }
        if (!verifyManifestPath.empty()) {
            ok = VerifyReleaseManifest(verifyManifestPath, verifyManifestReportPath) && ok;
        }
        if (listProfiles) {
            ListProfiles();
        }
        if (!createProfileTemplateFile.empty()) {
            ok = CreateProfileTemplate(createProfileTemplateFile) && ok;
        }
        if (!validateProfileFile.empty()) {
            ok = ValidateProfileFile(validateProfileFile) && ok;
        }
        return ok ? 0 : 1;
    }

    const bool interactiveLegacyMode = !verifyOnly && !autoMode;
    const bool legacyMutationMode =
        explicitAutoFlag || smbiosOnly || registryOnly ||
        (autoMode && !g_DryRun) ||
        interactiveLegacyMode;
    if (legacyMutationMode && !legacyProvisioning) {
        std::cerr
            << "[!] Legacy provisioning is quarantined.\n"
            << "    Use --privacy-audit for the hardware privacy audit, or add\n"
            << "    --legacy-provisioning to intentionally run legacy machine-changing flows.\n";
        return 1;
    }

    // Auto-elevate if not admin
    const bool needsAdmin = !(g_DryRun || verifyOnly || localUtilityMode);
    if (!IsRunningAsAdmin() && needsAdmin) {
        if (!g_Silent) {
            SetColor(Color::INFO);
            std::cout << "[*] Not running as Administrator. Requesting elevation...\n";
            SetColor(Color::RESET);
        }
        RelaunchAsAdmin(argc, argv);
        return 0;
    }

    // Init logging
    std::string logFilename = "DmiUpdater_log_" + GetTimestamp() + ".txt";
    g_LogFile.open((g_WorkDir / logFilename).string());

    PrintHeader();
    if (g_DryRun) {
        PrintInfo("Dry-run mode enabled. No system changes will be applied.");
    } else if (IsRunningAsAdmin()) {
        PrintSuccess("Running with Administrator privileges.");
    } else {
        PrintInfo("Running without Administrator privileges in read-only mode.");
    }

    // Extract embedded resources if missing
    if (g_DryRun || verifyOnly) {
        PrintInfo(g_DryRun ? "Dry run: resource extraction skipped." : "Verify mode: resource extraction skipped.");
    } else if (!fs::exists(g_AmidewinPath)) {
        PrintInfo("Extracting embedded AMIDEWINx64.EXE...");
        if (ExtractResource(IDR_AMIDEWIN, g_AmidewinPath.wstring()))
            PrintSuccess("Extracted AMIDEWINx64.EXE.");
        else
            PrintError("Failed to extract AMIDEWINx64.EXE!");
    }
    if (!g_DryRun && !verifyOnly && !fs::exists(g_AmifldrvPath)) {
        PrintInfo("Extracting embedded amifldrv64.sys...");
        if (ExtractResource(IDR_AMIFLDRV, g_AmifldrvPath.wstring()))
            PrintSuccess("Extracted amifldrv64.sys.");
        else
            PrintError("Failed to extract amifldrv64.sys!");
    }

    // Verify-only mode
    if (verifyOnly) {
        auto snap = CaptureCurrentIdentity();
        DisplayIdentity(snap, "CURRENT SYSTEM IDENTITY");
        return 0;
    }

    // Capture current identity for backup
    PrintInfo("Capturing current system identity...");
    g_Before = CaptureCurrentIdentity();
    DisplayIdentity(g_Before, "CURRENT SYSTEM IDENTITY");

    // Auto mode (CLI driven)
    if (autoMode) {
        auto profiles = GetOemProfiles(g_WorkDir);
        int profileIdx = static_cast<int>(profiles.size()) - 1; // Default: Generic

        GeneratedConfig cfg = GenerateNewConfig(profiles[profileIdx]);
        if (!profileFile.empty()) {
            if (!LoadConfig(profileFile, cfg)) {
                return 1;
            }
        }

        BackupCurrentValues(g_Before);

        bool ok = true;
        if (smbiosOnly) {
            ok = ApplySmbiosUpdates(cfg);
        } else if (registryOnly) {
            if (!UpdateMachineGuid(cfg.machineGuid)) ok = false;
            if (!UpdateComputerName(cfg.computerName)) ok = false;
            if (!UpdateRegisteredOwner(L"Enterprise Professional User", L"Staging Organization Corp")) ok = false;
        } else {
            ok = ApplyAll(cfg);
        }

        GenerateReport(g_Before, cfg);
        AppendHistory(cfg, ok);

        if (!g_Silent) RebootPrompt();
        return ok ? 0 : 1;
    }

    // Interactive menu loop
    bool running = true;
    GeneratedConfig currentCfg;
    bool cfgGenerated = false;
    int selectedProfile = -1;

    while (running) {
        ShowMenu();
        int sel = -1;
        if (!ReadInt(sel)) {
            PrintError("Invalid selection.");
            continue;
        }
        std::cout << std::endl;

        switch (sel) {
            case 1: {
                // Full run
                selectedProfile = SelectOemProfile();
                auto profiles = GetOemProfiles(g_WorkDir);
                currentCfg = GenerateNewConfig(profiles[selectedProfile]);
                cfgGenerated = true;

                PrintInfo("Generated new values:");
                PrintBox({
                    {"System Serial",   currentCfg.sysSerial},
                    {"System UUID",     currentCfg.uuid},
                    {"Board Serial",    currentCfg.mbSerial},
                    {"Chassis Serial",  currentCfg.chassisSerial},
                    {"System SKU",      currentCfg.systemSku},
                    {"MachineGuid",     currentCfg.machineGuid},
                    {"Computer Name",   currentCfg.computerName},
                    {"MAC Address",     currentCfg.macAddress},
                    {"OEM Profile",     profiles[selectedProfile].name},
                });
                std::cout << "\n";

                PrintInfo("Proceed? (y/N): ");
                char ch; std::cin >> ch;
                if (ch != 'y' && ch != 'Y') { PrintInfo("Cancelled."); break; }

                BackupCurrentValues(g_Before);
                bool ok = ApplyAll(currentCfg);
                GenerateReport(g_Before, currentCfg);
                AppendHistory(currentCfg, ok);

                if (ok) PrintSuccess("All modifications applied successfully!");
                else PrintError("Some modifications failed.");

                std::cout << "\nClean up extracted tools? (y/N): ";
                std::cin >> ch;
                if (ch == 'y' || ch == 'Y') SelfCleanup();

                RebootPrompt();
                break;
            }
            case 2: {
                // SMBIOS only
                if (!cfgGenerated) {
                    selectedProfile = SelectOemProfile();
                    auto profiles = GetOemProfiles(g_WorkDir);
                    currentCfg = GenerateNewConfig(profiles[selectedProfile]);
                    cfgGenerated = true;
                }
                if (ApplySmbiosUpdates(currentCfg)) {
                    PrintSuccess("SMBIOS updates complete.");
                } else {
                    PrintError("SMBIOS updates failed.");
                }
                break;
            }
            case 3: {
                // Registry only
                if (!cfgGenerated) {
                    currentCfg = GenerateNewConfig(GetOemProfiles(g_WorkDir).back());
                    cfgGenerated = true;
                }
                UpdateMachineGuid(currentCfg.machineGuid);
                UpdateComputerName(currentCfg.computerName);
                UpdateRegisteredOwner(L"Enterprise Professional User", L"Staging Organization Corp");
                FlushDnsCache();
                PrintSuccess("Registry updates complete.");
                break;
            }
            case 4: {
                // MAC only
                if (!cfgGenerated) {
                    currentCfg = GenerateNewConfig(GetOemProfiles(g_WorkDir).back());
                    cfgGenerated = true;
                }
                UpdateNetworkAdapterMacs(currentCfg.macAddress);
                std::cout << "\nReset adapters now to apply? (y/N): ";
                char ch; std::cin >> ch;
                if (ch == 'y' || ch == 'Y') ResetNetworkAdapters();
                break;
            }
            case 5: {
                // Cleanup
                ClearAdministrativeLogs();
                CleanStagingDirectories();
                PrintSuccess("Cleanup complete.");
                break;
            }
            case 6: {
                // View identity
                auto snap = CaptureCurrentIdentity();
                DisplayIdentity(snap, "CURRENT SYSTEM IDENTITY");
                break;
            }
            case 7: {
                // Restore
                RestoreFromBackup();
                break;
            }
            case 8: {
                // Save config
                if (!cfgGenerated) {
                    PrintError("No config generated yet. Run option [1] first, or generate via profile.");
                    break;
                }
                std::string fn = "config_" + GetTimestamp() + ".ini";
                SaveConfig(currentCfg, fn);
                break;
            }
            case 9: {
                // Load config
                std::cout << "Enter config filename: ";
                std::string fn; std::cin >> fn;
                if (LoadConfig(fn, currentCfg)) cfgGenerated = true;
                break;
            }
            case 0:
                running = false;
                break;
            default:
                PrintError("Invalid selection.");
                break;
        }
    }

    PrintInfo("Goodbye.");
    if (g_LogFile.is_open()) g_LogFile.close();
    return 0;
}
