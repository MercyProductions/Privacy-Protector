#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "privacy_audit.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <ctime>
#include <exception>
#include <fstream>
#include <functional>
#include <iomanip>
#include <map>
#include <sstream>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")

namespace fs = std::filesystem;

namespace {

constexpr int kSchemaVersion = 2;

struct Finding {
    std::string surface;
    std::string identifierType;
    std::string risk;
    std::string redactedSample;
    std::string fullValue;
    std::string evidenceSource;
    std::string recommendation;
    bool sensitive = true;
};

struct CollectorResult {
    std::string name;
    std::string status;
    std::string message;
    std::vector<Finding> findings;
};

struct CommandResult {
    bool started = false;
    bool timedOut = false;
    DWORD exitCode = 0;
    std::string output;
};

struct RegistryCounts {
    bool opened = false;
    DWORD subkeyCount = 0;
    DWORD valueCount = 0;
};

struct AuditContext {
    std::string runId;
    std::string createdAt;
};

std::string TimestampForFile() {
    std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &now);

    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &local);
    return buf;
}

std::string TimestampIso() {
    std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &now);

    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &local);
    return buf;
}

std::string BytesToHex(const unsigned char* bytes, size_t length) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        out << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return out.str();
}

std::string GenerateRunId() {
    unsigned char bytes[16]{};
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        std::string stamp = TimestampForFile();
        return "audit-" + stamp;
    }

    std::ostringstream out;
    out << std::hex << std::setfill('0')
        << std::setw(2) << static_cast<int>(bytes[0])
        << std::setw(2) << static_cast<int>(bytes[1])
        << std::setw(2) << static_cast<int>(bytes[2])
        << std::setw(2) << static_cast<int>(bytes[3]) << "-"
        << std::setw(2) << static_cast<int>(bytes[4])
        << std::setw(2) << static_cast<int>(bytes[5]) << "-"
        << std::setw(2) << static_cast<int>(bytes[6])
        << std::setw(2) << static_cast<int>(bytes[7]) << "-"
        << std::setw(2) << static_cast<int>(bytes[8])
        << std::setw(2) << static_cast<int>(bytes[9]) << "-"
        << std::setw(2) << static_cast<int>(bytes[10])
        << std::setw(2) << static_cast<int>(bytes[11])
        << std::setw(2) << static_cast<int>(bytes[12])
        << std::setw(2) << static_cast<int>(bytes[13])
        << std::setw(2) << static_cast<int>(bytes[14])
        << std::setw(2) << static_cast<int>(bytes[15]);
    return out.str();
}

std::string Narrow(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) {
        return {};
    }

    std::string out(static_cast<size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, out.data(), size, nullptr, nullptr);
    return out;
}

std::string Trim(std::string value) {
    auto isSpace = [](unsigned char ch) { return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n'; };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [&](unsigned char ch) { return !isSpace(ch); }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [&](unsigned char ch) { return !isSpace(ch); }).base(), value.end());
    return value;
}

std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool LooksLikeCollectorFailure(const std::string& value) {
    std::string lower = ToLower(value);
    return lower.find("not recognized") != std::string::npos ||
           lower.find("cannot find") != std::string::npos ||
           lower.find("access is denied") != std::string::npos ||
           lower.find("invalid class") != std::string::npos ||
           lower.find("get-ciminstance :") != std::string::npos ||
           lower.find("wmic :") != std::string::npos;
}

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
                    escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch)
                            << std::dec << std::setfill(' ');
                } else {
                    escaped << static_cast<char>(ch);
                }
                break;
        }
    }
    return escaped.str();
}

std::string Redact(const std::string& value) {
    std::string compact;
    for (unsigned char ch : value) {
        compact.push_back((ch == '\r' || ch == '\n' || ch == '\t') ? ' ' : static_cast<char>(ch));
    }
    compact = Trim(compact);

    if (compact.empty()) {
        return "(empty)";
    }
    if (compact.size() <= 8) {
        return std::string(compact.size(), '*');
    }

    size_t prefix = (std::min<size_t>)(4, compact.size() / 4);
    size_t suffix = (std::min<size_t>)(4, compact.size() / 4);
    return compact.substr(0, prefix) + "..." + compact.substr(compact.size() - suffix);
}

std::string ReadRegistryString(HKEY root, const std::wstring& subKey, const std::wstring& valueName) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) {
        return {};
    }

    wchar_t buf[2048]{};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    LONG status = RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type, reinterpret_cast<BYTE*>(buf), &size);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        return {};
    }

    return Narrow(buf);
}

bool EnumRegistrySubkeys(HKEY root, const std::wstring& subKey, const std::function<void(HKEY, const std::wstring&)>& callback) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    wchar_t name[256]{};
    DWORD index = 0;
    DWORD nameSize = static_cast<DWORD>(std::size(name));
    while (RegEnumKeyExW(hKey, index, name, &nameSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        HKEY child = nullptr;
        if (RegOpenKeyExW(hKey, name, 0, KEY_READ | KEY_WOW64_64KEY, &child) == ERROR_SUCCESS) {
            callback(child, name);
            RegCloseKey(child);
        }

        ++index;
        nameSize = static_cast<DWORD>(std::size(name));
    }

    RegCloseKey(hKey);
    return true;
}

std::string ReadOpenSubkeyString(HKEY hKey, const std::wstring& valueName) {
    wchar_t buf[2048]{};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    if (RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type, reinterpret_cast<BYTE*>(buf), &size) != ERROR_SUCCESS) {
        return {};
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        return {};
    }
    return Narrow(buf);
}

bool ReadOpenSubkeyDword(HKEY hKey, const std::wstring& valueName, DWORD& value) {
    DWORD size = sizeof(value);
    DWORD type = 0;
    return RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type, reinterpret_cast<BYTE*>(&value), &size) == ERROR_SUCCESS &&
           type == REG_DWORD;
}

RegistryCounts GetRegistryCounts(HKEY root, const std::wstring& subKey) {
    RegistryCounts counts;
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) {
        return counts;
    }

    counts.opened = true;
    RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &counts.subkeyCount, nullptr, nullptr,
        &counts.valueCount, nullptr, nullptr, nullptr, nullptr);
    RegCloseKey(hKey);
    return counts;
}

CommandResult CaptureCommandResult(const std::wstring& commandLine, DWORD timeoutMs = 15000) {
    CommandResult result;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        return result;
    }
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');

    if (!CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(writePipe);
        CloseHandle(readPipe);
        return result;
    }

    result.started = true;
    CloseHandle(writePipe);

    DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (waitResult == WAIT_TIMEOUT) {
        result.timedOut = true;
        TerminateProcess(pi.hProcess, 1);
    }
    GetExitCodeProcess(pi.hProcess, &result.exitCode);

    char buffer[4096];
    DWORD bytesRead = 0;
    while (ReadFile(readPipe, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
        result.output.append(buffer, bytesRead);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(readPipe);
    result.output = Trim(result.output);
    return result;
}

std::string CaptureCommand(const std::wstring& commandLine, DWORD timeoutMs = 15000) {
    return CaptureCommandResult(commandLine, timeoutMs).output;
}

std::vector<std::string> SplitLines(const std::string& value) {
    std::vector<std::string> lines;
    std::istringstream input(value);
    std::string line;
    while (std::getline(input, line)) {
        line = Trim(line);
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    return lines;
}

std::string StripWmicValue(const std::string& value) {
    auto lines = SplitLines(value);
    for (const auto& line : lines) {
        size_t eq = line.find('=');
        if (eq != std::string::npos && eq + 1 < line.size()) {
            return Trim(line.substr(eq + 1));
        }
        if (line.find("SerialNumber") == std::string::npos &&
            line.find("UUID") == std::string::npos &&
            line.find("PNPDeviceID") == std::string::npos) {
            return line;
        }
    }
    return {};
}

bool CommandUnavailable(const CommandResult& result) {
    return !result.started || result.timedOut || LooksLikeCollectorFailure(result.output);
}

void AddFinding(CollectorResult& collector, const std::string& surface, const std::string& identifierType,
    const std::string& risk, const std::string& value, const std::string& source, const std::string& recommendation,
    bool sensitive = true) {
    std::string clean = Trim(value);
    if (clean.empty() || LooksLikeCollectorFailure(clean)) {
        return;
    }

    collector.findings.push_back({
        surface,
        identifierType,
        risk,
        sensitive ? Redact(clean) : clean,
        clean,
        source,
        recommendation,
        sensitive,
    });
}

CollectorResult MakeCollector(const std::string& name) {
    CollectorResult result;
    result.name = name;
    result.status = "error";
    result.message = "Collector did not complete.";
    return result;
}

void SetStatus(CollectorResult& result, const std::string& status, const std::string& message) {
    result.status = status;
    result.message = message;
}

CollectorResult CollectMachineGuid() {
    auto result = MakeCollector("MachineGuid");
    AddFinding(result,
        "Windows registry",
        "MachineGuid",
        "high",
        ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid"),
        "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid",
        "Treat MachineGuid as a stable cross-application identifier; avoid exposing it to apps unless strictly required.");
    SetStatus(result, result.findings.empty() ? "unavailable" : "ok",
        result.findings.empty() ? "MachineGuid value was not readable." : "MachineGuid value was detected.");
    return result;
}

CollectorResult CollectHardwareProfileGuid() {
    auto result = MakeCollector("Hardware profile GUID");
    std::string value = ReadRegistryString(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", L"HwProfileGuid");
    if (value.empty()) {
        value = ReadRegistryString(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current", L"HwProfileGuid");
    }

    AddFinding(result,
        "Windows registry",
        "Hardware profile GUID",
        "high",
        value,
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles",
        "Treat hardware profile GUIDs as stable OS hardware identity data and avoid exposing them to application logs.");
    SetStatus(result, result.findings.empty() ? "unavailable" : "ok",
        result.findings.empty() ? "Hardware profile GUID was not readable." : "Hardware profile GUID was detected.");
    return result;
}

CollectorResult CollectComputerName() {
    auto result = MakeCollector("Computer name");
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(name, &size)) {
        SetStatus(result, "error", "GetComputerNameW failed.");
        return result;
    }

    AddFinding(result,
        "Windows identity",
        "Computer name",
        "medium",
        Narrow(name),
        "GetComputerNameW",
        "Avoid embedding personal names or account details in the device name.");
    SetStatus(result, "ok", "Computer name was detected.");
    return result;
}

CollectorResult CollectMacs() {
    auto result = MakeCollector("MAC addresses");
    CommandResult command = CaptureCommandResult(L"getmac /fo csv /nh");
    if (CommandUnavailable(command)) {
        SetStatus(result, "unavailable", "getmac output was not available.");
        return result;
    }

    for (const auto& line : SplitLines(command.output)) {
        if (line.find("Media disconnected") != std::string::npos) {
            continue;
        }
        AddFinding(result,
            "Network adapters",
            "MAC address",
            "high",
            line,
            "getmac /fo csv /nh",
            "Use OS network randomization where appropriate and avoid sharing raw MAC values with applications.");
    }

    SetStatus(result, result.findings.empty() ? "unavailable" : "ok",
        result.findings.empty() ? "No active MAC addresses were returned by getmac." : "Active MAC address rows were detected.");
    return result;
}

CollectorResult CollectNetworkState() {
    auto result = MakeCollector("Network adapter state");
    const std::wstring classKey = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
    int overrideCount = 0;
    bool classOpened = EnumRegistrySubkeys(HKEY_LOCAL_MACHINE, classKey, [&](HKEY adapterKey, const std::wstring&) {
        std::string overrideValue = ReadOpenSubkeyString(adapterKey, L"NetworkAddress");
        if (overrideValue.empty()) {
            return;
        }

        ++overrideCount;
        std::string desc = ReadOpenSubkeyString(adapterKey, L"DriverDesc");
        AddFinding(result,
            "Network adapters",
            "NetworkAddress override",
            "medium",
            desc.empty() ? overrideValue : (desc + " " + overrideValue),
            "HKLM network adapter class NetworkAddress",
            "Document adapter override values and keep them compartment-specific when used for privacy testing.");
    });

    if (classOpened && overrideCount == 0) {
        AddFinding(result,
            "Network adapters",
            "NetworkAddress override state",
            "low",
            "No registry-level adapter override values found",
            "HKLM network adapter class NetworkAddress",
            "No adapter override values were detected by this read-only scan.",
            false);
    }

    int randomizationStateCount = 0;
    bool wlanOpened = EnumRegistrySubkeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\WlanSvc\\Interfaces",
        [&](HKEY interfaceKey, const std::wstring&) {
            DWORD state = 0;
            if (!ReadOpenSubkeyDword(interfaceKey, L"RandomMacState", state)) {
                return;
            }
            ++randomizationStateCount;
            AddFinding(result,
                "Network adapters",
                "MAC randomization state",
                "low",
                "RandomMacState=" + std::to_string(state),
                "HKLM\\SOFTWARE\\Microsoft\\WlanSvc\\Interfaces",
                "Review per-network randomization policy for Wi-Fi contexts where stable MAC exposure is unnecessary.",
                false);
        });

    if (classOpened || wlanOpened) {
        SetStatus(result, classOpened ? "ok" : "partial",
            "Adapter override entries=" + std::to_string(overrideCount) +
            "; randomization state entries=" + std::to_string(randomizationStateCount) + ".");
    } else {
        SetStatus(result, "unavailable", "Network adapter registry state was not readable.");
    }
    return result;
}

CollectorResult CollectDiskSerials() {
    auto result = MakeCollector("Disk serials");
    CommandResult command = CaptureCommandResult(
        L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Get-CimInstance Win32_DiskDrive | ForEach-Object { $_.SerialNumber }\"");
    if (CommandUnavailable(command) || command.output.empty()) {
        command = CaptureCommandResult(L"wmic diskdrive get serialnumber /value");
    }

    if (CommandUnavailable(command) || command.output.empty()) {
        SetStatus(result, "unavailable", "Disk serial query did not return readable output.");
        return result;
    }

    for (const auto& line : SplitLines(command.output)) {
        std::string value = StripWmicValue(line);
        if (!value.empty() && value.find("SerialNumber") == std::string::npos) {
            AddFinding(result,
                "Storage",
                "Disk serial",
                "high",
                value,
                "Win32_DiskDrive",
                "Treat disk serials as stable identifiers; prefer app sandboxes that do not expose storage hardware IDs.");
        }
    }

    SetStatus(result, result.findings.empty() ? "unavailable" : "ok",
        result.findings.empty() ? "No disk serial values were returned." : "Disk serial values were detected.");
    return result;
}

CollectorResult CollectSmbios() {
    auto result = MakeCollector("SMBIOS");
    struct SmbiosQuery {
        const wchar_t* cimCommand;
        const wchar_t* wmicCommand;
        const char* type;
    };

    const std::array<SmbiosQuery, 3> queries = {{
        {
            L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"(Get-CimInstance Win32_BIOS).SerialNumber\"",
            L"wmic bios get serialnumber /value",
            "BIOS serial",
        },
        {
            L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"(Get-CimInstance Win32_ComputerSystemProduct).UUID\"",
            L"wmic csproduct get uuid /value",
            "System UUID",
        },
        {
            L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"(Get-CimInstance Win32_BaseBoard).SerialNumber\"",
            L"wmic baseboard get serialnumber /value",
            "Baseboard serial",
        },
    }};

    int attempted = 0;
    for (const auto& query : queries) {
        ++attempted;
        std::string value = StripWmicValue(CaptureCommand(query.cimCommand));
        if (value.empty() || LooksLikeCollectorFailure(value)) {
            value = StripWmicValue(CaptureCommand(query.wmicCommand));
        }
        AddFinding(result,
            "SMBIOS",
            query.type,
            "high",
            value,
            "PowerShell/CIM SMBIOS query",
            "Minimize application access to SMBIOS data and keep full values out of logs and support bundles.");
    }

    if (result.findings.empty()) {
        AddFinding(result,
            "SMBIOS",
            "SMBIOS availability",
            "low",
            "No SMBIOS serial or UUID values returned by read-only WMI/CIM queries",
            "PowerShell/CIM SMBIOS query",
            "The scan did not receive SMBIOS values; retry from a standard desktop session if this was unexpected.",
            false);
        SetStatus(result, "unavailable", "No SMBIOS serial or UUID values were returned.");
    } else {
        SetStatus(result, result.findings.size() < static_cast<size_t>(attempted) ? "partial" : "ok",
            "SMBIOS values detected=" + std::to_string(result.findings.size()) + " of " + std::to_string(attempted) + ".");
    }
    return result;
}

CollectorResult CollectTpmMetadata() {
    auto result = MakeCollector("TPM metadata");
    CommandResult command = CaptureCommandResult(
        L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Get-CimInstance -Namespace root\\cimv2\\Security\\MicrosoftTpm -ClassName Win32_Tpm | ForEach-Object { 'ManufacturerId=' + [string]($_.ManufacturerId); 'ManufacturerVersion=' + [string]($_.ManufacturerVersion); 'ManufacturerVersionInfo=' + [string]($_.ManufacturerVersionInfo); 'SpecVersion=' + [string]($_.SpecVersion); 'Enabled=' + [string]($_.IsEnabled_InitialValue); 'Activated=' + [string]($_.IsActivated_InitialValue) }\"");

    if (CommandUnavailable(command) || command.output.empty()) {
        AddFinding(result,
            "TPM",
            "TPM presence",
            "low",
            "No TPM metadata returned by Win32_Tpm",
            "Win32_Tpm metadata query",
            "No TPM metadata was detected by this read-only scan.",
            false);
        SetStatus(result, "unavailable", "Win32_Tpm metadata was not available.");
        return result;
    }

    for (const auto& line : SplitLines(command.output)) {
        AddFinding(result,
            "TPM",
            "TPM metadata",
            "medium",
            line,
            "Win32_Tpm metadata query",
            "Treat TPM manufacturer and specification details as fingerprinting metadata; never export TPM keys or secrets.");
    }

    SetStatus(result, result.findings.empty() ? "unavailable" : "ok",
        result.findings.empty() ? "TPM metadata output contained no usable values." : "TPM metadata values were detected.");
    return result;
}

CollectorResult CollectGpu() {
    auto result = MakeCollector("GPU identifiers");
    CommandResult command = CaptureCommandResult(
        L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Get-CimInstance Win32_VideoController | ForEach-Object { $_.Name + ' | ' + $_.PNPDeviceID }\"");

    if (CommandUnavailable(command) || command.output.empty()) {
        SetStatus(result, "unavailable", "GPU query did not return readable output.");
        return result;
    }

    for (const auto& line : SplitLines(command.output)) {
        AddFinding(result,
            "Graphics",
            "GPU identifier",
            "medium",
            line,
            "Win32_VideoController",
            "Browser and graphics APIs can increase fingerprint entropy; prefer hardened browser profiles for untrusted sites.");
    }

    SetStatus(result, result.findings.empty() ? "unavailable" : "ok",
        result.findings.empty() ? "No GPU identifiers were returned." : "GPU identifiers were detected.");
    return result;
}

CollectorResult CollectEdid() {
    auto result = MakeCollector("Monitor EDID");
    int count = 0;
    bool opened = EnumRegistrySubkeys(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY",
        [&](HKEY vendorKey, const std::wstring& vendorName) {
            wchar_t childName[256]{};
            DWORD index = 0;
            DWORD childSize = static_cast<DWORD>(std::size(childName));
            while (RegEnumKeyExW(vendorKey, index, childName, &childSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                ++count;
                AddFinding(result,
                    "Display",
                    "Monitor EDID presence",
                    "medium",
                    Narrow(vendorName + L"\\" + childName),
                    "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY",
                    "Monitor EDID data can add display fingerprint entropy; avoid exposing it to untrusted contexts.");
                ++index;
                childSize = static_cast<DWORD>(std::size(childName));
            }
        });

    if (!opened) {
        SetStatus(result, "unavailable", "Display registry enumeration was not available.");
        return result;
    }

    if (count == 0) {
        AddFinding(result,
            "Display",
            "Monitor EDID presence",
            "low",
            "No monitor EDID registry entries found",
            "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY",
            "No display EDID entries were detected by this read-only scan.",
            false);
    }
    SetStatus(result, "ok", "Monitor EDID entries detected=" + std::to_string(count) + ".");
    return result;
}

CollectorResult CollectBrowserHints() {
    auto result = MakeCollector("Browser fingerprint hints");
    const std::array<std::pair<const wchar_t*, const char*>, 4> browsers = {{
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe", "Google Chrome" },
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe", "Microsoft Edge" },
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe", "Mozilla Firefox" },
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\brave.exe", "Brave" },
    }};

    int appPathCount = 0;
    for (const auto& [key, name] : browsers) {
        std::string path = ReadRegistryString(HKEY_LOCAL_MACHINE, key, L"");
        if (path.empty()) {
            path = ReadRegistryString(HKEY_CURRENT_USER, key, L"");
        }
        if (!path.empty()) {
            ++appPathCount;
            AddFinding(result,
                "Browser",
                "Browser fingerprint surface",
                "medium",
                std::string(name) + " " + path,
                "App Paths registry",
                "Use hardened browser profiles and extension policies to reduce canvas, WebGL, font, and device API entropy.");
        }
    }

    struct PolicyKey {
        HKEY root;
        const wchar_t* path;
        const char* name;
    };
    const std::array<PolicyKey, 8> policyKeys = {{
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Google\\Chrome", "Google Chrome machine policy" },
        { HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\Google\\Chrome", "Google Chrome user policy" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Edge", "Microsoft Edge machine policy" },
        { HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\Microsoft\\Edge", "Microsoft Edge user policy" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Mozilla\\Firefox", "Mozilla Firefox machine policy" },
        { HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\Mozilla\\Firefox", "Mozilla Firefox user policy" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\BraveSoftware\\Brave", "Brave machine policy" },
        { HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\BraveSoftware\\Brave", "Brave user policy" },
    }};

    int policyCount = 0;
    for (const auto& policy : policyKeys) {
        RegistryCounts counts = GetRegistryCounts(policy.root, policy.path);
        if (!counts.opened) {
            continue;
        }

        ++policyCount;
        AddFinding(result,
            "Browser",
            "Browser policy hint",
            "low",
            std::string(policy.name) + " present; values=" + std::to_string(counts.valueCount) +
                "; subkeys=" + std::to_string(counts.subkeyCount),
            "Browser policy registry",
            "Review browser policies for fingerprinting controls such as WebGL, extensions, privacy sandbox, and device API exposure.",
            false);
    }

    if (result.findings.empty()) {
        SetStatus(result, "unavailable", "No supported browser app paths or policy keys were detected.");
    } else {
        SetStatus(result, "ok", "Browser app paths=" + std::to_string(appPathCount) +
            "; policy keys=" + std::to_string(policyCount) + ".");
    }
    return result;
}

CollectorResult SafeCollect(const std::string& name, const std::function<CollectorResult()>& fn) {
    try {
        return fn();
    } catch (const std::exception& e) {
        auto result = MakeCollector(name);
        SetStatus(result, "error", e.what());
        return result;
    } catch (...) {
        auto result = MakeCollector(name);
        SetStatus(result, "error", "Unhandled collector exception.");
        return result;
    }
}

std::map<std::string, int> RiskCounts(const std::vector<Finding>& findings) {
    std::map<std::string, int> counts = { {"low", 0}, {"medium", 0}, {"high", 0} };
    for (const auto& finding : findings) {
        counts[finding.risk]++;
    }
    return counts;
}

std::map<std::string, int> CollectorCounts(const std::vector<CollectorResult>& collectors) {
    std::map<std::string, int> counts = { {"ok", 0}, {"partial", 0}, {"unavailable", 0}, {"error", 0} };
    for (const auto& collector : collectors) {
        counts[collector.status]++;
    }
    return counts;
}

fs::path ResolveOutputBase(const PrivacyAuditOptions& options, const std::string& stamp) {
    if (options.outputPath.empty()) {
        return options.workDir / ("privacy_audit_" + stamp);
    }

    fs::path p = options.outputPath;
    if (p.is_relative()) {
        p = options.workDir / p;
    }

    if ((fs::exists(p) && fs::is_directory(p)) || p.extension().empty()) {
        return p / ("privacy_audit_" + stamp);
    }

    return p.parent_path() / p.stem();
}

std::string BuildTextReport(const AuditContext& context, const std::vector<Finding>& findings,
    const std::map<std::string, int>& counts, const std::map<std::string, int>& collectorCounts,
    const std::vector<CollectorResult>& collectors) {
    std::ostringstream f;
    f << "Windows Hardware Privacy Audit\n";
    f << "Schema Version: " << kSchemaVersion << "\n";
    f << "Run ID: " << context.runId << "\n";
    f << "Created: " << context.createdAt << "\n";
    f << "Mode: redacted snapshot\n";
    f << "Tool: DmiUpdater privacy-audit v2\n\n";
    f << "Risk summary: high=" << counts.at("high")
      << ", medium=" << counts.at("medium")
      << ", low=" << counts.at("low") << "\n";
    f << "Collector summary: ok=" << collectorCounts.at("ok")
      << ", partial=" << collectorCounts.at("partial")
      << ", unavailable=" << collectorCounts.at("unavailable")
      << ", error=" << collectorCounts.at("error") << "\n\n";

    f << "Collectors:\n";
    for (const auto& collector : collectors) {
        f << "- " << collector.name << ": " << collector.status
          << " (" << collector.findings.size() << " finding";
        if (collector.findings.size() != 1) {
            f << "s";
        }
        f << ") - " << collector.message << "\n";
    }
    f << "\n";

    const std::array<std::string, 3> order = { "high", "medium", "low" };
    for (const auto& risk : order) {
        f << "[" << risk << "]\n";
        bool any = false;
        for (const auto& finding : findings) {
            if (finding.risk != risk) continue;
            any = true;
            f << "- " << finding.surface << " / " << finding.identifierType << "\n"
              << "  sample: " << finding.redactedSample << "\n"
              << "  source: " << finding.evidenceSource << "\n"
              << "  recommendation: " << finding.recommendation << "\n";
        }
        if (!any) {
            f << "- none\n";
        }
        f << "\n";
    }

    return f.str();
}

std::string BuildJsonReport(const AuditContext& context, const std::vector<Finding>& findings,
    const std::map<std::string, int>& counts, const std::map<std::string, int>& collectorCounts,
    const std::vector<CollectorResult>& collectors, bool includeFullValues) {
    std::ostringstream f;
    f << "{\n";
    f << "  \"schemaVersion\": " << kSchemaVersion << ",\n";
    f << "  \"runId\": \"" << JsonEscape(context.runId) << "\",\n";
    f << "  \"createdAt\": \"" << JsonEscape(context.createdAt) << "\",\n";
    f << "  \"mode\": \"" << (includeFullValues ? "full-local-export" : "redacted-snapshot") << "\",\n";
    f << "  \"tool\": {\n";
    f << "    \"name\": \"DmiUpdater\",\n";
    f << "    \"component\": \"privacy-audit\",\n";
    f << "    \"version\": \"2\"\n";
    f << "  },\n";
    f << "  \"riskSummary\": {\n";
    f << "    \"high\": " << counts.at("high") << ",\n";
    f << "    \"medium\": " << counts.at("medium") << ",\n";
    f << "    \"low\": " << counts.at("low") << "\n";
    f << "  },\n";
    f << "  \"collectorSummary\": {\n";
    f << "    \"ok\": " << collectorCounts.at("ok") << ",\n";
    f << "    \"partial\": " << collectorCounts.at("partial") << ",\n";
    f << "    \"unavailable\": " << collectorCounts.at("unavailable") << ",\n";
    f << "    \"error\": " << collectorCounts.at("error") << "\n";
    f << "  },\n";
    f << "  \"collectorStatus\": [\n";
    for (size_t i = 0; i < collectors.size(); ++i) {
        const auto& collector = collectors[i];
        f << "    {\n";
        f << "      \"collector\": \"" << JsonEscape(collector.name) << "\",\n";
        f << "      \"status\": \"" << JsonEscape(collector.status) << "\",\n";
        f << "      \"message\": \"" << JsonEscape(collector.message) << "\",\n";
        f << "      \"findingCount\": " << collector.findings.size() << "\n";
        f << "    }" << (i + 1 == collectors.size() ? "\n" : ",\n");
    }
    f << "  ],\n";
    f << "  \"findings\": [\n";

    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& finding = findings[i];
        f << "    {\n";
        f << "      \"surface\": \"" << JsonEscape(finding.surface) << "\",\n";
        f << "      \"identifierType\": \"" << JsonEscape(finding.identifierType) << "\",\n";
        f << "      \"risk\": \"" << JsonEscape(finding.risk) << "\",\n";
        f << "      \"redactedSample\": \"" << JsonEscape(finding.redactedSample) << "\",\n";
        if (includeFullValues) {
            f << "      \"fullValue\": \"" << JsonEscape(finding.fullValue) << "\",\n";
        }
        f << "      \"evidenceSource\": \"" << JsonEscape(finding.evidenceSource) << "\",\n";
        f << "      \"recommendation\": \"" << JsonEscape(finding.recommendation) << "\"\n";
        f << "    }" << (i + 1 == findings.size() ? "\n" : ",\n");
    }

    f << "  ]\n";
    f << "}\n";
    return f.str();
}

std::vector<std::string> SensitiveLeakTokens(const Finding& finding) {
    std::vector<std::string> tokens;
    std::string full = Trim(finding.fullValue);
    if (full.size() >= 8) {
        tokens.push_back(full);
    }

    std::string token;
    auto flush = [&]() {
        token = Trim(token);
        if (token.size() >= 8) {
            tokens.push_back(token);
        }
        token.clear();
    };

    for (char ch : full) {
        if (ch == ',' || ch == ';' || ch == '|' || ch == '"' || ch == '\'' || ch == '\r' || ch == '\n' || ch == '\t') {
            flush();
        } else {
            token.push_back(ch);
        }
    }
    flush();

    std::sort(tokens.begin(), tokens.end());
    tokens.erase(std::unique(tokens.begin(), tokens.end()), tokens.end());
    return tokens;
}

bool ValidateNoSensitiveLeaks(const std::string& content, const std::vector<Finding>& findings, std::string& detail) {
    for (const auto& finding : findings) {
        if (!finding.sensitive) {
            continue;
        }

        for (const auto& token : SensitiveLeakTokens(finding)) {
            if (content.find(token) != std::string::npos) {
                detail = finding.identifierType + " token appeared in a redacted report.";
                return false;
            }
        }
    }
    return true;
}

bool WriteStringFile(const fs::path& path, const std::string& content) {
    std::ofstream f(path, std::ios::binary);
    if (!f.is_open()) {
        return false;
    }
    f << content;
    return f.good();
}

bool ComputeSha256(const fs::path& path, std::string& hash, std::string& error) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        error = "cannot open file";
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

    char buffer[8192];
    while (f.good()) {
        f.read(buffer, sizeof(buffer));
        std::streamsize bytesRead = f.gcount();
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

    hash = BytesToHex(digest.data(), digest.size());
    return true;
}

bool WriteManifest(const fs::path& path, const AuditContext& context, const std::vector<std::pair<std::string, fs::path>>& files,
    bool containsFullExport, std::string& error) {
    struct ManifestFile {
        std::string role;
        fs::path path;
        unsigned long long size = 0;
        std::string sha256;
    };

    std::vector<ManifestFile> manifestFiles;
    for (const auto& [role, filePath] : files) {
        ManifestFile entry;
        entry.role = role;
        entry.path = filePath;

        try {
            entry.size = static_cast<unsigned long long>(fs::file_size(filePath));
        } catch (...) {
            error = "cannot read file size for " + filePath.string();
            return false;
        }

        if (!ComputeSha256(filePath, entry.sha256, error)) {
            error = "cannot hash " + filePath.string() + ": " + error;
            return false;
        }
        manifestFiles.push_back(entry);
    }

    std::ostringstream f;
    f << "{\n";
    f << "  \"schemaVersion\": " << kSchemaVersion << ",\n";
    f << "  \"runId\": \"" << JsonEscape(context.runId) << "\",\n";
    f << "  \"createdAt\": \"" << JsonEscape(context.createdAt) << "\",\n";
    f << "  \"tool\": {\n";
    f << "    \"name\": \"DmiUpdater\",\n";
    f << "    \"component\": \"privacy-audit\",\n";
    f << "    \"version\": \"2\"\n";
    f << "  },\n";
    f << "  \"containsFullExport\": " << (containsFullExport ? "true" : "false") << ",\n";
    f << "  \"files\": [\n";
    for (size_t i = 0; i < manifestFiles.size(); ++i) {
        const auto& entry = manifestFiles[i];
        f << "    {\n";
        f << "      \"role\": \"" << JsonEscape(entry.role) << "\",\n";
        f << "      \"path\": \"" << JsonEscape(entry.path.string()) << "\",\n";
        f << "      \"fileName\": \"" << JsonEscape(entry.path.filename().string()) << "\",\n";
        f << "      \"size\": " << entry.size << ",\n";
        f << "      \"sha256\": \"" << JsonEscape(entry.sha256) << "\"\n";
        f << "    }" << (i + 1 == manifestFiles.size() ? "\n" : ",\n");
    }
    f << "  ]\n";
    f << "}\n";

    if (!WriteStringFile(path, f.str())) {
        error = "cannot write manifest";
        return false;
    }
    return true;
}

void AppendPrivacyHistory(const fs::path& workDir, const PrivacyAuditResult& result) {
    std::ofstream f(workDir / "history.log", std::ios::app);
    if (!f.is_open()) {
        return;
    }

    f << TimestampIso()
      << " | PRIVACY-AUDIT"
      << " | schema:" << kSchemaVersion
      << " | high:" << result.highCount
      << " | medium:" << result.mediumCount
      << " | low:" << result.lowCount
      << " | collectors:ok=" << result.collectorOkCount
      << ",partial=" << result.collectorPartialCount
      << ",unavailable=" << result.collectorUnavailableCount
      << ",error=" << result.collectorErrorCount
      << " | report:" << result.jsonReportPath.filename().string()
      << " | manifest:" << result.manifestPath.filename().string()
      << "\n";
}

} // namespace

PrivacyAuditResult RunPrivacyAudit(const PrivacyAuditOptions& options) {
    PrivacyAuditResult result;
    AuditContext context{ GenerateRunId(), TimestampIso() };

    std::vector<CollectorResult> collectors;
    collectors.push_back(SafeCollect("MachineGuid", CollectMachineGuid));
    collectors.push_back(SafeCollect("Hardware profile GUID", CollectHardwareProfileGuid));
    collectors.push_back(SafeCollect("Computer name", CollectComputerName));
    collectors.push_back(SafeCollect("MAC addresses", CollectMacs));
    collectors.push_back(SafeCollect("Network adapter state", CollectNetworkState));
    collectors.push_back(SafeCollect("Disk serials", CollectDiskSerials));
    collectors.push_back(SafeCollect("SMBIOS", CollectSmbios));
    collectors.push_back(SafeCollect("TPM metadata", CollectTpmMetadata));
    collectors.push_back(SafeCollect("GPU identifiers", CollectGpu));
    collectors.push_back(SafeCollect("Monitor EDID", CollectEdid));
    collectors.push_back(SafeCollect("Browser fingerprint hints", CollectBrowserHints));

    std::vector<Finding> findings;
    for (const auto& collector : collectors) {
        findings.insert(findings.end(), collector.findings.begin(), collector.findings.end());
    }

    auto counts = RiskCounts(findings);
    auto collectorCounts = CollectorCounts(collectors);
    result.highCount = counts["high"];
    result.mediumCount = counts["medium"];
    result.lowCount = counts["low"];
    result.collectorOkCount = collectorCounts["ok"];
    result.collectorPartialCount = collectorCounts["partial"];
    result.collectorUnavailableCount = collectorCounts["unavailable"];
    result.collectorErrorCount = collectorCounts["error"];

    std::string stamp = TimestampForFile();
    fs::path base = ResolveOutputBase(options, stamp);

    try {
        if (!base.parent_path().empty()) {
            fs::create_directories(base.parent_path());
        }
    } catch (const std::exception& e) {
        result.errorMessage = e.what();
        return result;
    } catch (...) {
        result.errorMessage = "failed to create output directory";
        return result;
    }

    result.textReportPath = base;
    result.textReportPath += ".txt";
    result.jsonReportPath = base;
    result.jsonReportPath += ".json";
    result.manifestPath = base;
    result.manifestPath += "_manifest.json";

    std::string textReport = BuildTextReport(context, findings, counts, collectorCounts, collectors);
    std::string jsonReport = BuildJsonReport(context, findings, counts, collectorCounts, collectors, false);

    std::string leakDetail;
    if (!ValidateNoSensitiveLeaks(textReport, findings, leakDetail) ||
        !ValidateNoSensitiveLeaks(jsonReport, findings, leakDetail)) {
        result.errorMessage = "redaction self-check failed: " + leakDetail;
        return result;
    }

    if (!WriteStringFile(result.textReportPath, textReport)) {
        result.errorMessage = "failed to write text report";
        return result;
    }
    if (!WriteStringFile(result.jsonReportPath, jsonReport)) {
        result.errorMessage = "failed to write JSON report";
        return result;
    }

    std::vector<std::pair<std::string, fs::path>> manifestFiles = {
        { "text-report", result.textReportPath },
        { "redacted-json", result.jsonReportPath },
    };

    if (options.fullExport) {
        result.fullExportPath = base;
        result.fullExportPath += "_full.json";
        std::string fullJsonReport = BuildJsonReport(context, findings, counts, collectorCounts, collectors, true);
        if (!WriteStringFile(result.fullExportPath, fullJsonReport)) {
            result.errorMessage = "failed to write full export";
            return result;
        }
        manifestFiles.push_back({ "full-export-json", result.fullExportPath });
    }

    std::string manifestError;
    if (!WriteManifest(result.manifestPath, context, manifestFiles, options.fullExport, manifestError)) {
        result.errorMessage = manifestError;
        return result;
    }

    result.ok = true;
    AppendPrivacyHistory(options.workDir, result);
    return result;
}
