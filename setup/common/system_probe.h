#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "setup_common.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace SetupProbe {

struct CommandResult {
    bool started = false;
    DWORD exitCode = 1;
    DWORD errorCode = 0;
    std::string output;
};

struct TpmProbe {
    std::string present = "unknown";
    std::string ready = "unknown";
    std::string enabled = "unknown";
    std::string activated = "unknown";
    std::string managedAuthLevel;
    std::string error;
};

struct SecureBootProbe {
    std::string firmwareType = "unknown";
    std::string state = "unknown";
};

struct BitLockerVolumeProbe {
    std::string mountPoint;
    std::string protectionStatus;
    std::string volumeStatus;
    std::string encryptionMethod;
};

struct SecurityProbe {
    TpmProbe tpm;
    SecureBootProbe secureBoot;
    std::vector<BitLockerVolumeProbe> bitLockerVolumes;
};

struct ControllerProbe {
    std::string name;
    std::string manufacturer;
    std::string driverName;
    std::string inferredMode;
};

struct DiskProbe {
    std::string friendlyName;
    std::string serialNumber;
    std::string busType;
    std::string mediaType;
    std::string healthStatus;
    std::string sizeBytes;
};

struct StoragePoolProbe {
    std::string friendlyName;
    std::string operationalStatus;
    std::string healthStatus;
    std::string resiliency;
};

struct StorageProbe {
    std::vector<ControllerProbe> controllers;
    std::vector<DiskProbe> disks;
    std::vector<StoragePoolProbe> pools;
    bool raidDetected = false;
    bool vmdDetected = false;
    bool storageSpacesDetected = false;
    std::string error;
};

inline std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    int needed = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (needed <= 0) {
        return {};
    }
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), needed);
    return out;
}

inline std::string WideToUtf8(const wchar_t* value, int length) {
    if (value == nullptr || length <= 0) {
        return {};
    }
    int needed = WideCharToMultiByte(CP_UTF8, 0, value, length, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, length, out.data(), needed, nullptr, nullptr);
    return out;
}

inline std::string Trim(std::string value) {
    auto isSpace = [](unsigned char ch) { return std::isspace(ch) != 0; };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [&](unsigned char ch) {
        return !isSpace(ch);
    }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [&](unsigned char ch) {
        return !isSpace(ch);
    }).base(), value.end());
    return value;
}

inline std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

inline bool ContainsCi(const std::string& value, const std::string& needle) {
    return Lower(value).find(Lower(needle)) != std::string::npos;
}

inline std::vector<std::string> Split(const std::string& value, char delimiter) {
    std::vector<std::string> parts;
    std::stringstream stream(value);
    std::string part;
    while (std::getline(stream, part, delimiter)) {
        parts.push_back(Trim(part));
    }
    return parts;
}

inline std::vector<std::string> Lines(const std::string& value) {
    std::vector<std::string> lines;
    std::stringstream stream(value);
    std::string line;
    while (std::getline(stream, line)) {
        line = Trim(line);
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    return lines;
}

inline CommandResult CaptureCommand(const std::wstring& commandLine) {
    CommandResult result;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        result.errorCode = GetLastError();
        return result;
    }
    if (!SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0)) {
        result.errorCode = GetLastError();
        CloseHandle(readPipe);
        CloseHandle(writePipe);
        return result;
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = writePipe;
    startup.hStdError = writePipe;

    PROCESS_INFORMATION process{};
    std::vector<wchar_t> command(commandLine.begin(), commandLine.end());
    command.push_back(L'\0');

    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
        result.errorCode = GetLastError();
        CloseHandle(readPipe);
        CloseHandle(writePipe);
        return result;
    }

    result.started = true;
    CloseHandle(writePipe);

    char buffer[4096]{};
    DWORD bytesRead = 0;
    while (ReadFile(readPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        result.output += buffer;
    }

    WaitForSingleObject(process.hProcess, INFINITE);
    GetExitCodeProcess(process.hProcess, &result.exitCode);

    CloseHandle(process.hProcess);
    CloseHandle(process.hThread);
    CloseHandle(readPipe);
    return result;
}

inline CommandResult CapturePowerShell(const std::string& script) {
    std::wstring wideScript = Utf8ToWide(script);
    std::wstring command = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ";
    command += L"\"";
    for (wchar_t ch : wideScript) {
        if (ch == L'"') {
            command += L'\\';
        }
        command += ch;
    }
    command += L"\"";
    return CaptureCommand(command);
}

inline std::string FirmwareTypeText() {
    FIRMWARE_TYPE type = FirmwareTypeUnknown;
    if (!GetFirmwareType(&type)) {
        return "unknown";
    }
    switch (type) {
        case FirmwareTypeBios: return "legacy BIOS";
        case FirmwareTypeUefi: return "UEFI";
        case FirmwareTypeMax: break;
        case FirmwareTypeUnknown: break;
    }
    return "unknown";
}

inline std::string SecureBootText() {
    HKEY key = nullptr;
    const wchar_t* subKey = L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State";
    LONG openStatus = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &key);
    if (openStatus != ERROR_SUCCESS) {
        return "unknown";
    }

    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = REG_NONE;
    LONG queryStatus = RegQueryValueExW(key, L"UEFISecureBootEnabled", nullptr, &type,
        reinterpret_cast<BYTE*>(&value), &size);
    RegCloseKey(key);

    if (queryStatus != ERROR_SUCCESS || type != REG_DWORD) {
        return "unknown";
    }
    return value == 0 ? "disabled" : "enabled";
}

inline std::map<std::string, std::string> ParseKeyValues(const std::string& output) {
    std::map<std::string, std::string> values;
    for (const auto& line : Lines(output)) {
        size_t equals = line.find('=');
        if (equals == std::string::npos) {
            continue;
        }
        values[Trim(line.substr(0, equals))] = Trim(line.substr(equals + 1));
    }
    return values;
}

inline std::string ProbeValueOrUnknown(const std::map<std::string, std::string>& values, const std::string& key) {
    auto it = values.find(key);
    if (it == values.end() || Trim(it->second).empty()) {
        return "unknown";
    }
    return Trim(it->second);
}

inline void ApplyTpmKeyValues(TpmProbe& probe, const std::map<std::string, std::string>& values) {
    if (values.count("Error") > 0 && !Trim(values.at("Error")).empty()) {
        probe.error = Trim(values.at("Error"));
    }
    probe.present = ProbeValueOrUnknown(values, "TpmPresent");
    probe.ready = ProbeValueOrUnknown(values, "TpmReady");
    probe.enabled = ProbeValueOrUnknown(values, "TpmEnabled");
    probe.activated = ProbeValueOrUnknown(values, "TpmActivated");
    probe.managedAuthLevel = values.count("ManagedAuthLevel") > 0 ? Trim(values.at("ManagedAuthLevel")) : std::string{};
}

inline bool TpmProbeNeedsFallback(const TpmProbe& probe) {
    return probe.present == "unknown" && probe.ready == "unknown" &&
           probe.enabled == "unknown" && probe.activated == "unknown";
}

inline TpmProbe ProbeTpmCimFallback() {
    TpmProbe probe;
    CommandResult result = CapturePowerShell(
        "try { $t=Get-CimInstance -Namespace 'ROOT\\CIMV2\\Security\\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop | Select-Object -First 1; "
        "if ($null -eq $t) { 'Error=CIM TPM returned no data' } else { "
        "'TpmPresent=True'; "
        "'TpmReady=unknown'; "
        "'TpmEnabled=' + [string]$t.IsEnabled_InitialValue; "
        "'TpmActivated=' + [string]$t.IsActivated_InitialValue; "
        "'ManagedAuthLevel=' "
        "} } catch { 'Error=' + $_.Exception.Message }");

    if (!result.started) {
        probe.error = "failed to start PowerShell";
        return probe;
    }

    ApplyTpmKeyValues(probe, ParseKeyValues(result.output));
    return probe;
}

inline TpmProbe ProbeTpm() {
    TpmProbe probe;
    CommandResult result = CapturePowerShell(
        "try { $t=Get-Tpm; "
        "'TpmPresent=' + $t.TpmPresent; "
        "'TpmReady=' + $t.TpmReady; "
        "'TpmEnabled=' + $t.TpmEnabled; "
        "'TpmActivated=' + $t.TpmActivated; "
        "'ManagedAuthLevel=' + $t.ManagedAuthLevel "
        "} catch { 'Error=' + $_.Exception.Message }");

    if (!result.started) {
        probe.error = "failed to start PowerShell";
        return probe;
    }

    auto values = ParseKeyValues(result.output);
    ApplyTpmKeyValues(probe, values);
    if (TpmProbeNeedsFallback(probe)) {
        TpmProbe fallback = ProbeTpmCimFallback();
        if (!TpmProbeNeedsFallback(fallback)) {
            return fallback;
        }
        if (probe.error.empty()) {
            probe.error = fallback.error;
        }
    }
    return probe;
}

inline std::vector<BitLockerVolumeProbe> ProbeBitLocker() {
    std::vector<BitLockerVolumeProbe> volumes;
    CommandResult result = CapturePowerShell(
        "try { Get-BitLockerVolume | ForEach-Object { "
        "$_.MountPoint + '|' + $_.ProtectionStatus + '|' + $_.VolumeStatus + '|' + $_.EncryptionMethod "
        "} } catch { }");

    if (!result.started || result.exitCode != 0) {
        return volumes;
    }

    for (const auto& line : Lines(result.output)) {
        auto parts = Split(line, '|');
        if (parts.size() < 4) {
            continue;
        }
        volumes.push_back({ parts[0], parts[1], parts[2], parts[3] });
    }
    return volumes;
}

inline SecurityProbe ProbeSecurity() {
    SecurityProbe probe;
    probe.tpm = ProbeTpm();
    probe.secureBoot.firmwareType = FirmwareTypeText();
    probe.secureBoot.state = SecureBootText();
    probe.bitLockerVolumes = ProbeBitLocker();
    return probe;
}

inline std::string InferControllerMode(const std::string& name, const std::string& driverName) {
    if (ContainsCi(name, "vmd") || ContainsCi(driverName, "vmd")) {
        return "VMD";
    }
    if (ContainsCi(name, "raid") || ContainsCi(driverName, "iastor")) {
        return "RAID";
    }
    if (ContainsCi(name, "nvme") || ContainsCi(driverName, "stornvme")) {
        return "NVMe";
    }
    if (ContainsCi(name, "ahci") || ContainsCi(driverName, "storahci")) {
        return "AHCI";
    }
    return "Unknown";
}

inline std::vector<ControllerProbe> ProbeControllers() {
    std::vector<ControllerProbe> controllers;
    CommandResult result = CapturePowerShell(
        "try { "
        "Get-CimInstance Win32_SCSIController | ForEach-Object { $_.Name + '|' + $_.Manufacturer + '|' + $_.DriverName }; "
        "Get-CimInstance Win32_IDEController | ForEach-Object { $_.Name + '|' + $_.Manufacturer + '|' + $_.DriverName } "
        "} catch { }");

    if (!result.started || result.exitCode != 0) {
        return controllers;
    }

    for (const auto& line : Lines(result.output)) {
        auto parts = Split(line, '|');
        if (parts.size() < 3) {
            continue;
        }
        ControllerProbe controller{ parts[0], parts[1], parts[2], InferControllerMode(parts[0], parts[2]) };
        controllers.push_back(std::move(controller));
    }
    return controllers;
}

inline std::vector<DiskProbe> ProbeDisks() {
    std::vector<DiskProbe> disks;
    CommandResult result = CapturePowerShell(
        "try { Get-PhysicalDisk | ForEach-Object { "
        "$_.FriendlyName + '|' + $_.SerialNumber + '|' + $_.BusType + '|' + $_.MediaType + '|' + $_.HealthStatus + '|' + $_.Size "
        "} } catch { }");

    if (!result.started || result.exitCode != 0) {
        return disks;
    }

    for (const auto& line : Lines(result.output)) {
        auto parts = Split(line, '|');
        if (parts.size() < 6) {
            continue;
        }
        disks.push_back({ parts[0], parts[1], parts[2], parts[3], parts[4], parts[5] });
    }
    return disks;
}

inline std::vector<StoragePoolProbe> ProbeStoragePools() {
    std::vector<StoragePoolProbe> pools;
    CommandResult result = CapturePowerShell(
        "try { Get-StoragePool | Where-Object { -not $_.IsPrimordial } | ForEach-Object { "
        "$_.FriendlyName + '|' + $_.OperationalStatus + '|' + $_.HealthStatus + '|' + $_.ResiliencySettingName "
        "} } catch { }");

    if (!result.started || result.exitCode != 0) {
        return pools;
    }

    for (const auto& line : Lines(result.output)) {
        auto parts = Split(line, '|');
        if (parts.size() < 4) {
            continue;
        }
        pools.push_back({ parts[0], parts[1], parts[2], parts[3] });
    }
    return pools;
}

inline StorageProbe ProbeStorage() {
    StorageProbe probe;
    probe.controllers = ProbeControllers();
    probe.disks = ProbeDisks();
    probe.pools = ProbeStoragePools();
    probe.storageSpacesDetected = !probe.pools.empty();

    for (const auto& controller : probe.controllers) {
        if (controller.inferredMode == "RAID") {
            probe.raidDetected = true;
        }
        if (controller.inferredMode == "VMD") {
            probe.vmdDetected = true;
        }
    }
    for (const auto& disk : probe.disks) {
        if (ContainsCi(disk.busType, "raid")) {
            probe.raidDetected = true;
        }
    }
    if (probe.storageSpacesDetected) {
        probe.raidDetected = true;
    }

    return probe;
}

inline std::string YesNo(bool value) {
    return value ? "yes" : "no";
}

inline std::string BuildReadinessText(const SecurityProbe& security, const StorageProbe& storage) {
    std::ostringstream out;
    out << "Hardware Readiness Probe\n";
    out << "========================\n";
    out << "Created: " << SetupCommon::TimestampIso() << "\n\n";

    out << "TPM / Secure Boot\n";
    out << "-----------------\n";
    out << "Firmware: " << security.secureBoot.firmwareType << "\n";
    out << "Secure Boot: " << security.secureBoot.state << "\n";
    out << "TPM present: " << security.tpm.present << "\n";
    out << "TPM ready: " << security.tpm.ready << "\n";
    out << "TPM enabled: " << security.tpm.enabled << "\n";
    out << "TPM activated: " << security.tpm.activated << "\n";
    if (!security.tpm.managedAuthLevel.empty()) {
        out << "TPM auth level: " << security.tpm.managedAuthLevel << "\n";
    }
    if (!security.tpm.error.empty()) {
        out << "TPM probe note: " << security.tpm.error << "\n";
    }

    out << "\nBitLocker\n";
    out << "---------\n";
    if (security.bitLockerVolumes.empty()) {
        out << "No BitLocker volumes reported by Get-BitLockerVolume.\n";
    } else {
        for (const auto& volume : security.bitLockerVolumes) {
            out << "- " << volume.mountPoint << ": protection=" << volume.protectionStatus
                << ", status=" << volume.volumeStatus
                << ", method=" << volume.encryptionMethod << "\n";
        }
    }

    out << "\nStorage / RAID\n";
    out << "--------------\n";
    out << "RAID detected: " << YesNo(storage.raidDetected) << "\n";
    out << "VMD detected: " << YesNo(storage.vmdDetected) << "\n";
    out << "Storage Spaces detected: " << YesNo(storage.storageSpacesDetected) << "\n";
    if (storage.controllers.empty()) {
        out << "Controllers: none reported.\n";
    } else {
        out << "Controllers:\n";
        for (const auto& controller : storage.controllers) {
            out << "- " << controller.name << " [" << controller.inferredMode << "]"
                << " driver=" << controller.driverName
                << " manufacturer=" << controller.manufacturer << "\n";
        }
    }
    if (!storage.disks.empty()) {
        out << "Disks:\n";
        for (const auto& disk : storage.disks) {
            out << "- " << disk.friendlyName << " bus=" << disk.busType
                << " media=" << disk.mediaType
                << " health=" << disk.healthStatus << "\n";
        }
    }
    if (!storage.pools.empty()) {
        out << "Storage pools:\n";
        for (const auto& pool : storage.pools) {
            out << "- " << pool.friendlyName << " status=" << pool.operationalStatus
                << " health=" << pool.healthStatus
                << " resiliency=" << pool.resiliency << "\n";
        }
    }

    out << "\nGuidance\n";
    out << "--------\n";
    out << "- Back up BitLocker recovery keys before firmware, TPM, Secure Boot, or partition changes.\n";
    out << "- If RAID or VMD is detected, save the storage controller driver for Windows Setup before reinstalling.\n";
    out << "- These probes are read-only and do not change firmware, TPM, BitLocker, partitions, or controller mode.\n";
    return out.str();
}

inline std::string BuildReadinessJson(const SecurityProbe& security, const StorageProbe& storage) {
    std::ostringstream out;
    out << "{\n";
    out << "  \"schemaVersion\": 1,\n";
    out << "  \"createdAt\": \"" << SetupCommon::JsonEscape(SetupCommon::TimestampIso()) << "\",\n";
    out << "  \"security\": {\n";
    out << "    \"firmwareType\": \"" << SetupCommon::JsonEscape(security.secureBoot.firmwareType) << "\",\n";
    out << "    \"secureBoot\": \"" << SetupCommon::JsonEscape(security.secureBoot.state) << "\",\n";
    out << "    \"tpm\": {\n";
    out << "      \"present\": \"" << SetupCommon::JsonEscape(security.tpm.present) << "\",\n";
    out << "      \"ready\": \"" << SetupCommon::JsonEscape(security.tpm.ready) << "\",\n";
    out << "      \"enabled\": \"" << SetupCommon::JsonEscape(security.tpm.enabled) << "\",\n";
    out << "      \"activated\": \"" << SetupCommon::JsonEscape(security.tpm.activated) << "\",\n";
    out << "      \"managedAuthLevel\": \"" << SetupCommon::JsonEscape(security.tpm.managedAuthLevel) << "\",\n";
    out << "      \"error\": \"" << SetupCommon::JsonEscape(security.tpm.error) << "\"\n";
    out << "    },\n";
    out << "    \"bitLockerVolumes\": [\n";
    for (size_t i = 0; i < security.bitLockerVolumes.size(); ++i) {
        const auto& volume = security.bitLockerVolumes[i];
        out << "      {\n";
        out << "        \"mountPoint\": \"" << SetupCommon::JsonEscape(volume.mountPoint) << "\",\n";
        out << "        \"protectionStatus\": \"" << SetupCommon::JsonEscape(volume.protectionStatus) << "\",\n";
        out << "        \"volumeStatus\": \"" << SetupCommon::JsonEscape(volume.volumeStatus) << "\",\n";
        out << "        \"encryptionMethod\": \"" << SetupCommon::JsonEscape(volume.encryptionMethod) << "\"\n";
        out << "      }" << (i + 1 == security.bitLockerVolumes.size() ? "\n" : ",\n");
    }
    out << "    ]\n";
    out << "  },\n";
    out << "  \"storage\": {\n";
    out << "    \"raidDetected\": " << (storage.raidDetected ? "true" : "false") << ",\n";
    out << "    \"vmdDetected\": " << (storage.vmdDetected ? "true" : "false") << ",\n";
    out << "    \"storageSpacesDetected\": " << (storage.storageSpacesDetected ? "true" : "false") << ",\n";
    out << "    \"controllers\": [\n";
    for (size_t i = 0; i < storage.controllers.size(); ++i) {
        const auto& controller = storage.controllers[i];
        out << "      {\n";
        out << "        \"name\": \"" << SetupCommon::JsonEscape(controller.name) << "\",\n";
        out << "        \"manufacturer\": \"" << SetupCommon::JsonEscape(controller.manufacturer) << "\",\n";
        out << "        \"driverName\": \"" << SetupCommon::JsonEscape(controller.driverName) << "\",\n";
        out << "        \"inferredMode\": \"" << SetupCommon::JsonEscape(controller.inferredMode) << "\"\n";
        out << "      }" << (i + 1 == storage.controllers.size() ? "\n" : ",\n");
    }
    out << "    ],\n";
    out << "    \"disks\": [\n";
    for (size_t i = 0; i < storage.disks.size(); ++i) {
        const auto& disk = storage.disks[i];
        out << "      {\n";
        out << "        \"friendlyName\": \"" << SetupCommon::JsonEscape(disk.friendlyName) << "\",\n";
        out << "        \"serialNumber\": \"" << SetupCommon::JsonEscape(disk.serialNumber) << "\",\n";
        out << "        \"busType\": \"" << SetupCommon::JsonEscape(disk.busType) << "\",\n";
        out << "        \"mediaType\": \"" << SetupCommon::JsonEscape(disk.mediaType) << "\",\n";
        out << "        \"healthStatus\": \"" << SetupCommon::JsonEscape(disk.healthStatus) << "\",\n";
        out << "        \"sizeBytes\": \"" << SetupCommon::JsonEscape(disk.sizeBytes) << "\"\n";
        out << "      }" << (i + 1 == storage.disks.size() ? "\n" : ",\n");
    }
    out << "    ],\n";
    out << "    \"storagePools\": [\n";
    for (size_t i = 0; i < storage.pools.size(); ++i) {
        const auto& pool = storage.pools[i];
        out << "      {\n";
        out << "        \"friendlyName\": \"" << SetupCommon::JsonEscape(pool.friendlyName) << "\",\n";
        out << "        \"operationalStatus\": \"" << SetupCommon::JsonEscape(pool.operationalStatus) << "\",\n";
        out << "        \"healthStatus\": \"" << SetupCommon::JsonEscape(pool.healthStatus) << "\",\n";
        out << "        \"resiliency\": \"" << SetupCommon::JsonEscape(pool.resiliency) << "\"\n";
        out << "      }" << (i + 1 == storage.pools.size() ? "\n" : ",\n");
    }
    out << "    ]\n";
    out << "  }\n";
    out << "}\n";
    return out.str();
}

} // namespace SetupProbe
