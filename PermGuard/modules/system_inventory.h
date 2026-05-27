#pragma once
#include <string>
#include <vector>
#include <utility>
#include <cstdint>
#include "widgets/status_card.h"

namespace Modules {

struct HardwareInfo {
    // Motherboard
    std::string mbManufacturer, mbProduct, mbSerial, mbVersion;
    // BIOS
    std::string biosManufacturer, biosVersion, biosDate, smbiosVersion;
    // CPU
    std::string cpuName, cpuManufacturer;
    int cpuCores = 0, cpuThreads = 0, cpuMaxClock = 0;
    // GPU
    std::string gpuName, gpuDriver, gpuVram;
    // RAM
    int ramTotalGB = 0, ramSpeed = 0, ramSticks = 0;
    std::string ramType;
    // Storage (multiple drives)
    struct DriveInfo {
        std::string model, serial, interfaceType, mediaType;
        uint64_t sizeBytes = 0;
    };
    std::vector<DriveInfo> drives;
    // Network
    struct NetworkAdapter {
        std::string name, macAddress, ipAddress;
        bool connected = false;
    };
    std::vector<NetworkAdapter> adapters;
    // Windows
    std::string windowsEdition, windowsBuild, windowsVersion;
    std::string activationStatus;
    std::string computerName, registeredOwner;
    // Counts
    int driverCount = 0, serviceCount = 0, runningServiceCount = 0;

    bool collected = false;
};

class SystemInventory {
public:
    void Refresh();  // Collect all data via WMI
    void Render();   // Render the UI
    const HardwareInfo& GetInfo() const { return m_info; }

private:
    HardwareInfo m_info;
    bool m_collecting = false;
    std::string m_searchFilter;
};

} // namespace Modules
