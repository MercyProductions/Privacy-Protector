#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "widgets/status_card.h"
#include "widgets/checklist.h"

namespace Modules {

struct StorageController {
    std::string name;
    std::string manufacturer;
    std::string driverName;
    std::string mode;  // AHCI, RAID, NVMe, VMD, Unknown
};

struct DiskInfo {
    std::string model;
    std::string serial;
    std::string mediaType;  // HDD, SSD, NVMe
    std::string busType;    // SATA, NVMe, RAID, etc.
    std::string healthStatus;
    uint64_t sizeBytes = 0;
    bool isBootDrive = false;
};

struct RaidArray {
    std::string name;
    std::string level;  // RAID0, RAID1, RAID5, etc.
    std::string status;
    std::vector<std::string> memberDisks;
};

struct StorageState {
    std::vector<StorageController> controllers;
    std::vector<DiskInfo> disks;
    std::vector<RaidArray> arrays;
    std::string osSystemDrive;  // e.g., "C:"
    bool raidDetected = false;
    bool collected = false;
};

class StorageRaid {
public:
    void Refresh();
    void Render();
    const StorageState& GetState() const { return m_state; }

private:
    StorageState m_state;
    Widgets::Checklist m_preReinstallChecklist;

    void DetectControllerModes();
    void DetectRaid();
    void InitChecklist();
};

} // namespace Modules
