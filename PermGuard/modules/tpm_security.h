#pragma once
#include <string>
#include <vector>
#include "widgets/checklist.h"
#include "widgets/status_card.h"

namespace Modules {

struct TpmInfo {
    bool present = false;
    bool enabled = false;
    bool activated = false;
    std::string specVersion;
    std::string manufacturer;
    std::string firmwareVersion;
};

struct SecureBootInfo {
    bool supported = false;
    bool enabled = false;
};

struct BitLockerVolume {
    std::string driveLetter;
    std::string protectionStatus;
    std::string encryptionMethod;
    std::string volumeStatus;
    bool isProtected = false;
};

struct SecurityState {
    TpmInfo tpm;
    SecureBootInfo secureBoot;
    std::vector<BitLockerVolume> bitlockerVolumes;
    bool collected = false;
    bool requiresAdmin = false;
};

class TpmSecurity {
public:
    void Refresh();
    void Render();
    const SecurityState& GetState() const { return m_state; }
    Widgets::CardStatus GetOverallStatus() const;

private:
    SecurityState m_state;
    Widgets::Checklist m_recoveryChecklist;
    bool m_showTpmClearWarning = false;

    void InitChecklist();
};

} // namespace Modules
