#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>

namespace Core {

class Admin {
public:
    // Check if current process is running elevated
    static bool IsElevated();

    // Request elevation via UAC (relaunches the process)
    static void RequestElevation();

    // Get current username
    static std::string GetCurrentUser();

    // Get computer name
    static std::string GetComputerName();
};

} // namespace Core
