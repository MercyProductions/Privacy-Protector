#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <winioctl.h>
#endif

#define AEGIS_IOCTL_DEVICE_NAME "\\\\.\\AegisIoctl"

#define AEGIS_IOCTL_TYPE 0x8000

#define IOCTL_AEGIS_GET_VERSION \
    CTL_CODE(AEGIS_IOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_AEGIS_PING \
    CTL_CODE(AEGIS_IOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_AEGIS_SESSION_BEGIN \
    CTL_CODE(AEGIS_IOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_AEGIS_SESSION_END \
    CTL_CODE(AEGIS_IOCTL_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_AEGIS_GET_POLICY_STATUS \
    CTL_CODE(AEGIS_IOCTL_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_AEGIS_GET_EVENT_COUNTS \
    CTL_CODE(AEGIS_IOCTL_TYPE, 0x805, METHOD_BUFFERED, FILE_READ_DATA)

#define AEGIS_IOCTL_VERSION_MAJOR 0
#define AEGIS_IOCTL_VERSION_MINOR 2
#define AEGIS_IOCTL_VERSION_PATCH 0

typedef struct _AEGIS_IOCTL_VERSION {
    unsigned long Major;
    unsigned long Minor;
    unsigned long Patch;
    wchar_t Name[32];
} AEGIS_IOCTL_VERSION;

typedef struct _AEGIS_IOCTL_PING {
    unsigned long Input;
    unsigned long Output;
} AEGIS_IOCTL_PING;

typedef struct _AEGIS_IOCTL_SESSION {
    unsigned long SessionId;
    unsigned long Mode;
    wchar_t Name[64];
} AEGIS_IOCTL_SESSION;

typedef struct _AEGIS_IOCTL_POLICY_STATUS {
    unsigned long Active;
    unsigned long Mode;
    unsigned long SessionId;
    wchar_t Name[64];
} AEGIS_IOCTL_POLICY_STATUS;

typedef struct _AEGIS_IOCTL_EVENT_COUNTS {
    unsigned long SessionBeginCount;
    unsigned long SessionEndCount;
    unsigned long PolicyStatusQueryCount;
    unsigned long EventCountQueryCount;
    unsigned long DeniedRequestCount;
} AEGIS_IOCTL_EVENT_COUNTS;
