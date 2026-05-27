#include <ntddk.h>
#include <initguid.h>
#include <ntstrsafe.h>
#include <wdmsec.h>

#include "..\include\aegis_ioctl.h"

#define AEGIS_DEVICE_NAME L"\\Device\\AegisIoctl"
#define AEGIS_SYMBOLIC_LINK_NAME L"\\DosDevices\\AegisIoctl"

// Admins and LocalSystem only. Keep this driver as a narrow control-plane stub.
#define AEGIS_DEVICE_SDDL L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

DEFINE_GUID(
    GUID_AEGIS_IOCTL_DEVICE,
    0x6a1f2e4b, 0x4a5f, 0x4d49, 0xa5, 0x20, 0x31, 0x12, 0x82, 0x3f, 0x59, 0x1d);

DRIVER_INITIALIZE DriverEntry;

static DRIVER_UNLOAD AegisUnload;
static DRIVER_DISPATCH AegisDispatchCreateClose;
static DRIVER_DISPATCH AegisDispatchDeviceControl;
static DRIVER_DISPATCH AegisDispatchUnsupported;

static volatile LONG gSessionActive = 0;
static volatile LONG gSessionMode = 0;
static volatile LONG gSessionId = 0;
static volatile LONG gSessionBeginCount = 0;
static volatile LONG gSessionEndCount = 0;
static volatile LONG gPolicyStatusQueryCount = 0;
static volatile LONG gEventCountQueryCount = 0;
static volatile LONG gDeniedRequestCount = 0;
static WCHAR gSessionName[64] = L"";

static NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR information)
{
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS AegisDispatchUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return CompleteRequest(Irp, STATUS_NOT_SUPPORTED, 0);
}

static NTSTATUS AegisDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return CompleteRequest(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS HandleGetVersion(PIRP Irp, PIO_STACK_LOCATION stack)
{
    if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(AEGIS_IOCTL_VERSION)) {
        return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    AEGIS_IOCTL_VERSION* version = (AEGIS_IOCTL_VERSION*)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(version, sizeof(*version));

    version->Major = AEGIS_IOCTL_VERSION_MAJOR;
    version->Minor = AEGIS_IOCTL_VERSION_MINOR;
    version->Patch = AEGIS_IOCTL_VERSION_PATCH;
    RtlStringCchCopyW(version->Name, RTL_NUMBER_OF(version->Name), L"AegisIoctl");

    return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(*version));
}

static NTSTATUS HandlePing(PIRP Irp, PIO_STACK_LOCATION stack)
{
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(AEGIS_IOCTL_PING) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(AEGIS_IOCTL_PING)) {
        return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    AEGIS_IOCTL_PING* ping = (AEGIS_IOCTL_PING*)Irp->AssociatedIrp.SystemBuffer;
    ping->Output = ping->Input + 1;

    return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(*ping));
}

static NTSTATUS HandleSessionBegin(PIRP Irp, PIO_STACK_LOCATION stack)
{
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(AEGIS_IOCTL_SESSION) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(AEGIS_IOCTL_SESSION)) {
        return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    AEGIS_IOCTL_SESSION* session = (AEGIS_IOCTL_SESSION*)Irp->AssociatedIrp.SystemBuffer;
    InterlockedExchange(&gSessionActive, 1);
    InterlockedExchange(&gSessionMode, (LONG)session->Mode);
    InterlockedExchange(&gSessionId, (LONG)session->SessionId);
    InterlockedIncrement(&gSessionBeginCount);

    RtlZeroMemory(gSessionName, sizeof(gSessionName));
    RtlStringCchCopyW(gSessionName, RTL_NUMBER_OF(gSessionName), session->Name);

    return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(*session));
}

static NTSTATUS HandleSessionEnd(PIRP Irp, PIO_STACK_LOCATION stack)
{
    UNREFERENCED_PARAMETER(stack);

    InterlockedExchange(&gSessionActive, 0);
    InterlockedExchange(&gSessionMode, 0);
    InterlockedExchange(&gSessionId, 0);
    InterlockedIncrement(&gSessionEndCount);
    RtlZeroMemory(gSessionName, sizeof(gSessionName));

    return CompleteRequest(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS HandlePolicyStatus(PIRP Irp, PIO_STACK_LOCATION stack)
{
    if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(AEGIS_IOCTL_POLICY_STATUS)) {
        return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    AEGIS_IOCTL_POLICY_STATUS* status = (AEGIS_IOCTL_POLICY_STATUS*)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(status, sizeof(*status));
    status->Active = (unsigned long)gSessionActive;
    status->Mode = (unsigned long)gSessionMode;
    status->SessionId = (unsigned long)gSessionId;
    RtlStringCchCopyW(status->Name, RTL_NUMBER_OF(status->Name), gSessionName);
    InterlockedIncrement(&gPolicyStatusQueryCount);

    return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(*status));
}

static NTSTATUS HandleEventCounts(PIRP Irp, PIO_STACK_LOCATION stack)
{
    if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(AEGIS_IOCTL_EVENT_COUNTS)) {
        return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    AEGIS_IOCTL_EVENT_COUNTS* counts = (AEGIS_IOCTL_EVENT_COUNTS*)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(counts, sizeof(*counts));
    counts->SessionBeginCount = (unsigned long)gSessionBeginCount;
    counts->SessionEndCount = (unsigned long)gSessionEndCount;
    counts->PolicyStatusQueryCount = (unsigned long)gPolicyStatusQueryCount;
    counts->EventCountQueryCount = (unsigned long)gEventCountQueryCount;
    counts->DeniedRequestCount = (unsigned long)gDeniedRequestCount;
    InterlockedIncrement(&gEventCountQueryCount);

    return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(*counts));
}

static NTSTATUS AegisDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_AEGIS_GET_VERSION:
            status = HandleGetVersion(Irp, stack);
            break;
        case IOCTL_AEGIS_PING:
            status = HandlePing(Irp, stack);
            break;
        case IOCTL_AEGIS_SESSION_BEGIN:
            status = HandleSessionBegin(Irp, stack);
            break;
        case IOCTL_AEGIS_SESSION_END:
            status = HandleSessionEnd(Irp, stack);
            break;
        case IOCTL_AEGIS_GET_POLICY_STATUS:
            status = HandlePolicyStatus(Irp, stack);
            break;
        case IOCTL_AEGIS_GET_EVENT_COUNTS:
            status = HandleEventCounts(Irp, stack);
            break;
        default:
            InterlockedIncrement(&gDeniedRequestCount);
            status = CompleteRequest(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
            break;
    }

    return status;
}

static void AegisUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicLink;
    RtlInitUnicodeString(&symbolicLink, AEGIS_SYMBOLIC_LINK_NAME);
    IoDeleteSymbolicLink(&symbolicLink);

    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;
    UNICODE_STRING sddl;
    PDEVICE_OBJECT deviceObject = NULL;

    RtlInitUnicodeString(&deviceName, AEGIS_DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLink, AEGIS_SYMBOLIC_LINK_NAME);
    RtlInitUnicodeString(&sddl, AEGIS_DEVICE_SDDL);

    NTSTATUS status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        &GUID_AEGIS_IOCTL_DEVICE,
        &deviceObject);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) {
        DriverObject->MajorFunction[i] = AegisDispatchUnsupported;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = AegisDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = AegisDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AegisDispatchDeviceControl;
    DriverObject->DriverUnload = AegisUnload;

    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
