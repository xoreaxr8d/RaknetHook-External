#pragma once
#include <Windows.h>
#include <vector>
#include <cstdint>
#include <string>
#include <winternl.h>

typedef CLIENT_ID* PCLIENT_ID;

/*
	VCLIB | JAN 2026 | VOLXPHY
	SYSCALLS (ASM / C)

*/
typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemorySectionName,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation,
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped,
	MemoryPhysicalContiguityInformation,
	MemoryBadInformation,
	MemoryBadInformationAllProcesses,
	MemoryImageExtensionInformation,
	MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;


namespace Syscall {
	extern "C" NTSTATUS NtOpenProcess(
		PHANDLE				ProcessHandle,
		ACCESS_MASK			DesiredAccess,
		POBJECT_ATTRIBUTES	ObjectAttributes,
		PCLIENT_ID			ClientId
	);
	extern "C" NTSTATUS NtWriteVirtualMemory(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T NumberOfBytesToWrite,
		PSIZE_T NumberOfBytesWritten
	);
	extern "C" NTSTATUS NtReadVirtualMemory(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T NumberOfBytesToRead,
		PSIZE_T NumberOfBytesRead
	);
	extern "C" NTSTATUS NtProtectVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		PSIZE_T RegionSize,
		ULONG NewProtection,
		PULONG OldProtection
	);
	extern "C" NTSTATUS NtAllocateVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		ULONG_PTR ZeroBits,
		PSIZE_T RegionSize,
		ULONG AllocationType,
		ULONG PageProtection
	);
	extern "C" NTSTATUS NtQueryVirtualMemory(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		MEMORY_INFORMATION_CLASS MemoryInformationClass,
		PVOID MemoryInformation,
		SIZE_T MemoryInformationLength,
		PSIZE_T ReturnLength
	);
	extern "C" NTSTATUS NtUnmapViewOfSection(
		HANDLE ProcessHandle,
		PVOID BaseAddress
	);
	extern "C" NTSTATUS NtQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);

    extern "C" NTSTATUS NtQueryObject(
        HANDLE                   Handle,
        OBJECT_INFORMATION_CLASS ObjectInformationClass,
        PVOID                    ObjectInformation,
        ULONG                    ObjectInformationLength,
        PULONG                   ReturnLength
    );
}

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO { HANDLE HandleValue; ULONG_PTR HandleCount;    ULONG_PTR PointerCount;    ULONG GrantedAccess;    ULONG ObjectTypeIndex;    ULONG HandleAttributes;    ULONG Reserved; } PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;
typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    _Field_size_(NumberOfHandles) PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex; // since WINBLUE
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _TP_TASK
{
    struct _TP_TASK_CALLBACKS* Callbacks;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    char Padding_242[3];
    struct _LIST_ENTRY ListEntry;
} TP_TASK, * PTP_TASK;

typedef struct _TP_DIRECT
{
    struct _TP_TASK Task;
    UINT64 Lock;
    struct _LIST_ENTRY IoCompletionInformationList;
    void* Callback;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    char __PADDING__[3];
} TP_DIRECT, * PTP_DIRECT;