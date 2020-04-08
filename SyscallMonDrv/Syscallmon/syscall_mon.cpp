// Copyright (c) 2015-2018, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements DdiMon functions.

#include "syscall_mon.h"
#include <ntimage.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#undef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#include <array>
#include "../DdiMon/shadow_hook.h"

#include "NativeEnums.h"
#include "NativeStructs.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

// A helper type for parsing a PoolTag value
union PoolTag {
	ULONG value;
	UCHAR chars[4];
};

// A callback type for EnumExportedSymbols()
using EnumExportedSymbolsCallbackType = bool(*)(
	ULONG index, ULONG_PTR base_address, PIMAGE_EXPORT_DIRECTORY directory,
	ULONG_PTR directory_base, ULONG_PTR directory_end, void* context);

// For SystemProcessInformation
enum SystemInformationClass {
	kSystemProcessInformation = 5,
};

// For NtQuerySystemInformation
struct SystemProcessInformation {
	ULONG next_entry_offset;
	ULONG number_of_threads;
	LARGE_INTEGER working_set_private_size;
	ULONG hard_fault_count;
	ULONG number_of_threads_high_watermark;
	ULONG64 cycle_time;
	LARGE_INTEGER create_time;
	LARGE_INTEGER user_time;
	LARGE_INTEGER kernel_time;
	UNICODE_STRING image_name;
	// omitted. see ole32!_SYSTEM_PROCESS_INFORMATION
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//
_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static void SyscallmonpFreeAllocatedTrampolineRegions();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C static NTSTATUS
SyscallmonpEnumExportedSymbols(_In_ ULONG_PTR base_address,
	_In_ EnumExportedSymbolsCallbackType callback,
	_In_opt_ void* context);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static bool SyscallmonpEnumExportedSymbolsCallback(
	_In_ ULONG index, _In_ ULONG_PTR base_address,
	_In_ PIMAGE_EXPORT_DIRECTORY directory, _In_ ULONG_PTR directory_base,
	_In_ ULONG_PTR directory_end, _In_opt_ void* context);

static std::array<char, 5> DdimonpTagToString(_In_ ULONG tag_value);

template <typename T>
static T SyscallmonpFindOrignal(_In_ T handler);



#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE, SyscallmonInitialization)
#pragma alloc_text(PAGE, SyscallmonpEnumExportedSymbols)
#pragma alloc_text(PAGE, SyscallmonpEnumExportedSymbolsCallback)
#pragma alloc_text(PAGE, SyscallmonTermination)
#pragma alloc_text(PAGE, SyscallmonpFreeAllocatedTrampolineRegions)
#endif

//HookAPIs

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NTAPI NewNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);


_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NTAPI NewNtOpenProcess(
	_Out_    PHANDLE            ProcessHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID         ClientId
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NTAPI NewNtOpenThread(
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NTAPI NewNtTerminateProcess(
	_In_opt_ HANDLE ProcessHandle,
	_In_ NTSTATUS ExitStatus
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NTAPI NewNtAllocateVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NTAPI NewNtReadVirtualMemory(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__out_bcount(BufferSize) PVOID Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesRead
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NTAPI NewNtWriteVirtualMemory(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__in_bcount(BufferSize) PVOID Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesWritten
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NTAPI NewNtProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NewNtQueryVirtualMemory(
	__in HANDLE ProcessHandle,
	__in PVOID BaseAddress,
	__in MEMORY_INFORMATION_CLASS_EX MemoryInformationClass,
	__out_bcount(MemoryInformationLength) PVOID MemoryInformation,
	__in SIZE_T MemoryInformationLength,
	__out_opt PSIZE_T ReturnLength
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NTAPI NewNtLoadDriver(PUNICODE_STRING DriverServiceName);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NTAPI NewNtCreateMutant(
	__out PHANDLE MutantHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in BOOLEAN InitialOwner
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NTAPI NewNtOpenMutant(
	__out PHANDLE MutantHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NTAPI NewNtCreateDirectoryObject(
	__out PHANDLE DirectoryHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NTAPI NewNtOpenDirectoryObject(
	__out PHANDLE DirectoryHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static NTSTATUS NTAPI NewNtQueryDirectoryObject(
	__in HANDLE DirectoryHandle,
	__out_bcount_opt(Length) PVOID Buffer,
	__in ULONG Length,
	__in BOOLEAN ReturnSingleEntry,
	__in BOOLEAN RestartScan,
	__inout PULONG Context,
	__out_opt PULONG ReturnLength
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static PVOID NTAPI NewNtUserSetWindowsHookEx(
	HANDLE hmod,
	PUNICODE_STRING pstrLib,
	DWORD ThreadId,
	int nFilterType,
	PVOID pfnFilterProc,
	UCHAR chFlags);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static PVOID NTAPI NewNtUserSetWindowsHookAW(
	IN int nFilterType,
	IN PVOID pfnFilterProc,
	IN UCHAR chFlags);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static PVOID NTAPI NewNtUserFindWindowEx(
	IN PVOID hwndParent,
	IN PVOID hwndChild,
	IN PUNICODE_STRING pstrClassName OPTIONAL,
	IN PUNICODE_STRING pstrWindowName OPTIONAL,
	IN DWORD dwType);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static int NTAPI NewNtUserInternalGetWindowText(
		IN PVOID hwnd,
		OUT LPWSTR lpString,
		IN int nMaxCount);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static int NTAPI NewNtUserGetClassName(
	IN PVOID hwnd,
	IN int bReal,
	IN OUT PUNICODE_STRING pstrClassName);


EXTERN_C
extern "C" volatile LONG m_HookLock;
////////////////////////////////////////////////////////////////////////////////
//
// variables
//

// Defines where to install shadow hooks and their handlers
//
// Because of simplified implementation of DdiMon, DdiMon is unable to handle
// any of following exports properly:
//  - already unmapped exports (eg, ones on the INIT section) because it no
//    longer exists on memory
//  - exported data because setting 0xcc does not make any sense in this case
//  - functions does not comply x64 calling conventions, for example Zw*
//    functions. Because contents of stack do not hold expected values leading
//    handlers to failure of parameter analysis that may result in bug check.
//
// Also the following care should be taken:
//  - Function parameters may be an user-address space pointer and not
//    trusted. Even a kernel-address space pointer should not be trusted for
//    production level security. Verity and capture all contents from user
//    supplied address to VMM, then use them.
static ShadowHookTarget g_scmonp_hook_targets[] = {
	{
		RTL_CONSTANT_STRING(L"NtQuerySystemInformation"),
		NewNtQuerySystemInformation,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtOpenProcess"),
		NewNtOpenProcess,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtOpenThread"),
		NewNtOpenThread,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtTerminateProcess"),
		NewNtTerminateProcess,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtAllocateVirtualMemory"),
		NewNtAllocateVirtualMemory,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtReadVirtualMemory"),
		NewNtReadVirtualMemory,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtWriteVirtualMemory"),
		NewNtWriteVirtualMemory,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtProtectVirtualMemory"),
		NewNtProtectVirtualMemory,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtQueryVirtualMemory"),
		NewNtQueryVirtualMemory,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtLoadDriver"),
		NewNtLoadDriver,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtCreateMutant"),
		NewNtCreateMutant,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtOpenMutant"),
		NewNtOpenMutant,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtCreateDirectoryObject"),
		NewNtCreateDirectoryObject,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtOpenDirectoryObject"),
		NewNtOpenDirectoryObject,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtQueryDirectoryObject"),
		NewNtQueryDirectoryObject,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtUserSetWindowsHookEx"),
		NewNtUserSetWindowsHookEx,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtUserSetWindowsHookEx"),
		NewNtUserSetWindowsHookEx,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtUserSetWindowsHookAW"),
		NewNtUserSetWindowsHookAW,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtUserFindWindowEx"),
		NewNtUserFindWindowEx,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtUserInternalGetWindowText"),
		NewNtUserInternalGetWindowText,
		nullptr,
	},
	{
		RTL_CONSTANT_STRING(L"NtUserGetClassName"),
		NewNtUserGetClassName,
		nullptr,
	},
};

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Initializes DdiMon
_Use_decl_annotations_ EXTERN_C NTSTATUS
SyscallmonInitialization(SharedShadowHookData* shared_sh_data) {
	// Get a base address of ntoskrnl
	auto nt_base = UtilPcToFileHeader(KdDebuggerEnabled);
	if (!nt_base) {
		return STATUS_UNSUCCESSFUL;
	}

	// Install hooks by enumerating exports of ntoskrnl, but not activate them yet
	auto status = SyscallmonpEnumExportedSymbols(reinterpret_cast<ULONG_PTR>(nt_base),
		SyscallmonpEnumExportedSymbolsCallback,
		shared_sh_data);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// Activate installed hooks
	status = ShEnableHooks();
	if (!NT_SUCCESS(status)) {
		SyscallmonpFreeAllocatedTrampolineRegions();
		return status;
	}

	HYPERPLATFORM_LOG_INFO("DdiMon has been initialized.");
	return status;
}

// Terminates DdiMon
_Use_decl_annotations_ EXTERN_C void 
SyscallmonTermination() {
	PAGED_CODE();

	ShDisableHooks();
	UtilSleep(1000);
	SyscallmonpFreeAllocatedTrampolineRegions();
	HYPERPLATFORM_LOG_INFO("DdiMon has been terminated.");
}

// Frees trampoline code allocated and stored in g_scmonp_hook_targets by
// SyscallmonpEnumExportedSymbolsCallback()
_Use_decl_annotations_ EXTERN_C static void
SyscallmonpFreeAllocatedTrampolineRegions() {
	PAGED_CODE();

	for (auto& target : g_scmonp_hook_targets) {
		if (target.original_call) {
			ExFreePoolWithTag(target.original_call, kHyperPlatformCommonPoolTag);
			target.original_call = nullptr;
		}
	}
}

// Enumerates all exports in a module specified by base_address.
_Use_decl_annotations_ EXTERN_C static NTSTATUS SyscallmonpEnumExportedSymbols(
	ULONG_PTR base_address, EnumExportedSymbolsCallbackType callback,
	void* context) {
	PAGED_CODE();

	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + dos->e_lfanew);
	auto dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(
		&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	if (!dir->Size || !dir->VirtualAddress) {
		return STATUS_SUCCESS;
	}

	auto dir_base = base_address + dir->VirtualAddress;
	auto dir_end = base_address + dir->VirtualAddress + dir->Size - 1;
	auto exp_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base_address +
		dir->VirtualAddress);
	for (auto i = 0ul; i < exp_dir->NumberOfNames; i++) {
		if (!callback(i, base_address, exp_dir, dir_base, dir_end, context)) {
			return STATUS_SUCCESS;
		}
	}
	return STATUS_SUCCESS;
}

// Checks if the export is listed as a hook target, and if so install a hook.
_Use_decl_annotations_ EXTERN_C static bool SyscallmonpEnumExportedSymbolsCallback(
	ULONG index, ULONG_PTR base_address, PIMAGE_EXPORT_DIRECTORY directory,
	ULONG_PTR directory_base, ULONG_PTR directory_end, void* context) {
	PAGED_CODE();

	if (!context) {
		return false;
	}

	auto functions =
		reinterpret_cast<ULONG*>(base_address + directory->AddressOfFunctions);
	auto ordinals = reinterpret_cast<USHORT*>(base_address +
		directory->AddressOfNameOrdinals);
	auto names =
		reinterpret_cast<ULONG*>(base_address + directory->AddressOfNames);

	auto ord = ordinals[index];
	auto export_address = base_address + functions[ord];
	auto export_name = reinterpret_cast<const char*>(base_address + names[index]);

	// Check if an export is forwarded one? If so, ignore it.
	if (UtilIsInBounds(export_address, directory_base, directory_end)) {
		return true;
	}

	// convert the name to UNICODE_STRING
	wchar_t name[100];
	auto status =
		RtlStringCchPrintfW(name, RTL_NUMBER_OF(name), L"%S", export_name);
	if (!NT_SUCCESS(status)) {
		return true;
	}
	UNICODE_STRING name_u = {};
	RtlInitUnicodeString(&name_u, name);

	for (auto& target : g_scmonp_hook_targets) {
		// Is this export listed as a target
		if (!FsRtlIsNameInExpression(&target.target_name, &name_u, TRUE, nullptr)) {
			continue;
		}

		// Yes, install a hook to the export
		if (!ShInstallHook(reinterpret_cast<SharedShadowHookData*>(context),
			reinterpret_cast<void*>(export_address), &target)) {
			// This is an error which should not happen
			SyscallmonpFreeAllocatedTrampolineRegions();
			return false;
		}
		HYPERPLATFORM_LOG_INFO("Hook has been installed at %016Ix %s.",
			export_address, export_name);
	}
	return true;
}

// Finds a handler to call an original function
template <typename T>
static T SyscallmonpFindOrignal(T handler) {
	for (const auto& target : g_scmonp_hook_targets) {
		if (target.handler == handler) {
			NT_ASSERT(target.original_call);
			return reinterpret_cast<T>(target.original_call);
		}
	}
	NT_ASSERT(false);
	return nullptr;
}


/// @file
/// Implements DdiMon functions.

#include <intrin.h>
#include "../DdiMon/ddi_mon.h"
#include <ntimage.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include "../HyperPlatform/HyperPlatform/performance.h"
#include "../HyperPlatform/HyperPlatform/asm.h"

#include "../DdiMon/shadow_hook.h"
#include "main.h"
#include "NativeEnums.h"
#include "NativeStructs.h"
#include "../../Shared/Protocol.h"

extern CProcList *m_IgnoreProcList;
extern CFileList *m_IgnoreFileList;
extern CEventList *m_EventList;
extern HANDLE m_SyscallMonPID;

extern PFLT_FILTER m_pFilterHandle;
extern PFLT_PORT m_pClientPort;

EXTERN_C
{

extern DYNAMIC_DATA dynData;

extern POBJECT_TYPE *PsProcessType;

extern PVOID g_ThisModuleBase;

NTSTATUS GetProcessIdByHandle(__in HANDLE ProcessHandle, __out PHANDLE ProcessId);

HANDLE GetCsrssProcessId(VOID);

PVOID CreateCallStackEvent(ULONG64 EventId);

//ULONG_PTR m_CsrssCR3 = NULL;

NTKERNELAPI PCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);

//volatile LONG m_HookLock;

}

//NtQuerySystemInformation
NTSTATUS NTAPI NewNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = SyscallmonpFindOrignal(NewNtQuerySystemInformation);

	const auto status = original(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	svc_nt_query_systeminfo_data *data = NULL;

	if (m_EventList->IsCapturing())
	{
		if (NT_SUCCESS(status) && ExGetPreviousMode() == UserMode)
		{
			//Hide me from user-mode program
#if 0
			__try
			{
				if (SystemInformationClass == SystemProcessInformation) {
					PSYSTEM_PROCESS_INFORMATION_EX next = (PSYSTEM_PROCESS_INFORMATION_EX)SystemInformation;
					while (next->NextEntryOffset) {
						PSYSTEM_PROCESS_INFORMATION_EX curr = next;
						next = (PSYSTEM_PROCESS_INFORMATION_EX)((PUCHAR)curr + curr->NextEntryOffset);
						if (next->UniqueProcessId == m_SyscallMonPID) {
							if (next->NextEntryOffset) {
								curr->NextEntryOffset += next->NextEntryOffset;
							}
							else {
								curr->NextEntryOffset = 0;
							}
							next = curr;
						}
					}
				}
				else if (SystemInformationClass == SystemModuleInformation) {
					PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)SystemInformation;
					for (ULONG i = 0; i < mods->NumberOfModules; ++i) {
						if (mods->Modules[i].ImageBase == g_ThisModuleBase)
						{
							memcpy(&mods->Modules[i], &mods->Modules[i + 1], sizeof(RTL_PROCESS_MODULE_INFORMATION) * (mods->NumberOfModules - i - 1));
							--mods->NumberOfModules;
							for (ULONG j = i; j < mods->NumberOfModules; ++j)
								--mods->Modules[i].LoadOrderIndex;

							break;
						}
					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
#endif

			ULONG64 EventId = m_EventList->GetEventId();
			if (EventId)
			{
				data = (svc_nt_query_systeminfo_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_query_systeminfo_data), 'TXSB');
				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_nt_query_systeminfo_data));
					data->protocol = svc_nt_query_systeminfo;
					data->size = sizeof(svc_nt_query_systeminfo_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
					data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
					data->QueryClass = (ULONG)(UINT_PTR)SystemInformationClass;

					m_EventList->Lock();
					m_EventList->SendEvent(data);
					m_EventList->SendEvent(CreateCallStackEvent(EventId));
					m_EventList->Unlock();
					m_EventList->NotifyEvent();
				}
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtOpenProcess
NTSTATUS NTAPI NewNtOpenProcess(
	_Out_    PHANDLE            ProcessHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID         ClientId
)
{
	InterlockedIncrement(&m_HookLock);

	svc_nt_open_process_data *data = NULL;
	ULONG64 EventId = 0;
	BOOLEAN ValidProcessId = FALSE;
	CLIENT_ID CapturedCid = { 0 };

	const auto original = SyscallmonpFindOrignal(NtOpenProcess);

	if (m_EventList->IsCapturing())
	{
		__try
		{
			if (ARGUMENT_PRESENT(ClientId) && ExGetPreviousMode() == UserMode)
			{
				ProbeForRead(ClientId, sizeof(CLIENT_ID), sizeof(ULONG));
				CapturedCid = *ClientId;
				ValidProcessId = TRUE;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
		if (ValidProcessId)
		{
			EventId = m_EventList->GetEventId();
			if (EventId)
			{
				data = (svc_nt_open_process_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_open_process_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_nt_open_process_data));
					data->protocol = svc_nt_open_process;
					data->size = sizeof(svc_nt_open_process_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
					data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
					data->TargetProcessId = (ULONG)(UINT_PTR)CapturedCid.UniqueProcess;
					data->DesiredAccess = (ULONG)DesiredAccess;
				}
			}
		}
	}

	NTSTATUS status = STATUS_SUCCESS;

	if (ValidProcessId)
	{
		PEPROCESS ProcessObj = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(CapturedCid.UniqueProcess, &ProcessObj)))
		{
			if (!_stricmp(PsGetProcessImageFileName(ProcessObj), "Xubei.exe")) {
				PEPROCESS CurrentProcessObj = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId(PsGetCurrentProcessId(), &CurrentProcessObj)))
				{
					if (!_stricmp(PsGetProcessImageFileName(CurrentProcessObj), "crossfire.exe"))
						status = STATUS_ACCESS_DENIED;

					ObfDereferenceObject(CurrentProcessObj);
				}
			}
			ObfDereferenceObject(ProcessObj);
		}
	}

	if (status == STATUS_SUCCESS)
		status = original(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

	if (data) {
		data->ResultStatus = (ULONG)status;

		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

NTSTATUS NTAPI NewNtOpenThread(
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
)
{
	InterlockedIncrement(&m_HookLock);

	BOOLEAN ValidThreadId = FALSE;
	CLIENT_ID CapturedCid = { 0 };

	const auto original = SyscallmonpFindOrignal(NewNtOpenThread);

	NTSTATUS status = original(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);

	if (m_EventList->IsCapturing())
	{
		__try
		{
			if (ARGUMENT_PRESENT(ClientId) && ExGetPreviousMode() == UserMode)
			{
				ProbeForRead(ClientId, sizeof(CLIENT_ID), sizeof(ULONG));
				CapturedCid = *ClientId;
				ValidThreadId = TRUE;

				PETHREAD Thread = NULL;
				if (NT_SUCCESS(PsLookupThreadByThreadId(CapturedCid.UniqueThread, &Thread)))
				{
					CapturedCid.UniqueProcess = PsGetThreadProcessId(Thread);
					ObDereferenceObject(Thread);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
		if (ValidThreadId)
		{
			ULONG64 EventId = m_EventList->GetEventId();
			if (EventId)
			{
				svc_nt_open_thread_data *data = (svc_nt_open_thread_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_open_thread_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_nt_open_thread_data));
					data->protocol = svc_nt_open_thread;
					data->size = sizeof(svc_nt_open_thread_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
					data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
					data->TargetProcessId = (ULONG)(UINT_PTR)CapturedCid.UniqueProcess;
					data->TargetThreadId = (ULONG)(UINT_PTR)CapturedCid.UniqueThread;
					data->DesiredAccess = (ULONG)DesiredAccess;
					data->ResultStatus = (ULONG)status;

					m_EventList->Lock();
					m_EventList->SendEvent(data);
					m_EventList->SendEvent(CreateCallStackEvent(EventId));
					m_EventList->Unlock();
					m_EventList->NotifyEvent();
				}
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtTerminateProcess
NTSTATUS NTAPI NewNtTerminateProcess(
	_In_opt_ HANDLE ProcessHandle,
	_In_ NTSTATUS ExitStatus
)
{
	InterlockedIncrement(&m_HookLock);

	ULONG64 EventId = 0;
	HANDLE ProcessId = NULL;
	BOOLEAN bValid = FALSE;

	if (ARGUMENT_PRESENT(ProcessHandle) && !ObIsKernelHandle(ProcessHandle) && ExGetPreviousMode() == UserMode)
	{
		if (NT_SUCCESS(GetProcessIdByHandle(ProcessHandle, &ProcessId)) && PsGetCurrentProcessId() != ProcessId)
		{
			bValid = TRUE;
		}
	}

	const auto original = SyscallmonpFindOrignal(NewNtTerminateProcess);

	svc_nt_terminate_process_data *data = NULL;

	if (bValid && m_EventList->IsCapturing())
	{
		EventId = m_EventList->GetEventId();
		if (EventId)
		{
			data = (svc_nt_terminate_process_data *)
				ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_terminate_process_data), 'TXSB');

			if (data)
			{
				RtlZeroMemory(data, sizeof(svc_nt_terminate_process_data));
				data->protocol = svc_nt_terminate_process;
				data->size = sizeof(svc_nt_terminate_process_data);
				data->time = PerfGetSystemTime();
				data->eventId = EventId;
				data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
				data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
				data->TargetProcessId = (ULONG)(UINT_PTR)ProcessId;
				data->ResultStatus = (ULONG)STATUS_SUCCESS;
			}
		}
	}

	NTSTATUS status;
	//if (bValid && ProcessId == m_SyscallMonPID)
	//	status = STATUS_ACCESS_DENIED;
	//else
	status = original(ProcessHandle, ExitStatus);

	if (data)
	{
		data->ResultStatus = (ULONG)status;

		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtAllocateVirtualMemory
NTSTATUS NTAPI NewNtAllocateVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
)
{
	InterlockedIncrement(&m_HookLock);

	PVOID OldBaseAddress = NULL;
	PVOID NewBaseAddress = NULL;
	SIZE_T OldRegionSize = 0;
	SIZE_T NewRegionSize = 0;
	HANDLE ProcessId = NULL;
	BOOLEAN bValid = FALSE;

	KPROCESSOR_MODE mode = ExGetPreviousMode();

	if (ARGUMENT_PRESENT(ProcessHandle) && !ObIsKernelHandle(ProcessHandle) && mode == UserMode)
	{
		if (NT_SUCCESS(GetProcessIdByHandle(ProcessHandle, &ProcessId)) && ProcessId != PsGetCurrentProcessId())
		{
			bValid = TRUE;
		}
	}

	if (bValid)
	{
		__try
		{
			ProbeForWrite(BaseAddress, sizeof(PVOID), sizeof(ULONG));
			ProbeForWrite(RegionSize, sizeof(SIZE_T), sizeof(ULONG));

			OldBaseAddress = *BaseAddress;
			OldRegionSize = *RegionSize;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
	}

	const auto original = SyscallmonpFindOrignal(NewNtAllocateVirtualMemory);

	NTSTATUS status;
	//if (bValid && ProcessId == m_SyscallMonPID && PsGetCurrentProcessId() != ProcessId)
	//	status = STATUS_ACCESS_DENIED;
	//else
	status = original(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

	if (bValid)
	{
		__try
		{
			ProbeForWrite(BaseAddress, sizeof(PVOID), sizeof(ULONG));
			ProbeForWrite(RegionSize, sizeof(SIZE_T), sizeof(ULONG));

			NewBaseAddress = *BaseAddress;
			NewRegionSize = *RegionSize;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
	}

	svc_nt_alloc_virtual_mem_data *data = NULL;

	if (bValid && m_EventList->IsCapturing())
	{
		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			ULONG64 EventId = m_EventList->GetEventId();
			if (EventId)
			{
				data = (svc_nt_alloc_virtual_mem_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_alloc_virtual_mem_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_nt_alloc_virtual_mem_data));
					data->protocol = svc_nt_alloc_virtual_mem;
					data->size = sizeof(svc_nt_alloc_virtual_mem_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
					data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
					data->TargetProcessId = (ULONG)(UINT_PTR)ProcessId;
					data->OldBaseAddress = (ULONG64)OldBaseAddress;
					data->OldRegionSize = (ULONG64)OldRegionSize;
					data->NewBaseAddress = (ULONG64)NewBaseAddress;
					data->NewRegionSize = (ULONG64)NewRegionSize;
					data->AllocationType = AllocationType;
					data->Protect = Protect;
					data->ResultStatus = (ULONG)status;

					m_EventList->Lock();
					m_EventList->SendEvent(data);
					m_EventList->SendEvent(CreateCallStackEvent(EventId));
					m_EventList->Unlock();
					m_EventList->NotifyEvent();
				}
			}
			ObDereferenceObject(Process);
		}
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtReadVirtualMemory
NTSTATUS NTAPI NewNtReadVirtualMemory(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__out_bcount(BufferSize) PVOID Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesRead
)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = SyscallmonpFindOrignal(NewNtReadVirtualMemory);

	NTSTATUS status = original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);

	svc_nt_readwrite_virtual_mem_data *data = NULL;

	if (m_EventList->IsCapturing())
	{
		if (ARGUMENT_PRESENT(ProcessHandle) && !ObIsKernelHandle(ProcessHandle) && ExGetPreviousMode() == UserMode)
		{
			HANDLE ProcessId = NULL;
			if (NT_SUCCESS(GetProcessIdByHandle(ProcessHandle, &ProcessId)) && ProcessId != PsGetCurrentProcessId())
			{
				PEPROCESS Process = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
				{
					ULONG64 EventId = m_EventList->GetEventId();
					if (EventId)
					{
						data = (svc_nt_readwrite_virtual_mem_data *)
							ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_readwrite_virtual_mem_data), 'TXSB');

						if (data)
						{
							RtlZeroMemory(data, sizeof(svc_nt_readwrite_virtual_mem_data));
							data->protocol = svc_nt_readwrite_virtual_mem;
							data->size = sizeof(svc_nt_readwrite_virtual_mem_data);
							data->time = PerfGetSystemTime();
							data->eventId = EventId;
							data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
							data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
							data->TargetProcessId = (ULONG)(UINT_PTR)ProcessId;
							data->BaseAddress = (ULONG64)BaseAddress;
							data->BufferSize = (ULONG64)BufferSize;
							data->ResultStatus = (ULONG)status;

							m_EventList->Lock();
							m_EventList->SendEvent(data);
							m_EventList->SendEvent(CreateCallStackEvent(EventId));
							m_EventList->Unlock();
							m_EventList->NotifyEvent();
						}
					}
					ObDereferenceObject(Process);
				}
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtWriteVirtualMemory
NTSTATUS NTAPI NewNtWriteVirtualMemory(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__in_bcount(BufferSize) PVOID Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesWritten
)
{
	InterlockedIncrement(&m_HookLock);

	HANDLE ProcessId = NULL;
	BOOLEAN bValid = FALSE;

	KPROCESSOR_MODE mode = ExGetPreviousMode();

	if (ARGUMENT_PRESENT(ProcessHandle) && !ObIsKernelHandle(ProcessHandle) && mode == UserMode)
	{
		if (NT_SUCCESS(GetProcessIdByHandle(ProcessHandle, &ProcessId)) && ProcessId != PsGetCurrentProcessId())
		{
			bValid = TRUE;
		}
	}

	const auto original = SyscallmonpFindOrignal(NewNtReadVirtualMemory);

	NTSTATUS status;

	//if (bValid && ProcessId == m_SyscallMonPID && PsGetCurrentProcessId() != ProcessId)
	//	status = STATUS_ACCESS_DENIED;
	//else
	status = original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);

	svc_nt_readwrite_virtual_mem_data *data = NULL;

	if (bValid && m_EventList->IsCapturing())
	{
		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			ULONG64 EventId = m_EventList->GetEventId();
			if (EventId)
			{
				data = (svc_nt_readwrite_virtual_mem_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_readwrite_virtual_mem_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_nt_readwrite_virtual_mem_data));
					data->protocol = svc_nt_readwrite_virtual_mem;
					data->size = sizeof(svc_nt_readwrite_virtual_mem_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
					data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
					data->TargetProcessId = (ULONG)(UINT_PTR)ProcessId;
					data->BaseAddress = (ULONG64)BaseAddress;
					data->BufferSize = (ULONG64)BufferSize;
					data->ResultStatus = (ULONG)status;

					m_EventList->Lock();
					m_EventList->SendEvent(data);
					m_EventList->SendEvent(CreateCallStackEvent(EventId));
					m_EventList->Unlock();
					m_EventList->NotifyEvent();
				}
			}
			ObDereferenceObject(Process);
		}
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtProtectVirtualMemory
NTSTATUS NTAPI NewNtProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
)
{
	InterlockedIncrement(&m_HookLock);

	PVOID OldBaseAddress = NULL;
	PVOID NewBaseAddress = NULL;
	SIZE_T OldRegionSize = 0;
	SIZE_T NewRegionSize = 0;
	ULONG MyOldProtect = 0;
	HANDLE ProcessId = NULL;
	BOOLEAN bValid = FALSE;

	KPROCESSOR_MODE mode = ExGetPreviousMode();

	if (ARGUMENT_PRESENT(ProcessHandle) && !ObIsKernelHandle(ProcessHandle) && mode == UserMode)
	{
		if (NT_SUCCESS(GetProcessIdByHandle(ProcessHandle, &ProcessId)) && ProcessId != PsGetCurrentProcessId())
		{
			bValid = TRUE;
		}
	}

	if (bValid)
	{
		__try
		{
			ProbeForWrite(BaseAddress, sizeof(PVOID), sizeof(ULONG));
			ProbeForWrite(RegionSize, sizeof(SIZE_T), sizeof(ULONG));

			OldBaseAddress = *BaseAddress;
			OldRegionSize = *RegionSize;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
	}

	const auto original = SyscallmonpFindOrignal(NewNtProtectVirtualMemory);

	NTSTATUS status;

	//if (bValid && ProcessId == m_SyscallMonPID && PsGetCurrentProcessId() != ProcessId)
	//	status = STATUS_ACCESS_DENIED;
	//else
	status = original(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

	if (bValid)
	{
		__try
		{
			ProbeForWrite(BaseAddress, sizeof(PVOID), sizeof(ULONG));
			ProbeForWrite(RegionSize, sizeof(SIZE_T), sizeof(ULONG));

			NewBaseAddress = *BaseAddress;
			NewRegionSize = *RegionSize;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}

		__try
		{
			ProbeForWrite(OldProtect, sizeof(ULONG), sizeof(ULONG));
			MyOldProtect = *OldProtect;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
	}

	svc_nt_protect_virtual_mem_data *data = NULL;

	if (bValid && m_EventList->IsCapturing())
	{
		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			ULONG64 EventId = m_EventList->GetEventId();
			if (EventId)
			{
				data = (svc_nt_protect_virtual_mem_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_protect_virtual_mem_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_nt_protect_virtual_mem_data));
					data->protocol = svc_nt_protect_virtual_mem;
					data->size = sizeof(svc_nt_protect_virtual_mem_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
					data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
					data->TargetProcessId = (ULONG)(UINT_PTR)ProcessId;
					data->OldBaseAddress = (ULONG64)OldBaseAddress;
					data->OldRegionSize = (ULONG64)OldRegionSize;
					data->NewBaseAddress = (ULONG64)NewBaseAddress;
					data->NewRegionSize = (ULONG64)NewRegionSize;
					data->OldProtect = MyOldProtect;
					data->NewProtect = NewProtect;
					data->ResultStatus = (ULONG)status;

					m_EventList->Lock();
					m_EventList->SendEvent(data);
					m_EventList->SendEvent(CreateCallStackEvent(EventId));
					m_EventList->Unlock();
					m_EventList->NotifyEvent();
				}
			}
			ObDereferenceObject(Process);
		}
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtQueryVirtualMemory
NTSTATUS NewNtQueryVirtualMemory(
	__in HANDLE ProcessHandle,
	__in PVOID BaseAddress,
	__in MEMORY_INFORMATION_CLASS_EX MemoryInformationClass,
	__out_bcount(MemoryInformationLength) PVOID MemoryInformation,
	__in SIZE_T MemoryInformationLength,
	__out_opt PSIZE_T ReturnLength
)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = SyscallmonpFindOrignal(NewNtQueryVirtualMemory);

	NTSTATUS status = original(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

	svc_nt_query_virtual_mem_data *data = NULL;

	if (m_EventList->IsCapturing())
	{
		if (NT_SUCCESS(status) && ARGUMENT_PRESENT(ProcessHandle) && !ObIsKernelHandle(ProcessHandle) && ExGetPreviousMode() == UserMode)
		{
			HANDLE ProcessId = NULL;
			if (NT_SUCCESS(GetProcessIdByHandle(ProcessHandle, &ProcessId)) && ProcessId != PsGetCurrentProcessId())
			{
				PEPROCESS Process = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
				{
					ULONG64 EventId = m_EventList->GetEventId();
					if (EventId)
					{
						data = (svc_nt_query_virtual_mem_data *)
							ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_query_virtual_mem_data), 'TXSB');

						if (data)
						{
							RtlZeroMemory(data, sizeof(svc_nt_query_virtual_mem_data));
							data->protocol = svc_nt_query_virtual_mem;
							data->size = sizeof(svc_nt_query_virtual_mem_data);
							data->time = PerfGetSystemTime();
							data->eventId = EventId;
							data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
							data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
							data->TargetProcessId = (ULONG)(UINT_PTR)ProcessId;
							data->BaseAddress = (ULONG64)BaseAddress;
							data->QueryClass = (ULONG)MemoryInformationClass;
							__try
							{
								if (MemoryInformationClass == MemoryBasicInformationEx)
								{
									PMEMORY_BASIC_INFORMATION pmbi = (PMEMORY_BASIC_INFORMATION)MemoryInformation;
									data->mbi.AllocationBase = (ULONG64)pmbi->AllocationBase;
									data->mbi.BaseAddress = (ULONG64)pmbi->BaseAddress;
									data->mbi.RegionSize = (ULONG64)pmbi->RegionSize;
									data->mbi.AllocationProtect = pmbi->AllocationProtect;
									data->mbi.Protect = pmbi->Protect;
									data->mbi.State = pmbi->State;
									data->mbi.Type = pmbi->Type;
								}
								else if (MemoryInformationClass == MemoryMappedFilenameInformation)
								{
									PMEMORY_SECTION_NAME pSectionName = (PMEMORY_SECTION_NAME)MemoryInformation;
									UNICODE_STRING ustrSectionName;
									RtlInitEmptyUnicodeString(&ustrSectionName, data->MappedFileName, sizeof(data->MappedFileName) - sizeof(WCHAR));
									RtlCopyUnicodeString(&ustrSectionName, &pSectionName->SectionFileName);
								}
							}
							__except (EXCEPTION_EXECUTE_HANDLER) {
							}
							data->ResultStatus = (ULONG)status;

							m_EventList->Lock();
							m_EventList->SendEvent(data);
							m_EventList->SendEvent(CreateCallStackEvent(EventId));
							m_EventList->Unlock();
							m_EventList->NotifyEvent();
						}
					}
					ObDereferenceObject(Process);
				}
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtLoadDriver
NTSTATUS NTAPI NewNtLoadDriver(PUNICODE_STRING DriverServiceName)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = SyscallmonpFindOrignal(NewNtLoadDriver);

	svc_nt_load_driver_data *data = NULL;
	ULONG64 EventId = 0;

	if (m_EventList->IsCapturing())
	{
		__try
		{
			UNICODE_STRING NewServiceName;
			ProbeForRead(DriverServiceName, sizeof(UNICODE_STRING), sizeof(ULONG));
			ProbeForRead(DriverServiceName->Buffer, DriverServiceName->Length, sizeof(WCHAR));

			EventId = m_EventList->GetEventId();
			if (EventId)
			{
				data = (svc_nt_load_driver_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_load_driver_data), 'TXSB');
				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_nt_load_driver_data));
					data->protocol = svc_nt_load_driver;
					data->size = sizeof(svc_nt_load_driver_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
					data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
					data->ResultStatus = STATUS_SUCCESS;
					RtlInitEmptyUnicodeString(&NewServiceName, data->RegisterPath, sizeof(data->RegisterPath) - sizeof(WCHAR));
					RtlCopyUnicodeString(&NewServiceName, DriverServiceName);

					//Read ImagePath...
					HANDLE keyHandle = NULL;
					OBJECT_ATTRIBUTES oa;
					InitializeObjectAttributes(&oa, &NewServiceName,
						OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
						0, 0);
					if (NT_SUCCESS(ZwOpenKey(&keyHandle, KEY_READ, &oa)))
					{
						KEY_VALUE_PARTIAL_INFORMATION info = { 0 };
						ULONG ulValueSize = 0;
						UNICODE_STRING valueName;
						RtlInitUnicodeString(&valueName, L"ImagePath");
						if (ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, &info, sizeof(info), &ulValueSize) && ulValueSize > 0 && (info.Type == REG_SZ || info.Type == REG_EXPAND_SZ))
						{
							PKEY_VALUE_PARTIAL_INFORMATION infoBuffer = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulValueSize, 'TXSB');
							if (infoBuffer != NULL)
							{
								if (NT_SUCCESS(ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation,
									infoBuffer, ulValueSize, &ulValueSize)))
								{
									UNICODE_STRING ustrSrcValue, ustrDstValue;
									ustrSrcValue.Buffer = (PWCH)infoBuffer->Data;
									ustrSrcValue.Length = (USHORT)ulValueSize;
									ustrSrcValue.MaximumLength = (USHORT)ulValueSize;
									RtlInitEmptyUnicodeString(&ustrDstValue, data->ImagePath, sizeof(data->ImagePath) - sizeof(WCHAR));
									RtlCopyUnicodeString(&ustrDstValue, &ustrSrcValue);
								}
								ExFreePoolWithTag(infoBuffer, 'TXSB');
							}
						}

						ZwClose(keyHandle);
					}//ZwOpenKey
				}//data
			}//eventid
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			if (data != NULL)
			{
				ExFreePoolWithTag(data, 'TXSB');
				data = NULL;
			}
		}
	}
	//const auto status = STATUS_ACCESS_DENIED;
	const auto status = original(DriverServiceName);

	if (data)
	{
		data->ResultStatus = status;

		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtCreateMutant
NTSTATUS NTAPI NewNtCreateMutant(
	__out PHANDLE MutantHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in BOOLEAN InitialOwner
)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = SyscallmonpFindOrignal(NewNtCreateMutant);

	const auto status = original(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);

	svc_nt_createopen_mutant_data *data = NULL;
	ULONG64 EventId = 0;

	if (m_EventList->IsCapturing())
	{
		__try
		{
			if (ObjectAttributes && ObjectAttributes->ObjectName)
			{
				UNICODE_STRING ObjectName;
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), sizeof(ULONG));
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, sizeof(WCHAR));

				EventId = m_EventList->GetEventId();
				if (EventId)
				{
					data = (svc_nt_createopen_mutant_data *)
						ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_createopen_mutant_data), 'TXSB');
					if (data)
					{
						RtlZeroMemory(data, sizeof(svc_nt_createopen_mutant_data));
						data->protocol = svc_nt_createopen_mutant;
						data->size = sizeof(svc_nt_createopen_mutant_data);
						data->time = PerfGetSystemTime();
						data->eventId = EventId;
						data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
						data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
						data->ResultStatus = status;
						data->IsOpen = FALSE;
						data->InitialOwner = InitialOwner;
						data->DesiredAccess = (ULONG)DesiredAccess;
						RtlInitEmptyUnicodeString(&ObjectName, data->MutexName, sizeof(data->MutexName) - sizeof(WCHAR));
						RtlCopyUnicodeString(&ObjectName, ObjectAttributes->ObjectName);
					}//data
				}//eventid
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			if (data != NULL)
			{
				ExFreePoolWithTag(data, 'TXSB');
				data = NULL;
			}
		}
	}

	if (data)
	{
		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtOpenMutant
NTSTATUS NTAPI NewNtOpenMutant(
	__out PHANDLE MutantHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes
)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = SyscallmonpFindOrignal(NewNtOpenMutant);

	const auto status = original(MutantHandle, DesiredAccess, ObjectAttributes);

	svc_nt_createopen_mutant_data *data = NULL;
	ULONG64 EventId = 0;

	if (m_EventList->IsCapturing())
	{
		__try
		{
			if (ObjectAttributes && ObjectAttributes->ObjectName)
			{
				UNICODE_STRING ObjectName;
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), sizeof(ULONG));
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, sizeof(WCHAR));

				EventId = m_EventList->GetEventId();
				if (EventId)
				{
					data = (svc_nt_createopen_mutant_data *)
						ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_createopen_mutant_data), 'TXSB');
					if (data)
					{
						RtlZeroMemory(data, sizeof(svc_nt_createopen_mutant_data));
						data->protocol = svc_nt_createopen_mutant;
						data->size = sizeof(svc_nt_createopen_mutant_data);
						data->time = PerfGetSystemTime();
						data->eventId = EventId;
						data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
						data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
						data->ResultStatus = status;
						data->IsOpen = TRUE;
						data->InitialOwner = FALSE;
						data->DesiredAccess = (ULONG)DesiredAccess;
						RtlInitEmptyUnicodeString(&ObjectName, data->MutexName, sizeof(data->MutexName) - sizeof(WCHAR));
						RtlCopyUnicodeString(&ObjectName, ObjectAttributes->ObjectName);
					}//data
				}//eventid
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			if (data != NULL)
			{
				ExFreePoolWithTag(data, 'TXSB');
				data = NULL;
			}
		}
	}

	if (data)
	{
		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtCreateDirectoryObject
NTSTATUS NTAPI NewNtCreateDirectoryObject(
	__out PHANDLE DirectoryHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes
)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = SyscallmonpFindOrignal(NewNtCreateDirectoryObject);

	const auto status = original(DirectoryHandle, DesiredAccess, ObjectAttributes);

	svc_nt_createopen_dirobj_data *data = NULL;
	ULONG64 EventId = 0;

	if (m_EventList->IsCapturing())
	{
		__try
		{
			if (ObjectAttributes && ObjectAttributes->ObjectName)
			{
				UNICODE_STRING ObjectName;
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), sizeof(ULONG));
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, sizeof(WCHAR));

				EventId = m_EventList->GetEventId();
				if (EventId)
				{
					data = (svc_nt_createopen_dirobj_data *)
						ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_createopen_dirobj_data), 'TXSB');
					if (data)
					{
						RtlZeroMemory(data, sizeof(svc_nt_createopen_dirobj_data));
						data->protocol = svc_nt_createopen_dirobj;
						data->size = sizeof(svc_nt_createopen_dirobj_data);
						data->time = PerfGetSystemTime();
						data->eventId = EventId;
						data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
						data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
						data->ResultStatus = status;
						data->IsOpen = FALSE;
						data->DesiredAccess = (ULONG)DesiredAccess;
						RtlInitEmptyUnicodeString(&ObjectName, data->ObjectName, sizeof(data->ObjectName) - sizeof(WCHAR));
						RtlCopyUnicodeString(&ObjectName, ObjectAttributes->ObjectName);
					}//data
				}//eventid
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			if (data != NULL)
			{
				ExFreePoolWithTag(data, 'TXSB');
				data = NULL;
			}
		}
	}

	if (data)
	{
		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtOpenDirectoryObject

NTSTATUS NTAPI NewNtOpenDirectoryObject(
	__out PHANDLE DirectoryHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes
)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = SyscallmonpFindOrignal(NewNtOpenDirectoryObject);

	const auto status = original(DirectoryHandle, DesiredAccess, ObjectAttributes);

	svc_nt_createopen_dirobj_data *data = NULL;
	ULONG64 EventId = 0;

	if (m_EventList->IsCapturing())
	{
		__try
		{
			if (ObjectAttributes && ObjectAttributes->ObjectName)
			{
				UNICODE_STRING ObjectName;
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), sizeof(ULONG));
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, sizeof(WCHAR));

				EventId = m_EventList->GetEventId();
				if (EventId)
				{
					data = (svc_nt_createopen_dirobj_data *)
						ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_createopen_dirobj_data), 'TXSB');
					if (data)
					{
						RtlZeroMemory(data, sizeof(svc_nt_createopen_dirobj_data));
						data->protocol = svc_nt_createopen_dirobj;
						data->size = sizeof(svc_nt_createopen_dirobj_data);
						data->time = PerfGetSystemTime();
						data->eventId = EventId;
						data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
						data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
						data->ResultStatus = status;
						data->IsOpen = TRUE;
						data->DesiredAccess = (ULONG)DesiredAccess;
						RtlInitEmptyUnicodeString(&ObjectName, data->ObjectName, sizeof(data->ObjectName) - sizeof(WCHAR));
						RtlCopyUnicodeString(&ObjectName, ObjectAttributes->ObjectName);
					}//data
				}//eventid
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			if (data != NULL)
			{
				ExFreePoolWithTag(data, 'TXSB');
				data = NULL;
			}
		}
	}

	if (data)
	{
		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtQueryDirectoryObject

NTSTATUS NTAPI NewNtQueryDirectoryObject(
	__in HANDLE DirectoryHandle,
	__out_bcount_opt(Length) PVOID Buffer,
	__in ULONG Length,
	__in BOOLEAN ReturnSingleEntry,
	__in BOOLEAN RestartScan,
	__inout PULONG Context,
	__out_opt PULONG ReturnLength
)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = SyscallmonpFindOrignal(NewNtQueryDirectoryObject);

	const auto status = original(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength);

	svc_nt_query_dirobj_data *data = NULL;
	ULONG64 EventId = 0;

	if (m_EventList->IsCapturing())
	{
		__try
		{
			POBJECT_NAME_INFORMATION pObjectName = NULL;
			PVOID DirectoryObject = NULL;
			NTSTATUS st = ObReferenceObjectByHandle(DirectoryHandle, DIRECTORY_QUERY,
				NULL, ExGetPreviousMode(), &DirectoryObject, NULL);
			if (NT_SUCCESS(st))
			{
				ULONG returnedLength = 0;
				st = ObQueryNameString(DirectoryObject, pObjectName, 0, &returnedLength);
				if (st == STATUS_INFO_LENGTH_MISMATCH)
				{
					pObjectName = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, returnedLength, 'TXSB');
					st = ObQueryNameString(DirectoryObject, pObjectName, returnedLength, &returnedLength);
					if (NT_SUCCESS(st))
					{
						EventId = m_EventList->GetEventId();
						if (EventId)
						{
							data = (svc_nt_query_dirobj_data *)
								ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_query_dirobj_data), 'TXSB');
							if (data)
							{
								RtlZeroMemory(data, sizeof(svc_nt_query_dirobj_data));
								data->protocol = svc_nt_query_dirobj;
								data->size = sizeof(svc_nt_query_dirobj_data);
								data->time = PerfGetSystemTime();
								data->eventId = EventId;
								data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
								data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
								data->ResultStatus = status;
								UNICODE_STRING ObjectName;
								RtlInitEmptyUnicodeString(&ObjectName, data->ObjectName, sizeof(data->ObjectName) - sizeof(WCHAR));
								RtlCopyUnicodeString(&ObjectName, &pObjectName->Name);
							}//data
						}//eventid
						if (pObjectName)
							ExFreePoolWithTag(pObjectName, 'TXSB');
					}//obquery
				}
				ObDereferenceObject(DirectoryObject);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			if (data != NULL)
			{
				ExFreePoolWithTag(data, 'TXSB');
				data = NULL;
			}
		}
	}

	if (data)
	{
		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//Set Windows Hook
static PVOID MakeSetWindowsHookEvent(ULONG64 EventId, ULONG HookThreadId, int HookType, PVOID HookProc, UCHAR chFlags, PVOID hMod, PUNICODE_STRING pustrMod)
{
	svc_nt_setwindowshook_data *data = (svc_nt_setwindowshook_data *)
		ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_setwindowshook_data), 'TXSB');

	if (data)
	{
		RtlZeroMemory(data, sizeof(svc_nt_setwindowshook_data));

		data->protocol = svc_nt_setwindowshook;
		data->size = sizeof(svc_nt_setwindowshook_data);
		data->time = PerfGetSystemTime();
		data->eventId = EventId;
		data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
		data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
		data->HookThreadId = HookThreadId;
		data->HookType = HookType;
		data->HookProc = (ULONG64)HookProc;
		data->Flags = chFlags;
		data->Module = (ULONG64)hMod;

		if (ARGUMENT_PRESENT(pustrMod))
		{
			UNICODE_STRING ustrModName;
			RtlInitEmptyUnicodeString(&ustrModName, data->ModuleName, sizeof(data->ModuleName) - sizeof(WCHAR));
			__try
			{
				ProbeForRead(pustrMod, sizeof(UNICODE_STRING), sizeof(ULONG));
				ProbeForRead(pustrMod->Buffer, pustrMod->Length, sizeof(WCHAR));

				RtlCopyUnicodeString(&ustrModName, pustrMod);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		}
	}

	return data;
}

PVOID NTAPI NewNtUserSetWindowsHookEx(
	HANDLE hmod,
	PUNICODE_STRING pstrLib,
	DWORD ThreadId,
	int nFilterType,
	PVOID pfnFilterProc,
	UCHAR chFlags)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = SyscallmonpFindOrignal(NewNtUserSetWindowsHookEx);

	const auto result = original(hmod, pstrLib, ThreadId, nFilterType, pfnFilterProc, chFlags);

	if (m_EventList->IsCapturing())
	{
		ULONG64 EventId = m_EventList->GetEventId();
		if (EventId)
		{
			svc_nt_setwindowshook_data *data = (svc_nt_setwindowshook_data *)
				MakeSetWindowsHookEvent(EventId, ThreadId,
					nFilterType, pfnFilterProc, chFlags, hmod, pstrLib);
			if (data)
			{
				data->ResultHHook = (ULONG)(UINT_PTR)result;

				m_EventList->Lock();
				m_EventList->SendEvent(data);
				m_EventList->SendEvent(CreateCallStackEvent(EventId));
				m_EventList->Unlock();
				m_EventList->NotifyEvent();
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return result;
}

PVOID NTAPI NewNtUserSetWindowsHookAW(
	IN int nFilterType,
	IN PVOID pfnFilterProc,
	IN UCHAR chFlags)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = SyscallmonpFindOrignal(NewNtUserSetWindowsHookAW);

	const auto result = original(nFilterType, pfnFilterProc, chFlags);

	if (m_EventList->IsCapturing())
	{
		ULONG64 EventId = m_EventList->GetEventId();
		if (EventId)
		{
			svc_nt_setwindowshook_data *data = (svc_nt_setwindowshook_data *)
				MakeSetWindowsHookEvent(EventId, (ULONG)(UINT_PTR)PsGetCurrentThreadId(),
					nFilterType, pfnFilterProc, chFlags, NULL, NULL);
			if (data)
			{
				data->ResultHHook = (ULONG)(UINT_PTR)result;

				m_EventList->Lock();
				m_EventList->SendEvent(data);
				m_EventList->SendEvent(CreateCallStackEvent(EventId));
				m_EventList->Unlock();
				m_EventList->NotifyEvent();
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return result;
}

//NtUserFindWindowEx
PVOID NTAPI NewNtUserFindWindowEx(
	IN PVOID hwndParent,
	IN PVOID hwndChild,
	IN PUNICODE_STRING pstrClassName OPTIONAL,
	IN PUNICODE_STRING pstrWindowName OPTIONAL,
	IN DWORD dwType)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = SyscallmonpFindOrignal(NewNtUserFindWindowEx);

	const auto result = original(hwndParent, hwndChild, pstrClassName, pstrWindowName, dwType);

	if (m_EventList->IsCapturing())
	{
		ULONG64 EventId = m_EventList->GetEventId();
		if (EventId)
		{
			svc_nt_findwindow_data *data = (svc_nt_findwindow_data *)
				ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_findwindow_data), 'TXSB');

			if (data)
			{
				RtlZeroMemory(data, sizeof(svc_nt_findwindow_data));

				data->protocol = svc_nt_findwindow;
				data->size = sizeof(svc_nt_findwindow_data);
				data->time = PerfGetSystemTime();
				data->eventId = EventId;
				data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
				data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
				data->HwndParent = (ULONG)(UINT_PTR)hwndParent;
				data->HwndChild = (ULONG)(UINT_PTR)hwndChild;

				if (ARGUMENT_PRESENT(pstrClassName))
				{
					UNICODE_STRING ustrClass;
					RtlInitEmptyUnicodeString(&ustrClass, data->ClassName, sizeof(data->ClassName) - sizeof(WCHAR));
					__try
					{
						ProbeForRead(pstrClassName, sizeof(UNICODE_STRING), sizeof(ULONG));
						ProbeForRead(pstrClassName->Buffer, pstrClassName->Length, sizeof(WCHAR));

						RtlCopyUnicodeString(&ustrClass, pstrClassName);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
					}
				}

				if (ARGUMENT_PRESENT(pstrWindowName))
				{
					UNICODE_STRING ustrWindow;
					RtlInitEmptyUnicodeString(&ustrWindow, data->WindowName, sizeof(data->WindowName) - sizeof(WCHAR));
					__try
					{
						ProbeForRead(pstrWindowName, sizeof(UNICODE_STRING), sizeof(ULONG));
						ProbeForRead(pstrWindowName->Buffer, pstrWindowName->Length, sizeof(WCHAR));

						RtlCopyUnicodeString(&ustrWindow, pstrWindowName);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
					}
				}

				data->ResultHwnd = (ULONG)(UINT_PTR)result;

				m_EventList->Lock();
				m_EventList->SendEvent(data);
				m_EventList->SendEvent(CreateCallStackEvent(EventId));
				m_EventList->Unlock();
				m_EventList->NotifyEvent();
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return result;
}

int NTAPI NewNtUserInternalGetWindowText(
	IN PVOID hwnd,
	OUT LPWSTR lpString,
	IN int nMaxCount)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = SyscallmonpFindOrignal(NewNtUserInternalGetWindowText);

	const auto result = original(hwnd, lpString, nMaxCount);

	if (m_EventList->IsCapturing())
	{
		ULONG64 EventId = m_EventList->GetEventId();
		if (EventId)
		{
			svc_nt_getwindowtext_data *data = (svc_nt_getwindowtext_data *)
				ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_getwindowtext_data), 'TXSB');

			if (data)
			{
				RtlZeroMemory(data, sizeof(svc_nt_getwindowtext_data));

				data->protocol = svc_nt_getwindowtext;
				data->size = sizeof(svc_nt_getwindowtext_data);
				data->time = PerfGetSystemTime();
				data->eventId = EventId;
				data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
				data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
				data->Hwnd = (ULONG)(UINT_PTR)hwnd;
				data->MaxCount = (ULONG)nMaxCount;

				if (result)
				{
					__try
					{
						ULONG nMaxCopy = min(sizeof(data->WindowName) - sizeof(WCHAR), result * sizeof(WCHAR));
						ProbeForRead(lpString, nMaxCopy, 1);
						memcpy(data->WindowName, lpString, nMaxCopy);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
					}
				}

				data->ResultCount = (ULONG)result;

				m_EventList->Lock();
				m_EventList->SendEvent(data);
				m_EventList->SendEvent(CreateCallStackEvent(EventId));
				m_EventList->Unlock();
				m_EventList->NotifyEvent();
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return result;
}

//NtUserGetClassName
int NTAPI NewNtUserGetClassName(
	IN PVOID hwnd,
	IN int bReal,
	IN OUT PUNICODE_STRING pstrClassName)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = SyscallmonpFindOrignal(NewNtUserGetClassName);

	const auto result = original(hwnd, bReal, pstrClassName);

	if (m_EventList->IsCapturing())
	{
		ULONG64 EventId = m_EventList->GetEventId();
		if (EventId)
		{
			svc_nt_getwindowclass_data *data = (svc_nt_getwindowclass_data *)
				ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_getwindowclass_data), 'TXSB');

			if (data)
			{
				RtlZeroMemory(data, sizeof(svc_nt_getwindowclass_data));

				data->protocol = svc_nt_getwindowclass;
				data->size = sizeof(svc_nt_getwindowclass_data);
				data->time = PerfGetSystemTime();
				data->eventId = EventId;
				data->ProcessId = (ULONG)(UINT_PTR)PsGetCurrentProcessId();
				data->ThreadId = (ULONG)(UINT_PTR)PsGetCurrentThreadId();
				data->Hwnd = (ULONG)(UINT_PTR)hwnd;

				if (result && pstrClassName)
				{
					__try
					{
						data->MaxCount = pstrClassName->MaximumLength / sizeof(WCHAR);
						ULONG nMaxCopy = min(sizeof(data->WindowClass) - sizeof(WCHAR), result * sizeof(WCHAR));
						ProbeForRead(pstrClassName->Buffer, nMaxCopy, 1);
						memcpy(data->WindowClass, pstrClassName->Buffer, nMaxCopy);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
					}
				}

				data->ResultCount = (ULONG)result;

				m_EventList->Lock();
				m_EventList->SendEvent(data);
				m_EventList->SendEvent(CreateCallStackEvent(EventId));
				m_EventList->Unlock();
				m_EventList->NotifyEvent();
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return result;
}

