#include <ntddk.h>

//
static GUID ProviderGuid = {
  0xa4b4ba50, 0xa667, 0x43f5, { 0x91, 0x9b, 0x1e, 0x52, 0xa6, 0xd6, 0x9b, 0xd5 }
};

const EVENT_DESCRIPTOR TransferEvent = { 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

static REGHANDLE hSyscallmonReg = NULL;

NTSTATUS SyscallmonEventTraceInit(void)
{
	NTSTATUS ntStatus = EtwRegister(&ProviderGuid, NULL, NULL, &hSyscallmonReg);

	return ntStatus;
}

NTSTATUS SyscallmonEventTraceUninit(void)
{
	NTSTATUS ntStatus = EtwUnregister(hSyscallmonReg);
	hSyscallmonReg = NULL;

	return ntStatus;
}

NTSTATUS SyscallmonEventWriteMessage(void *msg, ULONG len)
{
	/*
	NTSTATUS
		EtwWriteEx(
			_In_ REGHANDLE RegHandle,
			_In_ PCEVENT_DESCRIPTOR EventDescriptor,
			_In_ ULONG64 Filter,
			_In_ ULONG Flags,
			_In_opt_ LPCGUID ActivityId,
			_In_opt_ LPCGUID RelatedActivityId,
			_In_ ULONG UserDataCount,
			_In_reads_opt_(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
		);
	NTSTATUS
		EtwWrite(
			_In_ REGHANDLE RegHandle,
			_In_ PCEVENT_DESCRIPTOR EventDescriptor,
			_In_opt_ LPCGUID ActivityId,
			_In_ ULONG UserDataCount,
			_In_reads_opt_(UserDataCount) PEVENT_DATA_DESCRIPTOR  UserData
		);
	*/
	if (hSyscallmonReg)
	{
		EVENT_DATA_DESCRIPTOR edd;
		EventDataDescCreate(&edd, msg, len);
		return EtwWrite(hSyscallmonReg, &TransferEvent, NULL, 1, &edd);
	}
	return STATUS_UNSUCCESSFUL;
}

