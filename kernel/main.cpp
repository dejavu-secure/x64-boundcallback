#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    short LoadCount;
    short TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID* EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

PVOID pCallBackPtr = 0;

void DriverUnload()
{
	KeDeregisterBoundCallback(pCallBackPtr);
}

BOUND_CALLBACK_STATUS BoundCallback(VOID)
{
	PKTHREAD pThread = KeGetCurrentThread();
	PKTRAP_FRAME pTrapFrame = *(PKTRAP_FRAME*)((PUCHAR)pThread + 0x90);

	if ((UINT32)pTrapFrame->Rax != 0xBBCCDDEE) return BoundExceptionContinueSearch;

	UINT64 Parameter = (pTrapFrame->Rcx | (pTrapFrame->Rdx << 32));
	DbgPrintEx(0, 0, "Parameter: 0x%llx\n", Parameter);

	pTrapFrame->Rip += 4;
	return BoundExceptionHandled;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistry)
{
	UNREFERENCED_PARAMETER(pRegistry);
	pDriverObject->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;

    ((PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection)->Flags |= 0x20;

	pCallBackPtr = KeRegisterBoundCallback(BoundCallback);
	if (pCallBackPtr) DbgPrintEx(0, 0, "ok");
	else DbgPrintEx(0, 0, "failed");

	return STATUS_SUCCESS;
}