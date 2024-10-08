#include <ntifs.h>
#include <ntdef.h>
#include <minwindef.h>
typedef PEPROCESS(*t_PsGetNextProcess)(PEPROCESS Process);
t_PsGetNextProcess PsGetNextProcess;
typedef PEPROCESS _PEPROCESS;
NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);

#define ppid CTL_CODE(FILE_DEVICE_UNKNOWN,0x69,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define CTL_START_LISTENER CTL_CODE(FILE_DEVICE_UNKNOWN,0x70,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define CTL_STOP_LISTENER CTL_CODE(FILE_DEVICE_UNKNOWN,0x71,METHOD_BUFFERED ,FILE_ANY_ACCESS)
UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\Tokenizer");
UNICODE_STRING SymbName = RTL_CONSTANT_STRING(L"\\??\\Tokenizer");
UNICODE_STRING DisabledComponentsValueName = RTL_CONSTANT_STRING(L"DisabledComponents");
UNICODE_STRING TcpIp6ParametersKey = RTL_CONSTANT_STRING(L"Services\\TCPIP6\\Parameters");

LARGE_INTEGER GlobalLargeInteger;
BOOLEAN GlobalRegistryListenerEnabled = FALSE;

HANDLE GlobalSourceToken = NULL;

struct IoControlParam {
    DWORD SourcePid;
    DWORD TargetPid;
    HANDLE SourceToken;
};

struct IoControlStartParam {
    HANDLE SourceToken;
};

NTSTATUS NTAPI MmCopyVirtualMemory
(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);
char* PsGetProcessImageFileName(PEPROCESS Process);

#define MAX_FAST_REFS 7

//
// Executive Fast Reference Structure
//
typedef union _EX_FAST_REF
{
    PVOID Object;
    ULONG_PTR RefCnt : 3;
    ULONG_PTR Value;
} EX_FAST_REF, * PEX_FAST_REF;

void FASTCALL ObReferenceObjectEx(LPVOID Object, int Count)
{
    while (Count--) {
        ObReferenceObject(Object);
    }
}

void FASTCALL ObDereferenceObjectEx(LPVOID Object, int Count)
{
    while (Count--) {
        ObDereferenceObject(Object);
    }
}

FORCEINLINE
EX_FAST_REF
ExSwapFastReference(IN PEX_FAST_REF FastRef,
    IN PVOID Object)
{
    EX_FAST_REF NewValue, OldValue;

    /* Sanity check */
    ASSERT((((ULONG_PTR)Object) & MAX_FAST_REFS) == 0);

    /* Check if an object is being set */
    if (!Object)
    {
        /* Clear the field */
        NewValue.Object = NULL;
    }
    else
    {
        /* Otherwise, we assume the object was referenced and is ready */
        NewValue.Value = (ULONG_PTR)Object | MAX_FAST_REFS;
    }

    /* Update the object */
    OldValue.Object = InterlockedExchangePointer(&FastRef->Object, NewValue.Object);
    return OldValue;
}

/* FAST REFS ******************************************************************/

FORCEINLINE
PVOID
ExGetObjectFastReference(IN EX_FAST_REF FastRef)
{
    /* Return the unbiased pointer */
    return (PVOID)(FastRef.Value & ~MAX_FAST_REFS);
}

FORCEINLINE
ULONG
ExGetCountFastReference(IN EX_FAST_REF FastRef)
{
    /* Return the reference count */
    return (ULONG)FastRef.RefCnt;
}

PVOID
FASTCALL
ObFastReplaceObject(IN PEX_FAST_REF FastRef,
    PVOID Object)
{
    EX_FAST_REF OldValue;
    PVOID OldObject;
    ULONG Count;

    /* Check if we were given an object and reference it 7 times */
    if (Object) ObReferenceObjectEx(Object, MAX_FAST_REFS);

    /* Do the swap */
    OldValue = ExSwapFastReference(FastRef, Object);
    OldObject = ExGetObjectFastReference(OldValue);

    /* Check if we had an active object and dereference it */
    Count = ExGetCountFastReference(OldValue);
    if ((OldObject) && (Count)) ObDereferenceObjectEx(OldObject, Count);

    /* Return the old object */
    return OldObject;
}

//void GetAccessTokenFromPid(int Pid)
//{
//    PVOID process = NULL;
//    PsLookupProcessByProcessId((HANDLE)Pid, &process);
//    PsReferencePrimaryToken(process);
//    ObDereferenceObject(process);
//}

int
ParseAndReplaceEProcessToken2(
    PEPROCESS TargetProcess,
    HANDLE SourceToken
)
{
    //PVOID sys = NULL;
    PACCESS_TOKEN TargetToken;
    //PACCESS_TOKEN sysToken;
    PACCESS_TOKEN AccessToken = NULL;
    __try
    {
        //PsLookupProcessByProcessId((HANDLE)SourcePid, &sys); // system process
        //if (ret != STATUS_SUCCESS)
        //{
        //    if (ret == STATUS_INVALID_PARAMETER)
        //    {
        //        DbgPrint("system process ID was not found.");
        //    }
        //    if (ret == STATUS_INVALID_CID)
        //    {
        //        DbgPrint("the system ID is not valid.");
        //    }
        //    ObDereferenceObject(process);
        //    return (-1);
        //}
        char* ImageName;

        SECURITY_QUALITY_OF_SERVICE Qos;
        Qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        Qos.ImpersonationLevel = SecurityImpersonation;
        Qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
        Qos.EffectiveOnly = FALSE;
        OBJECT_ATTRIBUTES TokenAttrs;
        InitializeObjectAttributes(&TokenAttrs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        TokenAttrs.SecurityQualityOfService = &Qos;

        DbgPrint("SourceToken: %p\n", SourceToken);

        HANDLE NewToken;
        NTSTATUS ret = ZwDuplicateToken(SourceToken, TOKEN_ALL_ACCESS, &TokenAttrs, FALSE, TokenPrimary, &NewToken);
        if (!NT_SUCCESS(ret))
        {
            DbgPrint("NtDuplicateToken failed: %x\n", ret);
            return (-1);
        }

        ret = ObReferenceObjectByHandle(NewToken, TOKEN_ASSIGN_PRIMARY, *SeTokenObjectType, KernelMode, (PVOID*)&AccessToken, NULL);
        ZwClose(NewToken);
        if (ret != STATUS_SUCCESS)
        {
            DbgPrint("ObReferenceObjectByHandle failed: %x\n", ret);
            return (-1);
        }
        EX_FAST_REF NewValue;
        ObReferenceObjectEx(AccessToken, MAX_FAST_REFS);
        NewValue.Value = (ULONG_PTR)AccessToken | MAX_FAST_REFS;

        DbgPrint("target process image name : %s \n", ImageName = PsGetProcessImageFileName(TargetProcess));

        TargetToken = PsReferencePrimaryToken(TargetProcess);
        if (!TargetToken)
        {
            ObDereferenceObject(AccessToken);
            //ObDereferenceObject(sys);
            return (-1);
        }
        DbgPrint("%s token : %p\n", ImageName, TargetToken);

        //sysToken = PsReferencePrimaryToken(sys);
        //if (!sysToken)
        //{
        //    ObDereferenceObject(AccessToken);
        //    ObDereferenceObject(sys);
        //    ObDereferenceObject(TargetToken);
        //    ObDereferenceObject(process);
        //    return (-1);
        //}
        //DbgPrint("system token : %x\n", sysToken);

        ULONG_PTR UniqueProcessIdAddress = (ULONG_PTR)TargetProcess + 0x4b8;

        DbgPrint("%s token address  %llx\n", ImageName, UniqueProcessIdAddress);

        //ULONG_PTR sysadd = (ULONG_PTR)sys + 0x4b8;

        //DbgPrint("system token address : %x\n", sysadd);

        //unsigned long long  usysid = *(PHANDLE)sysadd;

        *(PHANDLE)UniqueProcessIdAddress = NewValue.Object;

        DbgPrint("process %s Token updated to  :%p ", ImageName, *(PHANDLE)(UniqueProcessIdAddress));

        for (int i = 0; i < 8; i++)
        {
            unsigned char f = *(unsigned char*)(UniqueProcessIdAddress + i);
            DbgPrint(" %x ", f);
        }

        DbgPrint("\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return (-1);
    }

    //ObDereferenceObject(AccessToken);
    //ObDereferenceObject(sys);
    ObDereferenceObject(TargetToken);
    //ObDereferenceObject(sysToken);
    return (0);
}

int
ParseAndReplaceEProcessToken(
    int TargetPid,
    HANDLE SourceToken
)
{
    PEPROCESS TargetProcess;
    NTSTATUS ret = PsLookupProcessByProcessId((HANDLE)TargetPid, &TargetProcess);
    if (ret != STATUS_SUCCESS)
    {
        if (ret == STATUS_INVALID_PARAMETER)
        {
            DbgPrint("the process ID was not found.");
        }
        if (ret == STATUS_INVALID_CID)
        {
            DbgPrint("the specified client ID is not valid.");
        }
        return (-1);
    }
    int result = ParseAndReplaceEProcessToken2(TargetProcess, SourceToken);
    ObDereferenceObject(TargetProcess);
    return result;
}

int
ParseAndReplaceEProcessTokenFromPid(
    int SourcePid,
    int TargetPid
)
{
    UNREFERENCED_PARAMETER(SourcePid);

    PEPROCESS TargetProcess;
    NTSTATUS ret = PsLookupProcessByProcessId((HANDLE)TargetPid, &TargetProcess);
    if (ret != STATUS_SUCCESS)
    {
        if (ret == STATUS_INVALID_PARAMETER)
        {
            DbgPrint("the process ID was not found.");
        }
        if (ret == STATUS_INVALID_CID)
        {
            DbgPrint("the specified client ID is not valid.");
        }
        return (-1);
    }

    PEPROCESS SourceProcess;
    ret = PsLookupProcessByProcessId((HANDLE)SourcePid, &SourceProcess);
    if (ret != STATUS_SUCCESS)
    {
        ObDereferenceObject(TargetProcess);
        if (ret == STATUS_INVALID_PARAMETER)
        {
            DbgPrint("the process ID was not found.");
        }
        if (ret == STATUS_INVALID_CID)
        {
            DbgPrint("the specified client ID is not valid.");
        }
        return (-1);
    }



    PACCESS_TOKEN SourceAccessToken = PsReferencePrimaryToken(SourceProcess);
    HANDLE SourceProcessHandle;
    ret = ObOpenObjectByPointer(SourceAccessToken, OBJ_KERNEL_HANDLE, NULL, TOKEN_ALL_ACCESS, *SeTokenObjectType, KernelMode, &SourceProcessHandle);
    if (!NT_SUCCESS(ret))
    {
        ObDereferenceObject(SourceAccessToken);
        ObDereferenceObject(SourceProcess);
        ObDereferenceObject(TargetProcess);
        DbgPrint("ObOpenObjectByPointer failed: %x", ret);
        return -1;
    }

    int result = ParseAndReplaceEProcessToken2(TargetProcess, SourceProcessHandle);

    ZwClose(SourceProcessHandle);
    ObDereferenceObject(SourceAccessToken);
    ObDereferenceObject(SourceProcess);
    ObDereferenceObject(TargetProcess);

    return result;
}

EXTERN_C
VOID
OnProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);
    if (CreateInfo && CreateInfo->CommandLine && GlobalSourceToken)
    {
        DbgPrint("Command line: %wZ\n", CreateInfo->CommandLine);
        if (CreateInfo->CommandLine->Length > 2 && wcswcs(CreateInfo->CommandLine->Buffer, L"powershell"))
        {
            DbgPrint("Match command line\n");
            ParseAndReplaceEProcessToken2(Process, GlobalSourceToken);
        }
    }
}

void
StopListenProcess()
{
    if (GlobalSourceToken)
    {
        ZwClose(GlobalSourceToken);
        GlobalSourceToken = NULL;
        PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
    }
}

/// 回调函数
NTSTATUS MyRegCallback(
    __in PVOID CallbackContext,
    __in_opt PVOID Argument1, ///REG_NOTIFY_CLASS,标识注册表的操作
    __in_opt PVOID Argument2) ///KEY_INFORMATION，拿到相关的信息，比如文件路径
{
    NTSTATUS RegistryRet = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument2);
    if ((REG_NOTIFY_CLASS)(unsigned long long)Argument1 == RegNtSetValueKey)
    {
        PREG_SET_VALUE_KEY_INFORMATION SetValueInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        if (SetValueInfo && SetValueInfo->ValueName && SetValueInfo->Object)
        {
            if (SetValueInfo->ValueName->Buffer && SetValueInfo->ValueName->Length > 2)
            {
                if (RtlCompareUnicodeString(SetValueInfo->ValueName, &DisabledComponentsValueName, TRUE) == 0)
                {
                    PCUNICODE_STRING ObjectName = NULL;
                    NTSTATUS ret = CmCallbackGetKeyObjectIDEx(&GlobalLargeInteger, SetValueInfo->Object, NULL, &ObjectName, 0);
                    if (NT_SUCCESS(ret))
                    {
                        if (ObjectName)
                        {
                            if (ObjectName->Buffer && ObjectName->Length > 2)
                            {
                                if (RtlSuffixUnicodeString(&TcpIp6ParametersKey, ObjectName, TRUE))
                                {
                                    if (SetValueInfo->DataSize >= sizeof(DWORD) && SetValueInfo->Data && SetValueInfo->Type == REG_DWORD)
                                    {
                                        *(DWORD*)SetValueInfo->Data = 0;
                                    }
                                }
                            }
                            CmCallbackReleaseKeyObjectIDEx(ObjectName);
                        }
                    }
                }
            }
        }
    }

    return RegistryRet;
}

#define CALLBACK_LOW_ALTITUDE      L"380000"
#define CALLBACK_ALTITUDE          L"380010"
#define CALLBACK_HIGH_ALTITUDE     L"380020"

void StartRegistryListener(PDRIVER_OBJECT driverObject)
{
    if (!GlobalRegistryListenerEnabled)
    {
        UNICODE_STRING Altitude = RTL_CONSTANT_STRING(CALLBACK_ALTITUDE);
        NTSTATUS ret = CmRegisterCallbackEx(MyRegCallback, &Altitude, driverObject, NULL, &GlobalLargeInteger, NULL);
        if (NT_SUCCESS(ret))
        {
            GlobalRegistryListenerEnabled = TRUE;
            DbgPrint("CmRegisterCallbackEx success\n");
        }
        else
        {
            DbgPrint("CmRegisterCallbackEx failed: %x\n", ret);
        }
    }
}

void StopRegistryListener()
{
    if (GlobalRegistryListenerEnabled)
    {
        if (NT_SUCCESS(CmUnRegisterCallback(GlobalLargeInteger)))
        {
            GlobalRegistryListenerEnabled = FALSE;
        }
    }
}

void
unloadv(
    PDRIVER_OBJECT driverObject
)
{
    StopRegistryListener();
    StopListenProcess();
    IoDeleteSymbolicLink(&SymbName);
    IoDeleteDevice(driverObject->DeviceObject);
    DbgPrint("Driver Unloaded\n");
}

NTSTATUS processIoctlRequest(
    DEVICE_OBJECT* DeviceObject,
    IRP* Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION  pstack = IoGetCurrentIrpStackLocation(Irp);
    int pstatus = 0;
    if (pstack->Parameters.DeviceIoControl.IoControlCode == ppid)
    {
        struct IoControlParam Param;
        RtlCopyMemory(&Param, Irp->AssociatedIrp.SystemBuffer, sizeof(Param));

        if (Param.SourceToken)
        {
            pstatus = ParseAndReplaceEProcessToken(Param.TargetPid, Param.SourceToken);
        }
        else if (Param.SourcePid)
        {
            pstatus = ParseAndReplaceEProcessTokenFromPid(Param.SourcePid, Param.TargetPid);
        }
        else
        {
            pstatus = -1;
        }

        DbgPrint("Received source pid: %d, target pid: %d\n", Param.SourcePid, Param.TargetPid);
    }
    if (pstack->Parameters.DeviceIoControl.IoControlCode == CTL_START_LISTENER)
    {
        StopRegistryListener();
        StartRegistryListener(DeviceObject->DriverObject);

        StopListenProcess();

        DbgPrint("Set listener\n");

        struct IoControlStartParam Param;
        RtlCopyMemory(&Param, Irp->AssociatedIrp.SystemBuffer, sizeof(Param));

        SECURITY_QUALITY_OF_SERVICE Qos;
        Qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        Qos.ImpersonationLevel = SecurityImpersonation;
        Qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
        Qos.EffectiveOnly = FALSE;
        OBJECT_ATTRIBUTES TokenAttrs;
        InitializeObjectAttributes(&TokenAttrs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        TokenAttrs.SecurityQualityOfService = &Qos;

        DbgPrint("SourceToken: %p\n", Param.SourceToken);

        HANDLE NewToken;
        NTSTATUS ret = ZwDuplicateToken(Param.SourceToken, TOKEN_ALL_ACCESS, &TokenAttrs, FALSE, TokenPrimary, &NewToken);
        if (!NT_SUCCESS(ret))
        {
            DbgPrint("NtDuplicateToken failed: %x\n", ret);
            return (-1);
        }

        GlobalSourceToken = NewToken;
        PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
    }
    if (pstack->Parameters.DeviceIoControl.IoControlCode == CTL_STOP_LISTENER)
    {
        StopRegistryListener();

        DbgPrint("Remove listener\n");

        StopListenProcess();
    }
    
    memcpy(Irp->AssociatedIrp.SystemBuffer, &pstatus, sizeof(pstatus));
    Irp->IoStatus.Status = 0;
    Irp->IoStatus.Information = sizeof(int);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return 0;
}

NTSTATUS IRP_MJCreate(DEVICE_OBJECT* DeviceObject,
    IRP* Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    DbgPrint("IRP_CREATED\n");
    return 0;
}
NTSTATUS IRP_MJClose(DEVICE_OBJECT* DeviceObject,
    IRP* Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    DbgPrint("IRP_Closed\n");
    return 0;

}

NTSTATUS
DriverEntry(
    PDRIVER_OBJECT driverObject,
    PUNICODE_STRING registryPath
)
{
    DbgPrint("Driver Loaded\n");
    UNREFERENCED_PARAMETER(registryPath);
    UNREFERENCED_PARAMETER(driverObject);

    driverObject->DriverUnload = &unloadv;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = processIoctlRequest;
    driverObject->MajorFunction[IRP_MJ_CREATE] = IRP_MJCreate;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = IRP_MJClose;

    IoCreateDevice(driverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED, FALSE, &driverObject->DeviceObject);
    IoCreateSymbolicLink(&SymbName, &DeviceName);

    StartRegistryListener(driverObject);

    return STATUS_SUCCESS;
}
