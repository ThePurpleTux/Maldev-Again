#pragma once
#include <windows.h>

/*--------------------------------------------------------------------
  STRUCTURES
--------------------------------------------------------------------*/
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA           LoaderData;
	PVOID                   ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;

} CLIENT_ID, * PCLIENT_ID;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
	ULONG Flags;
	PCHAR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME* Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _GDI_TEB_BATCH {
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
	struct __RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	PACTIVATION_CONTEXT ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _TEB {
	NT_TIB				NtTib;
	PVOID				EnvironmentPointer;
	CLIENT_ID			ClientId;
	PVOID				ActiveRpcHandle;
	PVOID				ThreadLocalStoragePointer;
	PPEB				ProcessEnvironmentBlock;
	ULONG               LastErrorValue;
	ULONG               CountOfOwnedCriticalSections;
	PVOID				CsrClientThread;
	PVOID				Win32ThreadInfo;
	ULONG               User32Reserved[26];
	ULONG               UserReserved[5];
	PVOID				WOW32Reserved;
	LCID                CurrentLocale;
	ULONG               FpSoftwareStatusRegister;
	PVOID				SystemReserved1[54];
	LONG                ExceptionCode;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x30 - 3 * sizeof(PVOID)];
	ULONG                  TxFsContext;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x34 - 3 * sizeof(PVOID)];
#else
	ACTIVATION_CONTEXT_STACK ActivationContextStack;
	UCHAR                  SpareBytes1[24];
#endif
	GDI_TEB_BATCH			GdiTebBatch;
	CLIENT_ID				RealClientId;
	PVOID					GdiCachedProcessHandle;
	ULONG                   GdiClientPID;
	ULONG                   GdiClientTID;
	PVOID					GdiThreadLocalInfo;
	PSIZE_T					Win32ClientInfo[62];
	PVOID					glDispatchTable[233];
	PSIZE_T					glReserved1[29];
	PVOID					glReserved2;
	PVOID					glSectionInfo;
	PVOID					glSection;
	PVOID					glTable;
	PVOID					glCurrentRC;
	PVOID					glContext;
	NTSTATUS                LastStatusValue;
	UNICODE_STRING			StaticUnicodeString;
	WCHAR                   StaticUnicodeBuffer[261];
	PVOID					DeallocationStack;
	PVOID					TlsSlots[64];
	LIST_ENTRY				TlsLinks;
	PVOID					Vdm;
	PVOID					ReservedForNtRpc;
	PVOID					DbgSsReserved[2];
#if (NTDDI_VERSION >= NTDDI_WS03)
	ULONG                   HardErrorMode;
#else
	ULONG                  HardErrorsAreDisabled;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID					Instrumentation[13 - sizeof(GUID) / sizeof(PVOID)];
	GUID                    ActivityId;
	PVOID					SubProcessTag;
	PVOID					EtwLocalData;
	PVOID					EtwTraceData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PVOID					Instrumentation[14];
	PVOID					SubProcessTag;
	PVOID					EtwLocalData;
#else
	PVOID					Instrumentation[16];
#endif
	PVOID					WinSockData;
	ULONG					GdiBatchCount;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	BOOLEAN                SpareBool0;
	BOOLEAN                SpareBool1;
	BOOLEAN                SpareBool2;
#else
	BOOLEAN                InDbgPrint;
	BOOLEAN                FreeStackOnTermination;
	BOOLEAN                HasFiberData;
#endif
	UCHAR                  IdealProcessor;
#if (NTDDI_VERSION >= NTDDI_WS03)
	ULONG                  GuaranteedStackBytes;
#else
	ULONG                  Spare3;
#endif
	PVOID				   ReservedForPerf;
	PVOID				   ReservedForOle;
	ULONG                  WaitingOnLoaderLock;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID				   SavedPriorityState;
	ULONG_PTR			   SoftPatchPtr1;
	ULONG_PTR			   ThreadPoolData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	ULONG_PTR			   SparePointer1;
	ULONG_PTR              SoftPatchPtr1;
	ULONG_PTR              SoftPatchPtr2;
#else
	Wx86ThreadState        Wx86Thread;
#endif
	PVOID* TlsExpansionSlots;
#if defined(_WIN64) && !defined(EXPLICIT_32BIT)
	PVOID                  DeallocationBStore;
	PVOID                  BStoreLimit;
#endif
	ULONG                  ImpersonationLocale;
	ULONG                  IsImpersonating;
	PVOID                  NlsCache;
	PVOID                  pShimData;
	ULONG                  HeapVirtualAffinity;
	HANDLE                 CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME      ActiveFrame;
#if (NTDDI_VERSION >= NTDDI_WS03)
	PVOID FlsData;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID PreferredLangauges;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;
	union
	{
		struct
		{
			USHORT SpareCrossTebFlags : 16;
		};
		USHORT CrossTebFlags;
	};
	union
	{
		struct
		{
			USHORT DbgSafeThunkCall : 1;
			USHORT DbgInDebugPrint : 1;
			USHORT DbgHasFiberData : 1;
			USHORT DbgSkipThreadAttach : 1;
			USHORT DbgWerInShipAssertCode : 1;
			USHORT DbgIssuedInitialBp : 1;
			USHORT DbgClonedThread : 1;
			USHORT SpareSameTebBits : 9;
		};
		USHORT SameTebFlags;
	};
	PVOID TxnScopeEntercallback;
	PVOID TxnScopeExitCAllback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG ProcessRundown;
	ULONG64 LastSwitchTime;
	ULONG64 TotalSwitchOutTime;
	LARGE_INTEGER WaitReasonBitMap;
#else
	BOOLEAN SafeThunkCall;
	BOOLEAN BooleanSpare[3];
#endif
} TEB, * PTEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PACTIVATION_CONTEXT EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;

} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _INITIAL_TEB {
	PVOID                StackBase;
	PVOID                StackLimit;
	PVOID                StackCommit;
	PVOID                StackCommitMax;
	PVOID                StackReserved;
} INITIAL_TEB, * PINITIAL_TEB;

// -----------------------------------------------------------------------
// Structs for NtCreateUserProcess
// -----------------------------------------------------------------------
//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L2047

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;

} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];

} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

#define PS_ATTRIBUTE_NUMBER_MASK    0x0000ffff
#define PS_ATTRIBUTE_THREAD         0x00010000 // Attribute may be used with thread creation
#define PS_ATTRIBUTE_INPUT          0x00020000 // Attribute is input only
#define PS_ATTRIBUTE_ADDITIVE       0x00040000 // Attribute may be "accumulated", e.g. bitmasks, counters, etc.

//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L1930

typedef enum _PS_ATTRIBUTE_NUM
{
    PsAttributeParentProcess,                   // in HANDLE
    PsAttributeDebugPort,                       // in HANDLE
    PsAttributeToken,                           // in HANDLE
    PsAttributeClientId,                        // out PCLIENT_ID
    PsAttributeTebAddress,                      // out PTEB
    PsAttributeImageName,                       // in PWSTR
    PsAttributeImageInfo,                       // out PSECTION_IMAGE_INFORMATION
    PsAttributeMemoryReserve,                   // in PPS_MEMORY_RESERVE
    PsAttributePriorityClass,                   // in UCHAR
    PsAttributeErrorMode,                       // in ULONG
    PsAttributeStdHandleInfo,                   // in PPS_STD_HANDLE_INFO
    PsAttributeHandleList,                      // in PHANDLE
    PsAttributeGroupAffinity,                   // in PGROUP_AFFINITY
    PsAttributePreferredNode,                   // in PUSHORT
    PsAttributeIdealProcessor,                  // in PPROCESSOR_NUMBER
    PsAttributeUmsThread,                       // see MSDN UpdateProceThreadAttributeList (CreateProcessW) - in PUMS_CREATE_THREAD_ATTRIBUTES
    PsAttributeMitigationOptions,               // in UCHAR
    PsAttributeProtectionLevel,                 // in ULONG
    PsAttributeSecureProcess,                   // since THRESHOLD (Virtual Secure Mode, Device Guard)
    PsAttributeJobList,
    PsAttributeChildProcessPolicy,              // since THRESHOLD2
    PsAttributeAllApplicationPackagesPolicy,    // since REDSTONE
    PsAttributeWin32kFilter,
    PsAttributeSafeOpenPromptOriginClaim,
    PsAttributeBnoIsolation,
    PsAttributeDesktopAppPolicy,
    PsAttributeMax
} PS_ATTRIBUTE_NUM;

//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L1974

#define PsAttributeValue(Number, Thread, Input, Additive)		\
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK)	|					\
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0)	|					\
    ((Input) ? PS_ATTRIBUTE_INPUT : 0)		|					\
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

// Specifies the parent process of the new process
#define PS_ATTRIBUTE_PARENT_PROCESS \
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)
// Specifies the debug port to use
#define PS_ATTRIBUTE_DEBUG_PORT \
    PsAttributeValue(PsAttributeDebugPort, FALSE, TRUE, TRUE)
// Specifies the token to assign to the new process
#define PS_ATTRIBUTE_TOKEN \
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)
// Specifies the client ID to assign to the new process
#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)
// Specifies the TEB address to use for the new process
#define PS_ATTRIBUTE_TEB_ADDRESS \
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)
// Specifies the image name of the new process
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
// Specifies the image information of the new process
#define PS_ATTRIBUTE_IMAGE_INFO \
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)
// Specifies the amount of memory to reserve for the new process
#define PS_ATTRIBUTE_MEMORY_RESERVE \
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)
// Specifies the priority class to use for the new process
#define PS_ATTRIBUTE_PRIORITY_CLASS \
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)
// Specifies the error mode to use for the new process
#define PS_ATTRIBUTE_ERROR_MODE \
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)
// Specifies the standard handle information to use for the new process
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)
// Specifies the handle list to use for the new process
#define PS_ATTRIBUTE_HANDLE_LIST \
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)
// Specifies the group affinity to use for the new process
#define PS_ATTRIBUTE_GROUP_AFFINITY \
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)
// Specifies the preferred NUMA node to use for the new process
#define PS_ATTRIBUTE_PREFERRED_NODE \
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)
// Specifies the ideal processor to use for the new process
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)
// Specifies the process mitigation options to use for the new process
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE)
// Specifies the protection level to use for the new process
#define PS_ATTRIBUTE_PROTECTION_LEVEL \
    PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, FALSE)
// Specifies the UMS thread to associate with the new process
#define PS_ATTRIBUTE_UMS_THREAD \
    PsAttributeValue(PsAttributeUmsThread, TRUE, TRUE, FALSE)
// Specifies whether the new process is a secure process
#define PS_ATTRIBUTE_SECURE_PROCESS \
    PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE)
// Specifies the job list to associate with the new process
#define PS_ATTRIBUTE_JOB_LIST \
    PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE)
// Specifies the child process policy to use for the new process
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY \
    PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE)
// Specifies the all application packages policy to use for the new process
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY \
    PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE)
// Specifies the child process should have access to the Win32k subsystem.
#define PS_ATTRIBUTE_WIN32K_FILTER	\
    PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE)
// Specifies the child process is allowed to claim a specific origin when making a safe file open prompt
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM	\
    PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
// Specifies the child process is isolated using the BNO framework
#define PS_ATTRIBUTE_BNO_ISOLATION	\
    PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE)
// Specifies that the child's process desktop application policy
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY	\
    PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE)


//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L1315

#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT 0x00000002 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS 0x00000040 // NtCreateUserProcess only
#define PROCESS_CREATE_FLAGS_CREATE_SESSION 0x00000080 // NtCreateProcessEx & NtCreateUserProcess, requires SeLoadDriver
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT 0x00000100 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000200 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY 0x00000400 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_RELEASE_SECTION 0x00001000 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS 0x00008000 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_CREATE_STORE 0x00020000 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_USE_PROTECTED_ENVIRONMENT 0x00040000 // NtCreateProcessEx & NtCreateUserProcess



//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h#L2688

#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001	// indicates that the parameters passed to the process are already in a normalized form
#define RTL_USER_PROC_PROFILE_USER 0x00000002		// enables user-mode profiling for the process
#define RTL_USER_PROC_PROFILE_KERNEL 0x00000004		// enables kernel-mode profiling for the process
#define RTL_USER_PROC_PROFILE_SERVER 0x00000008		// enables server-mode profiling for the process
#define RTL_USER_PROC_RESERVE_1MB 0x00000020		// reserves 1 megabyte (MB) of virtual address space for the process
#define RTL_USER_PROC_RESERVE_16MB 0x00000040		// reserves 16 MB of virtual address space for the process
#define RTL_USER_PROC_CASE_SENSITIVE 0x00000080		// sets the process to be case-sensitive
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT 0x00000100	// disables heap decommitting for the process
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL 0x00001000	// enables local DLL redirection for the process
#define RTL_USER_PROC_APP_MANIFEST_PRESENT 0x00002000	// indicates that an application manifest is present for the process
#define RTL_USER_PROC_IMAGE_KEY_MISSING 0x00004000	// indicates that the image key is missing for the process
#define RTL_USER_PROC_OPTIN_PROCESS 0x00020000		// indicates that the process has opted in to some specific behavior or feature


typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName,
    PsCreateSuccess,
    PsCreateMaximumStates

} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                } s1;
            } u1;
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        struct
        {
            HANDLE FileHandle;
        } FailSection;

        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;

        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1;
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                } s2;
            } u2;
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };

} PS_CREATE_INFO, * PPS_CREATE_INFO;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;

} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PWCHAR Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;

} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;