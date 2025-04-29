// payload_dll.cpp - Simple Reflective DLL Test Payload
#include <windows.h>

// Define function pointer type for MessageBoxW
typedef int (WINAPI *MessageBoxW_t)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);

// DllMain function - Entry point of the DLL
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            {
                // Get MessageBoxW dynamically (good practice, avoids static import)
                MessageBoxW_t pMessageBoxW = NULL;
                HMODULE hUser32 = GetModuleHandleW(L"user32.dll"); // User32 is usually loaded
                if (hUser32) {
                    pMessageBoxW = (MessageBoxW_t)GetProcAddress(hUser32, "MessageBoxW");
                }

                // Call MessageBox if pointer is valid
                if (pMessageBoxW) {
                    pMessageBoxW(NULL, L"Reflective DLL loaded successfully!", L"AgentX Test Payload", MB_OK | MB_ICONINFORMATION);
                } else {
                     // Fallback or error handling if MessageBoxW couldn't be found
                     OutputDebugStringA("Test Payload: Failed to get MessageBoxW address.\n");
                     return FALSE; // Indicate failure to load if MessageBox is essential
                }
            }
            break;

        case DLL_THREAD_ATTACH:
            // Do thread-specific initialization here.
            break;

        case DLL_THREAD_DETACH:
            // Do thread-specific cleanup here.
            break;

        case DLL_PROCESS_DETACH:
            // Perform any necessary cleanup.
            break;
    }
    return TRUE; // Successful
} 