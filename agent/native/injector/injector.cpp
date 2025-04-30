#include "injector.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cwctype>

// === Поиск процессов браузеров ===

// Список имен исполняемых файлов браузеров (в нижнем регистре)
const std::vector<std::wstring> browserExes = {
    L"chrome.exe",
    L"firefox.exe",
    L"msedge.exe",
    L"opera.exe",
    L"brave.exe",
    L"vivaldi.exe"
    // Добавить другие по необходимости
};

// Вспомогательная функция для конвертации wstring в нижний регистр
std::wstring ToLowerW(const std::wstring& str) {
    std::wstring lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::towlower);
    return lowerStr;
}

DLLEXPORT bool FindBrowserProcesses(BrowserProcessInfo** processes, size_t* count) {
    if (!processes || !count) {
        return false;
    }

    *processes = nullptr;
    *count = 0;

    std::vector<BrowserProcessInfo> foundProcesses;
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    // Получаем список ID всех процессов
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return false;
    }

    // Вычисляем количество процессов
    cProcesses = cbNeeded / sizeof(DWORD);

    // Перебираем каждый процесс
    for (i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
            if (NULL != hProcess) {
                HMODULE hMod;
                DWORD cbNeeded2;
                wchar_t szProcessName[MAX_PATH] = L"<unknown>";

                // Получаем имя исполняемого файла
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded2)) {
                    GetModuleBaseNameW(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(wchar_t));

                    std::wstring processNameLower = ToLowerW(szProcessName);

                    // Сравниваем с нашим списком браузеров
                    for (const auto& browserExe : browserExes) {
                        if (processNameLower == browserExe) {
                            BrowserProcessInfo info;
                            info.processId = aProcesses[i];
                            wcscpy_s(info.processName, MAX_PATH, szProcessName);
                            foundProcesses.push_back(info);
                            break; // Нашли совпадение, переходим к следующему процессу
                        }
                    }
                }
                CloseHandle(hProcess);
            }
        }
    }

    // Копируем результаты в выходной буфер (выделяем память)
    if (!foundProcesses.empty()) {
        size_t bufferSize = foundProcesses.size() * sizeof(BrowserProcessInfo);
        *processes = (BrowserProcessInfo*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
        if (*processes == nullptr) {
            return false; // Ошибка выделения памяти
        }
        memcpy(*processes, foundProcesses.data(), bufferSize);
        *count = foundProcesses.size();
    }

    return true;
}

DLLEXPORT void FreeBrowserProcesses(BrowserProcessInfo* processes) {
    if (processes != nullptr) {
        HeapFree(GetProcessHeap(), 0, processes);
    }
}

// === Конец Поиска процессов браузеров ===

// === Инъекция DLL ===

// Стандартная DLL инъекция через CreateRemoteThread + LoadLibrary
DLLEXPORT bool InjectDLL(DWORD processId, const char* dllPath) {
    if (processId == 0 || dllPath == nullptr || strlen(dllPath) == 0) {
        return false;
    }

    HANDLE hProcess = NULL;
    LPVOID pDllPathRemote = NULL;
    HANDLE hThread = NULL;
    bool success = false;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        // Это очень странно, если kernel32 не загружен
        return false;
    }

    LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA) {
        return false;
    }

    // 1. Открываем целевой процесс
    hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | 
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 
        FALSE, processId
    );
    if (hProcess == NULL) {
        goto cleanup;
    }

    // 2. Выделяем память в целевом процессе под путь к DLL
    size_t dllPathSize = strlen(dllPath) + 1;
    pDllPathRemote = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pDllPathRemote == NULL) {
        goto cleanup;
    }

    // 3. Записываем путь к DLL в память целевого процесса
    if (!WriteProcessMemory(hProcess, pDllPathRemote, dllPath, dllPathSize, NULL)) {
        goto cleanup;
    }

    // 4. Создаем удаленный поток, который вызовет LoadLibraryA
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pDllPathRemote, 0, NULL);
    if (hThread == NULL) {
        goto cleanup;
    }

    // 5. Ожидаем завершения потока и проверяем результат
    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    if (GetExitCodeThread(hThread, &exitCode)) {
        // LoadLibrary возвращает HMODULE (не NULL в случае успеха)
        if (exitCode != 0) {
            success = true;
        } 
        // В противном случае exitCode == 0, инъекция не удалась в целевом процессе
    } else {
        // Не удалось получить код завершения потока
        success = false;
    }

cleanup:
    if (hThread != NULL) {
        CloseHandle(hThread);
    }
    // 6. Освобождаем память в целевом процессе
    if (pDllPathRemote != NULL && hProcess != NULL) {
        VirtualFreeEx(hProcess, pDllPathRemote, 0, MEM_RELEASE);
    }
    if (hProcess != NULL) {
        CloseHandle(hProcess);
    }

    return success;
}

// === Конец Инъекции DLL ===

// ... остальной код injector.cpp ... 