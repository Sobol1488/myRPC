#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <pwd.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <sys/file.h>
#include <sys/select.h>
#include "libmysyslog.h"

#define BUFFER_SIZE 2048
#define MAX_USERS 100
#define CONFIG_DIR "/etc/myRPC"
#define CONFIG_FILE CONFIG_DIR "/myRPC.conf"
#define USERS_FILE CONFIG_DIR "/client.conf"

/* Цвета для консоли */
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_RESET   "\x1b[0m"

/* Макросы для логирования (переименованы, чтобы избежать конфликтов) */
#define LOG_MSG_INFO(fmt, ...) do { \
    printf(COLOR_GREEN "[INFO] " fmt COLOR_RESET "\n", ##__VA_ARGS__); \
    char log_buf[BUFFER_SIZE]; \
    snprintf(log_buf, sizeof(log_buf), fmt, ##__VA_ARGS__); \
    log_info(log_buf); \
} while(0)

#define LOG_MSG_ERROR(fmt, ...) do { \
    fprintf(stderr, COLOR_RED "[ERROR] %s:%d: " fmt COLOR_RESET "\n", \
            __FILE__, __LINE__, ##__VA_ARGS__); \
    char log_buf[BUFFER_SIZE]; \
    snprintf(log_buf, sizeof(log_buf), fmt, ##__VA_ARGS__); \
    log_error(log_buf); \
} while(0)

#define LOG_MSG_WARN(fmt, ...) do { \
    printf(COLOR_YELLOW "[WARN] " fmt COLOR_RESET "\n", ##__VA_ARGS__); \
    char log_buf[BUFFER_SIZE]; \
    snprintf(log_buf, sizeof(log_buf), fmt, ##__VA_ARGS__); \
    log_info(log_buf); \
} while(0)

typedef enum {
    SOCKET_STREAM,
    SOCKET_DGRAM
} socket_type_t;

typedef struct {
    int port;
    socket_type_t socket_type;
} server_config_t;

typedef struct {
    char *users[MAX_USERS];
    int count;
} users_list_t;

/* Парсинг конфигурационного файла */
int parse_config(server_config_t *config) {
    FILE *file = fopen(CONFIG_FILE, "r");
    if (!file) {
        LOG_MSG_ERROR("Cannot open config file %s: %s", CONFIG_FILE, strerror(errno));
        return -1;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char key[50], value[50];
        if (sscanf(line, "%s = %s", key, value) == 2) {
            if (strcmp(key, "port") == 0) {
                config->port = atoi(value);
            } else if (strcmp(key, "socket_type") == 0) {
                if (strcmp(value, "stream") == 0) {
                    config->socket_type = SOCKET_STREAM;
                } else if (strcmp(value, "dgram") == 0) {
                    config->socket_type = SOCKET_DGRAM;
                }
            }
        }
    }

    fclose(file);
    return 0;
}

/* Загрузка списка пользователей */
int load_users(users_list_t *users) {
    FILE *file = fopen(USERS_FILE, "r");
    if (!file) {
        LOG_MSG_ERROR("Cannot open users file %s: %s", USERS_FILE, strerror(errno));
        return -1;
    }

    char line[BUFFER_SIZE];
    users->count = 0;
    while (fgets(line, sizeof(line), file) && users->count < MAX_USERS) {
        if (line[0] == '#' || line[0] == '\n') continue;
        line[strcspn(line, "\n")] = '\0';
        users->users[users->count++] = strdup(line);
    }

    fclose(file);
    return 0;
}

/* Проверка пользователя */
int is_user_allowed(users_list_t *users, const char *username) {
    for (int i = 0; i < users->count; i++) {
        if (strcmp(users->users[i], username) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Выполнение команды */
int execute_command(const char *command, char *output, size_t output_size) {
    FILE *fp = popen(command, "r");
    if (!fp) {
        LOG_MSG_ERROR("Command execution failed: %s", strerror(errno));
        return -1;
    }

    size_t total = 0;
    char *ptr = output;
    while (fgets(ptr, output_size - total, fp)) {
        size_t len = strlen(ptr);
        total += len;
        ptr += len;
        if (total >= output_size - 1) break;
    }
    
    output[output_size - 1] = '\0';
    return pclose(fp);
}

int main() {
    LOG_MSG_INFO("=== Starting myRPC-server ===");

    server_config_t config = {0};
    users_list_t users = {0};

    /* Загрузка конфигурации */
    if (parse_config(&config) != 0) {
        LOG_MSG_ERROR("Failed to load configuration");
        return 1;
    }
    LOG_MSG_INFO("Server configuration loaded");
    LOG_MSG_INFO("Port: %d, Socket type: %s", 
            config.port, 
            config.socket_type == SOCKET_STREAM ? "TCP" : "UDP");

    /* Загрузка пользователей */
    if (load_users(&users) != 0) {
        LOG_MSG_ERROR("Failed to load users list");
        return 1;
    }
    LOG_MSG_INFO("Loaded %d allowed users", users.count);

    /* Создание сокета */
    int sockfd;
    if (config.socket_type == SOCKET_STREAM) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        LOG_MSG_INFO("Creating TCP socket...");
    } else {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        LOG_MSG_INFO("Creating UDP socket...");
    }

    if (sockfd < 0) {
        LOG_MSG_ERROR("Socket creation failed: %s", strerror(errno));
        return 1;
    }

    /* Настройка адреса */
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(config.port);

    /* Привязка сокета */
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        LOG_MSG_ERROR("Bind failed: %s", strerror(errno));
        close(sockfd);
        return 1;
    }

    /* Для TCP: переход в режим ожидания соединений */
    if (config.socket_type == SOCKET_STREAM) {
        if (listen(sockfd, 5) < 0) {
            LOG_MSG_ERROR("Listen failed: %s", strerror(errno));
            close(sockfd);
            return 1;
        }
    }

    LOG_MSG_INFO("Server started successfully on port %d", config.port);
    LOG_MSG_INFO("Waiting for connections...");

    /* Основной цикл обработки запросов */
    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t clilen = sizeof(cli_addr);
        int newsockfd;

        /* Принятие соединения */
        if (config.socket_type == SOCKET_STREAM) {
            newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
            if (newsockfd < 0) {
                LOG_MSG_ERROR("Accept failed: %s", strerror(errno));
                continue;
            }
        } else {
            newsockfd = sockfd;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        LOG_MSG_INFO("New connection from %s", client_ip);

        /* Получение запроса */
        char request[BUFFER_SIZE];
        int bytes_received;
        if (config.socket_type == SOCKET_STREAM) {
            bytes_received = recv(newsockfd, request, BUFFER_SIZE - 1, 0);
        } else {
            bytes_received = recvfrom(newsockfd, request, BUFFER_SIZE - 1, 0,
                                    (struct sockaddr *)&cli_addr, &clilen);
        }

        if (bytes_received < 0) {
            LOG_MSG_ERROR("Receive failed: %s", strerror(errno));
            if (config.socket_type == SOCKET_STREAM) close(newsockfd);
            continue;
        }
        request[bytes_received] = '\0';

        LOG_MSG_INFO("Received request: %s", request);

        /* Парсинг JSON (упрощенный) */
        char *login_start = strstr(request, "\"login\":\"");
        char *command_start = strstr(request, "\"command\":\"");
        if (!login_start || !command_start) {
            LOG_MSG_WARN("Invalid request format");
            send(newsockfd, "{\"code\":1,\"result\":\"Invalid request format\"}", 45, 0);
            if (config.socket_type == SOCKET_STREAM) close(newsockfd);
            continue;
        }

        login_start += 9; // Пропускаем "\"login\":\""
        command_start += 11; // Пропускаем "\"command\":\""
        
        char *login_end = strchr(login_start, '\"');
        char *command_end = strchr(command_start, '\"');

        if (!login_end || !command_end) {
            LOG_MSG_WARN("Invalid request format");
            send(newsockfd, "{\"code\":1,\"result\":\"Invalid request format\"}", 45, 0);
            if (config.socket_type == SOCKET_STREAM) close(newsockfd);
            continue;
        }

        *login_end = '\0';
        *command_end = '\0';

        LOG_MSG_INFO("Processing command from user '%s': %s", login_start, command_start);

        /* Проверка пользователя */
        if (!is_user_allowed(&users, login_start)) {
            LOG_MSG_WARN("Unauthorized user: %s", login_start);
            send(newsockfd, "{\"code\":1,\"result\":\"Unauthorized user\"}", 40, 0);
            if (config.socket_type == SOCKET_STREAM) close(newsockfd);
            continue;
        }

        /* Выполнение команды */
        char output[BUFFER_SIZE];
        int status = execute_command(command_start, output, sizeof(output));

        /* Формирование ответа */
        char response[BUFFER_SIZE];
        if (status == 0) {
            snprintf(response, BUFFER_SIZE, "{\"code\":0,\"result\":\"%s\"}", output);
        } else {
            snprintf(response, BUFFER_SIZE, "{\"code\":1,\"result\":\"%s\"}", output);
        }

        /* Отправка ответа */
        if (config.socket_type == SOCKET_STREAM) {
            send(newsockfd, response, strlen(response), 0);
            close(newsockfd);
        } else {
            sendto(newsockfd, response, strlen(response), 0,
                  (struct sockaddr *)&cli_addr, clilen);
        }

        LOG_MSG_INFO("Command executed with status: %d", status);
    }

    close(sockfd);
    return 0;
}
