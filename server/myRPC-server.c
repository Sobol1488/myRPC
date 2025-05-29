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
#include <signal.h>
#include <syslog.h>
#include <sys/file.h>
#include <sys/select.h>
#include "libmysyslog.h"

#define BUFFER_SIZE 1024
#define MAX_USERS 100
#define CONFIG_DIR "/etc/myRPC"
#define CONFIG_FILE CONFIG_DIR "/myRPC.conf"
#define USERS_FILE CONFIG_DIR "/users.conf"

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

// Parse configuration file
int parse_config(server_config_t *config) {
    FILE *file = fopen(CONFIG_FILE, "r");
    if (!file) {
        log_error("Failed to open config file");
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

// Load list of allowed users
int load_users(users_list_t *users) {
    FILE *file = fopen(USERS_FILE, "r");
    if (!file) {
        log_error("Failed to open users file");
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

// Check if user is allowed
int is_user_allowed(users_list_t *users, const char *username) {
    for (int i = 0; i < users->count; i++) {
        if (strcmp(users->users[i], username) == 0) {
            return 1;
        }
    }
    return 0;
}

// Execute command and capture output
int execute_command(const char *command, char *output, size_t output_size) {
    FILE *fp = popen(command, "r");
    if (!fp) {
        log_error("Failed to execute command");
        return -1;
    }

    size_t bytes_read = fread(output, 1, output_size - 1, fp);
    output[bytes_read] = '\0';

    int status = pclose(fp);
    return WEXITSTATUS(status);
}

int main() {
    server_config_t config = {0};
    users_list_t users = {0};

    // Parse configuration
    if (parse_config(&config) != 0) {
        log_error("Failed to parse server config");
        return 1;
    }

    // Load allowed users
    if (load_users(&users) != 0) {
        log_error("Failed to load users list");
        return 1;
    }

    // Create socket
    int sockfd;
    if (config.socket_type == SOCKET_STREAM) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
    } else {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    }

    if (sockfd < 0) {
        log_error("Failed to create socket");
        return 1;
    }

    // Bind socket
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(config.port);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        log_error("Failed to bind socket");
        close(sockfd);
        return 1;
    }

    // Listen for connections (TCP only)
    if (config.socket_type == SOCKET_STREAM) {
        if (listen(sockfd, 5) < 0) {
            log_error("Failed to listen on socket");
            close(sockfd);
            return 1;
        }
    }

    log_info("Server started and listening for connections");

    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t clilen = sizeof(cli_addr);
        int newsockfd;

        // Accept connection (TCP) or receive directly (UDP)
        if (config.socket_type == SOCKET_STREAM) {
            newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
            if (newsockfd < 0) {
                log_error("Failed to accept connection");
                continue;
            }
        } else {
            newsockfd = sockfd;
        }

        // Receive request
        char request[BUFFER_SIZE];
        int bytes_received;
        if (config.socket_type == SOCKET_STREAM) {
            bytes_received = recv(newsockfd, request, BUFFER_SIZE - 1, 0);
        } else {
            bytes_received = recvfrom(newsockfd, request, BUFFER_SIZE - 1, 0,
                                    (struct sockaddr *)&cli_addr, &clilen);
        }

        if (bytes_received < 0) {
            log_error("Failed to receive request");
            if (config.socket_type == SOCKET_STREAM) close(newsockfd);
            continue;
        }
        request[bytes_received] = '\0';

        // Parse JSON request (simplified)
        char *login_start = strstr(request, "\"login\":\"");
        char *command_start = strstr(request, "\"command\":\"");
        if (!login_start || !command_start) {
            log_error("Invalid request format");
            send(newsockfd, "{\"code\":1,\"result\":\"Invalid request format\"}", 45, 0);
            if (config.socket_type == SOCKET_STREAM) close(newsockfd);
            continue;
        }

        login_start += 9; // Skip "\"login\":\""
        char *login_end = strchr(login_start, '\"');
        command_start += 11; // Skip "\"command\":\""
        char *command_end = strchr(command_start, '\"');

        if (!login_end || !command_end) {
            log_error("Invalid request format");
            send(newsockfd, "{\"code\":1,\"result\":\"Invalid request format\"}", 45, 0);
            if (config.socket_type == SOCKET_STREAM) close(newsockfd);
            continue;
        }

        *login_end = '\0';
        *command_end = '\0';

        // Check if user is allowed
        if (!is_user_allowed(&users, login_start)) {
            log_error("Unauthorized user");
            send(newsockfd, "{\"code\":1,\"result\":\"Unauthorized user\"}", 40, 0);
            if (config.socket_type == SOCKET_STREAM) close(newsockfd);
            continue;
        }

        // Execute command
        char output[BUFFER_SIZE];
        int status = execute_command(command_start, output, sizeof(output));

        // Prepare response
        char response[BUFFER_SIZE];
        if (status == 0) {
            snprintf(response, BUFFER_SIZE, "{\"code\":0,\"result\":\"%s\"}", output);
        } else {
            snprintf(response, BUFFER_SIZE, "{\"code\":1,\"result\":\"%s\"}", output);
        }

        // Send response
        if (config.socket_type == SOCKET_STREAM) {
            send(newsockfd, response, strlen(response), 0);
            close(newsockfd);
        } else {
            sendto(newsockfd, response, strlen(response), 0,
                  (struct sockaddr *)&cli_addr, clilen);
        }
    }

    close(sockfd);
    return 0;
}
