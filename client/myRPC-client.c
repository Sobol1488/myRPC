#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pwd.h>
#include "libmysyslog.h"

#define BUFFER_SIZE 1024

typedef enum {
    SOCKET_STREAM,
    SOCKET_DGRAM
} socket_type_t;

void print_help() {
    printf("Usage: myRPC-client -h <host> -p <port> [-s | -d] -c \"<command>\"\n");
    printf("Options:\n");
    printf("  -h, --host      Server IP address\n");
    printf("  -p, --port      Server port\n");
    printf("  -s, --stream    Use stream socket (TCP)\n");
    printf("  -d, --dgram     Use datagram socket (UDP)\n");
    printf("  -c, --command   Bash command to execute\n");
    printf("  --help          Show this help message\n");
}

int main(int argc, char *argv[]) {
    char *host = NULL;
    int port = 0;
    socket_type_t socket_type = SOCKET_STREAM;
    char *command = NULL;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--host") == 0) {
            if (i + 1 < argc) host = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (i + 1 < argc) port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--stream") == 0) {
            socket_type = SOCKET_STREAM;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dgram") == 0) {
            socket_type = SOCKET_DGRAM;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--command") == 0) {
            if (i + 1 < argc) command = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        }
    }

    if (!host || port == 0 || !command) {
        log_error("Missing required arguments");
        print_help();
        return 1;
    }

    // Get current username
    struct passwd *pw = getpwuid(getuid());
    const char *username = pw ? pw->pw_name : "unknown";

    // Create JSON request
    char request[BUFFER_SIZE];
    snprintf(request, BUFFER_SIZE, "{\"login\":\"%s\",\"command\":\"%s\"}", username, command);

    // Create socket
    int sockfd;
    if (socket_type == SOCKET_STREAM) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
    } else {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    }

    if (sockfd < 0) {
        log_error("Failed to create socket");
        return 1;
    }

    // Connect to server
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &serv_addr.sin_addr) <= 0) {
        log_error("Invalid address");
        close(sockfd);
        return 1;
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        log_error("Connection failed");
        close(sockfd);
        return 1;
    }

    // Send request
    if (send(sockfd, request, strlen(request), 0) < 0) {
        log_error("Failed to send request");
        close(sockfd);
        return 1;
    }

    // Receive response
    char response[BUFFER_SIZE];
    int bytes_received = recv(sockfd, response, BUFFER_SIZE - 1, 0);
    if (bytes_received < 0) {
        log_error("Failed to receive response");
        close(sockfd);
        return 1;
    }
    response[bytes_received] = '\0';

    printf("Server response: %s\n", response);
    close(sockfd);
    return 0;
}
