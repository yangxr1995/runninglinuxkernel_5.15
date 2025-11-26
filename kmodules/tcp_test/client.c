#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>

#define PORT 8888
#define BUFFER_SIZE 65536

int main(int argc, char *argv[]) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char *server_ip;
    int message_size = 1024;  // default 1KB
    int send_interval = 1000;  // default 1000ms
    char *buffer;
    int opt;
    int count = 0;

    // Parse command line arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server_ip> [message_size] [send_interval_ms] [send_cnt]\n", argv[0]);
        fprintf(stderr, "  server_ip: Server IP address (e.g., 127.0.0.1)\n");
        fprintf(stderr, "  message_size: Message size in bytes (default: 1024)\n");
        fprintf(stderr, "  send_interval: Send interval in milliseconds (default: 1000)\n");
        fprintf(stderr, "  send_cnt: 一轮发送几个包 (default: 4)\n");
        exit(EXIT_FAILURE);
    }

    server_ip = argv[1];

    if (argc >= 3) {
        message_size = atoi(argv[2]);
        if (message_size <= 0 || message_size > BUFFER_SIZE) {
            fprintf(stderr, "Error: message_size must be between 1 and %d\n", BUFFER_SIZE);
            exit(EXIT_FAILURE);
        }
    }

    if (argc >= 4) {
        send_interval = atoi(argv[3]);
        if (send_interval < 0) {
            fprintf(stderr, "Error: send_interval must be non-negative\n");
            exit(EXIT_FAILURE);
        }
    }

    int send_cnt = 4;

    if (argc >= 5) {
        send_cnt = atoi(argv[4]);
        if (send_cnt < 0) {
            fprintf(stderr, "Error: send_cnt must be non-negative\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("TCP Client Configuration:\n");
    printf("  Server IP: %s\n", server_ip);
    printf("  Server Port: %d\n", PORT);
    printf("  Message Size: %d bytes\n", message_size);
    printf("  Send Interval: %d ms\n", send_interval);
    printf("  Send Count: %d pkts\n", send_cnt);
    printf("  Nagle Algorithm: DISABLED\n\n");

    // Create socket file descriptor
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    // Disable Nagle algorithm (TCP_NODELAY)
    opt = 1;
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
        perror("Failed to disable Nagle algorithm");
        close(sock);
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 address from text to binary
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server at %s:%d\n\n", server_ip, PORT);

    // Allocate buffer and fill with pattern
    buffer = malloc(message_size);
    if (!buffer) {
        perror("Memory allocation failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    memset(buffer, 'A', message_size);

    // Send data at specified intervals
    while (1) {

        for (int i = 0; i < send_cnt; ++i) {
            ssize_t bytes_sent = send(sock, buffer, message_size, 0);
            if (bytes_sent < 0) {
                perror("Send failed");
                free(buffer);
                close(sock);
                exit(EXIT_FAILURE);
            }
            count++;
            printf("Sent packet %d: %zd bytes (total: %zd bytes)\n",
                   count, bytes_sent, (long)bytes_sent * count);
        }


        // Sleep for the specified interval
        if (send_interval > 0) {
            usleep(send_interval * 1000);  // Convert ms to microseconds
        }
    }

    free(buffer);
    close(sock);
    return 0;
}
