#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 8888
#define BUFFER_SIZE 65536

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    int opt = 1;
    ssize_t bytes_read;
    long total_received = 0;
    int client_count = 0;

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options to reuse address
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind socket to port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("TCP Server listening on port %d\n", PORT);
    printf("Server will only receive data, no response will be sent\n\n");

    // Accept connections
    while (1) {
        printf("Waiting for connection %d...\n", ++client_count);
        if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len)) < 0) {
            perror("accept");
            continue;
        }

        printf("Client %d connected from %s:%d\n",
               client_count,
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));

        total_received = 0;

        // Receive data without responding
        while ((bytes_read = recv(client_fd, buffer, BUFFER_SIZE, 0)) > 0) {
            total_received += bytes_read;
            printf("Received %zd bytes from client %d (total: %ld bytes)\n",
                   bytes_read, client_count, total_received);
        }

        if (bytes_read < 0) {
            perror("recv");
        }

        printf("Client %d disconnected. Total received: %ld bytes\n\n", client_count, total_received);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
