#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUFFER_SIZE 65507

int main(int argc, char *argv[]) {
    int server_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    int port = 8888;

    if (argc > 1) {
        port = atoi(argv[1]);
    }

    // 创建UDP socket
    server_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 设置socket选项
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    // 配置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // 绑定socket
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("UDP Server listening on port %d...\n", port);
    printf("Waiting for packets...\n");

    while (1) {
        // 接收数据包
        int recv_len = recvfrom(server_sock, buffer, BUFFER_SIZE, 0,
                               (struct sockaddr *)&client_addr, &client_addr_len);

        if (recv_len < 0) {
            perror("Recvfrom failed");
            continue;
        }

        printf("Received %d bytes from %s:%d\n",
               recv_len,
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));

        // 立即发送ACK回复
        int send_len = sendto(server_sock, buffer, recv_len, 0,
                            (struct sockaddr *)&client_addr, client_addr_len);

        if (send_len < 0) {
            perror("Sendto failed");
            continue;
        }

        printf("Sent ACK %d bytes to %s:%d\n",
               send_len,
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));
    }

    close(server_sock);
    return 0;
}
