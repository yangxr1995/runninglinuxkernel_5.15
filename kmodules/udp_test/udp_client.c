#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/time.h>

#define SERVER_PORT 8888
#define BUFFER_SIZE 65507

// 获取当前时间的微秒
long long get_timestamp_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000000 + tv.tv_usec;
}

int main(int argc, char *argv[]) {
    int client_sock;
    struct sockaddr_in server_addr;
    char *server_ip;
    int interval_ms = 1000;  // 默认时间间隔1秒
    int packet_size = 64;    // 默认报文大小64字节
    char buffer[BUFFER_SIZE];

    // 解析命令行参数
    if (argc < 4) {
        printf("Usage: %s <server_ip> <interval_ms> <packet_size>\n", argv[0]);
        printf("Example: %s 127.0.0.1 1000 100\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    server_ip = argv[1];
    interval_ms = atoi(argv[2]);
    packet_size = atoi(argv[3]);

    if (packet_size < 8) {
        fprintf(stderr, "Packet size must be at least 8 bytes (for seq and timestamp)\n");
        exit(EXIT_FAILURE);
    }

    if (packet_size > BUFFER_SIZE) {
        fprintf(stderr, "Packet size must be less than %d bytes\n", BUFFER_SIZE);
        exit(EXIT_FAILURE);
    }

    // 创建UDP socket
    client_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 配置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid server IP address");
        close(client_sock);
        exit(EXIT_FAILURE);
    }

    printf("UDP Client starting...\n");
    printf("Server: %s:%d\n", server_ip, SERVER_PORT);
    printf("Interval: %d ms\n", interval_ms);
    printf("Packet size: %d bytes\n", packet_size);
    printf("Press Ctrl+C to stop\n\n");

    int seq = 0;
    long long send_time, recv_time, rtt_us;

    while (1) {
        // 准备数据包：前8字节用于seq和send timestamp，其余为数据
        int data_size = packet_size - 8;
        char *data_ptr = buffer + 8;

        // 填充数据区域
        for (int i = 0; i < data_size; i++) {
            data_ptr[i] = 'A' + (i % 26);
        }

        // 设置seq编号
        *(int *)buffer = seq;

        // 获取发送时间并写入packet
        send_time = get_timestamp_us();
        *(long long *)(buffer + 4) = send_time;

        // 发送数据包
        socklen_t addr_len = sizeof(server_addr);
        int send_len = sendto(client_sock, buffer, packet_size, 0,
                            (struct sockaddr *)&server_addr, addr_len);

        if (send_len < 0) {
            perror("Send failed");
            sleep(interval_ms / 1000);
            continue;
        }

        printf("[Seq=%d] Sent %d bytes at %lld us\n", seq, send_len, send_time);

        // 接收ACK回复
        socklen_t recv_addr_len = sizeof(server_addr);
        int recv_len = recvfrom(client_sock, buffer, BUFFER_SIZE, 0,
                              (struct sockaddr *)&server_addr, &recv_addr_len);

        if (recv_len < 0) {
            perror("Receive failed");
            seq++;
            sleep(interval_ms / 1000);
            continue;
        }

        // 计算RTT
        recv_time = get_timestamp_us();
        rtt_us = recv_time - send_time;

        printf("[Seq=%d] Received %d bytes - RTT: %.2f ms (%.0f us)\n",
               seq, recv_len, rtt_us / 1000.0, (double)rtt_us);

        seq++;

        // 等待指定间隔
        usleep(interval_ms * 1000);
    }

    close(client_sock);
    return 0;
}
