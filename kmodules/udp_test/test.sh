#!/bin/bash

echo "=== UDP Client/Server 测试脚本 ==="
echo

# 检查编译的程序是否存在
if [ ! -f "./udp_server" ] || [ ! -f "./udp_client" ]; then
    echo "错误: 请先编译程序"
    echo "运行: gcc -o udp_server udp_server.c && gcc -o udp_client udp_client.c"
    exit 1
fi

echo "步骤1: 在后台启动UDP服务器"
echo "命令: ./udp_server [端口号]"
echo "例如: ./udp_server 8888"
echo

echo "步骤2: 启动UDP客户端"
echo "命令: ./udp_client <服务器IP> <时间间隔(毫秒)> <报文大小(字节)>"
echo "例如: ./udp_client 127.0.0.1 1000 100"
echo "  - 发送时间间隔: 1000ms (1秒)"
echo "  - 报文大小: 100字节"
echo

echo "实际测试:"
echo "在终端1中运行: ./udp_server"
echo "在终端2中运行: ./udp_client 127.0.0.1 1000 100"
echo

echo "预期输出:"
echo "客户端显示:"
echo "  [Seq=0] Sent XX bytes at XXXXX us"
echo "  [Seq=0] Received XX bytes - RTT: X.XX ms"
echo "  [Seq=1] Sent XX bytes at XXXXX us"
echo "  ..."
echo

echo "服务端显示:"
echo "  Received XX bytes from 127.0.0.1:XXXX"
echo "  Sent ACK XX bytes to 127.0.0.1:XXXX"
echo "  ..."
echo

echo "按 Ctrl+C 停止程序"
