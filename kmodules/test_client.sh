#!/bin/bash
# 简单测试客户端

echo "正在测试TCP服务器（延迟ACK模式）..."
echo ""

# 在后台启动服务器
./tcp_server_ack_delay > /dev/null 2>&1 &
SERVER_PID=$!

# 等待服务器启动
sleep 1

# 使用nc或telnet发送测试数据
echo -e "Hello Server!\nThis is a test message." | nc localhost 9999

# 等待一下让服务器处理
sleep 1

# 停止服务器
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "测试完成"
