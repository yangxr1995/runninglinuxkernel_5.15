# UDP Client/Server 测试程序

## 简介
这是一个用C语言实现的UDP客户端和服务器程序，用于测试网络延迟和报文传输。

## 功能特性
- **UDP服务器**: 接收客户端数据包并立即回复ACK
- **UDP客户端**: 发送带seq编号的数据包，计算并显示RTT
- **可配置参数**: 支持通过命令行设置发送间隔、报文大小和服务器IP
- **RTT计算**: 精确计算往返时间（毫秒和微秒）
- **Seq编号**: 使用序列号区分不同的请求包

## 编译
```bash
gcc -o udp_server udp_server.c -Wall
gcc -o udp_client udp_client.c -Wall
```

## 使用方法

### 启动服务器
```bash
./udp_server [端口号]
```
- 默认端口: 8888
- 示例: `./udp_server 8888`

### 启动客户端
```bash
./udp_client <服务器IP> <时间间隔(ms)> <报文大小(bytes)>
```
- 参数说明:
  - 服务器IP: 服务器的IP地址
  - 时间间隔: 发送包的间隔时间（毫秒）
  - 报文大小: 数据包大小（字节，最小8字节）

- 示例: `./udp_client 127.0.0.1 1000 100`
  - 服务器IP: 127.0.0.1
  - 发送间隔: 1000毫秒（1秒）
  - 报文大小: 100字节

## 报文格式
客户端发送的数据包格式：
- 前4字节: seq（序列号）
- 接下来8字节: 发送时间戳（微秒）
- 其余字节: 填充数据（字母A-Z重复）

## 输出示例

### 客户端输出
```
[Seq=0] Sent 100 bytes at 1234567890 us
[Seq=0] Received 100 bytes - RTT: 0.12 ms (120 us)
[Seq=1] Sent 100 bytes at 1234568890 us
[Seq=1] Received 100 bytes - RTT: 0.10 ms (100 us)
```

### 服务器输出
```
UDP Server listening on port 8888...
Received 100 bytes from 127.0.0.1:54321
Sent ACK 100 bytes to 127.0.0.1:54321
```

## 注意事项
- 报文大小至少8字节（用于存储seq和时间戳）
- 按Ctrl+C停止程序
- 建议在本地环回地址(127.0.0.1)上进行测试
- RTT值可能因系统负载而变化

## 测试脚本
运行 `./test.sh` 查看详细的使用说明和测试步骤。
