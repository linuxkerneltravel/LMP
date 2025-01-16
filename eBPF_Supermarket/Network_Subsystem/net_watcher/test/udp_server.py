# 服务端

import socket

UDP_IP = "0.0.0.0"  # 监听所有 IP 地址
UDP_PORT = 12345

# 创建 UDP 套接字
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"Listening for UDP packets on {UDP_IP}:{UDP_PORT}...")

while True:
    data, addr = sock.recvfrom(1024)  # 接收最大 1024 字节的数据
    print(f"Received message from {addr}: {data}")
