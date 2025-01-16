#客户端
import socket
import random
import time

UDP_IP = "192.168.60.136"  # 服务端 IP
UDP_PORT = 12345
NUM_PACKETS = 10

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

for i in range(NUM_PACKETS):
    # 随机生成源端口
    src_port = random.randint(10000, 65535)

    # 创建一个新的UDP套接字
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # 绑定套接字到随机源端口
        sock.bind(('0.0.0.0', src_port))
        print(f"Binding to source port: {src_port}")
    except OSError as e:
        print(f"Error binding to port {src_port}: {e}")
        continue  # 绑定失败
    
    # 每个数据包随机生成一个长度
    message_length = random.randint(10, 50)  # 随机字节数从10到50之间
    MESSAGE = bytes([random.randint(0, 255) for _ in range(message_length)])  # 生成随机数据包

    # 发送数据包到目标 IP 和端口
    sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))

    print(f"Sent message with length: {len(MESSAGE)} bytes")

    time.sleep(0.05)

    sock.close()
