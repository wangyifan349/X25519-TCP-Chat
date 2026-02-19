import socket
import os
import threading
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers

# 生成 X25519 私钥
private_key = X25519PrivateKey.generate()
public_key = private_key.public_key()

# 服务器配置
HOST = '127.0.0.1'  # 本地地址
PORT = 12345  # 端口

# 创建 TCP 套接字
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print(f"服务器启动，等待连接...")

# 等待客户端连接
conn, addr = server_socket.accept()
print(f"客户端 {addr} 已连接")

# 发送服务器公钥给客户端
conn.send(public_key.public_bytes())

# 接收客户端的公钥
client_public_key_bytes = conn.recv(1024)
client_public_key = X25519PublicKey.from_public_bytes(client_public_key_bytes)

# 使用双方的私钥和公钥计算共享密钥
shared_key = private_key.exchange(client_public_key)

# 通过密钥派生出对称加密密钥
salt = os.urandom(16)  # 盐值
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)

# 使用 KDF 从共享密钥派生对称密钥
key = kdf.derive(shared_key)

# 创建加密上下文
cipher = ciphers.Cipher(ciphers.algorithms.AES(key), ciphers.modes.CBC(os.urandom(16)), backend=default_backend())

# 处理消息的循环
def receive_message():
    while True:
        data = conn.recv(1024)
        if not data:
            print("客户端已断开连接")
            break
        print(f"[接收线程] 接收到的消息: {data}")
        
        # 加密消息
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(data) + encryptor.finalize()
        conn.send(encrypted_message)

# 创建并启动接收消息线程
receive_thread = threading.Thread(target=receive_message, name="Receive-Thread")
receive_thread.start()

# 主线程继续处理其他任务，保持服务器运行
receive_thread.join()

# 关闭连接
conn.close()
