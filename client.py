import socket
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import threading
from cryptography.hazmat.backends import default_backend

# 生成 X25519 私钥
private_key = X25519PrivateKey.generate()
public_key = private_key.public_key()

# 连接到服务器
HOST = '127.0.0.1'
PORT = 12345
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# 发送客户端公钥给服务器
client_socket.send(public_key.public_bytes())

# 接收服务器公钥
server_public_key_bytes = client_socket.recv(1024)
server_public_key = X25519PublicKey.from_public_bytes(server_public_key_bytes)

# 使用双方的私钥和公钥计算共享密钥
shared_key = private_key.exchange(server_public_key)

# 使用 KDF 从共享密钥派生对称密钥
salt = os.urandom(16)  # 盐值
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)

key = kdf.derive(shared_key)

# 创建加密上下文
cipher = ciphers.Cipher(ciphers.algorithms.AES(key), ciphers.modes.CBC(os.urandom(16)), backend=default_backend())

# 发送消息
def send_message():
    while True:
        message = input("请输入消息：").encode()
        # 加密消息
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message) + encryptor.finalize()
        client_socket.send(encrypted_message)

# 接收消息
def receive_message():
    while True:
        response = client_socket.recv(1024)
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(response) + decryptor.finalize()
        print(f"[接收线程] 服务器回复: {decrypted_message.decode()}")

# 创建并启动发送和接收消息线程
send_thread = threading.Thread(target=send_message, name="Send-Thread")
receive_thread = threading.Thread(target=receive_message, name="Receive-Thread")

send_thread.start()
receive_thread.start()

# 等待线程结束
send_thread.join()
receive_thread.join()

# 关闭连接
client_socket.close()
