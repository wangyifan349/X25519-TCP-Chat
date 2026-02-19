#!/usr/bin/env python3
# helper
import os, socket, struct, threading
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)              # X25519 key pair
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
SERVER_HOST = '127.0.0.1'                           # server address
SERVER_PORT = 12345                                 # server port
# ---------- helpers: encrypt / decrypt ----------
def send_encrypted(sock: socket.socket, aes_key: bytes, plaintext: bytes) -> None:
    nonce = os.urandom(12)                          # unique nonce for each message
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    packet = nonce + encryptor.tag + ciphertext
    sock.sendall(struct.pack('!I', len(packet)) + packet)

def recvn(sock: socket.socket, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionAbortedError
        buf += chunk
    return buf
def recv_encrypted(sock: socket.socket, aes_key: bytes) -> bytes:
    total_len, = struct.unpack('!I', recvn(sock, 4))
    data = recvn(sock, total_len)
    nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
# ---------- connect to server ----------
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_HOST, SERVER_PORT))
# ---------- X25519 key exchange ----------
server_public_bytes = client_socket.recv(32)            # receive server public
server_public_key = X25519PublicKey.from_public_bytes(server_public_bytes)
client_private_key = X25519PrivateKey.generate()        # generate client private
client_socket.sendall(client_private_key.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw
))
shared_secret = client_private_key.exchange(server_public_key)   # 32-byte secret
print('Shared secret (hex) ->', shared_secret.hex())             # debug output
# ---------- derive AES-256 key from shared secret ----------
aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
    backend=default_backend()
).derive(shared_secret)
# ---------- receive loop thread ----------
def receive_loop() -> None:
    while True:
        plaintext = recv_encrypted(client_socket, aes_key)
        print('[server]', plaintext.decode())
threading.Thread(target=receive_loop, daemon=True).start()
# ---------- main thread: send user input ----------
while True:
    try:
        user_input = input('> ').encode()
        if user_input:
            send_encrypted(client_socket, aes_key, user_input)
    except (KeyboardInterrupt, EOFError):
        break

client_socket.close()
