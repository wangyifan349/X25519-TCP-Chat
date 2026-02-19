#!/usr/bin/env python3
# helper
import os                                           # random bytes / file utils
import socket                                       # TCP communication
import struct                                       # pack / unpack fixed-size fields
import threading                                    # lightweight concurrency
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)              # X25519 key pair
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
SERVER_HOST = '0.0.0.0'                           # bind address
SERVER_PORT = 12345                                 # bind port
# ---------- helpers: encrypt / decrypt ----------
def send_encrypted(sock: socket.socket, aes_key: bytes, plaintext: bytes) -> None:
    nonce = os.urandom(12)                          # 12-byte nonce for AES-GCM
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    packet = nonce + encryptor.tag + ciphertext     # nonce | tag | ciphertext
    sock.sendall(struct.pack('!I', len(packet)) + packet)  # 4-byte length + data
def recvn(sock: socket.socket, n: int) -> bytes:
    buf = b''
    while len(buf) < n:                             # read exactly n bytes
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionAbortedError
        buf += chunk
    return buf
def recv_encrypted(sock: socket.socket, aes_key: bytes) -> bytes:
    total_len, = struct.unpack('!I', recvn(sock, 4))  # total packet length
    data = recvn(sock, total_len)
    nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
# ---------- set up listening socket ----------
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_HOST, SERVER_PORT))
server_socket.listen(1)
print(f'Server listening on {SERVER_HOST}:{SERVER_PORT}')
connection, client_address = server_socket.accept()     # wait for incoming client
print('Client connected ->', client_address)
# ---------- X25519 key exchange ----------
server_private_key = X25519PrivateKey.generate()        # server private
server_public_bytes = server_private_key.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw
)
connection.sendall(server_public_bytes)                 # send 32-byte public key
client_public_bytes = connection.recv(32)               # receive 32-byte public key
client_public_key = X25519PublicKey.from_public_bytes(client_public_bytes)
shared_secret = server_private_key.exchange(client_public_key)   # 32-byte secret
print('Shared secret (hex) ->', shared_secret.hex())             # debug output
# ---------- derive AES-256 key from shared secret ----------
aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,                               # 32 bytes = 256 bits
    salt=None,
    info=b'handshake data',
    backend=default_backend()
).derive(shared_secret)
# ---------- receive loop thread ----------
def receive_loop() -> None:
    while True:
        plaintext = recv_encrypted(connection, aes_key)
        print('[client]', plaintext.decode())
threading.Thread(target=receive_loop, daemon=True).start()
# ---------- main thread: send user input ----------
while True:
    try:
        user_input = input('> ').encode()
        if user_input:
            send_encrypted(connection, aes_key, user_input)
    except (KeyboardInterrupt, EOFError):
        break
connection.close()
server_socket.close()
