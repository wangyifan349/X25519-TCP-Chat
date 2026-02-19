#!/usr/bin/env python3
"""
X25519-TCP-Chat : client.py
---------------------------------
Usage examples
    python3 client.py                 # -> 127.0.0.1 12345 (defaults)
    python3 client.py 192.168.1.50    # -> 192.168.1.50 12345
    python3 client.py 192.168.1.50 9000
"""
import os
import sys
import socket
import struct
import threading
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
# ---------------------------------------------------------------------------
# Positional CLI arguments: host [port]
# ---------------------------------------------------------------------------
SERVER_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
SERVER_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 12345
# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def send_encrypted(sock: socket.socket, key: bytes, plaintext: bytes) -> None:
    """Encrypt *plaintext* with AES-256-GCM and send it."""
    nonce = os.urandom(12)                                   # new nonce per msg
    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(nonce), backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    packet = nonce + encryptor.tag + ciphertext              # 12|16|N bytes
    sock.sendall(struct.pack("!I", len(packet)) + packet)    # 4-byte length
def recvn(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock* (blocking)."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionAbortedError("Socket closed while reading")
        data += chunk
    return data
def recv_encrypted(sock: socket.socket, key: bytes) -> bytes:
    """Receive one AES-GCM packet and return the decrypted plaintext."""
    total_len, = struct.unpack("!I", recvn(sock, 4))
    blob = recvn(sock, total_len)
    nonce, tag, ciphertext = blob[:12], blob[12:28], blob[28:]
    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
# ---------------------------------------------------------------------------
# Connect to server
# ---------------------------------------------------------------------------
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((SERVER_HOST, SERVER_PORT))
print(f"Connected to {SERVER_HOST}:{SERVER_PORT}")
# ---------------------------------------------------------------------------
# X25519 key exchange
# ---------------------------------------------------------------------------
server_pub_bytes = sock.recv(32)                          # raw 32-byte key
server_pub_key = X25519PublicKey.from_public_bytes(server_pub_bytes)

client_priv_key = X25519PrivateKey.generate()
sock.sendall(client_priv_key.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
))
shared_secret = client_priv_key.exchange(server_pub_key)
print("Shared secret (hex) ->", shared_secret.hex())
# ---------------------------------------------------------------------------
# Derive AES-256 key from shared secret
# ---------------------------------------------------------------------------
aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"handshake data",
    backend=default_backend(),
).derive(shared_secret)
# ---------------------------------------------------------------------------
# Background receiver thread
# ---------------------------------------------------------------------------
def receiver() -> None:
    while True:
        try:
            plaintext = recv_encrypted(sock, aes_key)
            print(f"[server] {plaintext.decode()}")
        except Exception as exc:
            print("Receive error:", exc)
            break
threading.Thread(target=receiver, daemon=True).start()
# ---------------------------------------------------------------------------
# Main loop: read user input and send to server
# ---------------------------------------------------------------------------
try:
    while True:
        msg = input("> ").encode()
        if msg:
            send_encrypted(sock, aes_key, msg)
except (KeyboardInterrupt, EOFError):
    pass
finally:
    sock.close()
