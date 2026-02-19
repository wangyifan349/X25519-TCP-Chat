#!/usr/bin/env python3
"""
X25519-TCP-Chat : client.py
---------------------------------
Command-line client for the demo chat.  By default it connects to
127.0.0.1:12345, yet you can override host / port with CLI arguments:

    python client.py                         # 127.0.0.1:12345
    python client.py --host 192.168.1.50     # 192.168.1.50:12345
    python client.py -H chat.box -p 9000     # chat.box:9000
"""
import os
import socket
import struct
import threading
import argparse

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# Command-line arguments
# ---------------------------------------------------------------------------
parser = argparse.ArgumentParser(
    description="X25519-AES-GCM demo client (default: 127.0.0.1:12345)"
)
parser.add_argument(
    "-H", "--host", default="127.0.0.1",
    help="Server IP / hostname (default: 127.0.0.1)"
)
parser.add_argument(
    "-p", "--port", default=12345, type=int,
    help="Server TCP port (default: 12345)"
)
args = parser.parse_args()
SERVER_HOST, SERVER_PORT = args.host, args.port

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def send_encrypted(sock: socket.socket, key: bytes, plaintext: bytes) -> None:
    """
    Encrypt *plaintext* with AES-256-GCM and send to *sock*.
    Packet format: 4-byte length | 12-byte nonce | 16-byte tag | ciphertext
    """
    nonce = os.urandom(12)                                    # unique per packet
    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(nonce), backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    packet = nonce + encryptor.tag + ciphertext
    sock.sendall(struct.pack("!I", len(packet)) + packet)

def recvn(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock* (blocking)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionAbortedError("Socket closed while reading")
        buf += chunk
    return buf

def recv_encrypted(sock: socket.socket, key: bytes) -> bytes:
    """
    Receive one AES-GCM packet from *sock* and return the decrypted plaintext.
    """
    total_len, = struct.unpack("!I", recvn(sock, 4))
    data = recvn(sock, total_len)

    nonce        = data[:12]
    tag          = data[12:28]
    ciphertext   = data[28:]

    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
# ---------------------------------------------------------------------------
# Connect to server
# ---------------------------------------------------------------------------
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_HOST, SERVER_PORT))
print(f"Connected to {SERVER_HOST}:{SERVER_PORT}")
# ---------------------------------------------------------------------------
# X25519 key exchange
# ---------------------------------------------------------------------------
server_pub_bytes = client_socket.recv(32)                # 32-byte raw server key
server_pub_key   = X25519PublicKey.from_public_bytes(server_pub_bytes)

client_priv_key  = X25519PrivateKey.generate()           # new client key pair
client_pub_bytes = client_priv_key.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)
client_socket.sendall(client_pub_bytes)                  # send 32-byte raw key
shared_secret = client_priv_key.exchange(server_pub_key) # 32-byte secret
print("Shared secret (hex) ->", shared_secret.hex())
# ---------------------------------------------------------------------------
# Derive AES-256 key from shared secret
# ---------------------------------------------------------------------------
aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,                                           # 256-bit key
    salt=None,
    info=b"handshake data",
    backend=default_backend(),
).derive(shared_secret)
# ---------------------------------------------------------------------------
# Background receiver thread
# ---------------------------------------------------------------------------
def receiver() -> None:
    """Continuously receive and print messages from server."""
    while True:
        try:
            plaintext = recv_encrypted(client_socket, aes_key)
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
        user_input = input("> ").encode()
        if user_input:
            send_encrypted(client_socket, aes_key, user_input)
except (KeyboardInterrupt, EOFError):
    pass
finally:
    client_socket.close()
