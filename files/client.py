#!/usr/bin/env python3
# X25519-TCP-Chat  ─ client with text + file transfer

import os, sys, socket, struct, threading, hashlib            # stdlib imports
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)                        # X25519 key pair
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

HOST = sys.argv[1] if len(sys.argv) >= 2 else "127.0.0.1"     # server address
PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 12345      # server port
CHUNK = 4096                                                   # tx chunk size
TXT, META, CHUNK_T, END = 1, 2, 3, 4                           # message types
# ──────── AES-GCM helpers ───────────────────────────────────
def send_packet(sock: socket.socket, key: bytes, data: bytes) -> None:
    nonce = os.urandom(12)                                     # unique nonce
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce),
                 backend=default_backend()).encryptor()
    ct = enc.update(data) + enc.finalize()
    blob = nonce + enc.tag + ct
    sock.sendall(struct.pack('!I', len(blob)) + blob)          # length prefix

def recvn(sock: socket.socket, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionAbortedError
        buf += chunk
    return buf

def recv_packet(sock: socket.socket, key: bytes) -> bytes:
    length, = struct.unpack('!I', recvn(sock, 4))
    blob = recvn(sock, length)
    nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
    dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag),
                 backend=default_backend()).decryptor()
    return dec.update(ct) + dec.finalize()
# ──────── connect + X25519 handshake ────────────────────────
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
print(f"Connected to {HOST}:{PORT}")
priv = X25519PrivateKey.generate()                             # client private
sock.sendall(priv.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw))  # send pub
peer_pub = X25519PublicKey.from_public_bytes(sock.recv(32))    # recv pub
secret = priv.exchange(peer_pub)                               # shared secret
print("Shared secret (hex) ->", secret.hex())
aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"handshake", backend=default_backend()).derive(secret)  # AES key
# ──────── inbound file state ────────────────────────────────
file_rx = None                                                 # None while idle
def handle_payload(data: bytes) -> None:
    """Process one decrypted message from server."""
    global file_rx
    mtype = data[0]
    if mtype == TXT:                                           # plain text
        print("[server]", data[1:].decode())
    elif mtype == META:
        fn_len = struct.unpack('!H', data[1:3])[0]
        fname  = data[3:3+fn_len].decode()
        size   = struct.unpack('!Q', data[3+fn_len:3+fn_len+8])[0]
        digest = data[-32:]
        file_rx = {"name": fname, "size": size, "digest": digest,
                   "written": 0, "hasher": hashlib.sha256(),
                   "fh": open("recv_"+fname, "wb")}
        print(f"[file] receiving '{fname}' ({size} B)")
    elif mtype == CHUNK_T and file_rx:
        chunk = data[1:]
        file_rx["fh"].write(chunk)
        file_rx["hasher"].update(chunk)
        file_rx["written"] += len(chunk)
    elif mtype == END and file_rx:
        file_rx["fh"].close()
        ok = file_rx["hasher"].digest() == file_rx["digest"]
        print(f"[file] '{file_rx['name']}' complete ->", "OK" if ok else "FAIL")
        file_rx = None
# ──────── background receiver thread ────────────────────────
def rx_loop() -> None:
    while True:
        try:
            payload = recv_packet(sock, aes_key)
            handle_payload(payload)
        except Exception as e:
            print("Receive error:", e)
            break
threading.Thread(target=rx_loop, daemon=True).start()
# ──────── send helpers ──────────────────────────────────────
def send_text(msg: str) -> None:
    send_packet(sock, aes_key, bytes([TXT]) + msg.encode())
def send_file(path: str) -> None:
    if not os.path.isfile(path):
        print("No such file:", path)
        return
    size = os.path.getsize(path)
    digest = hashlib.sha256(open(path, "rb").read()).digest()
    name_bytes = os.path.basename(path).encode()
    meta = (bytes([META]) +
            struct.pack('!H', len(name_bytes)) + name_bytes +
            struct.pack('!Q', size) + digest)
    send_packet(sock, aes_key, meta)                           # send header
    with open(path, "rb") as fh:                               # stream chunks
        while chunk := fh.read(CHUNK):
            send_packet(sock, aes_key, bytes([CHUNK_T]) + chunk)
    send_packet(sock, aes_key, bytes([END]))                   # final marker
    print(f"[file] sent '{path}' ({size} B)")
# ──────── main CLI loop ─────────────────────────────────────
try:
    while True:
        line = input("> ")
        if not line:
            continue
        if line.startswith("/file "):                          # file command
            send_file(line[6:].strip())
        else:
            send_text(line)                                    # normal text
except (KeyboardInterrupt, EOFError):
    pass
finally:
    sock.close()                                               # tidy up
