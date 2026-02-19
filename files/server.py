#!/usr/bin/env python3
# X25519-TCP-Chat  ─ server with text + file transfer

import os, sys, socket, struct, threading, hashlib           # stdlib imports
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)                        # X25519 key pair
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ─────── configuration from positional arguments ─────────────
HOST = sys.argv[1] if len(sys.argv) >= 2 else "0.0.0.0"       # bind address
PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 12345      # bind port
CHUNK = 4096                                                   # file chunk size

TXT, META, CHUNK_T, END = 1, 2, 3, 4                           # message types

# ──────── AES-GCM wrapper helpers ────────────────────────────
def send_packet(sock: socket.socket, key: bytes, data: bytes) -> None:
    nonce = os.urandom(12)                                     # unique nonce
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce),
                 backend=default_backend()).encryptor()
    ct = enc.update(data) + enc.finalize()                     # encrypt payload
    blob = nonce + enc.tag + ct                                # 12|16|N layout
    sock.sendall(struct.pack('!I', len(blob)) + blob)          # length prefix

def recvn(sock: socket.socket, n: int) -> bytes:
    buf = b''
    while len(buf) < n:                                        # read exactly n
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionAbortedError
        buf += chunk
    return buf

def recv_packet(sock: socket.socket, key: bytes) -> bytes:
    length, = struct.unpack('!I', recvn(sock, 4))              # fetch length
    blob = recvn(sock, length)                                 # full ciphertext
    nonce, tag, ct = blob[:12], blob[12:28], blob[28:]         # split fields
    dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag),
                 backend=default_backend()).decryptor()
    return dec.update(ct) + dec.finalize()                     # return plaintext

# ──────── establish TCP + X25519 handshake ──────────────────
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        # create socket
srv.bind((HOST, PORT))                                         # bind address
srv.listen(1)                                                  # start listen
print(f"Server listening on {HOST}:{PORT}")
conn, addr = srv.accept()                                      # wait client
print("Client connected ->", addr)

priv = X25519PrivateKey.generate()                             # server private
conn.sendall(priv.public_key().public_bytes(                   # send public
    serialization.Encoding.Raw, serialization.PublicFormat.Raw))
peer_pub = X25519PublicKey.from_public_bytes(conn.recv(32))    # recv public
secret = priv.exchange(peer_pub)                               # shared secret
print("Shared secret (hex) ->", secret.hex())

aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"handshake", backend=default_backend()).derive(secret)  # AES key

# ──────── file-receive state vars ────────────────────────────
file_rx = None                                                 # None = idle

def handle_payload(data: bytes) -> None:
    """Parse an incoming decrypted payload."""
    global file_rx
    mtype = data[0]                                            # first byte = type
    if mtype == TXT:                                           # simple text
        print("[client]", data[1:].decode())
    elif mtype == META:                                        # file header
        fn_len = struct.unpack('!H', data[1:3])[0]             # filename length
        fname = data[3:3+fn_len].decode()                      # filename
        size  = struct.unpack('!Q', data[3+fn_len:3+fn_len+8])[0]  # total bytes
        digest = data[-32:]                                    # SHA-256 digest
        file_rx = {"name": fname, "size": size, "digest": digest,
                   "written": 0, "hasher": hashlib.sha256(),
                   "fh": open("recv_"+fname, "wb")}
        print(f"[file] receiving '{fname}' ({size} B)")
    elif mtype == CHUNK_T and file_rx:                         # file chunk
        chunk = data[1:]
        file_rx["fh"].write(chunk)
        file_rx["hasher"].update(chunk)
        file_rx["written"] += len(chunk)
    elif mtype == END and file_rx:                             # file done
        file_rx["fh"].close()
        ok = file_rx["hasher"].digest() == file_rx["digest"]
        print(f"[file] '{file_rx['name']}' complete ->", "OK" if ok else "FAIL")
        file_rx = None

# ──────── background receiver thread ─────────────────────────
def rx_loop() -> None:
    while True:
        try:
            payload = recv_packet(conn, aes_key)               # decrypt packet
            handle_payload(payload)                            # dispatch
        except Exception as e:
            print("Receive error:", e)
            break
threading.Thread(target=rx_loop, daemon=True).start()          # start thread

# ──────── sending helpers ────────────────────────────────────
def send_text(msg: str) -> None:
    send_packet(conn, aes_key, bytes([TXT]) + msg.encode())    # wrap & send

def send_file(path: str) -> None:
    if not os.path.isfile(path):
        print("No such file:", path)
        return
    size = os.path.getsize(path)                               # file size
    digest = hashlib.sha256(open(path, "rb").read()).digest()  # full digest
    name_bytes = os.path.basename(path).encode()               # basename
    meta = (bytes([META]) +
            struct.pack('!H', len(name_bytes)) + name_bytes +  # header
            struct.pack('!Q', size) + digest)
    send_packet(conn, aes_key, meta)                           # send meta
    with open(path, "rb") as fh:                               # stream chunks
        while chunk := fh.read(CHUNK):
            send_packet(conn, aes_key, bytes([CHUNK_T]) + chunk)
    send_packet(conn, aes_key, bytes([END]))                   # final marker
    print(f"[file] sent '{path}' ({size} B)")

# ──────── main stdin loop ────────────────────────────────────
try:
    while True:
        line = input("> ")
        if not line:
            continue
        if line.startswith("/file "):                          # file command
            send_file(line[6:].strip())
        else:                                                  # regular text
            send_text(line)
except (KeyboardInterrupt, EOFError):
    pass

conn.close()                                                   # clean shutdown
srv.close()
