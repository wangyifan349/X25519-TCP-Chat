#!/usr/bin/env python3
# x25519_chat.py  –  one-file secure chat with text & file transfer

import os                                                       # stdlib: FS ops
import sys                                                      # stdlib: argv
import socket                                                   # stdlib: TCP
import struct                                                   # stdlib: pack/unpack
import threading                                                # stdlib: threads
import hashlib                                                  # stdlib: SHA-256

from cryptography.hazmat.primitives.asymmetric.x25519 import (  # ECC key pair
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF        # HKDF-SHA256
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ────────────────────────── constants ──────────────────────────
CHUNK              = 4096                                       # file chunk size
TXT, META, BLK, END = 1, 2, 3, 4                                # message types

# ───────────────────── encryption helpers ─────────────────────
def send_packet(sock: socket.socket, key: bytes, body: bytes) -> None:
    nonce = os.urandom(12)                                      # 12-byte nonce
    enc   = Cipher(algorithms.AES(key), modes.GCM(nonce),
                   backend=default_backend()).encryptor()
    ct    = enc.update(body) + enc.finalize()                   # encrypt body
    blob  = nonce + enc.tag + ct                                # 12|16|cipher
    sock.sendall(struct.pack('!I', len(blob)) + blob)           # send length+data

def recvn(sock: socket.socket, n: int) -> bytes:
    buf = b''                                                   # read exactly n
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionAbortedError
        buf += chunk
    return buf

def recv_packet(sock: socket.socket, key: bytes) -> bytes:
    size, = struct.unpack('!I', recvn(sock, 4))                 # 4-byte length
    blob  = recvn(sock, size)                                   # encrypted blob
    nonce, tag, ct = blob[:12], blob[12:28], blob[28:]          # split fields
    dec   = Cipher(algorithms.AES(key), modes.GCM(nonce, tag),
                   backend=default_backend()).decryptor()
    return dec.update(ct) + dec.finalize()                      # return plaintext

# ───────────────────── handshake & key deriv ──────────────────
def x25519_handshake(sock: socket.socket, role: str) -> bytes:
    priv = X25519PrivateKey.generate()                          # generate private
    if role == 'server':                                        # server sends pub first
        sock.sendall(priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        peer_pub = X25519PublicKey.from_public_bytes(sock.recv(32))
    else:                                                       # client receives first
        peer_pub = X25519PublicKey.from_public_bytes(sock.recv(32))
        sock.sendall(priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    secret = priv.exchange(peer_pub)                            # shared secret
    print('Shared secret (hex) ->', secret.hex())               # debug
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b'handshake', backend=default_backend()
           ).derive(secret)                                     # 32-byte AES key

# ───────────────────── sending convenience ────────────────────
def send_text(sock: socket.socket, key: bytes, msg: str) -> None:
    send_packet(sock, key, bytes([TXT]) + msg.encode())         # wrap & send

def send_file(sock: socket.socket, key: bytes, path: str) -> None:
    if not os.path.isfile(path):
        print('No such file:', path)                            # sanity check
        return
    size   = os.path.getsize(path)                              # file length
    digest = hashlib.sha256(open(path, 'rb').read()).digest()   # full SHA-256
    name_b = os.path.basename(path).encode()                    # filename bytes
    meta   = (bytes([META]) +                                   # build header
              struct.pack('!H', len(name_b)) + name_b +
              struct.pack('!Q', size) + digest)
    send_packet(sock, key, meta)                                # send header
    with open(path, 'rb') as fh:                                # stream chunks
        while chunk := fh.read(CHUNK):
            send_packet(sock, key, bytes([BLK]) + chunk)        # each block
    send_packet(sock, key, bytes([END]))                        # send footer
    print(f'[file] sent "{path}" ({size} bytes)')               # report

# ───────────────────── receiver thread factory ────────────────
def start_receiver(sock: socket.socket, key: bytes, label: str) -> None:
    state = {'rx': None}                                        # holds current file

    def handle(pkt: bytes) -> None:
        mtype = pkt[0]                                          # first byte
        if mtype == TXT:                                        # chat message
            print(f'[{label}]', pkt[1:].decode())
        elif mtype == META:                                     # file metadata
            name_len = struct.unpack('!H', pkt[1:3])[0]
            name     = pkt[3:3+name_len].decode()
            size     = struct.unpack('!Q', pkt[3+name_len:3+name_len+8])[0]
            digest   = pkt[-32:]
            fh = open('recv_' + name, 'wb')
            state['rx'] = {'name': name, 'size': size,
                           'digest': digest, 'hasher': hashlib.sha256(),
                           'written': 0, 'fh': fh}
            print(f'[file] receiving "{name}" ({size} bytes)')
        elif mtype == BLK and state['rx']:                      # file block
            chunk = pkt[1:]
            rx = state['rx']
            rx['fh'].write(chunk)
            rx['hasher'].update(chunk)
            rx['written'] += len(chunk)
        elif mtype == END and state['rx']:                      # transfer end
            rx = state['rx']
            rx['fh'].close()
            ok = rx['hasher'].digest() == rx['digest']
            print(f'[file] "{rx["name"]}" complete ->', 'OK' if ok else 'FAILED')
            state['rx'] = None

    def loop() -> None:
        while True:
            try:
                plaintext = recv_packet(sock, key)              # decrypt packet
                handle(plaintext)                               # process it
            except Exception as exc:
                print('Receive error:', exc)
                break
    threading.Thread(target=loop, daemon=True).start()          # run thread

# ────────────────────────── program entry ─────────────────────
def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in {'server', 'client'}:
        print('Usage: python3 x25519_chat.py server|client [host] [port]')
        sys.exit(1)

    mode = sys.argv[1]                                          # server / client

    if mode == 'server':                                        # ── server part
        host = sys.argv[2] if len(sys.argv) >= 3 else '0.0.0.0'
        port = int(sys.argv[3]) if len(sys.argv) >= 4 else 12345
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind((host, port))
        listener.listen(1)
        print(f'Server listening on {host}:{port}')
        sock, addr = listener.accept()
        print('Client connected ->', addr)
    else:                                                       # ── client part
        host = sys.argv[2] if len(sys.argv) >= 3 else '127.0.0.1'
        port = int(sys.argv[3]) if len(sys.argv) >= 4 else 12345
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print(f'Connected to {host}:{port}')

    aes_key = x25519_handshake(sock, mode)                      # derive AES key
    peer    = 'client' if mode == 'server' else 'server'        # label for logs
    start_receiver(sock, aes_key, peer)                         # start RX thread

    try:                                                        # ── CLI loop
        while True:
            line = input('> ').strip()
            if not line:
                continue
            if line.startswith('/file '):                       # file command
                send_file(sock, aes_key, line[6:].strip())
            else:                                               # text message
                send_text(sock, aes_key, line)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        sock.close()                                            # graceful exit

if __name__ == '__main__':
    main()                                                      # run main
