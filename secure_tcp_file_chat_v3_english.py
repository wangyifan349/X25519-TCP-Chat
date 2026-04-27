#!/usr/bin/env python3
"""
secure_tcp_file_chat_v3_english.py
This is a command-line secure TCP communication tool. It supports plain text chat messages, concurrent sending of multiple large files, concurrent receiving of multiple large files, SHA-256 integrity verification after each file is received, and automatic storage in the default received_files directory. The program uses two TCP connections: the message channel is used for low-latency text communication, while the file channel is used for file metadata, file chunks, and file completion information. Sending and receiving run in separate threads, so large file transfers do not block normal message traffic.
Protocol overview: the client and server perform one handshake on the message channel and another handshake on the file channel. During each handshake, both sides exchange MAGIC, channel name, ephemeral X25519 public key, and a random nonce in plaintext. Both sides then compute the X25519 shared_secret, use the SHA-256 hash of the handshake transcript as the PBKDF2-SHA256 salt, derive a master_key with iterations, and expand it into separate client-to-server and server-to-client ChaCha20-Poly1305 keys plus nonce prefixes. After the handshake, every application frame is packed as `1-byte frame type + 4-byte plaintext length + plaintext payload`, encrypted as a whole, and sent as `4-byte ciphertext length + ChaCha20-Poly1305 ciphertext`. The message channel carries only text frames. The file channel carries FILE_META, FILE_CHUNK, and FILE_END frames; the receiver maintains multiple .part files by file_id and renames a file to its final name only after size and SHA-256 verification succeeds.
Security note: this program detects man-in-the-middle attacks by asking both users to compare the printed overall session verification code through a trusted channel. If the values differ, exit immediately. The program prints public keys, random nonces, transcript hashes, and derived key hashes, but it never prints the X25519 private key or the raw shared_secret.
"""
"""
python  -m pip install --upgrade pip cryptography

"""
import os
import sys
import json
import time
import hmac
import uuid
import queue
import socket
import struct
import hashlib
import threading
from dataclasses import dataclass
from contextlib import suppress
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

# Handshake parameters.
# MAGIC identifies the protocol version. NAME_SIZE is the fixed channel-name field length;
# the current program uses two channel names: msg and file.
# RANDOM_SIZE and PUBKEY_SIZE are both 32 bytes for the random nonce and X25519 public key.
MAGIC = b"TCP_FILE_CHAT_V4"
NAME_SIZE = 8
RANDOM_SIZE = 32
PUBKEY_SIZE = 32
KDF_ITERATIONS = 200_000

# Application frame types. After the handshake, all of these frames are encrypted with ChaCha20-Poly1305.
# The message channel accepts only MSG_TEXT. The file channel accepts FILE_META, FILE_CHUNK, and FILE_END.
MSG_TEXT = 1

FILE_META = 10
FILE_CHUNK = 11
FILE_END = 12

CHUNK_SIZE = 64 * 1024
MAX_FRAME_SIZE = 20 * 1024 * 1024
MAX_ACTIVE_FILE_SENDS = 4
RECV_DIR = "received_files"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_CLIENT_HOST = "127.0.0.1"
DEFAULT_MSG_PORT = 9000
DEFAULT_FILE_PORT = 9001
def kdf_expand(master: bytes, label: bytes, size: int) -> bytes:
    """Expand purpose-specific key material from master_key using HMAC-SHA256."""
    out = b""
    prev = b""
    counter = 1
    while len(out) < size:
        prev = hmac.new(master, prev + label + bytes([counter]), hashlib.sha256).digest()
        out += prev
        counter += 1
    return out[:size]

class SecureChannel:
    def __init__(self, sock: socket.socket, role: str, name: str):
        self.sock = sock
        self.role = role
        self.name = name
        self.name_bytes = name.encode("ascii")
        if len(self.name_bytes) > NAME_SIZE:
            raise ValueError("channel name is too long")
        self.name_field = self.name_bytes.ljust(NAME_SIZE, b"\0")
        self.send_lock = threading.Lock()
        self.send_aead = None
        self.recv_aead = None
        self.send_nonce_prefix = None
        self.recv_nonce_prefix = None
        self.send_seq = 0
        self.recv_seq = 0
        self.verify_code = None
    def close(self):
        with suppress(Exception):
            self.sock.shutdown(socket.SHUT_RDWR)
        with suppress(Exception):
            self.sock.close()
    def recv_exact(self, size: int) -> bytes:
        data = bytearray()

        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("connection closed")
            data.extend(chunk)
        return bytes(data)
    def handshake(self):
        print(f"\n========== {self.name} channel handshake start ==========")
        print(f"[role] {self.role}")
        print(f"[algorithm] X25519 + PBKDF2-SHA256({KDF_ITERATIONS}) + ChaCha20-Poly1305")
        private_key = x25519.X25519PrivateKey.generate()
        local_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        local_random = os.urandom(RANDOM_SIZE)

        # The plaintext handshake contains only the protocol marker, channel name,
        # ephemeral public key, and random nonce. No long-term secret is sent;
        # the X25519 private key stays only in this process memory.
        local_hello = MAGIC + self.name_field + local_public + local_random

        print("\n[local handshake material]")
        print(f"local_x25519_public = {local_public.hex()}")
        print(f"local_public_sha256 = {hashlib.sha256(local_public).hexdigest()}")
        print(f"local_random         = {local_random.hex()}")
        print(f"local_random_sha256  = {hashlib.sha256(local_random).hexdigest()}")

        self.sock.sendall(local_hello)

        hello_size = len(MAGIC) + NAME_SIZE + PUBKEY_SIZE + RANDOM_SIZE
        peer_hello = self.recv_exact(hello_size)

        if not peer_hello.startswith(MAGIC + self.name_field):
            raise RuntimeError(f"{self.name} channel handshake failed: protocol marker or channel name mismatch")

        offset = len(MAGIC) + NAME_SIZE
        peer_public = peer_hello[offset:offset + PUBKEY_SIZE]
        peer_random = peer_hello[offset + PUBKEY_SIZE:]
        print("\n[peer handshake material]")
        print(f"peer_x25519_public = {peer_public.hex()}")
        print(f"peer_public_sha256 = {hashlib.sha256(peer_public).hexdigest()}")
        print(f"peer_random        = {peer_random.hex()}")
        print(f"peer_random_sha256 = {hashlib.sha256(peer_random).hexdigest()}")
        shared_secret = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
        if self.role == "client":
            client_public, client_random = local_public, local_random
            server_public, server_random = peer_public, peer_random
        else:
            client_public, client_random = peer_public, peer_random
            server_public, server_random = local_public, local_random
        # The transcript is always built in client/server order so both sides get
        # the same hash regardless of send timing. It is fed into the KDF so the
        # channel name, public keys, and random nonces are bound to the session keys.
        transcript = b"".join([
            MAGIC,
            self.name_field,
            b"client-public", client_public,
            b"client-random", client_random,
            b"server-public", server_public,
            b"server-random", server_random,
        ])
        transcript_hash = hashlib.sha256(transcript).digest()
        print("\n[handshake transcript]")
        print(f"transcript_sha256   = {transcript_hash.hex()}")
        print(f"shared_secret_sha256 = {hashlib.sha256(shared_secret).hexdigest()}")
        print("note: the raw shared_secret is not printed; only its hash is shown.")
        master_key = hashlib.pbkdf2_hmac(
            "sha256",
            shared_secret,
            transcript_hash,
            KDF_ITERATIONS,
            dklen=32,
        )
        # Each direction uses a different key and nonce prefix.
        # The ChaCha20-Poly1305 nonce is 12 bytes: 4-byte direction prefix + 8-byte sequence number.
        key_c2s = kdf_expand(master_key, self.name_field + b"key-c2s", 32)
        key_s2c = kdf_expand(master_key, self.name_field + b"key-s2c", 32)
        nonce_c2s = kdf_expand(master_key, self.name_field + b"nonce-c2s", 4)
        nonce_s2c = kdf_expand(master_key, self.name_field + b"nonce-s2c", 4)
        if self.role == "client":
            send_key, recv_key = key_c2s, key_s2c
            self.send_nonce_prefix, self.recv_nonce_prefix = nonce_c2s, nonce_s2c
        else:
            send_key, recv_key = key_s2c, key_c2s
            self.send_nonce_prefix, self.recv_nonce_prefix = nonce_s2c, nonce_c2s
        self.send_aead = ChaCha20Poly1305(send_key)
        self.recv_aead = ChaCha20Poly1305(recv_key)
        self.verify_code = hashlib.sha256(b"verify" + self.name_field + transcript_hash + master_key).digest()
        print("\n[derived results]")
        print(f"master_key_sha256    = {hashlib.sha256(master_key).hexdigest()}")
        print(f"client_to_server_key = {hashlib.sha256(key_c2s).hexdigest()}")
        print(f"server_to_client_key = {hashlib.sha256(key_s2c).hexdigest()}")
        print(f"client_nonce_prefix  = {nonce_c2s.hex()}")
        print(f"server_nonce_prefix  = {nonce_s2c.hex()}")
        print(f"{self.name} channel verification code = {self.verify_code.hex()[:40]}")
        print(f"========== {self.name} channel handshake end ==========\n")

    def send_frame(self, frame_type: int, payload: bytes = b""):
        # Plaintext frame format: 1-byte frame_type + 4-byte payload length + payload.
        # The whole plaintext frame is then encrypted with AEAD; the network only sees ciphertext length and ciphertext.
        inner = struct.pack("!BI", frame_type, len(payload)) + payload

        with self.send_lock:
            nonce = self.send_nonce_prefix + self.send_seq.to_bytes(8, "big")
            self.send_seq += 1
            # AAD binds the protocol version and channel name to prevent cross-protocol or cross-channel ciphertext reuse.
            encrypted = self.send_aead.encrypt(nonce, inner, MAGIC + self.name_field)

            if len(encrypted) > MAX_FRAME_SIZE:
                raise ValueError("encrypted frame is too large")

            self.sock.sendall(struct.pack("!I", len(encrypted)) + encrypted)

    def recv_frame(self):
        # Network frame format: 4-byte ciphertext length + ChaCha20-Poly1305 ciphertext.
        # The inner application frame is parsed only after successful decryption.
        encrypted_len = struct.unpack("!I", self.recv_exact(4))[0]

        if encrypted_len > MAX_FRAME_SIZE:
            raise ValueError(f"encrypted frame is too large: {encrypted_len}")

        encrypted = self.recv_exact(encrypted_len)
        nonce = self.recv_nonce_prefix + self.recv_seq.to_bytes(8, "big")
        self.recv_seq += 1

        inner = self.recv_aead.decrypt(nonce, encrypted, MAGIC + self.name_field)
        frame_type, payload_len = struct.unpack("!BI", inner[:5])
        payload = inner[5:]

        if len(payload) != payload_len:
            raise ValueError("decrypted frame length mismatch")

        return frame_type, payload


@dataclass
class SendFileTask:
    file_id: str
    path: str
    name: str
    size: int
    fp: object
    sha256: object
    sent: int = 0


class ChatApp:
    def __init__(self, msg_channel: SecureChannel, file_channel: SecureChannel):
        self.msg_channel = msg_channel
        self.file_channel = file_channel
        self.running = threading.Event()
        self.running.set()

        self.msg_queue = queue.Queue()
        self.file_queue = queue.Queue()
        os.makedirs(RECV_DIR, exist_ok=True)

    def close(self):
        self.running.clear()
        self.msg_channel.close()
        self.file_channel.close()

    def do_handshake(self):
        self.msg_channel.handshake()
        self.file_channel.handshake()

        total_verify = hashlib.sha256(
            b"total-verify" + self.msg_channel.verify_code + self.file_channel.verify_code
        ).hexdigest()

        print("\n========== overall manual verification ==========")
        print("Compare the following value through a trusted channel.")
        print("If it matches: no handshake substitution was detected.")
        print("If it differs: exit immediately and do not send messages or files.")
        print(f"overall session verification code = {total_verify[:48]}")
        print("===============================================\n")

    def input_loop(self):
        try:
            while self.running.is_set():
                line = input("> ")

                if line.lower() in ("exit", "quit"):
                    break

                if line.startswith("/send "):
                    path = line[len("/send "):].strip()
                    if len(path) >= 2 and path[0] == path[-1] and path[0] in ("'", '"'):
                        path = path[1:-1]

                    if os.path.isfile(path):
                        self.file_queue.put(path)
                        print(f"[queued file for sending] {path}")
                    else:
                        print("[file does not exist; sending the line as a normal message]")
                        self.msg_queue.put(line)
                else:
                    self.msg_queue.put(line)

        except (EOFError, KeyboardInterrupt):
            pass
        finally:
            self.close()

    def msg_send_loop(self):
        try:
            while self.running.is_set():
                try:
                    text = self.msg_queue.get(timeout=0.2)
                except queue.Empty:
                    continue

                self.msg_channel.send_frame(MSG_TEXT, text.encode("utf-8"))
        except Exception as e:
            if self.running.is_set():
                print(f"[message sender thread exited] {e}")
            self.close()

    def msg_recv_loop(self):
        try:
            while self.running.is_set():
                frame_type, payload = self.msg_channel.recv_frame()

                if frame_type != MSG_TEXT:
                    raise RuntimeError(f"message channel received an unknown frame: {frame_type}")

                print(f"[received message] {payload.decode('utf-8', errors='replace')}")
        except Exception as e:
            if self.running.is_set():
                print(f"[message receiver thread exited] {e}")
            self.close()

    def add_file_task(self, path: str):
        task = SendFileTask(
            file_id=uuid.uuid4().hex,
            path=path,
            name=os.path.basename(path),
            size=os.path.getsize(path),
            fp=open(path, "rb"),
            sha256=hashlib.sha256(),
        )

        # File metadata is sent first, but it is still inside the encrypted file channel,
        # so the filename and size are not exposed in plaintext to passive observers.
        # file_id lets the receiver track multiple in-progress files at the same time.
        meta = {
            "id": task.file_id,
            "name": task.name,
            "size": task.size,
            "chunk_size": CHUNK_SIZE,
        }

        self.file_channel.send_frame(FILE_META, json.dumps(meta, ensure_ascii=False).encode("utf-8"))

        print(f"[start sending file] {task.name}")
        print(f"[file_id] {task.file_id}")
        print(f"[size] {task.size} bytes")

        return task

    def file_send_loop(self):
        active = []
        last_report = time.time()

        try:
            while self.running.is_set():
                while len(active) < MAX_ACTIVE_FILE_SENDS:
                    try:
                        active.append(self.add_file_task(self.file_queue.get_nowait()))
                    except queue.Empty:
                        break

                if not active:
                    try:
                        active.append(self.add_file_task(self.file_queue.get(timeout=0.2)))
                    except queue.Empty:
                        continue
                    continue

                for task in active[:]:
                    chunk = task.fp.read(CHUNK_SIZE)

                    if chunk:
                        task.sha256.update(chunk)
                        task.sent += len(chunk)
                        # File chunk payload: 16-byte file_id + raw file data chunk.
                        # The outer send_frame encrypts and authenticates the entire payload.
                        payload = bytes.fromhex(task.file_id) + chunk
                        self.file_channel.send_frame(FILE_CHUNK, payload)
                    else:
                        task.fp.close()
                        # The end frame carries the final SHA-256 and byte count computed by the sender.
                        # The receiver checks them against its own accumulated file hash and byte count.
                        end_info = {
                            "id": task.file_id,
                            "sha256": task.sha256.hexdigest(),
                            "size": task.sent,
                        }
                        self.file_channel.send_frame(
                            FILE_END,
                            json.dumps(end_info, ensure_ascii=False).encode("utf-8"),
                        )
                        print(f"[file send complete] {task.name}")
                        print(f"[file_id] {task.file_id}")
                        print(f"[SHA256] {task.sha256.hexdigest()}")
                        active.remove(task)

                now = time.time()
                if active and now - last_report >= 2:
                    for task in active:
                        percent = task.sent * 100 / task.size if task.size else 100
                        print(f"[send progress] {task.name} {percent:.2f}%")
                    last_report = now

        except Exception as e:
            if self.running.is_set():
                print(f"[file sender thread exited] {e}")
            self.close()
        finally:
            for task in active:
                with suppress(Exception):
                    task.fp.close()

    def safe_name(self, name: str) -> str:
        name = os.path.basename(name.replace("\\", "/")).replace("\x00", "")
        return name or "received_file"

    def unique_path(self, name: str) -> str:
        name = self.safe_name(name)
        base, ext = os.path.splitext(name)
        path = os.path.join(RECV_DIR, name)
        index = 1

        while os.path.exists(path) or os.path.exists(path + ".part"):
            path = os.path.join(RECV_DIR, f"{base}_{index}{ext}")
            index += 1

        return path

    def file_recv_loop(self):
        files = {}

        try:
            while self.running.is_set():
                frame_type, payload = self.file_channel.recv_frame()

                if frame_type == FILE_META:
                    meta = json.loads(payload.decode("utf-8"))
                    final_path = self.unique_path(meta["name"])
                    tmp_path = final_path + ".part"

                    # The receiver creates independent state per file_id; multiple files can be in progress at once.
                    files[meta["id"]] = {
                        "name": self.safe_name(meta["name"]),
                        "expected_size": int(meta["size"]),
                        "received": 0,
                        "sha256": hashlib.sha256(),
                        "final_path": final_path,
                        "tmp_path": tmp_path,
                        "fp": open(tmp_path, "wb"),
                    }

                    print(f"\n[start receiving file] {files[meta['id']]['name']}")
                    print(f"[file_id] {meta['id']}")
                    print(f"[temporary file] {tmp_path}")

                elif frame_type == FILE_CHUNK:
                    file_id = payload[:16].hex()
                    chunk = payload[16:]
                    item = files.get(file_id)

                    if not item:
                        raise RuntimeError(f"received a chunk for an unknown file: {file_id}")

                    item["fp"].write(chunk)
                    item["sha256"].update(chunk)
                    item["received"] += len(chunk)

                elif frame_type == FILE_END:
                    end_info = json.loads(payload.decode("utf-8"))
                    file_id = end_info["id"]
                    item = files.pop(file_id, None)

                    if not item:
                        raise RuntimeError(f"received an end frame for an unknown file: {file_id}")

                    item["fp"].close()
                    actual_hash = item["sha256"].hexdigest()
                    expected_hash = end_info["sha256"]
                    actual_size = item["received"]
                    expected_size = item["expected_size"]
                    end_size = int(end_info["size"])

                    # Verification condition: receiver hash, metadata size, and end-frame size must all match.
                    ok = (
                        actual_hash == expected_hash
                        and actual_size == expected_size
                        and actual_size == end_size
                    )

                    if ok:
                        os.replace(item["tmp_path"], item["final_path"])
                        print(f"[file receive complete] {item['name']}")
                        print(f"[saved path] {item['final_path']}")
                        print(f"[expected SHA256] {expected_hash}")
                        print(f"[actual SHA256] {actual_hash}")
                        print("[SHA256 verification succeeded]")
                    else:
                        with suppress(Exception):
                            os.remove(item["tmp_path"])
                        print(f"[file verification failed] {item['name']}")
                        print(f"[expected size] {expected_size}, [end-frame size] {end_size}, [actual size] {actual_size}")
                        print(f"[expected SHA256] {expected_hash}")
                        print(f"[actual SHA256] {actual_hash}")
                        print("[temporary file deleted]")

                else:
                    raise RuntimeError(f"file channel received an unknown frame: {frame_type}")

        except Exception as e:
            if self.running.is_set():
                print(f"[file receiver thread exited] {e}")
            self.close()
        finally:
            for item in files.values():
                with suppress(Exception):
                    item["fp"].close()
                with suppress(Exception):
                    os.remove(item["tmp_path"])

    def start(self):
        try:
            self.do_handshake()
        except Exception as e:
            print(f"[handshake failed] {e}")
            self.close()
            return

        threads = [
            threading.Thread(target=self.input_loop, daemon=True),
            threading.Thread(target=self.msg_send_loop, daemon=True),
            threading.Thread(target=self.msg_recv_loop, daemon=True),
            threading.Thread(target=self.file_send_loop, daemon=True),
            threading.Thread(target=self.file_recv_loop, daemon=True),
        ]

        for t in threads:
            t.start()

        try:
            while self.running.is_set():
                time.sleep(0.2)
        except KeyboardInterrupt:
            pass
        finally:
            self.close()


def run_server(host=DEFAULT_HOST, msg_port=DEFAULT_MSG_PORT, file_port=DEFAULT_FILE_PORT):
    msg_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    file_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    msg_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    file_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    msg_listener.bind((host, msg_port))
    file_listener.bind((host, file_port))

    msg_listener.listen(1)
    file_listener.listen(1)

    print(f"[server started] message port {msg_port}, file port {file_port}")
    print("[waiting for message channel connection]")
    msg_sock, msg_addr = msg_listener.accept()
    print(f"[message channel connected] {msg_addr}")

    print("[waiting for file channel connection]")
    file_sock, file_addr = file_listener.accept()
    print(f"[file channel connected] {file_addr}")

    with suppress(Exception):
        msg_listener.close()
    with suppress(Exception):
        file_listener.close()

    app = ChatApp(
        SecureChannel(msg_sock, "server", "msg"),
        SecureChannel(file_sock, "server", "file"),
    )
    app.start()


def run_client(host: str, msg_port=DEFAULT_MSG_PORT, file_port=DEFAULT_FILE_PORT):
    msg_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    file_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    msg_sock.connect((host, msg_port))
    file_sock.connect((host, file_port))

    print(f"[connected to server] {host}")
    print(f"[message port] {msg_port}")
    print(f"[file port] {file_port}")

    app = ChatApp(
        SecureChannel(msg_sock, "client", "msg"),
        SecureChannel(file_sock, "client", "file"),
    )
    app.start()


def main():
    if len(sys.argv) == 1:
        print("[default mode] no arguments provided; starting as server.")
        print(f"[default message port] {DEFAULT_MSG_PORT}")
        print(f"[default file port] {DEFAULT_FILE_PORT}")
        run_server(msg_port=DEFAULT_MSG_PORT, file_port=DEFAULT_FILE_PORT)
        return
    mode = sys.argv[1].lower()
    if mode == "server":
        msg_port = int(sys.argv[2]) if len(sys.argv) >= 3 else DEFAULT_MSG_PORT
        file_port = int(sys.argv[3]) if len(sys.argv) >= 4 else msg_port + 1
        run_server(msg_port=msg_port, file_port=file_port)
    elif mode == "client":
        if len(sys.argv) < 3:
            print("client mode requires a server address")
            print(f"example: python {os.path.basename(__file__)} client {DEFAULT_CLIENT_HOST} {DEFAULT_MSG_PORT} {DEFAULT_FILE_PORT}")
            return
        host = sys.argv[2]
        msg_port = int(sys.argv[3]) if len(sys.argv) >= 4 else DEFAULT_MSG_PORT
        file_port = int(sys.argv[4]) if len(sys.argv) >= 5 else msg_port + 1
        run_client(host, msg_port, file_port)
    elif mode in ("-h", "--help", "help"):
        print("usage:")
        print(f"  default server: python {os.path.basename(__file__)}")
        print(f"  server:         python {os.path.basename(__file__)} server [msg_port] [file_port]")
        print(f"  client:         python {os.path.basename(__file__)} client <host> [msg_port] [file_port]")
        print(f"default ports: message {DEFAULT_MSG_PORT}, file {DEFAULT_FILE_PORT}")
    else:
        print("invalid mode; use server or client")
        print(f"show help: python {os.path.basename(__file__)} --help")

main()
