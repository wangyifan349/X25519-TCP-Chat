#!/usr/bin/env python3
"""
secure_tcp_file_chat_v3.py

这是一个命令行 TCP 安全通信小工具，支持普通文本消息收发、多个大文件并发发送、多个大文件并发接收、接收后 SHA-256 完整性校验，以及默认的 received_files 目录落盘。程序使用两条 TCP 连接：消息通道负责低延迟文本通信，文件通道负责文件元信息、文件分块和文件结束校验信息；两条通道分别运行发送和接收线程，因此传输大文件时不会阻塞消息收发。

通信协议逻辑：客户端和服务端会在消息通道、文件通道上分别执行一次握手。握手阶段明文交换 MAGIC、通道名、X25519 临时公钥和随机数，然后双方用 X25519 得到 shared_secret，再把握手 transcript 的 SHA-256 作为 PBKDF2-SHA256 的 salt 迭代派生 master_key，最后扩展出 client->server 与 server->client 两个方向的 ChaCha20-Poly1305 密钥和 nonce 前缀。握手结束后，所有应用层帧都会先按 `1 字节帧类型 + 4 字节明文长度 + 明文载荷` 打包，再整体加密为 `4 字节密文长度 + ChaCha20-Poly1305 密文` 发送。消息通道只承载文本帧；文件通道承载 FILE_META、FILE_CHUNK、FILE_END，接收端按 file_id 同时维护多个 .part 文件，收到结束帧后核对大小和 SHA-256，校验成功才改名为最终文件。

安全提示：这个程序通过人工核对“总体会话校验码”来发现中间人攻击。双方必须通过可信渠道核对该值；如果不一致，应立即退出。程序会打印公钥、随机数、transcript hash 和派生密钥哈希，但不会打印 X25519 私钥或 shared_secret 原文。
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


# 握手层参数。
# MAGIC 用来区分协议版本；NAME_SIZE 固定通道名长度，当前使用 msg/file 两个通道名；
# RANDOM_SIZE 和 PUBKEY_SIZE 分别对应 32 字节随机数和 32 字节 X25519 公钥。
MAGIC = b"TCP_FILE_CHAT_V4"
NAME_SIZE = 8
RANDOM_SIZE = 32
PUBKEY_SIZE = 32
KDF_ITERATIONS = 200_000

# 应用层帧类型。握手完成后，这些帧都会被 ChaCha20-Poly1305 加密。
# 消息通道只允许 MSG_TEXT；文件通道允许 FILE_META、FILE_CHUNK、FILE_END。
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
    """用 HMAC-SHA256 从 master_key 扩展不同用途的密钥材料。"""
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
            raise ValueError("通道名过长")

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
                raise ConnectionError("连接已关闭")
            data.extend(chunk)

        return bytes(data)

    def handshake(self):
        print(f"\n========== {self.name} 通道握手开始 ==========")
        print(f"[角色] {self.role}")
        print(f"[算法] X25519 + PBKDF2-SHA256({KDF_ITERATIONS}) + ChaCha20-Poly1305")

        private_key = x25519.X25519PrivateKey.generate()
        local_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        local_random = os.urandom(RANDOM_SIZE)

        # 握手明文只包含协议标识、通道名、临时公钥和随机数。
        # 这里没有发送任何长期秘密；X25519 私钥只存在本进程内存中。
        local_hello = MAGIC + self.name_field + local_public + local_random

        print("\n[本地握手材料]")
        print(f"local_x25519_public = {local_public.hex()}")
        print(f"local_public_sha256 = {hashlib.sha256(local_public).hexdigest()}")
        print(f"local_random         = {local_random.hex()}")
        print(f"local_random_sha256  = {hashlib.sha256(local_random).hexdigest()}")

        self.sock.sendall(local_hello)

        hello_size = len(MAGIC) + NAME_SIZE + PUBKEY_SIZE + RANDOM_SIZE
        peer_hello = self.recv_exact(hello_size)

        if not peer_hello.startswith(MAGIC + self.name_field):
            raise RuntimeError(f"{self.name} 通道握手失败：协议或通道名不匹配")

        offset = len(MAGIC) + NAME_SIZE
        peer_public = peer_hello[offset:offset + PUBKEY_SIZE]
        peer_random = peer_hello[offset + PUBKEY_SIZE:]

        print("\n[对端握手材料]")
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

        # transcript 固定按 client/server 顺序拼接，避免两端因为发送先后不同得到不同哈希。
        # 它会进入 KDF，确保通道名、公钥和随机数都被绑定到最终会话密钥。
        transcript = b"".join([
            MAGIC,
            self.name_field,
            b"client-public", client_public,
            b"client-random", client_random,
            b"server-public", server_public,
            b"server-random", server_random,
        ])
        transcript_hash = hashlib.sha256(transcript).digest()

        print("\n[握手Transcript]")
        print(f"transcript_sha256   = {transcript_hash.hex()}")
        print(f"shared_secret_sha256 = {hashlib.sha256(shared_secret).hexdigest()}")
        print("注意：不打印 shared_secret 原文，只打印哈希。")

        master_key = hashlib.pbkdf2_hmac(
            "sha256",
            shared_secret,
            transcript_hash,
            KDF_ITERATIONS,
            dklen=32,
        )

        # 两个方向使用不同密钥和不同 nonce 前缀。
        # ChaCha20-Poly1305 的 nonce 是 12 字节：4 字节方向前缀 + 8 字节递增序号。
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

        print("\n[派生结果]")
        print(f"master_key_sha256    = {hashlib.sha256(master_key).hexdigest()}")
        print(f"client_to_server_key = {hashlib.sha256(key_c2s).hexdigest()}")
        print(f"server_to_client_key = {hashlib.sha256(key_s2c).hexdigest()}")
        print(f"client_nonce_prefix  = {nonce_c2s.hex()}")
        print(f"server_nonce_prefix  = {nonce_s2c.hex()}")
        print(f"{self.name}通道校验码 = {self.verify_code.hex()[:40]}")
        print(f"========== {self.name} 通道握手结束 ==========\n")

    def send_frame(self, frame_type: int, payload: bytes = b""):
        # 明文帧格式：1 字节 frame_type + 4 字节 payload 长度 + payload。
        # 整个明文帧随后被 AEAD 加密；网络上只能看到密文长度和密文内容。
        inner = struct.pack("!BI", frame_type, len(payload)) + payload

        with self.send_lock:
            nonce = self.send_nonce_prefix + self.send_seq.to_bytes(8, "big")
            self.send_seq += 1
            # AAD 绑定协议版本和通道名，避免密文被跨协议或跨通道误用。
            encrypted = self.send_aead.encrypt(nonce, inner, MAGIC + self.name_field)

            if len(encrypted) > MAX_FRAME_SIZE:
                raise ValueError("加密帧过大")

            self.sock.sendall(struct.pack("!I", len(encrypted)) + encrypted)

    def recv_frame(self):
        # 网络帧格式：4 字节密文长度 + ChaCha20-Poly1305 密文。
        # 解密成功才会解析内部的应用层帧类型和载荷。
        encrypted_len = struct.unpack("!I", self.recv_exact(4))[0]

        if encrypted_len > MAX_FRAME_SIZE:
            raise ValueError(f"加密帧过大: {encrypted_len}")

        encrypted = self.recv_exact(encrypted_len)
        nonce = self.recv_nonce_prefix + self.recv_seq.to_bytes(8, "big")
        self.recv_seq += 1

        inner = self.recv_aead.decrypt(nonce, encrypted, MAGIC + self.name_field)
        frame_type, payload_len = struct.unpack("!BI", inner[:5])
        payload = inner[5:]

        if len(payload) != payload_len:
            raise ValueError("解密后的帧长度不匹配")

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

        print("\n========== 总体人工校验 ==========")
        print("请双方通过可信渠道核对下面这个值。")
        print("一致：没有发现中间人替换握手。")
        print("不一致：立刻退出，不要继续传消息或文件。")
        print(f"总体会话校验码 = {total_verify[:48]}")
        print("=================================\n")

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
                        print(f"[已加入文件发送队列] {path}")
                    else:
                        print("[文件不存在，作为普通消息发送]")
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
                print(f"[消息发送线程退出] {e}")
            self.close()

    def msg_recv_loop(self):
        try:
            while self.running.is_set():
                frame_type, payload = self.msg_channel.recv_frame()

                if frame_type != MSG_TEXT:
                    raise RuntimeError(f"消息通道收到未知帧: {frame_type}")

                print(f"\n[收到消息] {payload.decode('utf-8', errors='replace')}")
        except Exception as e:
            if self.running.is_set():
                print(f"[消息接收线程退出] {e}")
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

        # 文件元信息先发，但仍然处于文件加密通道内，所以文件名和大小不会明文暴露给旁路观察者。
        # file_id 用于让接收端同时维护多个正在接收的文件。
        meta = {
            "id": task.file_id,
            "name": task.name,
            "size": task.size,
            "chunk_size": CHUNK_SIZE,
        }

        self.file_channel.send_frame(FILE_META, json.dumps(meta, ensure_ascii=False).encode("utf-8"))

        print(f"[开始发送文件] {task.name}")
        print(f"[file_id] {task.file_id}")
        print(f"[大小] {task.size} bytes")

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
                        # 文件分块载荷：16 字节 file_id + 文件原始数据分块。
                        # 外层 send_frame 会加密和认证整个载荷。
                        payload = bytes.fromhex(task.file_id) + chunk
                        self.file_channel.send_frame(FILE_CHUNK, payload)
                    else:
                        task.fp.close()
                        # 结束帧携带发送端计算出的最终 SHA-256 和已发送大小。
                        # 接收端会用自己落盘时累计的哈希和大小进行双重校验。
                        end_info = {
                            "id": task.file_id,
                            "sha256": task.sha256.hexdigest(),
                            "size": task.sent,
                        }
                        self.file_channel.send_frame(
                            FILE_END,
                            json.dumps(end_info, ensure_ascii=False).encode("utf-8"),
                        )
                        print(f"[文件发送完成] {task.name}")
                        print(f"[file_id] {task.file_id}")
                        print(f"[SHA256] {task.sha256.hexdigest()}")
                        active.remove(task)

                now = time.time()
                if active and now - last_report >= 2:
                    for task in active:
                        percent = task.sent * 100 / task.size if task.size else 100
                        print(f"[发送进度] {task.name} {percent:.2f}%")
                    last_report = now

        except Exception as e:
            if self.running.is_set():
                print(f"[文件发送线程退出] {e}")
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

                    # 接收端按 file_id 建立独立状态；多个文件可以同时处于接收中。
                    files[meta["id"]] = {
                        "name": self.safe_name(meta["name"]),
                        "expected_size": int(meta["size"]),
                        "received": 0,
                        "sha256": hashlib.sha256(),
                        "final_path": final_path,
                        "tmp_path": tmp_path,
                        "fp": open(tmp_path, "wb"),
                    }

                    print(f"\n[开始接收文件] {files[meta['id']]['name']}")
                    print(f"[file_id] {meta['id']}")
                    print(f"[保存临时文件] {tmp_path}")

                elif frame_type == FILE_CHUNK:
                    file_id = payload[:16].hex()
                    chunk = payload[16:]
                    item = files.get(file_id)

                    if not item:
                        raise RuntimeError(f"收到未知文件分块: {file_id}")

                    item["fp"].write(chunk)
                    item["sha256"].update(chunk)
                    item["received"] += len(chunk)

                elif frame_type == FILE_END:
                    end_info = json.loads(payload.decode("utf-8"))
                    file_id = end_info["id"]
                    item = files.pop(file_id, None)

                    if not item:
                        raise RuntimeError(f"收到未知文件结束帧: {file_id}")

                    item["fp"].close()
                    actual_hash = item["sha256"].hexdigest()
                    expected_hash = end_info["sha256"]
                    actual_size = item["received"]
                    expected_size = item["expected_size"]
                    end_size = int(end_info["size"])

                    # 校验条件：接收端实际哈希、元信息大小、结束帧大小三者都必须一致。
                    ok = (
                        actual_hash == expected_hash
                        and actual_size == expected_size
                        and actual_size == end_size
                    )

                    if ok:
                        os.replace(item["tmp_path"], item["final_path"])
                        print(f"[文件接收完成] {item['name']}")
                        print(f"[保存路径] {item['final_path']}")
                        print(f"[SHA256校验成功] {actual_hash}")
                    else:
                        with suppress(Exception):
                            os.remove(item["tmp_path"])
                        print(f"[文件校验失败] {item['name']}")
                        print(f"[期望大小] {expected_size}, [结束帧大小] {end_size}, [实际大小] {actual_size}")
                        print(f"[期望SHA256] {expected_hash}")
                        print(f"[实际SHA256] {actual_hash}")
                        print("[已删除临时文件]")

                else:
                    raise RuntimeError(f"文件通道收到未知帧: {frame_type}")

        except Exception as e:
            if self.running.is_set():
                print(f"[文件接收线程退出] {e}")
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
            print(f"[握手失败] {e}")
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

    print(f"[服务端启动] 消息端口 {msg_port}, 文件端口 {file_port}")
    print("[等待消息通道连接]")
    msg_sock, msg_addr = msg_listener.accept()
    print(f"[消息通道已连接] {msg_addr}")

    print("[等待文件通道连接]")
    file_sock, file_addr = file_listener.accept()
    print(f"[文件通道已连接] {file_addr}")

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

    print(f"[已连接服务端] {host}")
    print(f"[消息端口] {msg_port}")
    print(f"[文件端口] {file_port}")

    app = ChatApp(
        SecureChannel(msg_sock, "client", "msg"),
        SecureChannel(file_sock, "client", "file"),
    )
    app.start()


def main():
    if len(sys.argv) == 1:
        print("[默认模式] 未输入参数，直接作为服务端启动。")
        print(f"[默认消息端口] {DEFAULT_MSG_PORT}")
        print(f"[默认文件端口] {DEFAULT_FILE_PORT}")
        run_server(msg_port=DEFAULT_MSG_PORT, file_port=DEFAULT_FILE_PORT)
        return

    mode = sys.argv[1].lower()

    if mode == "server":
        msg_port = int(sys.argv[2]) if len(sys.argv) >= 3 else DEFAULT_MSG_PORT
        file_port = int(sys.argv[3]) if len(sys.argv) >= 4 else msg_port + 1
        run_server(msg_port=msg_port, file_port=file_port)

    elif mode == "client":
        if len(sys.argv) < 3:
            print("客户端模式需要指定服务端地址")
            print(f"示例: python {os.path.basename(__file__)} client {DEFAULT_CLIENT_HOST} {DEFAULT_MSG_PORT} {DEFAULT_FILE_PORT}")
            return

        host = sys.argv[2]
        msg_port = int(sys.argv[3]) if len(sys.argv) >= 4 else DEFAULT_MSG_PORT
        file_port = int(sys.argv[4]) if len(sys.argv) >= 5 else msg_port + 1
        run_client(host, msg_port, file_port)

    elif mode in ("-h", "--help", "help"):
        print("用法：")
        print(f"  默认服务端: python {os.path.basename(__file__)}")
        print(f"  服务端:     python {os.path.basename(__file__)} server [msg_port] [file_port]")
        print(f"  客户端:     python {os.path.basename(__file__)} client <host> [msg_port] [file_port]")
        print(f"默认端口：消息 {DEFAULT_MSG_PORT}, 文件 {DEFAULT_FILE_PORT}")

    else:
        print("模式错误，只能是 server 或 client")
        print(f"查看帮助: python {os.path.basename(__file__)} --help")


if __name__ == "__main__":
    main()
