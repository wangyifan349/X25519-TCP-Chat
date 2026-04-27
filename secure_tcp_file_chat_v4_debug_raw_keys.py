#!/usr/bin/env python3
"""
This is a command-line secure TCP communication tool. It supports plain text chat messages, concurrent sending of multiple large files, concurrent receiving of multiple large files, SHA-256 integrity verification after each file is received, and automatic storage in the default received_files directory. The program uses two TCP connections: the message channel is used for low-latency text communication, while the file channel is used for file metadata, file chunks, and file completion information. Sending and receiving run in separate threads, so large file transfers do not block normal message traffic.
Protocol overview: the client and server perform one handshake on the message channel and another handshake on the file channel. During each handshake, both sides exchange MAGIC, channel name, ephemeral X25519 public key, and a random nonce in plaintext. Both sides then compute the X25519 shared_secret, use the SHA-256 hash of the handshake transcript as the PBKDF2-SHA256 salt, derive a master_key with iterations, and expand it into separate client-to-server and server-to-client ChaCha20-Poly1305 keys plus nonce prefixes. After the handshake, every application frame is packed as `1-byte frame type + 4-byte plaintext length + plaintext payload`, encrypted as a whole, and sent as `4-byte ciphertext length + ChaCha20-Poly1305 ciphertext`. The message channel carries only text frames. The file channel carries FILE_META, FILE_CHUNK, and FILE_END frames; the receiver maintains multiple .part files by file_id and renames a file to its final name only after size and SHA-256 verification succeeds.
Security note: this study/debug version detects man-in-the-middle attacks by asking both users to compare the printed overall session verification code through a trusted channel. If the values differ, exit immediately. For learning purposes, this version prints very sensitive handshake material, including the X25519 private key, raw shared_secret, master key, and traffic keys. Do not use this verbose debug output in production or in any environment where logs may be exposed.
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
MAGIC = b"TCP_FILE_CHAT_V4"              # Protocol/version marker used before encryption starts.
NAME_SIZE = 8                             # Fixed channel-name field size; "msg" or "file" is NUL-padded.
RANDOM_SIZE = 32                          # Per-channel random nonce mixed into the transcript and KDF.
PUBKEY_SIZE = 32                          # Raw X25519 public keys are 32 bytes.
KDF_ITERATIONS = 200_000                  # PBKDF2 work factor for deriving the channel master key.

# Application frame types. After the handshake, all of these frames are encrypted with ChaCha20-Poly1305.
# The message channel accepts only MSG_TEXT. The file channel accepts FILE_META, FILE_CHUNK, and FILE_END.
MSG_TEXT = 1                              # Encrypted message-channel frame containing UTF-8 text.

FILE_META = 10                            # Encrypted file metadata frame: file_id, name, size, chunk size.
FILE_CHUNK = 11                           # Encrypted file chunk frame: 16-byte file_id + raw bytes.
FILE_END = 12                             # Encrypted file completion frame: final size and SHA-256.

CHUNK_SIZE = 64 * 1024                    # 64 KiB chunks keep memory usage stable for very large files.
MAX_FRAME_SIZE = 20 * 1024 * 1024         # Reject huge frames to avoid accidental memory abuse.
MAX_ACTIVE_FILE_SENDS = 4                 # Number of large files interleaved by the sender.
RECV_DIR = "received_files"               # Verified files are moved here after hash checking.
DEFAULT_HOST = "0.0.0.0"                  # Server listens on all IPv4 interfaces by default.
DEFAULT_CLIENT_HOST = "127.0.0.1"         # Example localhost address used in help text.
DEFAULT_MSG_PORT = 9000                   # Default TCP port for the encrypted message channel.
DEFAULT_FILE_PORT = 9001                  # Default TCP port for the encrypted file-transfer channel.

# Small HKDF-expand-like helper. It derives independent byte strings from master_key.
# The label is important because it prevents using the same derived bytes for different purposes.
def kdf_expand(master: bytes, label: bytes, size: int) -> bytes:
    """Expand purpose-specific key material from master_key using HMAC-SHA256."""
    out = b""                              # Accumulated output bytes.
    prev = b""                             # Previous HMAC block, chained into the next one.
    counter = 1                             # Single-byte expansion block counter.
    while len(out) < size:
        prev = hmac.new(master, prev + label + bytes([counter]), hashlib.sha256).digest()
        out += prev                         # Append one SHA-256-sized HMAC block.
        counter += 1                        # Move to the next expansion block.
    return out[:size]                       # Trim to exactly the requested output length.


# SecureChannel is the transport/security layer for one TCP connection.
# It owns the handshake, symmetric keys, nonces, encryption, decryption, and frame boundaries.
class SecureChannel:
    def __init__(self, sock: socket.socket, role: str, name: str):
        self.sock = sock                    # Connected TCP socket for this logical channel.
        self.role = role                    # "client" or "server"; controls key-direction mapping.
        self.name = name                    # Logical channel name: "msg" or "file".
        self.name_bytes = name.encode("ascii")
        if len(self.name_bytes) > NAME_SIZE:
            raise ValueError("channel name is too long")
        self.name_field = self.name_bytes.ljust(NAME_SIZE, b"\0")  # Fixed-width field used in handshake and AEAD AAD.
        self.send_lock = threading.Lock()   # Prevents concurrent writes from interleaving encrypted frames.
        self.send_aead = None               # ChaCha20-Poly1305 object for outgoing frames after handshake.
        self.recv_aead = None               # ChaCha20-Poly1305 object for incoming frames after handshake.
        self.send_nonce_prefix = None       # 4-byte prefix for outbound 12-byte nonces.
        self.recv_nonce_prefix = None       # 4-byte prefix for inbound 12-byte nonces.
        self.send_seq = 0                   # Outbound frame sequence; must not repeat with the same key.
        self.recv_seq = 0                   # Inbound frame sequence expected from the peer.
        self.verify_code = None             # Per-channel value used to build the manual verification code.
    def close(self):
        with suppress(Exception):
            self.sock.shutdown(socket.SHUT_RDWR)
        with suppress(Exception):
            self.sock.close()
    def recv_exact(self, size: int) -> bytes:
        data = bytearray()                  # Mutable buffer for assembling exact protocol fields.
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("connection closed")
            data.extend(chunk)              # Continue until the requested byte count is complete.
        return bytes(data)

    # Handshake flow:
    #   1. Exchange MAGIC + channel name + ephemeral X25519 public key + random nonce.
    #   2. Compute X25519 shared_secret locally; the secret itself never crosses the network.
    #   3. Hash the transcript and use it as PBKDF2 salt.
    #   4. Derive separate keys/nonces for client->server and server->client.
    #   5. Print verification values so users can detect handshake substitution.
    def handshake(self):
        print(f"\n========== {self.name} channel handshake start ==========")
        print(f"[role] {self.role}")
        print(f"[algorithm] X25519 + PBKDF2-SHA256({KDF_ITERATIONS}) + ChaCha20-Poly1305")
        private_key = x25519.X25519PrivateKey.generate()      # Ephemeral private key for this channel/session only.
        local_private = private_key.private_bytes(             # Study mode: expose raw local private key for learning/debugging.
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        local_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        local_random = os.urandom(RANDOM_SIZE)                 # Extra entropy bound into transcript/KDF.

        # The plaintext handshake contains only the protocol marker, channel name,
        # ephemeral public key, and random nonce. The private key is printed below
        # only because this file is being used for protocol-learning purposes.
        local_hello = MAGIC + self.name_field + local_public + local_random  # Plaintext handshake record.
        print("\n[local handshake material - study/debug mode]")
        print(f"local_x25519_private = {local_private.hex()}")
        print(f"local_x25519_public  = {local_public.hex()}")
        print(f"local_random          = {local_random.hex()}")
        self.sock.sendall(local_hello)                         # Send our handshake record.
        hello_size = len(MAGIC) + NAME_SIZE + PUBKEY_SIZE + RANDOM_SIZE  # Fixed-size peer handshake record.
        peer_hello = self.recv_exact(hello_size)               # Read the peer handshake record exactly.
        if not peer_hello.startswith(MAGIC + self.name_field):
            raise RuntimeError(f"{self.name} channel handshake failed: protocol marker or channel name mismatch")
        offset = len(MAGIC) + NAME_SIZE                        # Skip protocol marker and channel name.
        peer_public = peer_hello[offset:offset + PUBKEY_SIZE]  # Peer raw X25519 public key.
        peer_random = peer_hello[offset + PUBKEY_SIZE:]        # Peer random nonce.

        print("\n[peer handshake material]")
        print(f"peer_x25519_public = {peer_public.hex()}")
        print(f"peer_random        = {peer_random.hex()}")
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
        transcript_hash = hashlib.sha256(transcript).digest()  # Stable hash of both peers' handshake material.
        print("\n[handshake transcript and X25519 result - study/debug mode]")
        print(f"transcript_hex       = {transcript.hex()}")
        print(f"transcript_sha256    = {transcript_hash.hex()}")
        print(f"shared_secret        = {shared_secret.hex()}")
        print("warning: the raw shared_secret is printed for learning only; do not enable this in production.")
        master_key = hashlib.pbkdf2_hmac(      # Iterative KDF: X25519 secret -> channel master key.
            "sha256",
            shared_secret,                     # Secret input from X25519.
            transcript_hash,                   # Salt binds both peers' public handshake material.
            KDF_ITERATIONS,                    # Work factor.
            dklen=32,                          # 256-bit master key.
        )
        # Each direction uses a different key and nonce prefix.
        # The ChaCha20-Poly1305 nonce is 12 bytes: 4-byte direction prefix + 8-byte sequence number.
        key_c2s = kdf_expand(master_key, self.name_field + b"key-c2s", 32)      # Client-to-server AEAD key.
        key_s2c = kdf_expand(master_key, self.name_field + b"key-s2c", 32)      # Server-to-client AEAD key.
        nonce_c2s = kdf_expand(master_key, self.name_field + b"nonce-c2s", 4)  # Client-to-server nonce prefix.
        nonce_s2c = kdf_expand(master_key, self.name_field + b"nonce-s2c", 4)  # Server-to-client nonce prefix.
        if self.role == "client":
            send_key, recv_key = key_c2s, key_s2c
            self.send_nonce_prefix, self.recv_nonce_prefix = nonce_c2s, nonce_s2c
        else:
            send_key, recv_key = key_s2c, key_c2s
            self.send_nonce_prefix, self.recv_nonce_prefix = nonce_s2c, nonce_c2s
        self.send_aead = ChaCha20Poly1305(send_key)            # Encrypts and authenticates outbound frames.
        self.recv_aead = ChaCha20Poly1305(recv_key)            # Decrypts and verifies inbound frames.
        self.verify_code = hashlib.sha256(b"verify" + self.name_field + transcript_hash + master_key).digest()
        print("\n[derived key material - study/debug mode]")
        print(f"master_key           = {master_key.hex()}")
        print(f"client_to_server_key = {key_c2s.hex()}")
        print(f"server_to_client_key = {key_s2c.hex()}")
        print(f"client_nonce_prefix  = {nonce_c2s.hex()}")
        print(f"server_nonce_prefix  = {nonce_s2c.hex()}")
        print(f"{self.name} channel verification code = {self.verify_code.hex()}")
        print(f"========== {self.name} channel handshake end ==========\n")

    # Encrypt and send one application frame.
    # The caller chooses the application frame type; this method handles wire framing and AEAD.
    def send_frame(self, frame_type: int, payload: bytes = b""):
        # Plaintext frame format: 1-byte frame_type + 4-byte payload length + payload.
        # The whole plaintext frame is then encrypted with AEAD; the network only sees ciphertext length and ciphertext.
        inner = struct.pack("!BI", frame_type, len(payload)) + payload  # Inner plaintext frame before encryption.
        with self.send_lock:                   # Serialize socket writes and nonce increments.
            nonce = self.send_nonce_prefix + self.send_seq.to_bytes(8, "big")  # 12-byte AEAD nonce.
            self.send_seq += 1                 # Advance immediately so nonce reuse cannot occur.
            # AAD binds the protocol version and channel name to prevent cross-protocol or cross-channel ciphertext reuse.
            encrypted = self.send_aead.encrypt(nonce, inner, MAGIC + self.name_field)  # Encrypt + authenticate.
            if len(encrypted) > MAX_FRAME_SIZE:
                raise ValueError("encrypted frame is too large")
            self.sock.sendall(struct.pack("!I", len(encrypted)) + encrypted)  # Send length-prefixed ciphertext.

    # Receive, decrypt, authenticate, and parse one application frame.
    # If the Poly1305 tag is invalid, decrypt() raises and the connection is closed by the caller.
    def recv_frame(self):
        # Network frame format: 4-byte ciphertext length + ChaCha20-Poly1305 ciphertext.
        # The inner application frame is parsed only after successful decryption.
        encrypted_len = struct.unpack("!I", self.recv_exact(4))[0]  # Read ciphertext length prefix.
        if encrypted_len > MAX_FRAME_SIZE:
            raise ValueError(f"encrypted frame is too large: {encrypted_len}")
        encrypted = self.recv_exact(encrypted_len)             # Read exactly one encrypted frame.
        nonce = self.recv_nonce_prefix + self.recv_seq.to_bytes(8, "big")  # Expected peer nonce for this frame.
        self.recv_seq += 1                                     # Keep receiver sequence aligned.
        inner = self.recv_aead.decrypt(nonce, encrypted, MAGIC + self.name_field)  # Fails if ciphertext/tag/AAD is modified.
        frame_type, payload_len = struct.unpack("!BI", inner[:5])  # Parse decrypted application frame header.
        payload = inner[5:]                                     # Decrypted application payload.
        if len(payload) != payload_len:
            raise ValueError("decrypted frame length mismatch")
        return frame_type, payload


# Sender state for a file that may be interleaved with other active file transfers.
@dataclass
class SendFileTask:
    file_id: str                             # Unique file identifier; 32 hex chars, 16 bytes on the wire.
    path: str                                # Local source path.
    name: str                                # Basename sent to receiver, not the full local path.
    size: int                                # Source file size in bytes.
    fp: object                               # Open binary file object for this transfer.
    sha256: object                           # Running SHA-256 hasher for bytes sent.
    sent: int = 0                            # Number of bytes sent so far.


# ChatApp is the application layer. It keeps user input, message I/O, and file I/O separate.
# This is why a 5GB file transfer does not stop interactive messages from being sent or received.
class ChatApp:
    def __init__(self, msg_channel: SecureChannel, file_channel: SecureChannel):
        self.msg_channel = msg_channel        # Independent encrypted channel for chat messages.
        self.file_channel = file_channel      # Independent encrypted channel for file transfer.
        self.running = threading.Event()      # Shared shutdown flag used by all threads.
        self.running.set()
        self.msg_queue = queue.Queue()        # Outbound messages from input thread to sender thread.
        self.file_queue = queue.Queue()       # Outbound file paths from input thread to file sender thread.
        os.makedirs(RECV_DIR, exist_ok=True)  # Create receive directory if needed.

    def close(self):
        self.running.clear()
        self.msg_channel.close()
        self.file_channel.close()

    def do_handshake(self):
        self.msg_channel.handshake()
        self.file_channel.handshake()
        # The two channels are independent; combine their verification codes so users only
        # need to compare one final value to cover both the message and file channels.
        total_verify = hashlib.sha256(
            b"total-verify" + self.msg_channel.verify_code + self.file_channel.verify_code
        ).hexdigest()
        print("\n========== overall manual verification ==========")
        print("Compare the following value through a trusted channel.")
        print("If it matches: no handshake substitution was detected.")
        print("If it differs: exit immediately and do not send messages or files.")
        pretty_verify = ":".join(total_verify[i:i + 4] for i in range(0, 48, 4))
        print(f"overall session verification code = {total_verify}")
        print(f"overall session fingerprint        = {pretty_verify}")
        print("===============================================\n")

    # Reads terminal input only. It never performs large file I/O directly.
    # This keeps the prompt responsive even if multiple huge files are queued.
    def input_loop(self):
        try:
            while self.running.is_set():
                line = input("> ")

                if line.lower() in ("exit", "quit"):
                    # A local exit request shuts down all channels and worker threads.
                    break

                if line.startswith("/send "):
                    path = line[len("/send "):].strip()
                    if len(path) >= 2 and path[0] == path[-1] and path[0] in ("'", '"'):
                        path = path[1:-1]

                    if os.path.isfile(path):
                        # A real file path becomes a background file-transfer task.
                        self.file_queue.put(path)
                        print(f"[queued file for sending] {path}")
                    else:
                        # Requirement: if /send path does not exist, send the original line as normal text.
                        print("[file does not exist; sending the line as a normal message]")
                        self.msg_queue.put(line)
                else:
                    self.msg_queue.put(line)

        except (EOFError, KeyboardInterrupt):
            pass
        finally:
            self.close()

    # Dedicated message sender. It consumes msg_queue and writes to the message channel.
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

    # Dedicated message receiver. It is independent of file sending and file receiving.
    def msg_recv_loop(self):
        try:
            while self.running.is_set():
                frame_type, payload = self.msg_channel.recv_frame()
                if frame_type != MSG_TEXT:
                    # Protocol separation: message channel should never carry file frames.
                    raise RuntimeError(f"message channel received an unknown frame: {frame_type}")
                print(f"[received message] {payload.decode('utf-8', errors='replace')}")
        except Exception as e:
            if self.running.is_set():
                print(f"[message receiver thread exited] {e}")
            self.close()

    # Prepare one outgoing file and send its encrypted FILE_META frame.
    # The actual file bytes are sent later by file_send_loop.
    def add_file_task(self, path: str):
        task = SendFileTask(
            file_id=uuid.uuid4().hex,          # Fresh transfer ID; allows multiple files on one file channel.
            path=path,                         # Local file path; never sent to the peer.
            name=os.path.basename(path),       # Send only the basename to avoid leaking local directories.
            size=os.path.getsize(path),        # Sender-side size used by receiver for final verification.
            fp=open(path, "rb"),               # Open source file for streaming, not full-memory loading.
            sha256=hashlib.sha256(),           # Running sender-side hash for integrity verification.
        )
        # File metadata is sent first, but it is still inside the encrypted file channel,
        # so the filename and size are not exposed in plaintext to passive observers.
        # file_id lets the receiver track multiple in-progress files at the same time.
        meta = {
            "id": task.file_id,                # Correlates META, CHUNK, and END frames for one file.
            "name": task.name,                 # Suggested output filename on receiver side.
            "size": task.size,                 # Expected byte length from the sender.
            "chunk_size": CHUNK_SIZE,          # Informational chunk size used by this sender.
        }
        self.file_channel.send_frame(          # Metadata is encrypted; filename is not visible on the wire.
            FILE_META,
            json.dumps(meta, ensure_ascii=False).encode("utf-8"),
        )
        print(f"[start sending file] {task.name}")
        print(f"[file_id] {task.file_id}")
        print(f"[size] {task.size} bytes")
        return task

    # Dedicated file sender. It multiplexes up to MAX_ACTIVE_FILE_SENDS files.
    # Each loop sends at most one chunk per active file, so multiple large files progress together.
    def file_send_loop(self):
        active = []                             # Active outgoing file transfers, sent in round-robin order.
        last_report = time.time()               # Throttles progress output.
        try:
            while self.running.is_set():
                while len(active) < MAX_ACTIVE_FILE_SENDS:
                    # Non-blocking queue read: fill active slots without waiting.
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
                    chunk = task.fp.read(CHUNK_SIZE)          # Read one chunk from this file before moving to next active file.
                    if chunk:
                        # A normal chunk is sent immediately. The file channel encrypts it.
                        task.sha256.update(chunk)             # Hash exactly the bytes being sent.
                        task.sent += len(chunk)               # Sender-side byte counter.
                        # File chunk payload: 16-byte file_id + raw file data chunk.
                        # The outer send_frame encrypts and authenticates the entire payload.
                        payload = bytes.fromhex(task.file_id) + chunk  # Prefix chunk with binary file_id for multiplexing.
                        self.file_channel.send_frame(FILE_CHUNK, payload)  # Encrypted file chunk frame.
                    else:
                        # EOF for this file. Send final hash/size and remove it from active list.
                        task.fp.close()                       # Close source file before sending FILE_END.
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
                    task.fp.close()                       # Close source file before sending FILE_END.
    # File-name sanitization is important because filenames come from the peer.
    def safe_name(self, name: str) -> str:
        name = os.path.basename(name.replace("\\", "/")).replace("\x00", "")
        return name or "received_file"

    def unique_path(self, name: str) -> str:
        name = self.safe_name(name)             # Sanitize again at the path boundary.
        base, ext = os.path.splitext(name)
        path = os.path.join(RECV_DIR, name)
        index = 1
        while os.path.exists(path) or os.path.exists(path + ".part"):
            path = os.path.join(RECV_DIR, f"{base}_{index}{ext}")
            index += 1
        return path

    # Dedicated file receiver. It can receive chunks for many file_id values in any order.
    # Each file_id has its own .part file, byte counter, and SHA-256 context.
    def file_recv_loop(self):
        files = {}                              # file_id -> receiver state for multiple in-progress files.
        try:
            while self.running.is_set():
                frame_type, payload = self.file_channel.recv_frame()
                if frame_type == FILE_META:
                    # Start a new incoming file transfer state.
                    meta = json.loads(payload.decode("utf-8"))
                    final_path = self.unique_path(meta["name"])  # Pick a collision-free destination path.
                    tmp_path = final_path + ".part"               # Incomplete data is written here first.
                    # The receiver creates independent state per file_id; multiple files can be in progress at once.
                    files[meta["id"]] = {
                        "name": self.safe_name(meta["name"]),
                        "expected_size": int(meta["size"]),
                        "received": 0,                            # Bytes written so far for this file_id.
                        "sha256": hashlib.sha256(),               # Receiver-side running hash.
                        "final_path": final_path,
                        "tmp_path": tmp_path,
                        "fp": open(tmp_path, "wb"),               # Separate .part file for this file_id.
                    }
                    print(f"\n[start receiving file] {files[meta['id']]['name']}")
                    print(f"[file_id] {meta['id']}")
                    print(f"[temporary file] {tmp_path}")
                elif frame_type == FILE_CHUNK:
                    # Append one chunk to the correct in-progress file, chosen by file_id.
                    file_id = payload[:16].hex()                  # First 16 bytes select the target in-progress file.
                    chunk = payload[16:]                           # Remaining bytes are file data.
                    item = files.get(file_id)                       # Lookup receiver state for this file.
                    if not item:
                        raise RuntimeError(f"received a chunk for an unknown file: {file_id}")
                    item["fp"].write(chunk)                       # Append chunk to its .part file.
                    item["sha256"].update(chunk)                   # Hash exactly the received bytes.
                    item["received"] += len(chunk)                 # Receiver-side byte counter.
                elif frame_type == FILE_END:
                    # Finalize one file and verify size + SHA-256 before accepting it.
                    end_info = json.loads(payload.decode("utf-8")) # Sender final size and SHA-256.
                    file_id = end_info["id"]
                    item = files.pop(file_id, None)                 # Remove state; transfer should be complete.
                    if not item:
                        raise RuntimeError(f"received an end frame for an unknown file: {file_id}")
                    item["fp"].close()                            # Flush and close before rename/delete.
                    actual_hash = item["sha256"].hexdigest()       # Receiver-computed SHA-256.
                    expected_hash = end_info["sha256"]             # Sender-computed SHA-256 from FILE_END.
                    actual_size = item["received"]                 # Receiver byte count.
                    expected_size = item["expected_size"]          # Size advertised in FILE_META.
                    end_size = int(end_info["size"])               # Sender final byte count in FILE_END.
                    # Verification condition: receiver hash, metadata size, and end-frame size must all match.
                    ok = (
                    # Accept only if all independent checks agree.
                        actual_hash == expected_hash
                        and actual_size == expected_size
                        and actual_size == end_size
                    )
                    if ok:
                        os.replace(item["tmp_path"], item["final_path"])  # Atomic promotion after verification.
                        print(f"[file receive complete] {item['name']}")
                        print(f"[saved path] {item['final_path']}")
                        print(f"[expected SHA256] {expected_hash}")
                        print(f"[actual SHA256] {actual_hash}")
                        print("[SHA256 verification succeeded]")
                    else:
                        # Verification failed, so the temporary partial file must not be kept.
                        with suppress(Exception):
                            os.remove(item["tmp_path"])          # Delete failed/corrupt temporary file.
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
                    item["fp"].close()                            # Flush and close before rename/delete.
                with suppress(Exception):
                    os.remove(item["tmp_path"])          # Delete failed/corrupt temporary file.

    # Start all application threads after both encrypted channels have completed handshakes.
    def start(self):
        try:
            self.do_handshake()
        except Exception as e:
            print(f"[handshake failed] {e}")
            self.close()
            return
        threads = [
            # Five threads are intentional: input, msg send, msg receive, file send, file receive.
            threading.Thread(target=self.input_loop, daemon=True),      # Reads terminal input and queues work.
            threading.Thread(target=self.msg_send_loop, daemon=True),   # Sends queued messages.
            threading.Thread(target=self.msg_recv_loop, daemon=True),   # Receives messages independently.
            threading.Thread(target=self.file_send_loop, daemon=True),  # Streams queued files in chunks.
            threading.Thread(target=self.file_recv_loop, daemon=True),  # Writes and verifies incoming files.
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


# Server opens two listening sockets: one for chat, one for files.
def run_server(host=DEFAULT_HOST, msg_port=DEFAULT_MSG_PORT, file_port=DEFAULT_FILE_PORT):
    msg_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # Server listener for message channel.
    file_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Server listener for file channel.
    msg_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    file_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    msg_listener.bind((host, msg_port))
    file_listener.bind((host, file_port))
    msg_listener.listen(1)
    # This sample accepts one peer. Supporting multiple peers would require one ChatApp per peer.
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


# Client opens two outgoing sockets to the server, matching the server's two listeners.
def run_client(host: str, msg_port=DEFAULT_MSG_PORT, file_port=DEFAULT_FILE_PORT):
    msg_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)       # Client socket for message channel.
    file_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)      # Client socket for file channel.

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


# Command-line entry point. No arguments means default server mode.
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


if __name__ == "__main__":
    main()
