#!/usr/bin/env python3
"""
secure_tcp_file_chat_v6_pyqt5_orange_reviewed.py

This program is a PyQt5 desktop version of the secure TCP file chat tool.
It preserves the original protocol architecture while replacing the terminal
input loop with a responsive graphical interface.

The communication design still uses two independent TCP connections. The
message channel carries only encrypted text frames, while the file channel
carries only encrypted FILE_META, FILE_CHUNK, and FILE_END frames. Each channel
performs its own ephemeral X25519 handshake, derives independent per-direction
ChaCha20-Poly1305 traffic keys, and authenticates every encrypted application
frame. The overall manual verification fingerprint combines both channel
verification codes, so users can compare one value through a trusted channel.

The file-transfer design remains suitable for large files. Files are streamed in
64 KiB chunks instead of being loaded into memory, several outgoing files can be
interleaved in round-robin order, incoming data is first written to a .part file,
and the final file is accepted only after both the byte count and SHA-256 digest
match the sender's metadata and end frame. Failed verification removes the
temporary file.

The GUI is kept responsive by separating work by responsibility: socket
accept/connect and handshakes run in a connection worker thread; text sending,
text receiving, file sending, and file receiving each run in their own worker
loop; the Qt main thread only updates widgets through Qt signals. This means
large file transfer does not block text chat, and text chat does not block file
transfer or the window.

The message editor preserves spaces, tabs, blank lines, and indentation. Press
Ctrl+Enter to send; press Enter normally to insert a new line. Connection
settings are requested in a startup dialog so the main window can stay focused
on chat content and transfer progress.

Important security note:
This remains a study/debug build. It prints sensitive handshake material to the
console and keeps it available in the Ctrl+Q debug window, including private
keys, shared secrets, master keys, nonce prefixes, and traffic keys. Do not use
this debug logging in production or anywhere logs may be exposed.
"""
"""
This project grew out of a deeply personal and painful experience: the feeling of being followed, watched, targeted, and repeatedly pressured.
In this context, secure communication is not an abstract technical topic. It is about whether a person can still have basic private space; whether they can express themselves, protect themselves, and communicate with others normally without being monitored, disturbed, or intimidated.
When someone is treated as “suspicious” or “disloyal” simply because they hold different values, different views, or refuse to conform to a particular narrative; when grand terms such as “patriotism,” “national security,” or “public interest” are used to justify intrusions into personal life; when governments, institutions, or any party with power can freely cross boundaries, inspect, track, pressure, and interfere with a person’s communications and daily life, privacy is no longer a luxury. It becomes a basic line of defense.
The pain of being tracked is difficult to explain to those who have never experienced it. It is not a one-time violation, but a continuous form of exhaustion. It makes a person question every contact, every login, every message, and every unfamiliar interaction. Over time, it seeps into everyday life, making it impossible to truly relax or to believe that ordinary communication is safe, neutral, or harmless.
This GitHub repository exists because of that feeling of being targeted, because personal boundaries are repeatedly broken, and because privacy is too easily sacrificed in the name of power, public opinion, or so-called “security.”
It is also a response: when personal privacy is ignored, when freedom of communication is threatened, and when people are subjected to undue pressure simply because of different values, we need secure and reliable communication tools.
What I want to express is this: protecting privacy is not about avoiding responsibility, nor is it about opposing society. Protecting privacy is about ensuring that every person can retain the most basic dignity, boundaries, and freedom when facing power, prejudice, harassment, and surveillance.
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

from PyQt5.QtCore import QObject, pyqtSignal, Qt, QTimer, QEvent
from PyQt5.QtGui import QFont, QKeySequence

from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QPlainTextEdit,
    QProgressBar,
    QShortcut,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)


MAGIC = b"TCP_FILE_CHAT_V4"  # Protocol/version marker used by both plaintext handshakes.
NAME_SIZE = 8  # Fixed channel-name field length for "msg" and "file".
RANDOM_SIZE = 32  # Random nonce size mixed into each channel transcript.
PUBKEY_SIZE = 32  # Raw X25519 public keys are 32 bytes.
KDF_ITERATIONS = 200_000  # PBKDF2-SHA256 work factor for deriving the master key.

MSG_TEXT = 1  # Application frame type for encrypted chat text.
FILE_META = 10  # Application frame type for encrypted file metadata.
FILE_CHUNK = 11  # Application frame type for encrypted file data chunks.
FILE_END = 12  # Application frame type for encrypted file completion data.

CHUNK_SIZE = 64 * 1024  # File chunks stay small enough for stable large-file streaming.
MAX_FRAME_SIZE = 20 * 1024 * 1024  # Hard limit that rejects unexpectedly large encrypted frames.
MAX_ACTIVE_FILE_SENDS = 4  # Maximum number of outgoing files interleaved at one time.
RECV_DIR = "received_files"  # Directory where verified received files are stored.

DEFAULT_HOST = "0.0.0.0"  # Server listen address used by default.
DEFAULT_CLIENT_HOST = "127.0.0.1"  # Client-side default target for local testing.
DEFAULT_MESSAGE_PORT = 9000  # Default TCP port for the message channel.
DEFAULT_FILE_PORT = 9001  # Default TCP port for the file-transfer channel.


def kdf_expand(master: bytes, label: bytes, size: int) -> bytes:
    """Expand purpose-specific key material from master_key using HMAC-SHA256."""
    out = b""  # Accumulates HMAC output blocks.
    prev = b""  # Holds the previous HMAC block for chained expansion.
    counter = 1  # Single-byte expansion block counter.
    while len(out) < size:  # Continue expanding until enough bytes are available.
        prev = hmac.new(master, prev + label + bytes([counter]), hashlib.sha256).digest()
        out += prev  # Append the latest HMAC block.
        counter += 1  # Move to the next expansion block.
    return out[:size]  # Trim expansion output to the requested size.


class GuiBridge(QObject):
    """Thread-safe bridge from worker threads to the PyQt5 GUI thread."""

    debug_log = pyqtSignal(str)  # Carries console/debug text safely to the GUI thread.
    status_changed = pyqtSignal(str)  # Updates the status label from worker threads.
    message_received = pyqtSignal(str)  # Delivers received chat text to the GUI thread.
    message_sent = pyqtSignal(str)  # Confirms sent chat text to the GUI thread.
    file_send_started = pyqtSignal(str, str, int)  # Announces a new outgoing file transfer.
    file_send_progress = pyqtSignal(str, str, int, int)  # Updates outgoing file progress.
    file_send_complete = pyqtSignal(str, str, str)  # Announces completed outgoing file transfer.
    file_receive_started = pyqtSignal(str, str, str, int)  # Announces a new incoming file transfer.
    file_receive_progress = pyqtSignal(str, str, int, int)  # Updates incoming file progress.
    file_receive_complete = pyqtSignal(str, str, str)  # Announces verified incoming file completion.
    file_receive_failed = pyqtSignal(str, str)  # Reports failed incoming file verification.
    connected = pyqtSignal(str)  # Enables GUI controls after sockets are connected.
    disconnected = pyqtSignal(str)  # Disables GUI controls after shutdown or failure.
    verification_ready = pyqtSignal(str, str)  # Publishes the combined manual verification code.

    def emit_debug_log(self, text: str):
        print(text)  # Keep debug details visible in the console.
        self.debug_log.emit(text)  # Also store debug text for the Ctrl+Q window.

    def emit_status(self, text: str):
        print(text)  # Keep debug details visible in the console.
        self.status_changed.emit(text)  # Route status changes through Qt signals.


class SecureChannel:
    def __init__(self, sock: socket.socket, role: str, name: str, bridge: GuiBridge | None = None):
        self.sock = sock  # Connected TCP socket owned by this secure channel.
        self.role = role  # Role controls client-to-server versus server-to-client key mapping.
        self.name = name  # Logical channel name, normally "msg" or "file".
        self.bridge = bridge  # Optional Qt signal bridge for GUI-safe updates.
        self.name_bytes = name.encode("ascii")  # Encode the channel name for transcript and AAD use.
        if len(self.name_bytes) > NAME_SIZE:
            raise ValueError("channel name is too long")  # Refuse names that cannot fit the fixed handshake field.

        self.name_field = self.name_bytes.ljust(NAME_SIZE, b"\0")  # NUL-pad the channel name to a fixed-width field.
        self.send_lock = threading.Lock()  # Prevent concurrent writers from reusing or reordering nonces.
        self.send_aead = None  # Outgoing ChaCha20-Poly1305 context after handshake.
        self.recv_aead = None  # Incoming ChaCha20-Poly1305 context after handshake.
        self.send_nonce_prefix = None  # Four-byte prefix for outgoing 96-bit AEAD nonces.
        self.recv_nonce_prefix = None  # Four-byte prefix for incoming 96-bit AEAD nonces.
        self.send_seq = 0  # Monotonic outgoing sequence number for nonce uniqueness.
        self.recv_seq = 0  # Monotonic incoming sequence number expected from the peer.
        self.verify_code = None  # Per-channel verification value computed after handshake.

    def log(self, text: str):
        if self.bridge:
            self.bridge.emit_debug_log(text)
        else:
            print(text)  # Keep debug details visible in the console.

    def close(self):
        with suppress(Exception):
            self.sock.shutdown(socket.SHUT_RDWR)
        with suppress(Exception):
            self.sock.close()

    def recv_exact(self, size: int) -> bytes:
        data = bytearray()  # Mutable buffer used to assemble an exact-size read.
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))  # Blocking socket read runs only in worker threads.
            if not chunk:
                raise ConnectionError("connection closed")  # Treat EOF before the expected length as a broken connection.
            data.extend(chunk)  # Append received bytes until the exact length is reached.
        return bytes(data)  # Return an immutable byte string to the caller.

    def handshake(self):
        self.log(f"\n========== {self.name} channel handshake start ==========")
        self.log(f"[role] {self.role}")
        self.log(f"[algorithm] X25519 + PBKDF2-SHA256({KDF_ITERATIONS}) + ChaCha20-Poly1305")

        private_key = x25519.X25519PrivateKey.generate()  # Generate a fresh ephemeral X25519 private key.
        local_private = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        local_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        local_random = os.urandom(RANDOM_SIZE)  # Generate fresh random material for the transcript.
        local_hello = MAGIC + self.name_field + local_public + local_random  # Plaintext handshake record sent before encryption starts.

        self.log("\n[local handshake material - study/debug mode]")
        self.log(f"local_x25519_private = {local_private.hex()}")
        self.log(f"local_x25519_public  = {local_public.hex()}")
        self.log(f"local_random         = {local_random.hex()}")

        self.sock.sendall(local_hello)  # Send the local handshake record.
        hello_size = len(MAGIC) + NAME_SIZE + PUBKEY_SIZE + RANDOM_SIZE  # Fixed byte length of the peer handshake record.
        peer_hello = self.recv_exact(hello_size)  # Read the peer handshake record exactly.

        if not peer_hello.startswith(MAGIC + self.name_field):
            raise RuntimeError(f"{self.name} channel handshake failed: protocol marker or channel name mismatch")

        offset = len(MAGIC) + NAME_SIZE  # Skip protocol marker and channel-name fields.
        peer_public = peer_hello[offset:offset + PUBKEY_SIZE]  # Extract the peer X25519 public key.
        peer_random = peer_hello[offset + PUBKEY_SIZE:]  # Extract the peer random nonce.

        self.log("\n[peer handshake material]")
        self.log(f"peer_x25519_public = {peer_public.hex()}")
        self.log(f"peer_random        = {peer_random.hex()}")

        shared_secret = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))  # Compute the local X25519 shared secret.

        if self.role == "client":
            client_public, client_random = local_public, local_random  # Client role uses local values as client transcript values.
            server_public, server_random = peer_public, peer_random  # Client role uses peer values as server transcript values.
        else:
            client_public, client_random = peer_public, peer_random  # Server role uses peer values as client transcript values.
            server_public, server_random = local_public, local_random  # Server role uses local values as server transcript values.

        transcript = b"".join([
            MAGIC,
            self.name_field,
            b"client-public", client_public,
            b"client-random", client_random,
            b"server-public", server_public,
            b"server-random", server_random,
        ])
        transcript_hash = hashlib.sha256(transcript).digest()  # Bind both public keys, nonces, channel name, and protocol marker.

        self.log("\n[handshake transcript and X25519 result - study/debug mode]")
        self.log(f"transcript_hex    = {transcript.hex()}")
        self.log(f"transcript_sha256 = {transcript_hash.hex()}")
        self.log(f"shared_secret     = {shared_secret.hex()}")
        self.log("warning: the raw shared_secret is printed for learning only; do not enable this in production.")

        master_key = hashlib.pbkdf2_hmac(  # Derive the channel master key from X25519 plus transcript salt.
            "sha256",
            shared_secret,
            transcript_hash,
            KDF_ITERATIONS,
            dklen=32,
        )

        key_c2s = kdf_expand(master_key, self.name_field + b"key-c2s", 32)  # Derive the client-to-server traffic key.
        key_s2c = kdf_expand(master_key, self.name_field + b"key-s2c", 32)  # Derive the server-to-client traffic key.
        nonce_c2s = kdf_expand(master_key, self.name_field + b"nonce-c2s", 4)  # Derive the client-to-server nonce prefix.
        nonce_s2c = kdf_expand(master_key, self.name_field + b"nonce-s2c", 4)  # Derive the server-to-client nonce prefix.

        if self.role == "client":
            send_key, recv_key = key_c2s, key_s2c  # Client sends with c2s and receives with s2c.
            self.send_nonce_prefix, self.recv_nonce_prefix = nonce_c2s, nonce_s2c  # Match client nonce directions.
        else:
            send_key, recv_key = key_s2c, key_c2s  # Server sends with s2c and receives with c2s.
            self.send_nonce_prefix, self.recv_nonce_prefix = nonce_s2c, nonce_c2s  # Match server nonce directions.

        self.send_aead = ChaCha20Poly1305(send_key)  # Create outgoing AEAD context.
        self.recv_aead = ChaCha20Poly1305(recv_key)  # Create incoming AEAD context.
        self.verify_code = hashlib.sha256(b"verify" + self.name_field + transcript_hash + master_key).digest()  # Create channel verification material for manual comparison.

        self.log("\n[derived key material - study/debug mode]")
        self.log(f"master_key           = {master_key.hex()}")
        self.log(f"client_to_server_key = {key_c2s.hex()}")
        self.log(f"server_to_client_key = {key_s2c.hex()}")
        self.log(f"client_nonce_prefix  = {nonce_c2s.hex()}")
        self.log(f"server_nonce_prefix  = {nonce_s2c.hex()}")
        self.log(f"{self.name} channel verification code = {self.verify_code.hex()}")
        self.log(f"========== {self.name} channel handshake end ==========")

    def send_frame(self, frame_type: int, payload: bytes = b""):
        inner = struct.pack("!BI", frame_type, len(payload)) + payload  # Pack frame type and payload length before encryption.
        with self.send_lock:
            nonce = self.send_nonce_prefix + self.send_seq.to_bytes(8, "big")  # Build a unique 12-byte AEAD nonce.
            self.send_seq += 1  # Advance the send sequence before the next frame.
            encrypted = self.send_aead.encrypt(nonce, inner, MAGIC + self.name_field)  # Encrypt and authenticate the complete inner frame.
            if len(encrypted) > MAX_FRAME_SIZE:
                raise ValueError("encrypted frame is too large")  # Reject frames that exceed the configured safety limit.
            self.sock.sendall(struct.pack("!I", len(encrypted)) + encrypted)  # Send ciphertext as a length-prefixed record.

    def recv_frame(self):
        encrypted_len = struct.unpack("!I", self.recv_exact(4))[0]  # Read the encrypted record length.
        if encrypted_len > MAX_FRAME_SIZE:
            raise ValueError(f"encrypted frame is too large: {encrypted_len}")
        encrypted = self.recv_exact(encrypted_len)  # Read the complete ciphertext record.
        nonce = self.recv_nonce_prefix + self.recv_seq.to_bytes(8, "big")  # Reconstruct the expected incoming nonce.
        self.recv_seq += 1  # Advance the receive sequence for the next frame.
        inner = self.recv_aead.decrypt(nonce, encrypted, MAGIC + self.name_field)  # Decrypt and authenticate before parsing payload bytes.
        frame_type, payload_len = struct.unpack("!BI", inner[:5])  # Parse the decrypted inner frame header.
        payload = inner[5:]  # Extract decrypted application payload bytes.
        if len(payload) != payload_len:
            raise ValueError("decrypted frame length mismatch")  # Detect malformed or inconsistent decrypted frames.
        return frame_type, payload  # Give the application layer one complete plaintext frame.


@dataclass
class SendFileTask:
    file_id: str  # Unique transfer id used to multiplex several files.
    path: str  # Local source path for the outgoing file.
    name: str  # Basename sent to the receiver.
    size: int  # Total file size in bytes.
    file_object: object  # Open file object used for streaming reads.
    sha256_hash: object  # Running SHA-256 hasher for sent bytes.
    bytes_sent: int = 0  # Number of file bytes already transmitted.


class ChatApp:
    """Application layer. GUI calls send_text(), send_file(), and close()."""

    def __init__(self, message_channel: SecureChannel, file_channel: SecureChannel, bridge: GuiBridge):
        self.message_channel = message_channel  # Dedicated encrypted channel for text messages.
        self.file_channel = file_channel  # Dedicated encrypted channel for file transfer.
        self.bridge = bridge  # Optional Qt signal bridge for GUI-safe updates.
        self.running = threading.Event()  # Shared stop flag used by all worker loops.
        self.running.set()  # Mark the application as active.
        self.message_queue = queue.Queue()  # Thread-safe outbound text queue.
        self.file_queue = queue.Queue()  # Thread-safe outbound file path queue.
        self.threads: list[threading.Thread] = []  # Stores background worker threads.
        os.makedirs(RECV_DIR, exist_ok=True)  # Ensure the receive directory exists.

    def close(self):
        was_running = self.running.is_set()  # Avoid duplicate disconnect notifications where possible.
        self.running.clear()  # Ask all worker loops to stop.
        self.message_channel.close()  # Close the message socket.
        self.file_channel.close()  # Close the file socket.
        if was_running:
            self.bridge.disconnected.emit("connection closed")  # Notify the GUI through a Qt signal.

    def do_handshake(self):
        self.message_channel.handshake()  # Perform the message-channel secure handshake.
        self.file_channel.handshake()  # Perform the file-channel secure handshake.
        total_verify = hashlib.sha256(
            b"total-verify" + self.message_channel.verify_code + self.file_channel.verify_code
        ).hexdigest()
        pretty_verify = ":".join(total_verify[i:i + 4] for i in range(0, 48, 4))  # Format a shorter human-readable fingerprint.

        self.bridge.emit_debug_log("\n========== overall manual verification ==========")
        self.bridge.emit_debug_log("Compare the following value through a trusted channel.")
        self.bridge.emit_debug_log("If it matches: no handshake substitution was detected.")
        self.bridge.emit_debug_log("If it differs: exit immediately and do not send messages or files.")
        self.bridge.emit_debug_log(f"overall session verification code = {total_verify}")
        self.bridge.emit_debug_log(f"overall session fingerprint        = {pretty_verify}")
        self.bridge.emit_debug_log("===============================================\n")
        self.bridge.verification_ready.emit(total_verify, pretty_verify)  # Let the GUI know verification material is available.

    def start(self):
        try:
            self.do_handshake()
        except Exception as e:
            self.bridge.emit_debug_log(f"[handshake failed] {e}")
            self.close()
            return

        self.threads = [
            threading.Thread(target=self.message_send_loop, daemon=True),  # Worker: outbound text frames only.
            threading.Thread(target=self.message_receive_loop, daemon=True),  # Worker: inbound text frames only.
            threading.Thread(target=self.file_send_loop, daemon=True),  # Worker: outbound file frames only.
            threading.Thread(target=self.file_recv_loop, daemon=True),  # Worker: inbound file frames only.
        ]
        for thread in self.threads:
            thread.start()  # Start each worker without blocking the GUI thread.

    def send_text(self, text: str):
        if text == "":
            return
        if not self.running.is_set():
            self.bridge.emit_debug_log("[not connected] message was not sent")
            return
        self.message_queue.put(text)  # Queue text without blocking the GUI.

    def send_file(self, path: str):
        if not self.running.is_set():
            self.bridge.emit_debug_log("[not connected] file was not queued")
            return
        if os.path.isfile(path):
            self.file_queue.put(path)  # Queue the file path without reading it in the GUI thread.
            self.bridge.emit_debug_log(f"[queued file for sending] {path}")
        else:
            self.bridge.emit_debug_log(f"[file does not exist] {path}")

    def message_send_loop(self):
        try:
            while self.running.is_set():
                try:
                    text = self.message_queue.get(timeout=0.2)  # Wait briefly so shutdown remains responsive.
                except queue.Empty:
                    continue
                self.message_channel.send_frame(MSG_TEXT, text.encode("utf-8"))  # Send text over only the message channel.
                self.bridge.message_sent.emit(text)  # Update chat view through the GUI thread.
        except Exception as e:
            if self.running.is_set():
                self.bridge.emit_debug_log(f"[message sender thread exited] {e}")
            self.close()

    def message_receive_loop(self):
        try:
            while self.running.is_set():
                frame_type, payload = self.message_channel.recv_frame()  # Receive one encrypted message-channel frame.
                if frame_type != MSG_TEXT:
                    raise RuntimeError(f"message channel received an unknown frame: {frame_type}")  # Enforce channel separation.
                self.bridge.message_received.emit(payload.decode("utf-8", errors="replace"))  # Deliver received text safely to the GUI.
        except Exception as e:
            if self.running.is_set():
                self.bridge.emit_debug_log(f"[message receiver thread exited] {e}")
            self.close()

    def add_file_task(self, path: str):
        task = SendFileTask(
            file_id=uuid.uuid4().hex,  # Generate a unique id for this file transfer.
            path=path,  # Store the local path for this sender task.
            name=os.path.basename(path),  # Send only the filename, not local directories.
            size=os.path.getsize(path),  # Capture file size before streaming starts.
            file_object=open(path, "rb"),  # Open the source file for chunked streaming.
            sha256_hash=hashlib.sha256(),  # Initialize sender-side integrity hash.
        )
        meta = {
            "id": task.file_id,  # Correlates metadata, chunks, and end frame.
            "name": task.name,  # Suggested filename for the receiver.
            "size": task.size,  # Expected total byte count.
            "chunk_size": CHUNK_SIZE,  # Documents the sender chunk size.
        }
        self.file_channel.send_frame(FILE_META, json.dumps(meta, ensure_ascii=False).encode("utf-8"))  # Send encrypted file metadata before chunks.
        self.bridge.file_send_started.emit(task.file_id, task.name, task.size)  # Create/update the send progress bar.
        self.bridge.emit_debug_log(f"[start sending file] {task.name}")
        self.bridge.emit_debug_log(f"[file_id] {task.file_id}")
        self.bridge.emit_debug_log(f"[size] {task.size} bytes")
        return task

    def file_send_loop(self):
        active: list[SendFileTask] = []  # Currently interleaved outgoing file transfers.
        last_report = time.time()  # Throttle progress signal emission.
        try:
            while self.running.is_set():
                while len(active) < MAX_ACTIVE_FILE_SENDS:  # Fill available active-transfer slots.
                    try:
                        active.append(self.add_file_task(self.file_queue.get_nowait()))  # Start queued transfers without blocking.
                    except queue.Empty:
                        break

                if not active:
                    try:
                        active.append(self.add_file_task(self.file_queue.get(timeout=0.2)))  # Wait briefly for the next file when idle.
                    except queue.Empty:
                        continue
                    continue

                for task in active[:]:  # Iterate over a copy so completed transfers can be removed.
                    chunk = task.file_object.read(CHUNK_SIZE)  # Read at most one chunk before rotating to the next file.
                    if chunk:
                        task.sha256_hash.update(chunk)  # Hash exactly the bytes sent.
                        task.bytes_sent += len(chunk)  # Track sender-side progress.
                        payload = bytes.fromhex(task.file_id) + chunk  # Prefix each chunk with the binary transfer id.
                        self.file_channel.send_frame(FILE_CHUNK, payload)  # Send encrypted file chunk over the file channel only.
                    else:
                        task.file_object.close()  # Close the source file at EOF.
                        end_metadata = {
                            "id": task.file_id,  # Correlates metadata, chunks, and end frame.
                            "sha256": task.sha256_hash.hexdigest(),  # Sender final digest for receiver verification.
                            "size": task.bytes_sent,  # Sender final byte count for receiver verification.
                        }
                        self.file_channel.send_frame(FILE_END, json.dumps(end_metadata, ensure_ascii=False).encode("utf-8"))  # Send encrypted final size and digest.
                        self.bridge.file_send_complete.emit(task.file_id, task.name, task.sha256_hash.hexdigest())  # Mark the send progress as complete.
                        self.bridge.emit_debug_log(f"[file send complete] {task.name}")
                        self.bridge.emit_debug_log(f"[file_id] {task.file_id}")
                        self.bridge.emit_debug_log(f"[SHA256] {task.sha256_hash.hexdigest()}")
                        active.remove(task)  # Remove this file from active round-robin sending.

                now = time.time()  # Current time used for progress throttling.
                if active and now - last_report >= 0.5:
                    for task in active:
                        self.bridge.file_send_progress.emit(task.file_id, task.name, task.bytes_sent, task.size)  # Publish throttled send progress.
                    last_report = now
        except Exception as e:
            if self.running.is_set():
                self.bridge.emit_debug_log(f"[file sender thread exited] {e}")
            self.close()
        finally:
            for task in active:
                with suppress(Exception):
                    task.file_object.close()  # Close the source file at EOF.

    def safe_name(self, name: str) -> str:
        name = os.path.basename(name.replace("\\", "/")).replace("\x00", "")  # Remove directories and NULs from peer-provided filenames.
        return name or "received_file"  # Provide a safe fallback filename.

    def unique_path(self, name: str) -> str:
        name = self.safe_name(name)  # Sanitize again before path creation.
        base, ext = os.path.splitext(name)  # Split filename for collision suffixes.
        path = os.path.join(RECV_DIR, name)  # Candidate verified output path.
        index = 1  # Collision suffix counter.
        while os.path.exists(path) or os.path.exists(path + ".part"):  # Avoid overwriting final or partial files.
            path = os.path.join(RECV_DIR, f"{base}_{index}{ext}")  # Build a unique collision-safe filename.
            index += 1  # Try the next suffix.
        return path  # Return a safe unique receive path.

    def file_recv_loop(self):
        incoming_files = {}  # Transfer state keyed by file_id.
        last_progress_updates = {}  # Per-file receive progress throttle timestamps.
        try:
            while self.running.is_set():
                frame_type, payload = self.file_channel.recv_frame()

                if frame_type == FILE_META:
                    metadata = json.loads(payload.decode("utf-8"))  # Parse encrypted file metadata.
                    final_path = self.unique_path(metadata["name"])  # Choose a safe collision-free final path.
                    temporary_path = final_path + ".part"  # Write unverified data to a temporary path first.
                    incoming_files[metadata["id"]] = {
                        "name": self.safe_name(metadata["name"]),
                        "expected_size": int(metadata["size"]),
                        "received": 0,
                        "sha256_hash": hashlib.sha256(),  # Receiver-side running integrity hash.
                        "final_path": final_path,
                        "temporary_path": temporary_path,  # Temporary unverified file path.
                        "file_object": open(temporary_path, "wb"),  # Open partial file for streaming writes.
                    }
                    self.bridge.file_receive_started.emit(
                        metadata["id"],
                        incoming_files[metadata["id"]]["name"],
                        temporary_path,
                        int(metadata["size"]),
                    )
                    self.bridge.emit_debug_log(f"[start receiving file] {incoming_files[metadata['id']]['name']}")
                    self.bridge.emit_debug_log(f"[file_id] {metadata['id']}")
                    self.bridge.emit_debug_log(f"[temporary file] {temporary_path}")

                elif frame_type == FILE_CHUNK:
                    file_id = payload[:16].hex()  # Decode the transfer id prefix.
                    chunk = payload[16:]  # Remaining payload bytes are file content.
                    incoming_file = incoming_files.get(file_id)  # Look up the matching incoming file state.
                    if not incoming_file:
                        raise RuntimeError(f"received a chunk for an unknown file: {file_id}")
                    incoming_file["file_object"].write(chunk)  # Append chunk bytes to the partial file.
                    incoming_file["sha256_hash"].update(chunk)  # Hash exactly the received bytes.
                    incoming_file["received"] += len(chunk)  # Track receiver-side byte count.
                    now = time.time()  # Current time used for progress throttling.
                    if now - last_progress_updates.get(file_id, 0) >= 0.5:
                        self.bridge.file_receive_progress.emit(
                            file_id,
                            incoming_file["name"],
                            incoming_file["received"],
                            incoming_file["expected_size"],
                        )
                        last_progress_updates[file_id] = now

                elif frame_type == FILE_END:
                    end_metadata = json.loads(payload.decode("utf-8"))  # Parse sender final size and digest.
                    file_id = end_metadata["id"]  # Identify the file being finalized.
                    incoming_file = incoming_files.pop(file_id, None)  # Remove completed transfer state.
                    if not incoming_file:
                        raise RuntimeError(f"received an end frame for an unknown file: {file_id}")

                    incoming_file["file_object"].close()  # Flush and close the partial file before verification.
                    actual_hash = incoming_file["sha256_hash"].hexdigest()  # Receiver-computed digest.
                    expected_hash = end_metadata["sha256"]  # Sender-provided final digest.
                    actual_size = incoming_file["received"]  # Receiver-counted byte length.
                    expected_size = incoming_file["expected_size"]  # Metadata-advertised byte length.
                    end_size = int(end_metadata["size"])  # Sender final byte count.
                    verification_passed = actual_hash == expected_hash and actual_size == expected_size and actual_size == end_size  # Accept only when all independent checks match.

                    if verification_passed:
                        os.replace(incoming_file["temporary_path"], incoming_file["final_path"])  # Atomically promote verified data to final path.
                        self.bridge.file_receive_progress.emit(file_id, incoming_file["name"], actual_size, expected_size)
                        self.bridge.file_receive_complete.emit(file_id, incoming_file["final_path"], actual_hash)
                        self.bridge.emit_debug_log(f"[file receive complete] {incoming_file['name']}")
                        self.bridge.emit_debug_log(f"[saved path] {incoming_file['final_path']}")
                        self.bridge.emit_debug_log(f"[expected SHA256] {expected_hash}")
                        self.bridge.emit_debug_log(f"[actual SHA256] {actual_hash}")
                        self.bridge.emit_debug_log("[SHA256 verification succeeded]")
                    else:
                        with suppress(Exception):
                            os.remove(incoming_file["temporary_path"])  # Delete unverified or incomplete temporary data.
                        reason = (
                            f"expected size {expected_size}, end-frame size {end_size}, actual size {actual_size}; "
                            f"expected SHA256 {expected_hash}, actual SHA256 {actual_hash}"
                        )
                        self.bridge.file_receive_failed.emit(file_id, reason)
                        self.bridge.emit_debug_log(f"[file verification failed] {incoming_file['name']}")
                        self.bridge.emit_debug_log(f"[{reason}]")
                        self.bridge.emit_debug_log("[temporary file deleted]")
                else:
                    raise RuntimeError(f"file channel received an unknown frame: {frame_type}")
        except Exception as e:
            if self.running.is_set():
                self.bridge.emit_debug_log(f"[file receiver thread exited] {e}")
            self.close()
        finally:
            for incoming_file in incoming_files.values():
                with suppress(Exception):
                    incoming_file["file_object"].close()  # Flush and close the partial file before verification.
                with suppress(Exception):
                    os.remove(incoming_file["temporary_path"])  # Delete unverified or incomplete temporary data.


class ConnectionWorker(threading.Thread):
    """Creates sockets and then starts ChatApp. Runs outside the GUI thread."""

    def __init__(self, mode: str, host: str, message_port: int, file_port: int, bridge: GuiBridge):
        super().__init__(daemon=True)
        self.mode = mode
        self.host = host
        self.message_port = message_port
        self.file_port = file_port
        self.bridge = bridge  # Optional Qt signal bridge for GUI-safe updates.
        self.app: ChatApp | None = None
        self._listeners = []

    def close(self):
        if self.app:
            self.app.close()
        for listener in self._listeners:
            with suppress(Exception):
                listener.close()

    def run(self):
        try:
            if self.mode == "server":
                self._run_server()
            else:
                self._run_client()
        except Exception as e:
            self.bridge.emit_debug_log(f"[connection failed] {e}")
            self.bridge.disconnected.emit(str(e))

    def _run_server(self):
        message_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Listening socket for the message channel.
        file_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Listening socket for the file channel.
        self._listeners = [message_listener, file_listener]  # Keep listeners so disconnect can close them.
        message_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow fast restart on the same message port.
        file_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow fast restart on the same file port.
        message_listener.bind((self.host, self.message_port))  # Bind the message listener.
        file_listener.bind((self.host, self.file_port))  # Bind the file listener.
        message_listener.listen(1)  # Accept one peer for this study application.
        file_listener.listen(1)  # Accept one file-channel connection for the same peer.

        self.bridge.emit_debug_log(f"[server started] host {self.host}, message port {self.message_port}, file port {self.file_port}")
        self.bridge.emit_debug_log("[waiting for message channel connection]")
        message_socket, message_address = message_listener.accept()  # Blocking accept runs in the connection worker thread.
        self.bridge.emit_debug_log(f"[message channel connected] {message_address}")

        self.bridge.emit_debug_log("[waiting for file channel connection]")
        file_socket, file_address = file_listener.accept()  # Blocking file-channel accept also stays off the GUI thread.
        self.bridge.emit_debug_log(f"[file channel connected] {file_address}")

        with suppress(Exception):
            message_listener.close()  # Close listener after the single peer is accepted.
        with suppress(Exception):
            file_listener.close()  # Close file listener after the single peer is accepted.

        self.app = ChatApp(
            SecureChannel(message_socket, "server", "msg", self.bridge),
            SecureChannel(file_socket, "server", "file", self.bridge),
            self.bridge,
        )
        self.bridge.connected.emit("server connected")
        self.app.start()

    def _run_client(self):
        message_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Client socket for encrypted text messages.
        file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Client socket for encrypted file transfer.
        self.bridge.emit_debug_log(f"[connecting] {self.host}:{self.message_port} and {self.host}:{self.file_port}")
        message_socket.connect((self.host, self.message_port))  # Blocking connect runs outside the GUI thread.
        file_socket.connect((self.host, self.file_port))  # Connect the independent file channel.
        self.bridge.emit_debug_log(f"[connected to server] {self.host}")
        self.bridge.emit_debug_log(f"[message port] {self.message_port}")
        self.bridge.emit_debug_log(f"[file port] {self.file_port}")

        self.app = ChatApp(
            SecureChannel(message_socket, "client", "msg", self.bridge),
            SecureChannel(file_socket, "client", "file", self.bridge),
            self.bridge,
        )
        self.bridge.connected.emit("client connected")
        self.app.start()


class ConnectionDialog(QDialog):
    """Startup dialog for connection settings so the main chat window stays clean."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Connection")  # Keep connection settings outside the main chat window.
        self.setModal(True)  # Require connection settings before starting.

        self.mode_combo = QComboBox()  # Mode selector for server/client startup.
        self.mode_combo.addItems(["server", "client"])

        self.host_edit = QLineEdit(DEFAULT_HOST)  # Host input for listen/connect address.

        self.message_port_spin = QSpinBox()  # Numeric input for message TCP port.
        self.message_port_spin.setRange(1, 65535)
        self.message_port_spin.setValue(DEFAULT_MESSAGE_PORT)

        self.file_port_spin = QSpinBox()  # Numeric input for file TCP port.
        self.file_port_spin.setRange(1, 65535)
        self.file_port_spin.setValue(DEFAULT_FILE_PORT)

        form_layout = QFormLayout(self)
        form_layout.addRow("Mode", self.mode_combo)
        form_layout.addRow("Host", self.host_edit)
        form_layout.addRow("Message port", self.message_port_spin)
        form_layout.addRow("File port", self.file_port_spin)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form_layout.addRow(buttons)

        self.mode_combo.currentTextChanged.connect(self._on_mode_changed)

    def _on_mode_changed(self, mode: str):
        if mode == "server":
            self.host_edit.setText(DEFAULT_HOST)
        else:
            self.host_edit.setText(DEFAULT_CLIENT_HOST)

    def connection_settings(self) -> tuple[str, str, int, int]:
        mode = self.mode_combo.currentText()  # Read selected startup mode.
        host = self.host_edit.text().strip() or (DEFAULT_HOST if mode == "server" else DEFAULT_CLIENT_HOST)  # Fall back to the appropriate default host.
        message_port = int(self.message_port_spin.value())  # Read message-channel port.
        file_port = int(self.file_port_spin.value())  # Read file-channel port.
        return mode, host, message_port, file_port  # Return settings to the main window.


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure TCP File Chat - PyQt5 Reviewed")  # Main chat window title.
        self.resize(1280, 860)  # Provide a large default window size.

        self.bridge = GuiBridge()  # Shared Qt signal bridge for all workers.
        self.worker: ConnectionWorker | None = None  # Connection worker created after the startup dialog.
        self.file_progress_bars: dict[str, QProgressBar] = {}  # Progress bars keyed by file_id.
        self.debug_lines: list[str] = []  # Stored console/debug text for Ctrl+Q.
        self.connection_dialog_has_been_shown = False  # Ensure the startup dialog appears only once.

        self._build_ui()  # Create widgets and layouts.
        self._connect_signals()  # Connect Qt signals and slots.
        self._set_connected_ui(False)  # Disable send controls until connected.

        QShortcut(QKeySequence("Ctrl+Q"), self, activated=self.show_debug_window)  # Show handshake/debug output on demand.

    def _build_ui(self):
        central_widget = QWidget()  # Root container for the main window.
        root_layout = QVBoxLayout(central_widget)  # Main vertical layout prioritizes chat space.
        root_layout.setContentsMargins(8, 8, 8, 8)  # Keep margins small to maximize usable area.
        root_layout.setSpacing(6)  # Keep spacing compact.

        self.status_label = QLabel("Not connected. Connection settings will open automatically.")  # Top status line.
        self.status_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        root_layout.addWidget(self.status_label)

        self.chat_view = QPlainTextEdit()  # Large read-only chat transcript.
        self.chat_view.setReadOnly(True)  # Prevent accidental edits to chat history.
        self.chat_view.setPlaceholderText("Chat messages will appear here.")
        self.chat_view.setFont(QFont("Consolas", 12))  # Larger monospace font preserves code alignment.
        self.chat_view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        root_layout.addWidget(self.chat_view, 1)  # Give chat history most of the vertical space.

        self.progress_group = QGroupBox("File Progress")  # Compact transfer-progress area.
        self.progress_layout = QVBoxLayout(self.progress_group)
        self.progress_layout.setContentsMargins(8, 8, 8, 8)
        self.progress_layout.setSpacing(4)
        root_layout.addWidget(self.progress_group, 0)

        self.message_edit = QPlainTextEdit()  # Multiline editor that preserves indentation.
        self.message_edit.setPlaceholderText("Type a message. Ctrl+Enter sends. Enter keeps a new line and indentation.")
        self.message_edit.setFont(QFont("Consolas", 12))
        self.message_edit.setFixedHeight(110)  # Keep input useful without shrinking chat history too much.
        self.message_edit.installEventFilter(self)  # Capture Ctrl+Enter while keeping Enter as newline.
        root_layout.addWidget(self.message_edit, 0)

        button_layout = QHBoxLayout()
        self.send_button = QPushButton("Send  Ctrl+Enter")  # Explicitly show the send shortcut.
        self.send_file_button = QPushButton("Send File")  # Opens a file picker for queued file transfer.
        self.disconnect_button = QPushButton("Disconnect")  # Closes sockets and stops worker loops.
        button_layout.addWidget(self.send_button)
        button_layout.addWidget(self.send_file_button)
        button_layout.addStretch(1)
        button_layout.addWidget(self.disconnect_button)
        root_layout.addLayout(button_layout)

        self.setCentralWidget(central_widget)  # Attach the completed UI to the main window.
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #000000;
                color: #ff0000;
            }
            QLabel, QGroupBox {
                color: #ffcc00;
                font-size: 13px;
            }
            QPlainTextEdit {
                background-color: #1a0400;
                color: #ffdd00;
                border: 1px solid #c83200;
                border-radius: 6px;
                selection-background-color: #c83200;
                selection-color: #1a0400;
            }
            QPushButton {
                background-color: #c83200;
                color: #ffd000;
                border: 1px solid #e03a00;
                border-radius: 6px;
                padding: 7px 14px;
                font-size: 13px;
            }
            QPushButton:disabled {
                background-color: #5a1600;
                color: #b65a00;
                border-color: #7a1f00;
            }
            QPushButton:hover:!disabled {
                background-color: #e03a00;
            }
            QProgressBar {
                background-color: #1a0400;
                color: #ffd000;
                border: 1px solid #c83200;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #c83200;
                border-radius: 5px;
            }
            QDialog, QLineEdit, QComboBox, QSpinBox {
                background-color: #2a0700;
                color: #ffd000;
            }
            QLineEdit, QComboBox, QSpinBox {
                border: 1px solid #c83200;
                border-radius: 4px;
                padding: 4px;
                selection-background-color: #c83200;
                selection-color: #1a0400;
            }
        """)

    def _connect_signals(self):
        self.send_button.clicked.connect(self.send_message)  # Button sends the current text editor contents.
        self.send_file_button.clicked.connect(self.choose_and_send_file)  # Button queues a selected file for transfer.
        self.disconnect_button.clicked.connect(self.disconnect)  # Button closes the active connection.

        self.bridge.debug_log.connect(self.append_debug_log)  # Store debug output without showing it in the main chat area.
        self.bridge.status_changed.connect(self.on_status_changed)
        self.bridge.message_received.connect(self.on_message_received)  # Route received text into the chat area.
        self.bridge.message_sent.connect(self.on_message_sent)  # Route sent text into the chat area.
        self.bridge.file_send_started.connect(self.on_file_send_started)
        self.bridge.file_send_progress.connect(self.on_file_progress)  # Update outgoing file progress bars.
        self.bridge.file_send_complete.connect(self.on_file_send_complete)
        self.bridge.file_receive_started.connect(self.on_file_receive_started)
        self.bridge.file_receive_progress.connect(self.on_file_progress)  # Update incoming file progress bars.
        self.bridge.file_receive_complete.connect(self.on_file_receive_complete)
        self.bridge.file_receive_failed.connect(self.on_file_receive_failed)
        self.bridge.connected.connect(self.on_connected)
        self.bridge.disconnected.connect(self.on_disconnected)
        self.bridge.verification_ready.connect(self.on_verification_ready)

    def showEvent(self, event):
        super().showEvent(event)
        if not self.connection_dialog_has_been_shown:
            self.connection_dialog_has_been_shown = True
            QTimer.singleShot(0, self.open_connection_dialog)  # Open startup dialog after the window appears.

    def eventFilter(self, watched, event):
        if watched is self.message_edit and event.type() == QEvent.KeyPress:  # Intercept only key events from the message editor.
            if event.key() in (Qt.Key_Return, Qt.Key_Enter) and event.modifiers() & Qt.ControlModifier:
                self.send_message()  # Ctrl+Enter sends without removing preserved indentation first.
                return True  # Stop Qt from also inserting a newline for Ctrl+Enter.
        return super().eventFilter(watched, event)

    def _set_connected_ui(self, connected: bool):
        self.message_edit.setEnabled(connected)  # Enable text input only while connected.
        self.send_button.setEnabled(connected)  # Enable text send only while connected.
        self.send_file_button.setEnabled(connected)  # Enable file queueing only while connected.
        self.disconnect_button.setEnabled(connected)  # Enable disconnect only while connected.

    def open_connection_dialog(self):
        dialog = ConnectionDialog(self)  # Show connection settings in a separate dialog.
        if dialog.exec_() != QDialog.Accepted:
            self.status_label.setText("Not connected. Close the window or restart to enter connection settings.")
            return
        mode, host, message_port, file_port = dialog.connection_settings()  # Collect validated dialog values.
        self.start_connection(mode, host, message_port, file_port)  # Start the connection worker.

    def start_connection(self, mode: str, host: str, message_port: int, file_port: int):
        self.status_label.setText(f"Starting {mode}: {host}, message port {message_port}, file port {file_port}")
        self.bridge.emit_debug_log(
            f"[starting] mode={mode}, host={host}, message_port={message_port}, file_port={file_port}"
        )
        self.worker = ConnectionWorker(mode, host, message_port, file_port, self.bridge)  # Create a worker so connect/accept never blocks the GUI.
        self.worker.start()  # Run connection setup in the background.
        self.disconnect_button.setEnabled(True)

    def disconnect(self):
        if self.worker:
            self.worker.close()
        self._set_connected_ui(False)  # Disable send controls until connected.

    def send_message(self):
        text = self.message_edit.toPlainText()  # Read text exactly as typed, including indentation.
        if not text:
            return
        if not self.worker or not self.worker.app:
            self.append_chat("[not connected] message was not sent")
            return
        self.worker.app.send_text(text)  # Queue message for the message-send worker.
        self.message_edit.clear()  # Clear editor only after queueing succeeds.

    def choose_and_send_file(self):
        if not self.worker or not self.worker.app:
            self.append_chat("[not connected] file was not sent")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Choose file to send")  # File chooser runs in GUI, but file reading occurs later in worker thread.
        if path:
            self.worker.app.send_file(path)  # Queue the selected file path for background transfer.

    def append_debug_log(self, text: str):
        self.debug_lines.append(text)  # Store debug line for Ctrl+Q window.

    def append_chat(self, text: str):
        self.chat_view.appendPlainText(text)  # Append plain text so indentation is preserved.
        self.chat_view.verticalScrollBar().setValue(self.chat_view.verticalScrollBar().maximum())

    def on_status_changed(self, status: str):
        self.status_label.setText(status)

    def on_connected(self, status: str):
        self._set_connected_ui(True)
        self.status_label.setText(status)
        self.append_chat(f"[{status}]")

    def on_disconnected(self, reason: str):
        self._set_connected_ui(False)  # Disable send controls until connected.
        self.status_label.setText(f"Disconnected: {reason}")
        self.append_chat(f"[disconnected] {reason}")

    def on_verification_ready(self, full_code: str, pretty: str):
        self.status_label.setText("Connected. Press Ctrl+Q to view handshake and verification debug details.")

    def on_message_sent(self, text: str):
        self.append_chat(f"Me:\n{text}")

    def on_message_received(self, text: str):
        self.append_chat(f"Peer:\n{text}")

    def _make_progress_bar(self, file_id: str, label: str, total_size: int):
        progress_bar = QProgressBar()  # Visual progress indicator for one file_id.
        progress_bar.setRange(0, 1000)  # Use tenths of a percent for smoother display.
        progress_bar.setValue(0)
        progress_bar.setFormat(f"{label}: 0.0%")
        progress_bar.setToolTip(f"file_id: {file_id}; size: {total_size} bytes")
        self.progress_layout.addWidget(progress_bar)
        self.file_progress_bars[file_id] = progress_bar  # Remember progress bar by transfer id.
        return progress_bar

    def on_file_send_started(self, file_id: str, name: str, size: int):
        self._make_progress_bar(file_id, f"Sending {name}", size)

    def on_file_receive_started(self, file_id: str, name: str, temporary_path: str, size: int):
        self._make_progress_bar(file_id, f"Receiving {name}", size)

    def on_file_progress(self, file_id: str, name: str, done: int, total: int):
        progress_bar = self.file_progress_bars.get(file_id)
        if not progress_bar:
            progress_bar = self._make_progress_bar(file_id, name, total)
        percent = 100.0 if total == 0 else min(100.0, done * 100.0 / total)  # Safely compute percentage for empty or normal files.
        progress_bar.setValue(int(percent * 10))
        progress_bar.setFormat(f"{name}: {percent:.1f}% ({done}/{total} bytes)")

    def on_file_send_complete(self, file_id: str, name: str, sha256_hex: str):
        progress_bar = self.file_progress_bars.get(file_id)
        if progress_bar:
            progress_bar.setValue(1000)
            progress_bar.setFormat(f"Sent {name}: 100.0%")
        self.append_chat(f"[file sent] {name} SHA256={sha256_hex}")

    def on_file_receive_complete(self, file_id: str, saved_path: str, sha256_hex: str):
        progress_bar = self.file_progress_bars.get(file_id)
        if progress_bar:
            progress_bar.setValue(1000)
            progress_bar.setFormat(f"Received {os.path.basename(saved_path)}: 100.0%")
        self.append_chat(f"[file received] {saved_path} SHA256={sha256_hex}")

    def on_file_receive_failed(self, file_id: str, reason: str):
        progress_bar = self.file_progress_bars.get(file_id)
        if progress_bar:
            progress_bar.setFormat("File verification failed")
        self.append_chat(f"[file verification failed] {reason}")

    def show_debug_window(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Handshake / Debug Output")
        dialog.resize(980, 720)
        layout = QVBoxLayout(dialog)
        debug_view = QPlainTextEdit()
        debug_view.setReadOnly(True)
        debug_view.setFont(QFont("Consolas", 10))
        debug_view.setPlainText("\n".join(self.debug_lines))  # Populate Ctrl+Q window with stored debug output.
        layout.addWidget(debug_view)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec_()

    def closeEvent(self, event):
        self.disconnect()
        event.accept()
def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.showMaximized()  # Start maximized to reduce unused screen space.
    sys.exit(app.exec_())  # Enter the Qt event loop.
if __name__ == "__main__":
    main()
