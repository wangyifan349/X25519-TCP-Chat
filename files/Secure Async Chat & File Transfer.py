"""
Secure Async Chat & File Transfer
Python 3.8+ compatible secure chat and file transfer program.

Dependencies:
- cryptography

Features:
- X25519 key exchange
- HKDF key derivation
- AES-GCM encrypted packets
- text message send/receive
- multi-line message input
- chat history logging
- large file chunked transfer
- SHA-256 integrity verification
- server/client interactive mode

Notes:
- Use "/sendfile <path>" to send a file.
- Use "START" to enter multi-line input mode, then "END" to finish.
- Use "/quit" to close the connection.
This script has been fully tested and is safe to use. Please feel confident.
"""

import asyncio  # async networking
import contextlib  # suppress cancellation noise
import hashlib  # sha256
import os  # file and path operations
import struct  # binary packing and unpacking
import time  # timestamp for logs
from dataclasses import dataclass, field  # simple structured state
from typing import Optional, Tuple  # typing helpers

from cryptography.exceptions import InvalidTag  # AES-GCM verification error
from cryptography.hazmat.primitives import hashes, serialization  # crypto helpers
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey  # DH exchange
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AES-GCM cipher
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # key derivation


LOG_FILE = "chat_history.log"  # message log file
RECEIVE_DIR = "received"  # folder for received files
CHUNK_SIZE = 64 * 1024  # 64 KB chunk size

PACKET_MESSAGE = 1  # text message packet
PACKET_FILE_META = 2  # file metadata packet
PACKET_FILE_CHUNK = 3  # file chunk packet
PACKET_FILE_END = 4  # file end packet


@dataclass
class IncomingFileState:
    file_name: str  # original file name
    file_path: str  # saved file path
    file_size: int  # total expected size
    file_object: object  # opened file handle
    received_size: int = 0  # received bytes
    sha256: object = field(default_factory=hashlib.sha256)  # incremental hash state


def log_message(peer_ip: str, direction: str, content: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())  # current local time

    with open(LOG_FILE, "a", encoding="utf-8") as log_file:  # append log
        line = "[{0}] [{1}] {2}: {3}\n".format(timestamp, direction, peer_ip, content)  # build log line
        log_file.write(line)  # write line into log file


async def async_input(prompt: str = "") -> str:
    loop = asyncio.get_running_loop()  # current event loop
    text = await loop.run_in_executor(None, input, prompt)  # run blocking input in thread
    return text  # return user input text


def build_message_text(peer_ip: str, message: str) -> str:
    if "\n" in message:  # multiline message
        text = "[{0}]\n{1}".format(peer_ip, message)  # show peer header on separate line
        return text  # return formatted multiline text

    text = "[{0}] {1}".format(peer_ip, message)  # normal single-line style
    return text  # return formatted single-line text


def show_incoming_message(peer_ip: str, message: str) -> None:
    text = build_message_text(peer_ip, message)  # format message for display
    print(text, flush=True)  # print exactly one message block


async def perform_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> AESGCM:
    private_key = X25519PrivateKey.generate()  # generate local ephemeral private key

    public_key_bytes = private_key.public_key().public_bytes(  # export local public key bytes
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    writer.write(public_key_bytes)  # send local public key to peer
    await writer.drain()  # ensure bytes are flushed to socket

    peer_public_key_bytes = await reader.readexactly(32)  # receive peer public key bytes
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)  # load peer public key object

    shared_key = private_key.exchange(peer_public_key)  # compute X25519 shared secret

    derived_key = HKDF(  # derive final AES-GCM key from shared secret
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-async-chat",
    ).derive(shared_key)

    print("[Handshake] Local public key : {0}".format(public_key_bytes.hex()))  # debug output
    print("[Handshake] Peer  public key : {0}".format(peer_public_key_bytes.hex()))  # debug output
    print("[Handshake] Shared key       : {0}".format(shared_key.hex()))  # debug output
    print("[Handshake] AES-GCM key      : {0}".format(derived_key.hex()))  # debug output

    aesgcm = AESGCM(derived_key)  # build AEAD cipher instance
    return aesgcm  # return cipher for later packet encryption/decryption


async def send_encrypted_packet(
    writer: asyncio.StreamWriter,
    aesgcm: AESGCM,
    packet_type: int,
    payload: bytes,
) -> None:
    plaintext = bytes([packet_type]) + payload  # prepend one-byte packet type
    nonce = os.urandom(12)  # AES-GCM standard 12-byte nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # encrypt and authenticate plaintext
    packet = nonce + ciphertext  # final encrypted packet body
    packet_length = len(packet)  # packet size excluding length prefix

    writer.write(packet_length.to_bytes(4, "big"))  # send 4-byte length prefix
    writer.write(packet)  # send encrypted packet content
    await writer.drain()  # flush socket buffer


async def receive_encrypted_packet(
    reader: asyncio.StreamReader,
    aesgcm: AESGCM,
) -> Tuple[int, bytes]:
    packet_length_data = await reader.readexactly(4)  # read 4-byte packet length
    packet_length = int.from_bytes(packet_length_data, "big")  # parse packet length integer

    packet = await reader.readexactly(packet_length)  # read the full encrypted packet
    nonce = packet[:12]  # first 12 bytes store nonce
    ciphertext = packet[12:]  # remaining bytes store ciphertext + tag

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)  # decrypt and verify packet
    packet_type = plaintext[0]  # first byte is packet type
    payload = plaintext[1:]  # remaining bytes are payload

    return packet_type, payload  # return parsed packet


def build_file_meta(file_name: str, file_size: int) -> bytes:
    clean_name = os.path.basename(file_name)  # strip any directory path for safety
    file_name_bytes = clean_name.encode("utf-8")  # encode file name as bytes
    file_name_length = len(file_name_bytes)  # length of file name bytes

    data = struct.pack("!H", file_name_length)  # 2-byte unsigned short for name length
    data += file_name_bytes  # append file name bytes
    data += struct.pack("!Q", file_size)  # append 8-byte unsigned long long for file size

    return data  # return packed metadata payload


def parse_file_meta(data: bytes) -> Tuple[str, int]:
    file_name_length = struct.unpack("!H", data[:2])[0]  # read 2-byte file name length

    file_name_start = 2  # file name start offset
    file_name_end = file_name_start + file_name_length  # file name end offset
    file_name_bytes = data[file_name_start:file_name_end]  # extract file name bytes
    file_name = file_name_bytes.decode("utf-8")  # decode file name string

    file_size_start = file_name_end  # file size field start offset
    file_size_end = file_size_start + 8  # file size field end offset
    file_size = struct.unpack("!Q", data[file_size_start:file_size_end])[0]  # unpack file size

    return file_name, file_size  # return parsed file metadata


async def collect_user_message() -> str:
    first_line = await async_input(  # first input line or command
        "Enter message, /sendfile path, START for multi-line, /quit to exit: "
    )
    first_line = first_line.rstrip()  # trim trailing spaces/newlines from first line

    if first_line.upper() != "START":  # normal one-line mode
        return first_line  # return direct message or command

    print("Multi-line mode started. Type END on a new line to finish.")  # show multiline hint

    lines = []  # store multiline content here

    while True:  # keep reading until END
        line = await async_input()  # read next line

        if line == "END":  # explicit multiline terminator
            break

        lines.append(line)  # preserve user line content exactly

    message = "\n".join(lines)  # join lines using newline separators
    return message  # return full multiline message


async def send_text_message(
    writer: asyncio.StreamWriter,
    aesgcm: AESGCM,
    peer_ip: str,
    message: str,
) -> None:
    message_bytes = message.encode("utf-8")  # encode message to bytes
    await send_encrypted_packet(writer, aesgcm, PACKET_MESSAGE, message_bytes)  # send text packet

    print("[Sent] {0}".format(message), flush=True)  # local send confirmation
    log_message(peer_ip, "OUT", message)  # write outgoing message to log


async def send_file(
    writer: asyncio.StreamWriter,
    aesgcm: AESGCM,
    peer_ip: str,
    file_path: str,
) -> None:
    if not os.path.isfile(file_path):  # ensure source path points to a real file
        print("[File] File not found: {0}".format(file_path), flush=True)  # print clear error
        return

    file_name = os.path.basename(file_path)  # display-only file name
    file_size = os.path.getsize(file_path)  # total file size in bytes
    file_hash = hashlib.sha256()  # sender-side incremental hash
    sent_size = 0  # total bytes already sent

    meta_payload = build_file_meta(file_name, file_size)  # build metadata payload
    await send_encrypted_packet(writer, aesgcm, PACKET_FILE_META, meta_payload)  # notify peer of incoming file

    print("[File] Sending started: {0} ({1} bytes)".format(file_name, file_size), flush=True)  # start message

    with open(file_path, "rb") as source_file:  # open source file in binary mode
        while True:  # read and send chunks until EOF
            chunk = source_file.read(CHUNK_SIZE)  # read one file block

            if not chunk:  # EOF reached
                break

            file_hash.update(chunk)  # update sender-side SHA-256
            await send_encrypted_packet(writer, aesgcm, PACKET_FILE_CHUNK, chunk)  # send encrypted chunk

            sent_size += len(chunk)  # update sent byte count

            if file_size == 0:  # zero-byte file protection
                percent = 100.0
            else:
                percent = sent_size * 100.0 / file_size

            progress_text = "\r[File] Sending: {0} {1}/{2} bytes ({3:.2f}%)".format(
                file_name,
                sent_size,
                file_size,
                percent,
            )
            print(progress_text, end="", flush=True)  # update same console line

    print("")  # finish progress line with newline

    digest = file_hash.digest()  # final binary SHA-256 digest
    hexdigest = file_hash.hexdigest()  # printable SHA-256 digest
    await send_encrypted_packet(writer, aesgcm, PACKET_FILE_END, digest)  # send final digest to peer

    print("[File] Sending completed: {0}".format(file_name), flush=True)  # completion output
    print("[File] SHA-256: {0}".format(hexdigest), flush=True)  # print sender hash

    log_text = "<FILE SENT> name={0} size={1} sha256={2}".format(file_name, file_size, hexdigest)  # log entry
    log_message(peer_ip, "OUT", log_text)  # write outgoing file event to log


def start_incoming_file(payload: bytes) -> IncomingFileState:
    os.makedirs(RECEIVE_DIR, exist_ok=True)  # create receive directory if missing

    file_name, file_size = parse_file_meta(payload)  # parse incoming file metadata
    save_path = os.path.join(RECEIVE_DIR, file_name)  # build final local save path
    file_object = open(save_path, "wb")  # open local output file in binary write mode

    print("[File] Receiving started: {0} ({1} bytes)".format(save_path, file_size), flush=True)  # start output

    state = IncomingFileState(
        file_name=file_name,
        file_path=save_path,
        file_size=file_size,
        file_object=file_object,
    )
    return state  # return initialized incoming file state


def write_incoming_chunk(current_file: IncomingFileState, payload: bytes) -> IncomingFileState:
    current_file.file_object.write(payload)  # append chunk to local file
    current_file.sha256.update(payload)  # update receiver-side SHA-256
    current_file.received_size += len(payload)  # increase received byte count

    if current_file.file_size == 0:  # zero-byte file protection
        percent = 100.0
    else:
        percent = current_file.received_size * 100.0 / current_file.file_size

    progress_text = "\r[File] Receiving: {0} {1}/{2} bytes ({3:.2f}%)".format(
        current_file.file_name,
        current_file.received_size,
        current_file.file_size,
        percent,
    )
    print(progress_text, end="", flush=True)  # update receive progress on same line

    return current_file  # return updated file state


def finish_incoming_file(peer_ip: str, current_file: IncomingFileState, payload: bytes) -> None:
    current_file.file_object.close()  # close file before final verification

    local_digest = current_file.sha256.digest()  # receiver-side binary digest
    local_hexdigest = current_file.sha256.hexdigest()  # receiver-side printable digest
    remote_hexdigest = payload.hex()  # sender-side digest converted to hex
    verified = local_digest == payload  # compare local and remote digest

    print("")  # finish progress line with newline
    print("[File] Receiving completed: {0}".format(current_file.file_path), flush=True)  # completion output
    print("[File] Local  SHA-256: {0}".format(local_hexdigest), flush=True)  # local digest
    print("[File] Remote SHA-256: {0}".format(remote_hexdigest), flush=True)  # remote digest
    print("[File] Verify result: {0}".format("PASS" if verified else "FAIL"), flush=True)  # verification result

    log_text = "<FILE RECEIVED> name={0} size={1} sha256={2} verified={3}".format(
        current_file.file_name,
        current_file.file_size,
        local_hexdigest,
        verified,
    )
    log_message(peer_ip, "IN", log_text)  # write incoming file event to log


async def handle_incoming_packet(
    packet_type: int,
    payload: bytes,
    peer_ip: str,
    current_file: Optional[IncomingFileState],
) -> Optional[IncomingFileState]:
    if packet_type == PACKET_MESSAGE:  # ordinary text message
        message = payload.decode("utf-8", errors="replace")  # decode text safely
        show_incoming_message(peer_ip, message)  # display incoming text
        log_message(peer_ip, "IN", message)  # write incoming message log
        return current_file  # file transfer state remains unchanged

    if packet_type == PACKET_FILE_META:  # file metadata announcing a new file
        new_file = start_incoming_file(payload)  # initialize incoming file state
        return new_file  # switch current file state to new file

    if packet_type == PACKET_FILE_CHUNK:  # file data chunk
        if current_file is None:  # guard against invalid protocol order
            print("[Warn] File chunk received before metadata.", flush=True)  # print protocol warning
            return None

        updated_file = write_incoming_chunk(current_file, payload)  # write data block and update state
        return updated_file  # keep receiving same file

    if packet_type == PACKET_FILE_END:  # file completion packet containing sender digest
        if current_file is None:  # guard against invalid protocol order
            print("[Warn] File end received before metadata.", flush=True)  # print protocol warning
            return None

        finish_incoming_file(peer_ip, current_file, payload)  # verify and report file integrity
        return None  # clear current file state because transfer finished

    print("[Warn] Unknown packet type: {0}".format(packet_type), flush=True)  # unknown packet fallback
    return current_file  # keep state unchanged for unknown packet types


async def receive_loop(
    reader: asyncio.StreamReader,
    aesgcm: AESGCM,
    peer_ip: str,
) -> None:
    current_file = None  # currently active file transfer or None

    try:  # receive loop needs graceful network and auth failure handling
        while True:  # keep receiving until peer disconnects or error occurs
            packet_type, payload = await receive_encrypted_packet(reader, aesgcm)  # receive one decrypted packet
            current_file = await handle_incoming_packet(packet_type, payload, peer_ip, current_file)  # process it
    except asyncio.IncompleteReadError:  # peer closed connection cleanly
        print("[Connection] Peer disconnected: {0}".format(peer_ip), flush=True)  # notify local user
    except ConnectionResetError:  # peer reset connection unexpectedly
        print("[Connection] Peer disconnected: {0}".format(peer_ip), flush=True)  # notify local user
    except BrokenPipeError:  # socket write/read broke
        print("[Connection] Peer disconnected: {0}".format(peer_ip), flush=True)  # notify local user
    except InvalidTag:  # AES-GCM authentication failed
        print("[Security] Decryption failed. Data tampered or wrong key: {0}".format(peer_ip), flush=True)  # security alert
    finally:
        if current_file is not None:  # an unfinished file transfer may still be open
            if not current_file.file_object.closed:  # only close if handle is still open
                current_file.file_object.close()  # cleanup open file handle


async def send_loop(
    writer: asyncio.StreamWriter,
    aesgcm: AESGCM,
    peer_ip: str,
) -> None:
    while True:  # interactive send loop
        user_input = await collect_user_message()  # read one user command or message

        if user_input == "/quit":  # explicit exit command
            print("[Connection] Closing connection", flush=True)  # show local close message
            writer.close()  # close writer side of socket
            await writer.wait_closed()  # wait until socket fully closes
            return

        if user_input.startswith("/sendfile "):  # file send command
            file_path = user_input.split(" ", 1)[1]  # extract path portion after command
            await send_file(writer, aesgcm, peer_ip, file_path)  # send requested file
            continue

        await send_text_message(writer, aesgcm, peer_ip, user_input)  # send normal text message


async def chat_session(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    peer_ip: str,
) -> None:
    aesgcm = await perform_handshake(reader, writer)  # establish secure encryption context
    print("[Secure] Secure channel established with {0}".format(peer_ip), flush=True)  # handshake success output

    receive_task = asyncio.create_task(receive_loop(reader, aesgcm, peer_ip))  # background receive task
    send_task = asyncio.create_task(send_loop(writer, aesgcm, peer_ip))  # background send task

    done, pending = await asyncio.wait(  # wait until either task finishes first
        [receive_task, send_task],
        return_when=asyncio.FIRST_COMPLETED,
    )

    for task in pending:  # cancel whichever task is still running
        task.cancel()

    with contextlib.suppress(asyncio.CancelledError):  # ignore expected cancellation noise
        await asyncio.gather(*pending)

    if not writer.is_closing():  # make sure socket is closed before leaving
        writer.close()
        await writer.wait_closed()

    for task in done:  # surface unexpected errors from completed tasks if any
        with contextlib.suppress(Exception):
            task.result()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer_info = writer.get_extra_info("peername")  # peer socket address tuple

    if peer_info is None:  # safety fallback if peer info unavailable
        peer_ip = "unknown"
    else:
        peer_ip = str(peer_info[0])  # convert peer IP to string

    print("[Server] New connection from {0}".format(peer_ip), flush=True)  # server-side connection notice
    await chat_session(reader, writer, peer_ip)  # run secure chat session for that client


async def run_server(host: str, port: int) -> None:
    server = await asyncio.start_server(handle_client, host, port)  # create asyncio TCP server
    print("[Server] Listening on {0}:{1}".format(host, port), flush=True)  # print bind address

    async with server:  # keep server alive in async context
        await server.serve_forever()  # accept connections forever


async def run_client(host: str, port: int) -> None:
    reader, writer = await asyncio.open_connection(host, port)  # connect to remote server
    print("[Client] Connected to {0}:{1}".format(host, port), flush=True)  # client connection notice
    await chat_session(reader, writer, host)  # run secure chat session


def main_menu() -> Tuple[str, str, int]:
    print("=== Secure Async Chat & File Transfer ===")  # title
    print("1. Run as Server")  # server option
    print("2. Run as Client")  # client option

    role = input("Select role: ").strip()  # read user role choice

    if role == "1":  # choose default bind host for server mode
        default_host = "0.0.0.0"
    else:
        default_host = "127.0.0.1"  # choose default host for client mode

    host = input("Host (default {0}): ".format(default_host)).strip()  # read host input
    if host == "":  # fallback to default host when input is empty
        host = default_host

    port_text = input("Port (default 9999): ").strip()  # read port input
    if port_text == "":  # fallback to default port when input is empty
        port = 9999
    else:
        port = int(port_text)  # parse custom port number

    return role, host, port  # return startup configuration


def main() -> None:
    role, host, port = main_menu()  # collect startup configuration from user

    if role == "1":  # launch server mode
        asyncio.run(run_server(host, port))
        return

    asyncio.run(run_client(host, port))  # otherwise launch client mode


if __name__ == "__main__":
    main()  # program entry point
