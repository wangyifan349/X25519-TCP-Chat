import socket
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import threading
# Generate X25519 private and public keys
private_key = X25519PrivateKey.generate()
public_key = private_key.public_key()
# Connect to the server
HOST = '127.0.0.1'
PORT = 12345
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
# Send client's public key to the server
client_socket.send(public_key.public_bytes())
# Receive server's public key
server_public_key_bytes = client_socket.recv(1024)
server_public_key = X25519PublicKey.from_public_bytes(server_public_key_bytes)
# Compute shared secret using both private and public keys
shared_key = private_key.exchange(server_public_key)
# Derive symmetric encryption key from shared secret using PBKDF2
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(shared_key)
# Generate AES-GCM cipher object for encryption/decryption
nonce = os.urandom(12)  # AES-GCM requires a nonce (12 bytes)
cipher = ciphers.Cipher(ciphers.algorithms.AES(key), ciphers.modes.GCM(nonce), backend=default_backend())
# Send message function
def send_message():
    while True:
        message = input("Enter message: ").encode()
        # Encrypt the message using AES-GCM
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message) + encryptor.finalize()
        tag = encryptor.tag  # Message Authentication Code (MAC)
        # Send encrypted message and tag to the server
        client_socket.send(encrypted_message + tag)
# Receive message function
def receive_message():
    while True:
        response = client_socket.recv(1024)
        encrypted_message = response[:-16]  # Extract encrypted message
        tag = response[-16:]  # Extract tag
        # Decrypt the message using AES-GCM
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize_with_tag(tag)
        print(f"[Receive Thread] Server reply: {decrypted_message.decode()}")
# Create and start send and receive threads
send_thread = threading.Thread(target=send_message, name="Send-Thread")
receive_thread = threading.Thread(target=receive_message, name="Receive-Thread")
send_thread.start()
receive_thread.start()
# Wait for threads to finish
send_thread.join()
receive_thread.join()
# Close the connection
client_socket.close()
