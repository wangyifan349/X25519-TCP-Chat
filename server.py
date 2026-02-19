import socket
import os
import threading
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Generate X25519 private and public keys
private_key = X25519PrivateKey.generate()
public_key = private_key.public_key()

# Server configuration
HOST = '127.0.0.1'  # Localhost
PORT = 12345  # Port

# Create TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print("Server started, waiting for connection...")

# Wait for client connection
conn, addr = server_socket.accept()
print(f"Client {addr} connected")
# Send server's public key to the client
conn.send(public_key.public_bytes())
# Receive client's public key
client_public_key_bytes = conn.recv(1024)
client_public_key = X25519PublicKey.from_public_bytes(client_public_key_bytes)
# Compute shared secret using both private and public keys
shared_key = private_key.exchange(client_public_key)
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
# Create AES-GCM cipher object for encryption
nonce = os.urandom(12)  # AES-GCM requires a nonce (12 bytes)
cipher = ciphers.Cipher(ciphers.algorithms.AES(key), ciphers.modes.GCM(nonce), backend=default_backend())
# Handle the reception and encryption of messages
def receive_message():
    while True:
        data = conn.recv(1024)
        if not data:
            print("Client disconnected")
            break
        print(f"[Receive Thread] Received message: {data}")
        # Encrypt the message using AES-GCM
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag  # Message Authentication Code (MAC)
        # Send encrypted message and tag to the client
        conn.send(encrypted_message + tag)

# Create and start the receive message thread
receive_thread = threading.Thread(target=receive_message, name="Receive-Thread")
receive_thread.start()
# Wait for the receive thread to complete
receive_thread.join()
# Close the connection
conn.close()
