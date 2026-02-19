# X25519-TCP-Chat

A small, educational TCP chat that demonstrates how to combine the X25519 Elliptic-Curve Diffie-Hellman (ECDH) key exchange with AES-GCM encryption to build a confidential and authenticated channel.  
The code is intentionally minimal: it shows the basic ideas of secure key exchange, symmetric encryption, and multi-threaded I/O in a classic client / server design. :lock:

---

## :rocket:  Features
- **X25519 Key Exchange** – A modern ECDH curve that lets the client and server derive the same 32-byte secret without ever sending that secret across the network.  
- **AES-256-GCM Encryption** – Provides confidentiality and integrity for every message.  
- **Pure TCP Transport** – Text messages are sent over a regular TCP socket.  
- **Multithreaded I/O** – A sender thread and a receiver thread run in parallel so neither side blocks the other.  

---

## :books:  How It Works

1. **Key Exchange**  
   Each side creates an X25519 key pair.  
   After exchanging raw 32-byte public keys, both sides call `private_key.exchange(peer_public)` to compute the same 32-byte shared secret.

2. **Key Derivation**  
   The shared secret is fed into HKDF-SHA256 to derive a 256-bit AES key that will encrypt all traffic.

3. **Encryption**  
   For every outbound message a fresh 12-byte nonce is generated.  
   The packet layout is  
   ```
   4-byte length | 12-byte nonce | 16-byte GCM tag | ciphertext
   ```  
   The receiver uses the length prefix to read the full packet and then decrypts it with the same AES key.

4. **Multithreading**  
   • Main thread: reads user input and sends encrypted packets.  
   • Background thread: blocks on `recv()` and prints decrypted messages.

---

## :warning:  Disclaimer

This repository is **for learning only**.  It is **not production ready** and deliberately omits:

- certificate or public-key authentication (susceptible to MITM)
- replay protection
- proper error handling and logging
- key rotation / forward secrecy beyond a single run

Do **not** rely on it for sensitive data in the real world.

---

## :hammer:  Requirements
* Python 3.8+  
* `cryptography` (`pip install cryptography`)

---

## :gear:  Usage

### 1. Clone
```bash
git clone https://github.com/your-name/X25519-TCP-Chat.git
cd X25519-TCP-Chat
```

### 2. Start the server
```bash
python server.py
```
The server listens on `127.0.0.1:12345` and waits for a client.

### 3. Start the client (new terminal)
```bash
python client.py
```

Type messages in either window; they will appear decrypted on the opposite side.

---

## :computer:  Example

**Server**
```
Server listening on 127.0.0.1:12345
Client connected -> ('127.0.0.1', 60836)
Shared secret (hex) -> 4e9a…c2d1
[client] hello!
```

**Client**
```
Shared secret (hex) -> 4e9a…c2d1
> hello!
[server] got it!
```
---
## :memo:  License
Released under the MIT License.  See `LICENSE` for details.

---
## :handshake:  Contributing
Pull requests, bug reports, and feature suggestions are welcome!  Feel free to open an issue or create a PR.
---

## :mailbox_with_mail:  Contact
For questions or ideas, please open an issue in the repository.
