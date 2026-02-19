# X25519-TCP-Chat

A simple and educational TCP communication tool that demonstrates how to use the X25519 elliptic curve key exchange and AES encryption to create a secure communication channel. This project is designed for learning purposes and demonstrates basic concepts such as secure key exchange, encryption, and multithreading in a client-server application. 🔐

## 🚀 Features
- **X25519 Key Exchange**: Securely exchange a shared secret key between client and server using elliptic curve cryptography (ECC).
- **AES Encryption**: Secure communication with AES encryption for confidentiality. 🔒
- **TCP Communication**: Implementing real-time message exchange over TCP. 🌐
- **Multithreading**: Both sending and receiving messages operate in separate threads for non-blocking communication. 💬

## 📜 How It Works
### 1. **X25519 Key Exchange**
- The core of the security in this project is the **X25519 elliptic curve Diffie-Hellman (ECDH)** key exchange algorithm.
- This algorithm allows the client and server to each generate a public and private key pair.
- The client sends its public key to the server, and the server sends its public key to the client.
- Using the private key of one party and the public key of the other party, both the client and the server can compute the same shared secret key without directly exchanging the secret itself.
- This shared secret will later be used to derive symmetric encryption keys for encrypting messages.

### 2. **AES Encryption**
- Once the shared secret is established, it is used to derive a **symmetric key** using a key derivation function (KDF). This symmetric key is then used for **AES (Advanced Encryption Standard)** encryption and decryption.
- AES is a symmetric encryption algorithm, meaning the same key is used for both encryption and decryption.
- In this project, AES is used in **CBC mode (Cipher Block Chaining)**, which requires an initialization vector (IV) for each message to ensure that identical plaintexts produce different ciphertexts. This IV is generated randomly for each message.

### 3. **Message Transmission**
- The client and server send encrypted messages over a **TCP** connection.
- The messages are encrypted using AES before being transmitted and decrypted by the receiving party after they are received.

### 4. **Multithreading for Communication**
- To prevent blocking (e.g., waiting for user input while also receiving messages), both the **sending** and **receiving** operations run in separate threads.
- This allows the client and server to send and receive messages continuously, without one operation blocking the other.

## ⚠️ **Important Disclaimer**
This program is designed **solely for educational purposes**. It **is not** a fully-secure or production-ready implementation of secure communication. The code demonstrates fundamental concepts of:
- **X25519 Key Exchange**
- **AES Encryption**
- **TCP Communication**
- **Multithreading**

It is **not suitable for use in production environments** as it lacks many important security features such as:
- **Message Authentication** (e.g., HMAC for integrity)
- **Secure key management**
- **Proper handling of errors and exceptions**
- **Defense against potential attacks (e.g., man-in-the-middle, replay attacks)**

This project is meant to **teach** how to set up a basic secure communication system using X25519 and AES, but **should not be used for real-world applications** without significant improvements and security enhancements.

## 🛠️ Requirements
- Python 3.x
- `cryptography` library

You can install the required Python libraries using:
```bash
pip install cryptography
````

## ⚙️ Usage

### Server

1. Clone the repository:

   ```bash
   git clone https://github.com/wangyifan349/X25519-TCP-Chat.git
   cd X25519-TCP-Chat
   ```
2. Run the server:

   ```bash
   python server.py
   ```

   The server will start and wait for the client to connect.

### Client

1. Clone the repository:

   ```bash
   git clone https://github.com/wangyifan349/X25519-TCP-Chat.git
   cd X25519-TCP-Chat
   ```
2. Run the client:

   ```bash
   python client.py
   ```

   The client will connect to the server and allow you to send and receive messages.

## 💡 Example

### Server Output:

```bash
服务器启动，等待连接...
客户端 ('127.0.0.1', 12345) 已连接
[接收线程] 接收到的消息: b'Hello from client!'
```

### Client Output:

```bash
请输入消息：Hello from client!
[接收线程] 服务器回复: Hello from server!
```

## 📃 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
