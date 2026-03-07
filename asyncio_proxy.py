"""
This is a Python asyncio-based multi-protocol proxy server supporting HTTP(S) and SOCKS5 protocols, 
including both TCP and UDP forwarding. 
Program logic:
1. Starts a TCP server listening on a specified port (default 1080).
2. Detects client protocol based on the first byte(s) of the connection:
   - HTTP/HTTPS requests (methods starting with G, P, C, D, H, O, T)
   - SOCKS5 requests (first byte is 0x05)
3. For SOCKS5:
   - Supports TCP CONNECT and UDP ASSOCIATE commands
   - Uses tcp_pipe() for bidirectional TCP forwarding
   - UDP packets are handled by the UdpProxyUdpAssoc class
4. For HTTP/HTTPS:
   - HTTPS CONNECT requests establish a TCP tunnel
   - HTTP requests are forwarded directly, with request body support
5. All requests are logged into a log file (proxy_requests.log) with source, target, protocol, and byte size
"""

import asyncio
import struct
import logging

PROXY_PORT = 1080  # Proxy listening port
LOG_FILE = 'proxy_requests.log'  # File to log all proxy requests

# Configure the logger
logging.basicConfig(
    level=logging.INFO,  # Set log level to INFO
    filename=LOG_FILE,   # Write logs to file
    filemode='a',        # Append mode
    format='[%(asctime)s] %(levelname)s %(message)s'  # Log format
)
logger = logging.getLogger('proxy')  # Create a logger named 'proxy'


# TCP bidirectional pipe function for forwarding data
async def tcp_pipe(reader_obj, writer_obj):
    try:
        while True:
            data = await reader_obj.read(65536)  # Read up to 64KB from source
            if not data:
                break  # End of stream, exit loop
            writer_obj.write(data)  # Forward data to destination
            await writer_obj.drain()  # Ensure data is sent
    except (ConnectionResetError, OSError):
        pass  # Ignore connection reset or closed errors
    finally:
        try:
            writer_obj.close()  # Close the writer
            await writer_obj.wait_closed()
        except Exception:
            pass  # Ignore exceptions on close


# Handle a SOCKS5 connection from a client
async def handle_socks5(reader_obj, writer_obj, client_addr):
    version_nmethods = await reader_obj.readexactly(2)  # Read version and number of auth methods
    version, nmethods = version_nmethods
    if version != 5:  # Not SOCKS5, close connection
        writer_obj.close()
        await writer_obj.wait_closed()
        return
    await reader_obj.readexactly(nmethods)  # Skip the list of authentication methods

    writer_obj.write(b'\x05\x00')  # Reply: no authentication required
    await writer_obj.drain()

    request_header = await reader_obj.readexactly(4)  # Read request header: version, command, reserved, address type
    version, command, reserved, addr_type = request_header

    # Parse the target address depending on address type
    if addr_type == 1:  # IPv4
        addr_bytes = await reader_obj.readexactly(4)
        target_host = '.'.join(str(b) for b in addr_bytes)  # Convert bytes to dotted decimal
    elif addr_type == 3:  # Domain name
        domain_len = (await reader_obj.readexactly(1))[0]  # Read domain length
        domain_bytes = await reader_obj.readexactly(domain_len)
        target_host = domain_bytes.decode()  # Decode domain
    elif addr_type == 4:  # IPv6
        addr_bytes = await reader_obj.readexactly(16)
        target_host = ':'.join('{:02x}{:02x}'.format(addr_bytes[i], addr_bytes[i+1]) for i in range(0,16,2))
    else:
        writer_obj.close()
        await writer_obj.wait_closed()
        return

    port_bytes = await reader_obj.readexactly(2)  # Read the target port
    target_port = struct.unpack(">H", port_bytes)[0]  # Convert to integer
    target_addr_port = f"{target_host}:{target_port}"

    # Handle TCP CONNECT command
    if command == 1:
        try:
            remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)  # Connect to target
            writer_obj.write(b'\x05\x00\x00\x01' + b'\x00'*6)  # Reply: connection granted
            await writer_obj.drain()
            logger.info('SOCKS5-TCP %s -> %s', client_addr, target_addr_port)
            # Forward data in both directions concurrently
            await asyncio.gather(
                tcp_pipe(reader_obj, remote_writer),  # Client -> Remote
                tcp_pipe(remote_reader, writer_obj)   # Remote -> Client
            )
        except Exception:
            try:
                writer_obj.write(b'\x05\x01\x00\x01' + b'\x00'*6)  # Reply: general failure
                await writer_obj.drain()
            except Exception:
                pass
    # Handle UDP ASSOCIATE command
    elif command == 3:
        loop = asyncio.get_running_loop()
        udp_transport, udp_protocol = await loop.create_datagram_endpoint(
            lambda: UdpProxyUdpAssoc(client_addr),  # Create UDP protocol instance
            local_addr=('0.0.0.0', 0)  # Bind to random local port
        )
        udp_port = udp_transport.get_extra_info('sockname')[1]  # Get actual UDP port
        try:
            reply = b'\x05\x00\x00\x01' + b'\x00\x00\x00\x00' + struct.pack('>H', udp_port)  # Reply with assigned UDP port
            writer_obj.write(reply)
            await writer_obj.drain()
        except Exception:
            pass
        logger.info('SOCKS5-UDP-ASSOC %s assigned_proxy_udpport=%s', client_addr, udp_port)
        await reader_obj.read()  # Keep TCP connection open until client closes
        udp_transport.close()
    else:
        try:
            writer_obj.write(b'\x05\x07\x00\x01' + b'\x00'*6)  # Reply: command not supported
            await writer_obj.drain()
        except Exception:
            pass

    writer_obj.close()
    await writer_obj.wait_closed()


# UDP proxy protocol class for SOCKS5 UDP forwarding
class UdpProxyUdpAssoc(asyncio.DatagramProtocol):
    def __init__(self, client_addr):
        self.client_addr = client_addr  # Store client address

    def connection_made(self, transport_obj):
        self.transport_obj = transport_obj  # Save transport object

    def datagram_received(self, data_chunk, addr):
        if len(data_chunk) < 10:  # Ignore too short packets
            return
        addr_type = data_chunk[3]  # Extract address type
        idx = 4
        # Parse destination address
        if addr_type == 1:  # IPv4
            dest_host = '.'.join(str(b) for b in data_chunk[idx:idx+4])
            idx += 4
        elif addr_type == 3:  # Domain
            domain_len = data_chunk[idx]
            idx += 1
            dest_host = data_chunk[idx:idx+domain_len].decode()
            idx += domain_len
        elif addr_type == 4:  # IPv6
            dest_host = ':'.join('{:02x}{:02x}'.format(data_chunk[idx+i], data_chunk[idx+i+1]) for i in range(0,16,2))
            idx += 16
        else:
            return
        dest_port = struct.unpack('>H', data_chunk[idx:idx+2])[0]  # Extract destination port
        idx += 2
        payload = data_chunk[idx:]  # Extract payload
        dest_addr_port = f"{dest_host}:{dest_port}"
        logger.info('SOCKS5-UDP %s -> %s bytes=%d', self.client_addr, dest_addr_port, len(payload))
        asyncio.create_task(self.relay_udp(dest_host, dest_port, addr_type, payload, addr))  # Relay asynchronously
    async def relay_udp(self, dest_host, dest_port, addr_type, payload, client_addr):
        loop = asyncio.get_running_loop()
        on_response = loop.create_future()  # Future to wait for response
        class ResponseProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, resp_data, resp_addr):
                if not on_response.done():
                    on_response.set_result(resp_data)

        transport_obj, _ = await loop.create_datagram_endpoint(
            ResponseProtocol, remote_addr=(dest_host, dest_port)  # Connect to target
        )
        try:
            transport_obj.sendto(payload)  # Send UDP payload
            resp_data = await asyncio.wait_for(on_response, timeout=5)  # Wait for response
            # Construct reply packet
            reply = b'\x00\x00\x00' + bytes([addr_type])
            if addr_type == 1:  # IPv4
                reply += b''.join(int(p).to_bytes(1,'big') for p in dest_host.split('.'))
            elif addr_type == 3:  # Domain
                reply += bytes([len(dest_host)]) + dest_host.encode()
            elif addr_type == 4:  # IPv6
                for s in dest_host.split(':'):
                    reply += bytes.fromhex(s)
            reply += struct.pack('>H', dest_port) + resp_data
            self.transport_obj.sendto(reply, client_addr)  # Send back to client
        except Exception:
            pass
        finally:
            transport_obj.close()


# HTTP/HTTPS handler
async def handle_http(reader_obj, writer_obj, client_addr, initial_data=b''):
    headers_data = initial_data  # Include already-read bytes
    header_end = headers_data.find(b'\r\n\r\n')
    while header_end == -1 and len(headers_data) < 65536:
        chunk = await reader_obj.read(4096)
        if not chunk:
            writer_obj.close()
            await writer_obj.wait_closed()
            return
        headers_data += chunk
        header_end = headers_data.find(b'\r\n\r\n')
    header_blob = headers_data[:header_end+4]  # HTTP headers
    remain_blob = headers_data[header_end+4:]  # Remaining body
    lines = header_blob.decode(errors='replace').split('\r\n')
    req_line = lines[0].split(' ',2)
    if len(req_line) != 3:
        writer_obj.close()
        await writer_obj.wait_closed()
        return
    method, url, proto = req_line
    # HTTPS CONNECT method
    if method.upper() == 'CONNECT':
        host, port = url.split(':')
        port = int(port)
        remote_address = f"{host}:{port}"
        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, port)  # Connect to target
            writer_obj.write(b'HTTP/1.1 200 Connection Established\r\nProxy-Agent: pyproxy\r\n\r\n')  # Reply 200
            await writer_obj.drain()
            logger.info('HTTPS-CONNECT %s -> %s method=CONNECT', client_addr, remote_address)
            await asyncio.gather(
                tcp_pipe(reader_obj, remote_writer),  # Client -> Remote
                tcp_pipe(remote_reader, writer_obj)   # Remote -> Client
            )
        except Exception:
            pass
        finally:
            try:
                writer_obj.close()
                await writer_obj.wait_closed()
            except Exception:
                pass
        return
    # Standard HTTP request handling
    dest_host = None
    for line in lines[1:]:
        if line.lower().startswith('host:'):
            dest_host = line[5:].strip()  # Extract host
            break
    if not dest_host:
        writer_obj.close()
        await writer_obj.wait_closed()
        return
    if ':' in dest_host:
        host, port = dest_host.split(':')
        port = int(port)
    else:
        host = dest_host
        port = 80
    # Construct full URL for logging
    full_url = url
    if not url.startswith('http://') and not url.startswith('https://'):
        if port == 80:
            full_url = f"http://{host}{url}"
        elif port == 443:
            full_url = f"https://{host}{url}"
        else:
            full_url = f"http://{host}:{port}{url}"
    remote_address = f"{host}:{port}"
    logger.info('HTTP %s -> %s method=%s full_url=%s', client_addr, remote_address, method, full_url)
    try:
        remote_reader, remote_writer = await asyncio.open_connection(host, port)
        remote_writer.write(header_blob)  # Send headers
        if remain_blob:
            remote_writer.write(remain_blob)  # Send remaining body
        await remote_writer.drain()
        content_length = None
        for line in lines[1:]:
            if line.lower().startswith('content-length:'):
                try:
                    content_length = int(line[15:].strip())
                except Exception:
                    content_length = None
                break
        if content_length and len(remain_blob) < content_length:
            body_rest = await reader_obj.readexactly(content_length - len(remain_blob))
            remote_writer.write(body_rest)
            await remote_writer.drain()

        await asyncio.gather(
            tcp_pipe(reader_obj, remote_writer),
            tcp_pipe(remote_reader, writer_obj)
        )
    except (ConnectionResetError, OSError):
        pass
    finally:
        try:
            writer_obj.close()
            await writer_obj.wait_closed()
        except Exception:
            pass


# Client handler entry point, detect protocol
async def handle_client(reader_obj, writer_obj):
    peer_info = writer_obj.get_extra_info('peername')
    client_addr = f"{peer_info[0]}:{peer_info[1]}" if peer_info else '-'

    first_two = await reader_obj.read(2)  # Read first two bytes
    if not first_two:
        writer_obj.close()
        await writer_obj.wait_closed()
        return
    proto_marker = first_two[0]
    if first_two[:1] in b'GPCDHOPT':  # HTTP methods (GET, POST, CONNECT, etc.)
        await handle_http(reader_obj, writer_obj, client_addr, initial_data=first_two)
    elif proto_marker == 0x05:  # SOCKS5
        combined_reader = asyncio.StreamReader()
        combined_reader.feed_data(first_two)
        async def feed_remaining():  # Feed remaining data into StreamReader
            while True:
                data = await reader_obj.read(65536)
                if not data:
                    combined_reader.feed_eof()
                    break
                combined_reader.feed_data(data)
        asyncio.create_task(feed_remaining())
        await handle_socks5(combined_reader, writer_obj, client_addr)
    else:
        writer_obj.close()
        await writer_obj.wait_closed()
# Main function to start the proxy server
async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', PROXY_PORT)  # Listen on all interfaces
    logger.info('Proxy server running (single process) on port %d', PROXY_PORT)
    print(f'Proxy server running (single process) on port {PROXY_PORT} ...')
    async with server:
        await server.serve_forever()  # Run indefinitely
if __name__ == '__main__':
    asyncio.run(main())  # Start asyncio event loop
