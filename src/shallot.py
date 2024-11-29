import asyncio
import base64
import time
import socketserver
import socket
import threading

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey

import crypto
import list_server
from config import SHALLOT
from config import CRYPTO

import file_server

_should_exit = threading.Event()

my_name = ''
my_port = 0
# note: public ip address is available at list_server.my_public_ip

request_counter = 0
active_requests = {}

prikey = X25519PrivateKey.generate()
pubkey = prikey.public_key()

def send_tcp(ip: str, port: int, data: bytes):
    if ip == list_server.my_public_ip:
        ip = 'localhost'
    # TODO open a TCP socket to the (IP, port), send the data, and close the connection
    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((ip, port))
            sock.sendall(data)
        except Exception as e:
            print(f"Failed to send data: {e}")
        finally:
            pass
    
class ShallotHandler(socketserver.BaseRequestHandler):
    """
    Handler for incoming Shallot protocol connections.
    """
    def handle(self):
        socket = self.request
        # TODO first, use the socket to receive data until the connection is closed
        #   Then, divide the data into the header and payload (use crypto.get_header_size(SHALLOT.CYCLE_LENGTH))
        #   Use crypto.decode_header to get the flags, next node's IP, next node's port, and next header
        #   If flags = 0, we are an intermediate node, so we just have to pass the payload to the next node
        #   Use send_tcp() to send the next header + unmodified payload to the next IP & port
        #   If flags = 2, we are the recipient of the request
        #   Decrypt the payload with our prikey (Use crypto.decrypt()) then pass the decrypted payload to
        #   file_server.handle_request()
        #   Once it returns the response, encrypt it (using the ephemeral public key included in the payload:
        #   it will be the first CONFIG.X25519_SIZE bytes) and send it + the unpeeled header to the next node
        #   If flags = 3, we are the originator of the request
        #   The IP field will contain the request ID
        #   Decrypt the payload (with active_requests[req_id]['ephprikey']
        #   then signal request completion by calling active_requests[req_id]['future'].set_result(decrypted_payload)
        data = socket.recv(1024)
        while data:
            data += socket.recv(1024)
        
        header_size = crypto.get_header_size(SHALLOT.CYCLE_LENGTH)
        header, payload = data[:header_size], data[header_size:]
        
        flags, next_ip, next_port, next_header = crypto.decode_header(header)
        
        if flags == 0:
            send_tcp(next_ip, next_port, next_header + payload)
        elif flags == 2:
            decrypted_payload = crypto.decrypt(prikey, payload)
            eph_pubkey = X25519PublicKey.from_public_bytes(decrypted_payload[:CRYPTO.X25519_SIZE])
            response = file_server.handle_request(decrypted_payload[CRYPTO.X25519_SIZE:])
            encrypted_response = crypto.encrypt(eph_pubkey, response)
            send_tcp(next_ip, next_port, next_header + encrypted_response)
        elif flags == 3:
            req_id = int(next_ip)
            decrypted_payload = crypto.decrypt(active_requests[req_id]['ephprikey'], payload)
            active_requests[req_id]['future'].set_result(decrypted_payload)

async def make_request(name: str, plaintext_payload: bytes):
    """
    Initiate a Shallot protocol request.
    Args:
        name: The user to send the request to.
        plaintext_payload: The payload to send (in plaintext).

    Returns:
        A tuple containing the response payload and the total elapsed time, or None if an error occurs.
    """
    global request_counter
    req_id = request_counter
    request_counter += 1  # increment global request counter

    # generate ephemeral key to receive response
    ephprikey = X25519PrivateKey.generate()

    # create request entry
    active_requests[req_id] = {
        'timestamp': time.perf_counter(),
        'ephprikey': ephprikey,
        'future': asyncio.get_running_loop().create_future()
    }

    # generate Shallot cycle and header
    cycle = crypto.generate_cycle(list_server.cached_list, my_name, name, SHALLOT.CYCLE_LENGTH)
    header = crypto.generate_header(cycle, my_name, name, req_id)

    # add ephemeral public key to request payload so the recipient node can encrypt the response payload
    plaintext_payload = ephprikey.public_key().public_bytes_raw() + plaintext_payload

    # encrypt payload with recipient's public key
    dest_pubkey = base64.b64decode(list_server.cached_list[name]['pubkey'])
    encrypted_payload = crypto.encrypt(dest_pubkey, plaintext_payload)

    send_tcp(cycle[0][1]['ip'], cycle[0][1]['port'], header + encrypted_payload)

    # wait until response is received
    try:
        async with asyncio.timeout(30):
            res = await active_requests[req_id]['future']
    except asyncio.TimeoutError:
        print('request timed out!')
        return None

    elapsed_time = time.perf_counter() - active_requests[req_id]['timestamp']
    del active_requests[req_id]
    return res, elapsed_time

def refresh_job():
    """
    Refresh the list server registration every 10 seconds.

    Returns:
        None
    """
    while not _should_exit.is_set():
        if not list_server.register(my_name, my_port, pubkey.public_bytes_raw()):
            print('Warning: node registration to list server failed!')
        _should_exit.wait(10)

def server_job():
    """
    Run the Shallot server (which mainly passes packets between nodes).

    Returns:
        None
    """
    global _server
    with socketserver.TCPServer(('localhost', my_port), ShallotHandler) as server:
        _server = server
        server.serve_forever()
        print('Shut down server successfully.')

def stop_server():
    """
    Stop the Shallot server and refresh job gracefully.
    Returns:
        None
    """
    global _should_exit
    _should_exit.set()
    _server.shutdown()

def run_server(name: str, port: int) -> bool:
    """
    Initialize and run the server and refresh jobs on separate threads. Also automatically generates a public key to
    be used for this node.
    Args:
        name: Name of the user.
        port: Port number that our local server listens on.

    Returns:
        Whether the threads were spawned successfully.
    """
    global _refresh_thread, _server_thread, pubkey, prikey, my_name, my_port
    my_name, my_port = name, port

    if not list_server.register(name, port, pubkey.public_bytes_raw()):
        print('Error: connection to list server failed!')
        return False

    print('Connected to list server.')
    print(f'Welcome to the Shallot file sharing system, {name}. Your public IP is {list_server.my_public_ip}.')

    _refresh_thread = threading.Thread(target=refresh_job)
    _refresh_thread.start()

    _server_thread = threading.Thread(target=server_job)
    _server_thread.start()

    return True

