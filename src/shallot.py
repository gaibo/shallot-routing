import asyncio
import base64
import time
import socketserver
import socket
import threading
from typing import Union
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey,
    X25519PrivateKey,
)

import crypto
import list_server
from config import SHALLOT, CRYPTO, cc

import file_server

import json

_should_exit = threading.Event()

my_name = ""
my_port = 0
# note: public ip address is available at list_server.my_public_ip

request_counter = 0
active_requests = {}

prikey = X25519PrivateKey.generate()
pubkey = prikey.public_key()

DIAG_MODE = True    # Set True for comprehensive print statements

import socket


def diagccprint(str_to_print, highlight=False, style='grey50', **cc_kwargs):
    if DIAG_MODE:
        cc.print(str_to_print, highlight=highlight, style=style, **cc_kwargs)


def prettydict(dict_to_print: dict) -> str:
    # Convert a dictionary into pretty-print string
    my_dict_str = json.dumps(dict_to_print, sort_keys=False, indent=4, default=str)
    return my_dict_str


def send_tcp(ip: str, port: int, data: bytes) -> None:
    """
    Send data to a specified IP and port using a TCP connection.

    This function establishes a TCP connection to the provided (IP, port) pair, sends the given data,
    and then closes the connection. If the provided IP matches the public IP of the node, it redirects
    the request to 'localhost'.

    Args:
        ip (str): The IP address of the target node.
        port (int): The port number of the target node.
        data (bytes): The data to send over the TCP connection.

    Returns:
        None

    Notes:
        The function suppresses detailed connection errors to maintain anonymity.
        Instead, it provides generic error messages to avoid leaking identifiable information.
    """
    # Redirect to localhost if the target IP matches the public IP
    if ip == list_server.my_public_ip:
        ip = "localhost"

    # Create and manage a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            # Attempt to connect to the target IP and port
            # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # sock.bind((ip, my_port))    # Apparently can't do this because the designated port is used for our server
            # Note that we must send out of a localhost ephemeral port - our designated port is used by our server
            # This makes tracking who sent to us and who we sent to way more difficult! Can't just check the list server
            sock.connect((ip, port))
            sock.sendall(data)  # Send the entire data
        except (socket.gaierror, socket.timeout, ConnectionRefusedError):
            cc.print(f"[red]Failed to send data due to a connection issue.")
        except Exception:
            cc.print(f"[red]An unexpected error occurred while sending data.")


class ShallotHandler(socketserver.BaseRequestHandler):
    """
    Handler for incoming Shallot protocol connections.

    This handler processes incoming connections based on Shallot protocol flags:
    - If `flags == 0`, the node is an intermediate relay and forwards the request.
    - If `flags == 2`, the node is the recipient and processes the payload.
    - If `flags == 3`, the node is the originator and processes the response.

    Steps:
    1. Receive data over the socket until the connection is closed.
    2. Split the data into the header and payload using `crypto.get_header_size`.
    3. Decode the header using `crypto.decode_header`.
    4. Process the request based on the flags:
       - Forward the request (flags == 0).
       - Process the payload and return a response (flags == 2).
       - Handle the response to complete the request (flags == 3).

    Attributes:
        request (socket.socket): The socket representing the incoming connection.
    """

    def handle(self):
        try:
            # Receive the full data from the socket
            recv_socket: socket.socket = self.request
            data = self._receive_data(recv_socket)

            # Split into header and payload
            header_size = crypto.get_header_size(SHALLOT.CYCLE_LENGTH)
            header, payload = data[:header_size], data[header_size:]

            # Decode the header to extract routing information
            flags, next_ip, next_port, next_header = crypto.decode_header(
                header, prikey.private_bytes_raw()
            )

            # Process the request based on the flags
            if flags == 0:
                self._handle_intermediate(next_ip, next_port, next_header, payload)
            elif flags == 2:
                self._handle_recipient(next_ip, next_port, next_header, payload)
            elif flags == 3:
                self._handle_originator(next_ip, payload)
            else:
                raise ValueError(f"Unknown flag value: {flags}")

        except Exception as e:
            # e being a number like 3288128678 may indicate trying to read from your own send socket
            cc.print(f"[red]Error in ShallotHandler: {e}")

    def _receive_data(self, recv_socket: socket.socket) -> bytes:
        """
        Receives data from the socket until the connection is closed.

        Args:
            recv_socket (socket.socket): The socket to receive data from.

        Returns:
            bytes: The complete data received.
        """
        data = b""
        while True:
            partial = recv_socket.recv(1024*1024)
            if not partial:
                break
            data += partial
        return data

    def get_name_from_list_server(ip, port):
        # print(ip, port)
        found_name = None
        for name in list_server.cached_list.keys():
            # print(list_server.cached_list[name]['ip'], list_server.cached_list[name]['port'])
            if (list_server.cached_list[name]['ip'] == ip 
                and list_server.cached_list[name]['port'] == port):
                found_name = name
                break
        return found_name   # None if not found

    def _handle_intermediate(
        self, next_ip: str, next_port: int, next_header: bytes, payload: bytes
    ) -> None:
        """
        Handles forwarding of the request to the next node.

        Args:
            next_ip (str): The IP address of the next node.
            next_port (int): The port number of the next node.
            next_header (bytes): The next header for the forwarded request.
            payload (bytes): The unmodified payload.
        """
        prev_ip, prev_port = self.client_address
        prev_name = ShallotHandler.get_name_from_list_server(prev_ip, prev_port)
        # assert prev_name, "We should be receiving from one of the other nodes known by the list server"
        if not prev_name:
            # May not be able to get this from list server if prev is also localhost, using ephemeral port!
            prev_name = "AMBIG_LOCALHOST_EPHEM_PORT"
        diagccprint(f"ShallotHandler: handle_intermediate():\n"
                    f"  Received Shallot message from: '{prev_name}' ({prev_ip}, {prev_port})")
        
        send_tcp(next_ip, next_port, next_header + payload)

        next_name = ShallotHandler.get_name_from_list_server(next_ip, next_port)
        # assert next_name, "We should be sending to one of the other nodes known by the list server"
        if next_name is None:
            diagccprint("WARNING: Node name NOT found on list server, but we were able to send to it "
                        "which means it is operational. List server was too slow to update!")
        diagccprint(f"ShallotHandler: handle_intermediate():\n"
                    f"  Sent Shallot message to: '{next_name}' ({next_ip}, {next_port})")
        diagccprint(f"SUCCESS: '{prev_name}' ({prev_ip}, {prev_port}) "
                    f"-> US (INTERMEDIATE) "
                    f"-> '{next_name}' ({next_ip}, {next_port})")

    def _handle_recipient(
        self, next_ip: str, next_port: int, next_header: bytes, payload: bytes
    ) -> None:
        """
        Handles processing of the payload for the recipient node.

        Args:
            next_ip (str): The IP address of the next node.
            next_port (int): The port number of the next node.
            next_header (bytes): The next header for the response.
            payload (bytes): The encrypted payload.
        """
        # Decrypt the payload using the recipient's private key
        decrypted_payload = crypto.decrypt(prikey.private_bytes_raw(), payload)
        eph_pubkey = decrypted_payload[: CRYPTO.X25519_SIZE]

        # Process the request and generate a response
        diagccprint("ShallotHandler: handle_recipient(): Handling request...")
        response = file_server.handle_request(decrypted_payload[CRYPTO.X25519_SIZE :])

        # Encrypt the response using the ephemeral public key
        encrypted_response = crypto.encrypt(eph_pubkey, response)

        # Forward the response to the next node
        send_tcp(next_ip, next_port, next_header + encrypted_response)

        prev_ip, prev_port = self.client_address
        prev_name = ShallotHandler.get_name_from_list_server(prev_ip, prev_port)
        # assert prev_name, "We should be receiving from one of the other nodes known by the list server"
        if not prev_name:
            # May not be able to get this from list server if prev is also localhost, using ephemeral port!
            prev_name = "AMBIG_LOCALHOST_EPHEM_PORT"
        next_name = ShallotHandler.get_name_from_list_server(next_ip, next_port)
        if next_name is None:
            diagccprint("WARNING: Node name NOT found on list server, but we were able to send to it "
                        "which means it is operational. List server was too slow to update!")
        diagccprint(f"SUCCESS: '{prev_name}' ({prev_ip}, {prev_port}) "
                    f"-> US (RECIPIENT) "
                    f"-> '{next_name}' ({next_ip}, {next_port})")

    def _handle_originator(self, next_ip: Union[int, str], payload: bytes) -> None:
        """
        Handles the response for the originator node.

        Args:
            next_ip (Union[int, str]): The request ID encoded as the IP field.
            payload (bytes): The encrypted payload containing the response.
        """
        prev_ip, prev_port = self.client_address
        prev_name = ShallotHandler.get_name_from_list_server(prev_ip, prev_port)
        # assert prev_name, "We should be receiving from one of the other nodes known by the list server"
        if not prev_name:
            # May not be able to get this from list server if prev is also localhost, using ephemeral port!
            prev_name = "AMBIG_LOCALHOST_EPHEM_PORT"
        diagccprint(f"SUCCESS: '{prev_name}' ({prev_ip}, {prev_port}) -> US (ORIGINATOR)")

        req_id = int(next_ip)
        decrypted_payload = crypto.decrypt(
            active_requests[req_id]["ephprikey"].private_bytes_raw(), payload
        )

        # Complete the request by setting the result of the associated future
        diagccprint(f"ShallotHandler: handle_originator(): req_id {req_id}: 'active_requests' table:\n{prettydict(active_requests)}")
        active_requests[req_id]["future"].set_result(decrypted_payload)
        diagccprint(f"ShallotHandler: handle_originator(): req_id {req_id}: Set 'future' result in 'active_requests' table:\n{prettydict(active_requests)}")


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
    request_counter += 1    # Increment global request counter; our req_id is now unconnected

    # generate ephemeral key to receive response
    ephprikey = X25519PrivateKey.generate()

    # generate Shallot cycle and header
    cycle = crypto.generate_cycle(
        list_server.cached_list, my_name, name, SHALLOT.CYCLE_LENGTH
    )
    diagccprint(f"make_request(): Targeting user '{name}', Shallot cycle generated:\n{[n for n, _ in cycle]}")
    header = crypto.generate_header(cycle, my_name, name, req_id)

    # add ephemeral public key to request payload so the recipient node can encrypt the response payload
    plaintext_payload = ephprikey.public_key().public_bytes_raw() + plaintext_payload

    # encrypt payload with recipient's public key
    dest_pubkey = base64.b64decode(list_server.cached_list[name]["pubkey"])
    encrypted_payload = crypto.encrypt(dest_pubkey, plaintext_payload)

    # create request entry
    future = asyncio.get_running_loop().create_future()     # Future will be asynchronously filled with result
    active_requests[req_id] = {
        "timestamp": time.perf_counter(),
        "ephprikey": ephprikey,
        "future": future,
    }
    diagccprint(f"make_request(): req_id {req_id}: Added to 'active_requests' table:\n{prettydict(active_requests)}")

    send_tcp(cycle[0][1]["ip"], cycle[0][1]["port"], header + encrypted_payload)

    # Wait until response is received (or timeout is enforced!)
    # We'll try an exponentially growing wait time to work for quick "list" and slow "send"/"receive"
    SHALLOT_INITIAL_WAIT = 0.001    # Found empirically
    SHALLOT_WAIT_DOUBLE_LIMIT = 10  # 0.001 * 2**15 = half a minute
    timeout_wait = SHALLOT_INITIAL_WAIT
    double_counter = 0
    while not future.done():
        diagccprint(f"make_request(): req_id {req_id}: Waiting for response {timeout_wait:.3f}s")
        await asyncio.sleep(timeout_wait)  # time.sleep(1)
        timeout_wait *= 2
        double_counter += 1
        if double_counter > SHALLOT_WAIT_DOUBLE_LIMIT:
            break   # Timeout enforced
    
    # Try to extract the response
    try:
        res = future.result()
        diagccprint(f"make_request(): req_id {req_id}: Got response!")
    except asyncio.InvalidStateError:
        cc.print("[red]Request Timed Out!")
        res = None  # NOTE: We still return a None and elapsed time; caller of make_request() will deal with that...

    # Clean up and return regardless of whether a response arrived before timeout
    elapsed_time = time.perf_counter() - active_requests[req_id]["timestamp"]
    del active_requests[req_id]
    diagccprint(f"make_request(): req_id {req_id}: Deleted from 'active_requests' table:\n{prettydict(active_requests)}")
    return res, elapsed_time


def refresh_job():
    """
    Refresh the list server registration every 10 seconds.

    Returns:
        None
    """
    while not _should_exit.is_set():
        if not list_server.register(my_name, my_port, pubkey.public_bytes_raw()):
            cc.print("[red]Warning: node registration to list server failed!")
        _should_exit.wait(10)


def server_job():
    """
    Run the Shallot server (which mainly passes packets between nodes).

    Returns:
        None
    """
    global _server
    with socketserver.TCPServer(("localhost", my_port), ShallotHandler) as server:
        _server = server
        server.serve_forever()
        cc.print("[green]Shut down server successfully.")


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

    cached_list = list_server.list_nodes()
    if name in cached_list.keys():
        cc.print(f"[red]Failed: Username '{name}' is not unique, according to list server! "
                 f"Choose something else or wait for this name to become available.")
        import sys
        sys.exit(1)
    
    if not list_server.register(name, port, pubkey.public_bytes_raw()):
        cc.print("[red]Error: connection to list server failed!")
        return False

    cc.print("[magenta]Connected to Shallot Server.")
    cc.print(
        f"[magenta]Welcome to the Shallot File Sharing System, '{name}'. Your public IP is {list_server.my_public_ip}."
    )   # NOTE: This is specific to file_server application - we should eventually separate shallot backbone from app

    _refresh_thread = threading.Thread(target=refresh_job)
    _refresh_thread.start()

    _server_thread = threading.Thread(target=server_job)
    _server_thread.start()

    return True
