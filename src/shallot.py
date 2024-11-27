import socketserver
import threading

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey

import list_server

_should_exit = threading.Event()

class ShallotHandler(socketserver.BaseRequestHandler):
    """
    Handler for incoming Shallot protocol connections.
    """
    def handle(self):
        pass

def refresh_job(name: str, port: int, pubkey: bytes):
    """
    Refresh the list server registration every 10 seconds.
    Args:
        name: Name of the user.
        port: Port number that our local server listens on.
        pubkey: Our public key.

    Returns:
        None
    """
    while not _should_exit.is_set():
        if not list_server.register(name, port, pubkey):
            print('Warning: node registration to list server failed!')
        _should_exit.wait(10)

def server_job(name: str, port: int, pubkey: bytes):
    """
    Run the Shallot server (which mainly passes packets between nodes).
    Args:
        name: Name of the user.
        port: Port number that our local server listens on.
        pubkey: Our public key.

    Returns:
        None
    """
    global _server
    with socketserver.TCPServer(('localhost', port), ShallotHandler) as server:
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
    global _refresh_thread, _server_thread
    prikey = X25519PrivateKey.generate()
    pubkey = prikey.public_key()
    pubkey_bytes = pubkey.public_bytes_raw()

    if not list_server.register(name, port, pubkey_bytes):
        print('Error: connection to list server failed!')
        return False

    print('Connected to list server.')
    print(f'Welcome to the Shallot file sharing system, {name}. Your public IP is {list_server.my_public_ip}.')

    _refresh_thread = threading.Thread(target=refresh_job, args=(name, port, pubkey_bytes))
    _refresh_thread.start()

    _server_thread = threading.Thread(target=server_job, args=(name, port, pubkey_bytes))
    _server_thread.start()

    return True

