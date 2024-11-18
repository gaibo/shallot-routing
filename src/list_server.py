import base64

import requests
from config import LIST_SERVER

def register(name: str, port: int, pubkey: bytes):
    """
    Send a register request to the list server.
    Args:
        name: Unique identifier for this user.
        port: Port number that this node listens on.
        pubkey: Public key.

    Returns:
        True if registration was successful.
    """
    r = requests.post(f'{LIST_SERVER.ADDRESS}/api/register', data={
        'name': name,
        'port': port,
        'pubkey': base64.b64encode(pubkey)
    })
    return r.text == 'OK'

def list_nodes():
    """
    Get a dict of all nodes currently registered in the list server.
    Returns:
        Dict of all nodes, with node names as keys. Each node is a dict with fields ['ip', 'port', 'pubkey'].
    """
    r = requests.get(f'{LIST_SERVER.ADDRESS}/api/list')
    return r.json()
