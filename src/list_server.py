import base64

import requests
from config import LIST_SERVER

my_public_ip = None
cached_list = None

def register(name: str, port: int, pubkey: bytes):
    """
    Send a register request to the list server. If successful, also sets my_public_ip.
    Args:
        name: Unique identifier for this user.
        port: Port number that this node listens on.
        pubkey: Public key.

    Returns:
        True if registration was successful.
    """
    global my_public_ip
    r = requests.post(f'{LIST_SERVER.ADDRESS}/api/register', data={
        'name': name,
        'port': port,
        'pubkey': base64.b64encode(pubkey)
    })
    if r.text != 'OK':
        return False
    list = list_nodes()
    if name not in list:
        return False
    my_public_ip = list[name]['ip']
    return True

def list_nodes():
    """
    Get a dict of all nodes currently registered in the list server.
    Returns:
        Dict of all nodes, with node names as keys. Each node is a dict with fields ['ip', 'port', 'pubkey'].
    """
    global cached_list
    r = requests.get(f'{LIST_SERVER.ADDRESS}/api/list')
    cached_list = r.json()
    return cached_list
