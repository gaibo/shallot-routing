import base64
import random
import secrets
import socket
import struct
from typing import Final, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from config import CRYPTO


def pad_payload(payload: bytes, size: int) -> bytes:
    """
    Pad the payload to be at least as large as size.
    The returned payload begins with a header (unsigned int) that indicates the actual size,
    so it has the length (4 + size).
    Args:
        payload: The payload to be padded.
        size: The size to pad.

    Returns:
        The padded payload.
    Raises:
        ValueError: If the payload is larger than size.
    """
    if len(payload) > size:
        raise ValueError("payload too large")
    # '!' stands for network byte ordering
    return struct.pack(f'!I{size}s', len(payload), payload)

def unpad_payload(payload: bytes) -> bytes:
    """
    Unpad a payload that was padded with the pad_payload function.
    Args:
        payload: The payload to be unpadded.

    Returns:
        The unpadded payload.
    """
    size = struct.unpack_from('!I', payload)[0]
    if 4 + size > len(payload):
        raise ValueError("malformed payload")
    return payload[4:4+size]

def generate_cycle(users: dict[str, dict], orig: str, dest: str, length: int) -> list[tuple[str, dict]]:
    """
    Generate a cycle that starts from orig, passes through dest, and returns back to orig.
    Args:
        users: Dict mapping names to users (returned from list_server.list_nodes()).
        orig: Origin name.
        dest: Destination name.
        length: Length of the cycle.

    Returns:
        A list of tuples in the cycle.
    """
    if length < 6:
        raise ValueError("cycle length must be at least 6")
    # convert to a list of tuples while excluding the orig and dest
    users_excluding_endpoints = [(k, v) for k, v in users.items() if k not in [orig, dest]]
    cycle = random.sample(users_excluding_endpoints, length - 2) # does not include orig and dest yet

    # choose where to insert destination (should not be too close to origin)
    dest_loc = random.randint(2, len(cycle) - 2)
    cycle.insert(dest_loc, (dest, users[dest]))
    cycle.append((orig, users[orig]))

    return cycle

ENCRYPT_HEADER_STRUCT: Final[struct.Struct] = struct.Struct(f'!{CRYPTO.X25519_SIZE}s{CRYPTO.NONCE_SIZE}s')

def encrypt(pubkey: bytes, data: bytes) -> bytes:
    """
    Encrypt data with X25519 key exchange and ChaCha20 symmetric encryption.
    The data can only be decrypted if the private key associated with pubkey is available.
    Args:
        pubkey: Public X25519 key as raw bytes.
        data: Data to encrypt.

    Returns:
        Encrypted data.
    """
    pubkey = X25519PublicKey.from_public_bytes(pubkey)

    # generate ephemeral key for key exchange
    ephprikey = X25519PrivateKey.generate()
    shared_key = ephprikey.exchange(pubkey)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=CRYPTO.KEY_SIZE, salt=None, info=b'shallot').derive(shared_key)

    # use derived key to encrypt data
    nonce = secrets.token_bytes(CRYPTO.NONCE_SIZE)
    cipher = Cipher(algorithms.ChaCha20(derived_key, nonce), mode=None)
    encryptor = cipher.encryptor()
    return ephprikey.public_key().public_bytes_raw() + nonce + encryptor.update(data) + encryptor.finalize()

def decrypt(prikey: bytes, data: bytes) -> bytes:
    """
    Decrypt data with X25519 key exchange and ChaCha20 symmetric encryption.
    Args:
        prikey: Private X25519 key as raw bytes.
        data:  Data to decrypt.

    Returns:
        Decrypted data.
    """
    prikey = X25519PrivateKey.from_private_bytes(prikey)

    # unpack ephemeral key and nonce and use them to derive shared key
    ephpubkey, nonce = ENCRYPT_HEADER_STRUCT.unpack_from(data)
    shared_key = prikey.exchange(X25519PublicKey.from_public_bytes(ephpubkey))
    derived_key = HKDF(algorithm=hashes.SHA256(), length=CRYPTO.KEY_SIZE, salt=None, info=b'shallot').derive(shared_key)

    cipher = Cipher(algorithms.ChaCha20(derived_key, nonce), mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(data[ENCRYPT_HEADER_STRUCT.size:]) + decryptor.finalize()

HEADER_STRUCT: Final[struct.Struct] = struct.Struct('!B4sI')

def generate_header_entry(flags: int, ip: bytes, port: int) -> bytes:
    """
    Generate a single header entry, excluding encryption-related metadata such as ephemeral keys.
    Args:
        flags: Shallot flags (0 for intermediate, 2 for destination, 3 for origin node).
        ip: IP address as raw bytes.
        port: Port number.

    Returns:
        Single header entry in byte form (unencrypted).
    """
    return HEADER_STRUCT.pack(flags, ip, port)

def generate_header(cycle: list[tuple[str, dict]], orig: str, dest: str, req_id: int) -> bytes:
    """
    Generate a Shallot header.
    Args:
        cycle: Shallot cycle.
        orig: Originating node.
        dest: Destination node.
        req_id: Request ID.

    Returns:
        Shallot header.
    """
    header = b''
    # address field is request ID for last entry (see diagram in proposal document)
    address = struct.pack('!I', req_id)
    port = 0
    for (n, u) in reversed(cycle):
        # READ & END flags
        flags = 3 if n == orig else 2 if n == dest else 0
        entry = generate_header_entry(flags, address, port)
        header = encrypt(base64.b64decode(u['pubkey']), entry + header)
        # each header entry contains the *next* node's IP and port
        address = socket.inet_aton(u['ip'])
        port = u['port']

    return header

def decode_header(header: bytes, prikey: bytes) -> tuple[int, Union[int, str], int, bytes]:
    """
    Decode Shallot header and derive the header to be passed on to the next node, padded appropriately.
    Args:
        header: Header to decode.
        prikey: Private key used to decode the header.

    Returns:
        A tuple (flags, ip, port, next_header). The first three elements are the fields in the header,
        and next_header is the header to be passed on to the next node. It is padded so the length does not change.
    """
    decrypted = decrypt(prikey, header)
    flags, raw_ip, port = HEADER_STRUCT.unpack_from(decrypted)

    # pad length of the remainder of the header to be same as before
    decrypted = decrypted[HEADER_STRUCT.size:]
    padding = secrets.token_bytes(len(header) - len(decrypted))
    next_header = decrypted + padding

    # handle origin separately (request id instead of ip)
    ip = struct.unpack('!I', raw_ip)[0] if flags == 3 else socket.inet_ntoa(raw_ip)
    return flags, ip, port, next_header
