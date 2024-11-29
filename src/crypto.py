import base64
import random
import secrets
import socket
import struct
from typing import Final, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey,
    X25519PrivateKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from config import CRYPTO


def pad_payload(payload: bytes, size: int) -> bytes:
    """
    Pads the payload to a specified size.

    The padded payload includes a 4-byte header indicating the actual size of the original payload.
    The remaining bytes are filled with null data.

    Args:
        payload (bytes): The payload to be padded.
        size (int): The total size to pad the payload to.

    Returns:
        bytes: The padded payload.

    Raises:
        ValueError: If the payload exceeds the specified size or if the size is less than 4 bytes.
    """
    if len(payload) > size or size < 4:
        raise ValueError("size too small")
    # '!' stands for network byte ordering
    return struct.pack(f"!I{size - 4}s", len(payload), payload)


def unpad_payload(payload: bytes) -> bytes:
    """
    Removes padding from a payload padded with `pad_payload`.

    Args:
        payload (bytes): The padded payload.

    Returns:
        bytes: The original unpadded payload.

    Raises:
        ValueError: If the payload structure is malformed.
    """
    true_size = struct.unpack_from("!I", payload)[0]
    if 4 + true_size > len(payload):
        raise ValueError("malformed payload")
    return payload[4 : 4 + true_size]


def generate_cycle(
    users: dict[str, dict], orig: str, dest: str, length: int
) -> list[tuple[str, dict]]:
    """
    Generates a Shallot routing cycle.

    The cycle includes an origin node, a destination node, and a specified number of intermediate nodes.
    It ensures that the destination node is not adjacent to the origin node in the cycle.

    Args:
        users (dict): A dictionary of nodes, mapping node names to their metadata (e.g., IP, port, public key).
        orig (str): The origin node's name.
        dest (str): The destination node's name.
        length (int): The total number of nodes in the cycle.

    Returns:
        list[tuple[str, dict]]: A list of nodes in the cycle, each represented as a tuple of name and metadata.

    Raises:
        ValueError: If the cycle length is less than 6 or the number of available nodes is insufficient.
    """
    if length < 6:
        raise ValueError("cycle length must be at least 6")
    if len(users) < length:
        raise ValueError(f"not enough users (must have at least {length})")
    # convert to a list of tuples while excluding the orig and dest
    users_excluding_endpoints = [
        (k, v) for k, v in users.items() if k not in [orig, dest]
    ]
    cycle = random.sample(
        users_excluding_endpoints, length - 2
    )  # does not include orig and dest yet

    # choose where to insert destination (should not be too close to origin)
    dest_loc = random.randint(2, len(cycle) - 2)
    cycle.insert(dest_loc, (dest, users[dest]))
    cycle.append((orig, users[orig]))

    return cycle


_ENCRYPT_HEADER_STRUCT: Final[struct.Struct] = struct.Struct(
    f"!{CRYPTO.X25519_SIZE}s{CRYPTO.NONCE_SIZE}s"
)


def encrypt(pubkey: bytes, data: bytes) -> bytes:
    """
    Encrypts data using X25519 key exchange and ChaCha20 symmetric encryption.

    A shared secret is derived using an ephemeral private key and the provided public key.
    The data is then encrypted using the derived shared secret.

    Args:
        pubkey (bytes): The recipient's public X25519 key in raw bytes.
        data (bytes): The plaintext data to encrypt.

    Returns:
        bytes: The encrypted data, including the ephemeral public key and nonce.
    """
    pubkey = X25519PublicKey.from_public_bytes(pubkey)

    # generate ephemeral key for key exchange
    ephprikey = X25519PrivateKey.generate()
    shared_key = ephprikey.exchange(pubkey)
    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=CRYPTO.KEY_SIZE, salt=None, info=b"shallot"
    ).derive(shared_key)

    # use derived key to encrypt data
    nonce = secrets.token_bytes(CRYPTO.NONCE_SIZE)
    cipher = Cipher(algorithms.ChaCha20(derived_key, nonce), mode=None)
    encryptor = cipher.encryptor()
    return (
        ephprikey.public_key().public_bytes_raw()
        + nonce
        + encryptor.update(data)
        + encryptor.finalize()
    )


def decrypt(prikey: bytes, data: bytes) -> bytes:
    """
    Decrypts data using X25519 key exchange and ChaCha20 symmetric encryption.

    A shared secret is derived using the provided private key and the ephemeral public key included in the data.
    The encrypted payload is then decrypted using the derived shared secret.

    Args:
        prikey (bytes): The recipient's private X25519 key in raw bytes.
        data (bytes): The encrypted data, including the ephemeral public key and nonce.

    Returns:
        bytes: The decrypted plaintext data.
    """
    prikey = X25519PrivateKey.from_private_bytes(prikey)

    # unpack ephemeral key and nonce and use them to derive shared key
    ephpubkey, nonce = _ENCRYPT_HEADER_STRUCT.unpack_from(data)
    shared_key = prikey.exchange(X25519PublicKey.from_public_bytes(ephpubkey))
    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=CRYPTO.KEY_SIZE, salt=None, info=b"shallot"
    ).derive(shared_key)

    cipher = Cipher(algorithms.ChaCha20(derived_key, nonce), mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(data[_ENCRYPT_HEADER_STRUCT.size :]) + decryptor.finalize()


_HEADER_STRUCT: Final[struct.Struct] = struct.Struct("!B4sI")


def _generate_header_entry(flags: int, ip: bytes, port: int) -> bytes:
    """
    Generates a single unencrypted Shallot header entry.

    Args:
        flags (int): Shallot flags (0 for intermediate, 2 for destination, 3 for origin).
        ip (bytes): IP address in raw bytes.
        port (int): Port number.

    Returns:
        bytes: The header entry in byte format.
    """
    return _HEADER_STRUCT.pack(flags, ip, port)


def get_header_size(cycle_length: int) -> int:
    """
    Computes the size of a Shallot header.

    Args:
        cycle_length (int): The number of nodes in the cycle.

    Returns:
        int: The size of the header in bytes.
    """
    return (_HEADER_STRUCT.size + _ENCRYPT_HEADER_STRUCT.size) * cycle_length


def generate_header(
    cycle: list[tuple[str, dict]], orig: str, dest: str, req_id: int
) -> bytes:
    """
    Generates a Shallot header with encrypted routing information.

    Args:
        cycle (list[tuple[str, dict]]): The Shallot cycle of nodes.
        orig (str): The origin node's name.
        dest (str): The destination node's name.
        req_id (int): The request ID for the origin node.

    Returns:
        bytes: The encrypted Shallot header.
    """
    header = b""
    # address field is request ID for last entry (see diagram in proposal document)
    address = struct.pack("!I", req_id)
    port = 0
    for n, u in reversed(cycle):
        # READ & END flags
        flags = 3 if n == orig else 2 if n == dest else 0
        entry = _generate_header_entry(flags, address, port)
        header = encrypt(base64.b64decode(u["pubkey"]), entry + header)
        # each header entry contains the *next* node's IP and port
        address = socket.inet_aton(u["ip"])
        port = u["port"]

    return header


def decode_header(
    header: bytes, prikey: bytes
) -> tuple[int, Union[int, str], int, bytes]:
    """
    Decodes and processes a Shallot header at a node.

    Args:
        header (bytes): The encrypted header to decode.
        prikey (bytes): The node's private X25519 key for decryption.

    Returns:
        tuple: A tuple containing:
            - flags (int): The Shallot flags.
            - ip (Union[int, str]): The IP address or request ID.
            - port (int): The port number.
            - next_header (bytes): The header for the next node in the cycle.
    """
    decrypted = decrypt(prikey, header)
    flags, raw_ip, port = _HEADER_STRUCT.unpack_from(decrypted)

    # pad length of the remainder of the header to be same as before
    decrypted = decrypted[_HEADER_STRUCT.size :]
    padding = secrets.token_bytes(len(header) - len(decrypted))
    next_header = decrypted + padding

    # handle origin separately (request id instead of ip)
    ip = struct.unpack("!I", raw_ip)[0] if flags == 3 else socket.inet_ntoa(raw_ip)
    return flags, ip, port, next_header
