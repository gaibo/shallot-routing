import random
import struct


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

