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
