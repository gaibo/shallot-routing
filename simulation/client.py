import base64
from ip_functions import ip_str_to_int
from nacl.public import SealedBox
from nacl.public import PublicKey
from nacl.public import PrivateKey
import random
import struct


def get_start_and_end(l_bound, r_bound):
    """Obtains start and end of cycle"""

    if r_bound - l_bound < 2:
        raise ValueError("Interval must contain at least two numbers")

    start = random.randint(l_bound, r_bound)
    end = random.randint(l_bound, r_bound)

    while start == end:
        end = random.randint(l_bound, r_bound)

    return start, end


def create_byte_array(text, length=200, encoding="utf-8", filler_byte=b"\x00"):
    """
    Creates a byte array of a specific length, ensuring the input text fits within it,
    and the last byte is always null (`\x00`).
    - text: The string to include in the byte array.
    - length: The desired total length of the byte array (default is 200 bytes).
    - encoding: The text encoding to use (default is 'utf-8').
    - filler_byte: The byte to use for padding (default is null byte `b"\x00"`).
    """
    # Ensure the array length is at least 1 (to accommodate the null byte)
    if length < 1:
        raise ValueError("Length must be at least 1 to include a null terminator.")
    
    # Convert the text to bytes
    text_bytes = base64.b64encode(bytes(text, 'utf-8'))
    
    # Ensure the text fits within the array, leaving space for the null terminator
    if len(text_bytes) >= length:
        # Truncate the text to length - 1 and add a null byte at the end
        byte_array = text_bytes[:length - 1] + b"\x00"
    else:
        # Add the text, pad with filler bytes, and ensure the last byte is null
        padding_length = length - len(text_bytes) - 1
        byte_array = text_bytes + (filler_byte * padding_length) + b"\x00"
    
    return byte_array


def generate_header(end_flag, read_flag, addr, port):
    """
    Generates a header for the encrypted cycle.
    
    Args:
        end_flag (int): A flag indicating the end of the cycle (1 or 0).
        read_flag (int): A flag indicating whether the cycle is in read mode (1 or 0).
        addr (int): The request ID or address.
        
    Returns:
        bytes: The generated header as a byte array.
    """
    # Ensure flags are 1 or 0
    if end_flag not in (0, 1) or read_flag not in (0, 1):
        raise ValueError("Flags must be 0 or 1.")

    # Pack the data into a binary header
    # Format:
    # - 1 byte: end flag
    # - 1 byte: read flag
    # - 4 bytes: addr (unsigned integer)
    header = struct.pack(
        ">BBII",  # Big-endian format: 32-byte string, 1-byte int, 1-byte int, 4-byte unsigned int, 4-byte unsigned int
        end_flag,
        read_flag,
        addr,
        port
    )

    return header   

def prev(cycle, num):
    return (len(cycle) + num - 1) % len(cycle)

def next(cycle, num):
    return (num + 1) % len(cycle)


class Client:
    def __init__(self):
        """
        Initializes a Client instance.
        
        Parameters:
        """
        self.request_map = {}
        
    def create_request(self, cycle, text):
        start, end = get_start_and_end(0, len(cycle) - 1)
        request_id = random.randint(0, 200)
        encrypted_cycle = self.create_encrypted_cycle(cycle, start, end, request_id)
        _, source_private_key, encrypted_message = self.generate_encrypted_message(text, end, cycle)
        
        self.request_map[request_id] = {
            'request_id': request_id,
            'request': text,
            'private_key': base64.b64encode(source_private_key.encode()),
            'response': None,
        }
        
        return encrypted_cycle, request_id, encrypted_message, start
    
    def create_encrypted_cycle(self, cycle, start, end, request_id):
        """
        Creates a cycle by iterating from the start to the end using the specified cycle logic.
        
        Parameters:
            cycle (list): Lists full cycle.
            start (int): The starting value.
            end (int): The ending value (exclusive).
            request_id (int): The request ID.
        
        Returns:
            encrypted_list: The encrypted cycle.
        """
        
        #Create source header
        current_node = cycle[start]     
        ephemeral_pub_key_bytes = base64.b64decode(current_node['public_key'])
        end_flag = 1
        read_flag = 1
        next_addr = request_id # Request ID
        next_port = 0
        header = generate_header(end_flag, read_flag, next_addr, next_port)
        output = header
        
        sealed_box = SealedBox(PublicKey(ephemeral_pub_key_bytes))
        encrypted = sealed_box.encrypt(output)
        output = ephemeral_pub_key_bytes + encrypted
        
        k = prev(cycle, start)
        
        while (k != end):
            current_node = cycle[k]
            ephemeral_pub_key_bytes = base64.b64decode(current_node['public_key'])

            end_flag = 0
            read_flag = 0
            next_addr = ip_str_to_int(cycle[next(cycle, k)]['ip'])
            next_port = cycle[next(cycle, k)]['port']
            header = generate_header(end_flag, read_flag, next_addr, next_port)

            output = header + output
            sealed_box = SealedBox(PublicKey(ephemeral_pub_key_bytes))
            encrypted = sealed_box.encrypt(output)
            
            output = ephemeral_pub_key_bytes + encrypted
            
            k = prev(cycle, k)
        
        assert end == k, f"Error: {end} != {k}"

        #Create destination header
        current_node = cycle[k]
        ephemeral_pub_key_bytes = base64.b64decode(current_node['public_key'])
        
        end_flag = 0
        read_flag = 1
        next_addr = ip_str_to_int(cycle[next(cycle, k)]['ip'])
        next_port = cycle[next(cycle, k)]['port']
        
        header = generate_header(end_flag, read_flag, next_addr, next_port)
        output = header + output
        
        sealed_box = SealedBox(PublicKey(ephemeral_pub_key_bytes))
        encrypted = sealed_box.encrypt(output)
        output = ephemeral_pub_key_bytes + encrypted
        
        k = prev(cycle, k)
        while (k != start):
            current_node = cycle[k]
            ephemeral_pub_key_bytes = base64.b64decode(current_node['public_key'])

            end_flag = 0
            read_flag = 0
            next_addr = ip_str_to_int(cycle[next(cycle, k)]['ip'])
            next_port = cycle[next(cycle, k)]['port']
            header = generate_header(end_flag, read_flag, next_addr, next_port)

            output = header + output
            sealed_box = SealedBox(PublicKey(ephemeral_pub_key_bytes))
            encrypted = sealed_box.encrypt(output)
            
            output = ephemeral_pub_key_bytes + encrypted
            
            k = prev(cycle, k)
        assert k == start, f"Error: {k} != {start}"
            
        return output
    
    def generate_encrypted_message(self, text_message: str, receiver: int, cycle: list):
        source_private_key = PrivateKey.generate()
        source_public_key = source_private_key.public_key
        byte_array = source_public_key.encode() + create_byte_array(text_message)
        assert text_message == base64.b64decode(byte_array[32:]).decode('utf-8'), f"Error: {text_message} != {base64.b64decode(byte_array[32:]).decode('utf-8')}"
        
        sealed_box = SealedBox(PublicKey(base64.b64decode(cycle[receiver]['public_key'])))
        encrypted = sealed_box.encrypt(byte_array)
        
        return source_public_key, source_private_key, encrypted
        
        
        
        