import socket
import struct
import random

def ip_str_to_int(ip_str):
    # Convert the IP address string to a packed binary format and then unpack it to an integer
    ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
    return ip_int

# Convert IP address integer back to string
def ip_int_to_str(ip_int):
    # Convert the integer back to a packed binary format and then to a string
    ip_str = socket.inet_ntoa(struct.pack("!I", ip_int))
    return ip_str

# Function to generate a random IP address and convert it to an integer
def generate_random_ip():
    # Generate a random IP address as a string (e.g., '192.168.1.1')
    ip_parts = [random.randint(0, 255) for _ in range(4)]
    ip_str = ".".join(map(str, ip_parts))
    
    # Convert the IP address string into an integer
    ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
    
    return ip_int, ip_str