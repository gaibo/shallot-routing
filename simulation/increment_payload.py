from nacl.public import PrivateKey
from nacl.public import PublicKey
from nacl.public import SealedBox
import random
import socket
import struct
import string
import time

# List of names
for i in range(20):
    names = [str(j) for j in range(0, i)]

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


# Dictionary to store keys
keys = {}
elapsed_times = []
i = 200
while i < 2_000_000_000:
    print(i)
    # Generate keys for each person
    for name in names:
        private_key = PrivateKey.generate()  # Generate a private key
        public_key = private_key.public_key  # Derive the public key from the private key
        ip_int, ip_str = generate_random_ip()  # Generate a random IP address

        # Store the keys in a dictionary
        keys[name] = {
            "private_key": private_key.encode().hex(),
            "public_key": public_key.encode().hex(),
            "ip_address": ip_int,  # Store the IP as an integer
            "ip_address_str": ip_str  # Store the IP as a string for reference
        }
        assert ip_str == ip_int_to_str(ip_int), f"Mismatch: {ip_str} != {ip_int_to_str(ip_int)}"
        assert ip_int == ip_str_to_int(ip_str), f"Mismatch: {ip_int} != {ip_str_to_int(ip_str)}"

    pub_to_person = {keys[name]["public_key"]: keys[name] for name in keys}

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
        text_bytes = text.encode(encoding)
        
        # Ensure the text fits within the array, leaving space for the null terminator
        if len(text_bytes) >= length:
            # Truncate the text to length - 1 and add a null byte at the end
            byte_array = text_bytes[:length - 1] + b"\x00"
        else:
            # Add the text, pad with filler bytes, and ensure the last byte is null
            padding_length = length - len(text_bytes) - 1
            byte_array = text_bytes + (filler_byte * padding_length) + b"\x00"
        
        return byte_array

    # Reorder the names in names list and store as cycle as a deep copy
    start_time = time.time()
    cycle = names.copy()
    random.shuffle(cycle)


    def get_two_random_nums(start, end):
        """Gets two unique random numbers between the specified interval."""

        if end - start < 2:
            raise ValueError("Interval must contain at least two numbers")

        num1 = random.randint(start, end)
        num2 = random.randint(start, end)

        while num1 == num2:
            num2 = random.randint(start, end)

        return num1, num2

    # Example usage
    num1, num2 = get_two_random_nums(0, len(cycle) - 1)

    send_source = cycle[num1]
    send_dest = cycle[num2]
        
    def generate_header(end_flag, read_flag, addr):
        """
        Generates a header for the encrypted cycle.
        
        Args:
            ephemeral_pub_key (str): The ephemeral public key (in hex format).
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
            ">BBI",  # Big-endian format: 32-byte string, 1-byte int, 1-byte int, 4-byte unsigned int
            end_flag,
            read_flag,
            addr
        )

        return header    
        
    def get_header_values(header):
        """
        Extracts values from the generated header.
        
        Args:
            header (bytes): The binary header generated by `generate_header`.
            
        Returns:
            dict: A dictionary containing the extracted values:
                - "end_flag" (int): The end flag.
                - "read_flag" (int): The read flag.
                - "addr" (int): The request ID.
        """
        # Ensure the header length is correct
        expected_length = 1 + 1 + 4  # 1 byte (end_flag) + 1 byte (read_flag) + 4 bytes (addr)
        if len(header) != expected_length:
            raise ValueError(f"Header length is invalid. Expected {expected_length} bytes, got {len(header)} bytes.")
        
        # Unpack the header using the same format as `generate_header`
        unpacked_data = struct.unpack(">BBI", header)
        
        # Extract and format values
        end_flag = unpacked_data[0]  # End flag (1 byte)
        read_flag = unpacked_data[1]  # Read flag (1 byte)
        addr = unpacked_data[2]  # Address (4 bytes)
        
        return end_flag, read_flag, addr

    def prev(cycle, num):
        return (len(cycle) + num - 1) % len(cycle)

    def next(cycle, num):
        return (num + 1) % len(cycle)

    '''
        The goal of this function is to generate the layered encrypted cycle that will be running through the network.
    '''
    def generate_encrypted_cycle(cycle, num1, num2):
        
        #Create source header
        ephemeral_pub_key_bytes = bytes.fromhex(keys[cycle[num1]]['public_key'])
        end_flag = 1
        read_flag = 1
        addr = 12 # Request ID
        header = generate_header(end_flag, read_flag, addr)
        output = header
        
        sealed_box = SealedBox(PublicKey(ephemeral_pub_key_bytes))
        encrypted = sealed_box.encrypt(output)
        output = ephemeral_pub_key_bytes + encrypted
        
        k = prev(cycle, num1)
        while (k != num2):
            ephemeral_pub_key_bytes = bytes.fromhex(keys[cycle[k]]['public_key'])

            end_flag = 0
            read_flag = 0
            addr = keys[cycle[next(cycle, k)]]['ip_address']
            header = generate_header(end_flag, read_flag, addr)

            output = header + output
            sealed_box = SealedBox(PublicKey(ephemeral_pub_key_bytes))
            encrypted = sealed_box.encrypt(output)
            
            
            # Test of encryption can be decrypted
            sealed_box = SealedBox(PrivateKey(bytes.fromhex(pub_to_person[ephemeral_pub_key_bytes.hex()]['private_key'])))
            decrypted = sealed_box.decrypt(encrypted)
            assert output == decrypted, f"Error: {output} != {decrypted}"
            
            temp = output
            output = ephemeral_pub_key_bytes + encrypted

            # Test of decryption can be encrypted after removing 32 bytes public key
            test = output[32:]
            sealed_box = SealedBox(PrivateKey(bytes.fromhex(pub_to_person[output[:32].hex()]['private_key'])))
            decrypted = sealed_box.decrypt(test)
            assert temp == decrypted, f"Error: {temp} != {decrypted}"
            
            k = prev(cycle, k)
        
        assert num2 == k, f"Error: {num2} != {k}"
        
        
        #Create destination header
        ephemeral_pub_key_bytes = bytes.fromhex(keys[cycle[k]]['public_key'])
        
        end_flag = 0
        read_flag = 1
        addr = keys[cycle[next(cycle, k)]]['ip_address']
        
        header = generate_header(end_flag, read_flag, addr)
        output = header + output
        
        sealed_box = SealedBox(PublicKey(ephemeral_pub_key_bytes))
        encrypted = sealed_box.encrypt(output)
        output = ephemeral_pub_key_bytes + encrypted
        
        k = prev(cycle, k)
        while (k != num1):
            ephemeral_pub_key_bytes = bytes.fromhex(keys[cycle[k]]['public_key'])

            end_flag = 0
            read_flag = 0
            addr = keys[cycle[next(cycle, k)]]['ip_address']
            header = generate_header(end_flag, read_flag, addr)

            output = header + output
            sealed_box = SealedBox(PublicKey(ephemeral_pub_key_bytes))
            encrypted = sealed_box.encrypt(output)
            
            output = ephemeral_pub_key_bytes + encrypted
            
            k = prev(cycle, k)
        assert k == num1
        
        return output
        
    encrypted_cycle = generate_encrypted_cycle(cycle, num1, num2)

    # Example usage
    # Generate random text message with limit of variable i in bytes
    text = ''.join(random.choices(string.ascii_letters + string.digits, k=i - 10))

    '''
        The goal of this function is to encrypt the message and return the public key, private key and the encrypted message.
    '''
    def encrypt_message(text_message: str, sender: str, receiver: str):
        source_private_key = PrivateKey.generate()
        source_public_key = source_private_key.public_key
        
        byte_array = bytes.fromhex(source_public_key.encode().hex()) + create_byte_array(text_message, i)
        
        sealed_box = SealedBox(PublicKey(bytes.fromhex(keys[receiver]["public_key"])))
        encrypted = sealed_box.encrypt(byte_array)
        
        return source_public_key, source_private_key, encrypted

    '''
        The goal of this function is to decrypt the request box and return the decrypted message.
    '''
    def parse_request(encrypted_message, private_key):
        sealed_box = SealedBox(private_key)
        decrypted = sealed_box.decrypt(encrypted_message)
        return decrypted


    '''
        The goal of this function is to create a response to the request and return the encrypted response.
    '''
    def create_response(public_key, message):
        text_message = message.rstrip(b'\x00').decode("utf-8")
        #print('Received:', text_message)
        
        response = text_message
        #print('Sending:', response)
        
        byte_array = bytes(bytearray(32) + create_byte_array(response))
        sealed_box = SealedBox(PublicKey(public_key))
        encrypted = sealed_box.encrypt(byte_array)
        return encrypted


    def handle_end_of_cycle(encrypted_message, private_key):
        decrypted = parse_request(encrypted_message, private_key)
        message = decrypted[32:].rstrip(b'\x00').decode("utf-8")
        #print('Received:', message)

    '''
        The goal of this function is to decrypt the encryption layer by later and print the readable information.
    '''
    def decrypt_cycle(encrypted_cycle, encrypted_message):
        #print('Decrypting cycle')
        ephemeral_public_key = encrypted_cycle[:32]
        private_key = pub_to_person[ephemeral_public_key.hex()]['private_key']
        
        encrypted = encrypted_cycle[32:]
        sealed_box = SealedBox(PrivateKey(bytes.fromhex(private_key)))
        decrypted = sealed_box.decrypt(encrypted)
        
        end_flag, read_flag, addr = get_header_values(decrypted[:6])
        
        if read_flag == 1 and end_flag == 1:
            #print(end_flag, read_flag, 'Request id:', addr)
            #print("End of cycle")
            handle_end_of_cycle(encrypted_message, source_private_key)
            return
        elif read_flag == 1:
            #print(end_flag, read_flag, ip_int_to_str(addr))
            #print('Received request')
            
            request = parse_request(encrypted_message, PrivateKey(bytes.fromhex(pub_to_person[ephemeral_public_key.hex()]['private_key'])))
            public_key = request[:32]
            message = request[32:]
            
            response = create_response(public_key, message)
            decrypt_cycle(decrypted[6:], response)
        else:
            #print(end_flag, read_flag, ip_int_to_str(addr))
            decrypt_cycle(decrypted[6:], encrypted_message)
        
        
    source_public_key, source_private_key, encrypted_message = encrypt_message(text, send_source, send_dest)    

    #print('Sending: ', text)
    decrypt_cycle(encrypted_cycle, encrypted_message)
    elapsed_times.append((i, time.time() - start_time))
    i *= 2

# Graph line graph where x = is number of clients y = elapsed time
import matplotlib.pyplot as plt
x = [i for i,j in elapsed_times]
y = [j for i,j in elapsed_times]
plt.plot(x, y)
plt.xlabel('Number of bytes in payload')
plt.ylabel('Elapsed Time')
plt.title('Elapsed Time vs Number of Clients')
plt.show()