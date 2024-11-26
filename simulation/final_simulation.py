import base64
from client import Client
from client_server import ClientServer
from ip_functions import ip_str_to_int, ip_int_to_str, generate_random_ip
from list_server import ListServer
from nacl.public import PrivateKey
from nacl.public import SealedBox
import random

    
# List of names
names = ["Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Helen", "Ivy", "Jack"]


# Initalize and register clients to list_server
def create_client_server(name):
    """
    Creates a client server with the specified name.
    
    Args:
        name (str): The name of the client server.
        
    Returns:
        ClientServer: The client server instance.
    """
    ip_address = generate_random_ip()[1]
    port = random.randint(10000, 65535)
    
    return ClientServer(ip_address, port, name)

clients_by_ip = {}

list_server = ListServer()
for name in names:
    client_server = create_client_server(name)
    
    # Create public private key pair
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    client_server.add_keys(
        base64.b64encode(public_key.encode()), 
         base64.b64encode(private_key.encode()))
    
    clients_by_ip[(client_server.ip_address, client_server.port_number)] = client_server
    
    list_server.register(name, client_server.ip_address, client_server.port_number, base64.b64encode(public_key.encode()))


# Client work
cycle = list_server.get_cycle()
text = "This is an example text that should fit in 200 bytes."

client = Client()
encrypted_cycle, request_id, encrypted_message, start = client.create_request(cycle, text)

# Decrypt message by going through cycle foreward

def next(cycle, k):
    return (k + 1) % len(cycle)

# This the simulation of moving between client servers
# We are currently at start and sending message to start + 1
read_flag, end_flag, next_addr, next_port, encrypted_cycle, encrypted_message = 0,0, cycle[next(cycle, start)]['ip'], cycle[next(cycle, start)]['port'], encrypted_cycle, encrypted_message
next_addr = ip_str_to_int(next_addr)
while True:
    next_client_server:ClientServer = clients_by_ip[(ip_int_to_str(next_addr), next_port)]
    read_flag, end_flag, next_addr, next_port, encrypted_cycle, encrypted_message = next_client_server.receive_encryption(encrypted_cycle, encrypted_message)
    
    if read_flag == 1 and end_flag == 1:
        # Now that we have the encrypted message, we can decrypt it with the source_private_key
        response = encrypted_message
        request_id = next_addr        
        private_key = client.request_map[request_id]['private_key']
        sealed_box = SealedBox(PrivateKey(base64.b64decode(private_key)))
        decrypted = sealed_box.decrypt(response)[32:]
        decrypted = base64.b64decode(decrypted.rstrip(b"\x00")).decode('utf-8')
        client.request_map[request_id]['response'] = decrypted
        break

# By end of the code, the client server should parse the request and send it to the request
print(client.request_map[request_id]['response'])