from client_server import ClientServer
from ip_functions import ip_str_to_int, ip_int_to_str, generate_random_ip
from nacl.public import PrivateKey
import random

class ListServer:
    def __init__(self):
        """
        Initializes the ListServer with an empty list to store registered items.
        """
        self.nodes= {}
    
    def register(self, name, ip, port, public_key) -> int:
        """
        Registers a node to the server.
        
        Parameters:
            name (str): The name of the node.
            ip (str): The IP address of the node.
            port (int): The port number of the node.
            public_key (PublicKey): The public key of the node.
        
        Returns:
            int: A status code indicating the success of the registration (200 for success).
        """
        self.nodes[name] = {
            'ip': ip,
            'port': port,
            'public_key': public_key,
        }
        
        return 200

    def list(self):
        """
        Returns the list of all registered items in a random order.
        
        Returns:
            list: A list of all registered items in a random order.
        """
        return self.nodes
    
    def get_cycle(self):
        """
        Returns the list of all registered items in a random order.
        
        Returns:
            list: A list of all registered items in a random order.
        """
        cycle = [self.nodes[node] for node in self.nodes]
        random.shuffle(cycle)
        return cycle
