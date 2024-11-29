from django.db import models

class Node(models.Model):
    """
    Model representing a node participating in the Shallot network (a user).

    Attributes:
        name (str): A *unique* name.
        ip (str): The IP address of the node.
        port (int): The port number of the node.
        pubkey (str): The public key of the node.
        timestamp (str): The timestamp of the entry.
    """
    name = models.CharField(max_length=32)
    ip = models.GenericIPAddressField()
    port = models.IntegerField()
    pubkey = models.CharField(max_length=64)
    timestamp = models.DateTimeField(auto_now=True)
