from dataclasses import dataclass

from rich.console import Console

cc = Console()


@dataclass(frozen=True)
class SHALLOT:
    """
    Configuration for the Shallot routing protocol.

    Attributes:
        CYCLE_LENGTH (int): The number of nodes in a Shallot routing cycle.
    """

    CYCLE_LENGTH: int = 6


@dataclass(frozen=True)
class LIST_SERVER:
    """
    Configuration for the Shallot list server.

    Attributes:
        ADDRESS (str): The URL of the list server, which maintains the list of participating nodes.
    """

    ADDRESS: str = "https://ldm2468.com/shallot"


@dataclass(frozen=True)
class CRYPTO:
    """
    Cryptographic configuration for Shallot routing.

    Attributes:
        X25519_SIZE (int): The size of X25519 public/private keys in bytes.
        KEY_SIZE (int): The size of derived symmetric keys in bytes.
        NONCE_SIZE (int): The size of the nonce used for encryption in bytes.
    """

    X25519_SIZE: int = 32
    KEY_SIZE: int = 32
    NONCE_SIZE: int = 16
