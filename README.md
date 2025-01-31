# **Shallot Routing - Secure and Anonymous Communication**

Shallot Routing is an implementation of an onion-routing-inspired protocol designed for secure, anonymous, and decentralized communication between nodes in a network. This project focuses on ensuring privacy by encrypting messages in layers, preventing any single node from knowing the entire communication path.

---

## **Table of Contents**
1. [Features](#features)
2. [How It Works](#how-it-works)
3. [Components](#components)
4. [Setup](#setup)
5. [Usage](#usage)
    - [Send a File](#send-a-file)
    - [Receive a File](#receive-a-file)
    - [List Files](#list-files)
6. [Testing](#testing)
7. [Contributing](#contributing)
8. [License](#license)

---

## **Features**
- **Anonymous Communication**: Ensures that no single node knows both the sender and receiver.
- **Layered Encryption**: Protects message content and routing information with multiple layers of encryption.
- **Decentralized**: No central server or authority required; nodes communicate directly.
- **Ephemeral Keys**: Uses ephemeral keys to ensure "return" secrecy - responder doesn't need to know requester's (potentially identifiable) public key.
- **File Sharing**: Enables secure file sharing between nodes in the network.

---

## **How It Works**

1. **Public/Private Key Infrastructure**:
    - Each node in the network has an X25519 public/private key pair.
    - Public keys are shared to facilitate secure communication.

2. **Routing**:
    - Messages are routed through multiple intermediate nodes to ensure anonymity.
    - Each node only knows the previous and next nodes in the route.

3. **Layered Encryption**:
    - The original requester (sender) encrypts the message in multiple layers, one for each node in the path.
    - Each node decrypts its layer to reveal the next hop.

4. **Requests and Responses**:
    - Communication is done through request-response pairs:
        - **Request**: An **"originator"** requester (e.g. Alice) creates a routing cycle and sends the Shallot-encrypted message.
        - **Response**: The ultimate **"recipient"** responder (intended by Alice, e.g. Bob) eventually receives and processes the request, then sends that response back *along the rest of the routing cycle* as encoded by the originator in the Shallot-header.

---

## **Components**

- **`crypto.py`**:
    - Handles cryptographic operations like key exchange, encryption, and decryption.
    - Implements padding and unpadding of payloads.

- **`shallot.py`**:
    - Manages Shallot routing, including request processing and message forwarding.

- **`file_server.py`**:
    - Implements file sharing functionality:
        - Sending, receiving, and listing files.

- **`list_server.py`**:
    - Provides node discovery by maintaining a registry of active nodes.

- **`tests/`**:
    - Contains unit tests for various components of the project.

---

## **Setup**

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/gaibo/shallot-routing.git
    cd shallot-routing
    ```

2. **Install Dependencies**:
    Ensure you have Python 3.11+ (3.10 needed for Django version, 3.11 needed for asyncio.timeout()) installed. Then, install required libraries:
    ```bash
    pip install -r requirements.txt
    ```

4. **Start a Shallot Node**:
    Each node must have a unique name. The following runs the Shallot server in the background and launches the Shallot commandline in the foreground:
    ```bash
    cd src
    python main.py <your_node_name> -p <port_number> -d <directory_to_send_and_receive>
    ```
    (Use `-h` for help and `-D` for diagnostic/demo verbose printing!)

    We currently enforce a **6 node minimum** before the network may operate (and unlock the file sharing application). This is to ensure the routing cycles can be reasonably long, for security.
---

## **Usage - *File Sharing* app (on top of Shallot Routing)**

1. List files available on your node or another node in the network:
```bash
>> list [<node_x>]
```

2.  Send a file to another node:
```bash
>> send <node_x> <file_x>
```

3. Request a file from another node:
```bash
>> receive <node_x> <file_y>
```

---

## **Contributing**

We welcome contributions! To get started:
1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add a new feature"
   ```
4. Push and create a pull request:
   ```bash
   git push origin feature-name
   ```

---

## **License**

This project is licensed under the [MIT License](LICENSE). Feel free to use, modify, and distribute this software under the terms of the license.

---

## **Contact**

For questions or support, please contact [Dongmin Lee](lee4818@purdue.edu).

Happy Routing! 🧅
