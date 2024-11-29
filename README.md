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
- **Ephemeral Keys**: Uses ephemeral keys to ensure forward secrecy.
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
    - The sender encrypts the message in multiple layers, one for each node in the path.
    - Each node decrypts its layer to reveal the next hop.

4. **Requests and Responses**:
    - Communication is done through request-response pairs:
        - **Request**: A sender creates a routing cycle and sends an encrypted message.
        - **Response**: The receiver processes the request and sends the response back through the same path.

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
    git clone https://github.com/ldm2468/shallot-routing.git
    cd shallot-routing
    ```

2. **Install Dependencies**:
    Ensure you have Python 3.9+ installed. Then, install required libraries:
    ```bash
    pip install -r requirements.txt
    ```

4. **Start a Shallot Node**:
    Each node must have a unique name. Run the Shallot server:
    ```bash
    cd src
    python main.py <your_node_name> -p <port_number> -d <directory_to_send_and_receive>
    ```
    This should launch a shallot commandline. There needs to be atleast 6 host for network to function well.
---

## **Usage**

### **Send a File**
Send a file to another node in the network:
```bash
>> send <node_x> <file_x>
```

### **Receive a File**
Request a file from another node:
```bash
>> receive <node_y> <file_y>
```

### **List Files**
List files available on another node:
```bash
>> list <node_z>
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
