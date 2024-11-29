import asyncio
import json
import os
from typing import Dict
import base64
import shallot
from crypto import pad_payload, unpad_payload
from typing import Optional

file_list_cache: Dict[str, Dict[str, int]] = {}

def send(name: str, filename: str) -> Optional[None]:
    """
    Send a file to another user in the Shallot network.

    This function reads a file from the local filesystem, encodes its contents,
    constructs a Shallot payload, and sends the payload to a specified user
    through the Shallot network. The response from the recipient, if any, is printed.

    Args:
        name (str): The recipient's name in the Shallot network.
        filename (str): The name of the file to send.

    Returns:
        Optional[None]: Returns `None` if the function completes successfully.
                        In case of errors (e.g., file not found), it prints an error message
                        and terminates early.
    
    Raises:
        Exception: Propagates exceptions related to Shallot's `make_request` if they occur
                   during asynchronous execution.
    """
    print(f'Sending {filename} to {name}...')
    
    if not os.path.isfile(filename):
        print(f"Error: File '{filename}' does not exist.")
        return
    
    with open(filename, 'rb') as f:
        file_contents = f.read()

    payload = json.dumps({"action": "send", "filename": filename, "contents": base64.b64encode(file_contents).decode()})
    padded_payload = pad_payload(payload.encode(), 1024)  # Pad to a fixed size, e.g., 1KB

    async def run():
        try:
            response, elapsed_time = await shallot.make_request(name, padded_payload)
            unpadded_response = unpad_payload(response).decode()
            print(f"Response from {name}: {unpadded_response} (elapsed time: {elapsed_time:.2f}s)")
        except Exception as e:
            print(f"Error during sending: {e}")

    asyncio.run(run())

def receive(name: str, filename: str) -> Optional[None]:
    """
    Receive a file from another user in the Shallot network.

    This function requests a file from a specified user, retrieves its contents through the Shallot network, 
    and saves the file to the local filesystem. The file must first be listed in the local file cache 
    before requesting it.

    Args:
        name (str): The sender's name in the Shallot network.
        filename (str): The name of the file to request.

    Returns:
        Optional[None]: Returns `None` if the function completes successfully.
                        Prints an error message and terminates early if the file is not listed in the cache.

    Raises:
        Exception: Propagates exceptions related to Shallot's `make_request` if they occur during asynchronous execution.
    """
    print(f'Receiving {filename} from {name}...')

    if name not in file_list_cache or filename not in file_list_cache[name]:
        print(f"Error: File '{filename}' not listed in cache. Use the 'list' command first.")
        return

    payload = json.dumps({"action": "receive", "filename": filename})
    padded_payload = pad_payload(payload.encode(), 1024)  # Pad to a fixed size, e.g., 1KB

    async def run():
        try:
            response, elapsed_time = await shallot.make_request(name, padded_payload)
            unpadded_response = unpad_payload(response)

            # Save the received file contents
            with open(filename, 'wb') as f:
                f.write(unpadded_response)

            print(f"File '{filename}' received successfully (elapsed time: {elapsed_time:.2f}s).")
        except Exception as e:
            print(f"Error during receiving: {e}")

    asyncio.run(run())

def list(name: str) -> Optional[None]:
    """
    Fetch the list of files stored by another user in the Shallot network.

    This function sends a request to the specified user in the Shallot network, asking for their
    list of shared files. It updates the global file cache (`file_list_cache`) with the retrieved
    file list and prints the available files and their sizes.

    Args:
        name (str): The user's name in the Shallot network whose file list is to be fetched.

    Returns:
        Optional[None]: Returns `None` after fetching and displaying the file list.
                        Prints an error message and terminates early if the request fails.

    Raises:
        Exception: Propagates exceptions related to Shallot's `make_request` if they occur during asynchronous execution.
    """
    global file_list_cache
    print(f'Retrieving list of files stored by {name}...')

    payload = json.dumps({"action": "list"})
    padded_payload = pad_payload(payload.encode(), 1024)  # Pad to a fixed size, e.g., 1KB

    async def run():
        try:
            response, elapsed_time = await shallot.make_request(name, padded_payload)
            unpadded_response = unpad_payload(response).decode()

            file_list = json.loads(unpadded_response)
            file_list_cache[name] = file_list

            print(f"Files available from {name}:")
            for fname, fsize in file_list.items():
                print(f"  {fname} ({fsize} bytes)")

        except Exception as e:
            print(f"Error during file listing: {e}")

    asyncio.run(run())

def handle_request(payload: bytes) -> bytes:
    """
    Handle incoming requests (send, receive, list) and return a response.

    This function processes Shallot network requests based on the specified action in the payload.
    Supported actions:
    - "send": Save the file received in the payload to the local filesystem.
    - "receive": Retrieve the requested file from the local filesystem and return its contents.
    - "list": Return a list of available files and their sizes from the local filesystem.

    Args:
        payload (bytes): The padded payload received in the request. It is expected to be a JSON-encoded object
                         with a field `action` specifying the request type.

    Returns:
        bytes: A padded response payload. The response contains:
               - "OK" for successful send operations.
               - File contents for receive operations.
               - A JSON-encoded list of files for list operations.
               - An error message for unsupported actions or failures.

    Raises:
        Exception: Propagates exceptions related to file handling or malformed payloads if not caught in the function.
    """
    try:
        # Decode the payload
        request = json.loads(unpad_payload(payload).decode())
        action = request.get("action")

        if action == "send":
            # Handle send request
            filename = request["filename"]
            contents = base64.b64decode(request["contents"])
            with open(filename, 'wb') as f:
                f.write(contents)
            return pad_payload(b"OK", len(payload))

        elif action == "receive":
            # Handle receive request
            filename = request["filename"]
            if not os.path.isfile(filename):
                return pad_payload(b"Error: File not found.", len(payload))

            with open(filename, 'rb') as f:
                file_contents = f.read()
            return pad_payload(file_contents, len(payload))

        elif action == "list":
            # Handle list request
            file_list = {f: os.path.getsize(f) for f in os.listdir() if os.path.isfile(f)}
            return pad_payload(json.dumps(file_list).encode(), len(payload))

        else:
            return pad_payload(b"Error: Unknown action.", len(payload))

    except Exception as e:
        print(f"Error handling request: {e}")
        return pad_payload(b"Error processing request.", len(payload))
