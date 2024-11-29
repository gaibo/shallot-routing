import asyncio
import json
import os
from typing import Dict
import base64
import shallot
from crypto import pad_payload, unpad_payload

file_list_cache: Dict[str, Dict[str, int]] = {}

def send(name: str, filename: str):
    """
    Send a file to another user in the Shallot network.
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

def receive(name: str, filename: str):
    """
    Receive a file from another user in the Shallot network.
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

def list(name: str):
    """
    Fetch the list of files stored by another user in the Shallot network.
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
