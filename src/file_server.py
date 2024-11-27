import asyncio

import shallot

file_list_cache = {}

def send(name: str, filename: str):
    print(f'Sending {filename} to {name}...')
    # TODO: implement send
    #   First, construct the payload (it should contain the filename and the file contents)
    #   After the payload is created, call shallot.make_request()
    #   (note that it is an async function)
    #   It will return the (decrypted) response payload, which should be either 'OK' or an error message
    #   It will also return the elapsed time, which will be useful for experiments
    payload = b'' # TODO create payload
    async def run():
        response, time = await shallot.make_request(name, payload)
        # TODO handle response
    asyncio.run(run())

def receive(name: str, filename: str):
    print(f'Receiving {filename} from {name}...')
    # TODO: implement receive
    #   First, construct the payload (it should contain the requested filename)
    #   Use the file list cache to make sure that the payload is large enough to fit the file contents
    #   (This is important because the payload should remain the same size for the whole loop!)
    #   If the file does not exist in the local cache (maybe because the user did not run the "list" command yet),
    #   give up or warn the user that privacy might suffer
    #   After the payload is created, call shallot.make_request()
    #   (note that it is an async function)
    #   It will return the (decrypted) response payload, which should either be an error or contain the requested file
    #   Handle either appropriately (e.g., create a new file with the provided contents)
    #   It will also return the elapsed time, which will be useful for experiments

def list(name: str):
    # TODO: implement list
    #   First, construct the payload (it can be empty, but it still has to be large enough to fit the file list)
    #   Since the size of the file list cannot be known ahead of time, just create a reasonably large buffer
    #   (Remember that the payload should remain the same size for the whole loop!)
    #   After the payload is created, call shallot.make_request()
    #   (note that it is an async function)
    #   It will return the (decrypted) response payload, which should contain the file list in JSON format (or similar)
    #   Add the file list to the file_list_cache, which will be important for preallocating space for 'receive' commands
    #   It will also return the elapsed time, which will be useful for experiments
    global file_list_cache
    print(f'Retrieving list of files stored by {name}...')
    # TODO: populate l with retrieved file list
    l = { 'a.txt': 53600, 'b.txt': 12345 }  # this is an example of file list format, with file sizes in bytes
    file_list_cache[name] = l  # update the file list cache
    return l

def handle_request(payload: bytes) -> bytes:
    # TODO: First, parse the payload to determine the type of request (send, receive, or list)
    #   Then, handle the request appropriately
    #   (e.g., for send requests, create a file with the appropriate name and contents)
    #   Then, return a response payload
    #   For 'send' requests, this is just a simple 'OK' or an error message
    #   For 'receive' requests, this is the contents of the requested file (or an error)
    #   For 'list' requests, this is a list of the files stored in the server (filename and file size info)
    #   JSON might be convenient here (but for the other request types, binary data may be better)
    #   Important: for maximum security and privacy, the size of the response should be same as the size of the request
    #   Use crypto.pad_payload() as necessary
    pass