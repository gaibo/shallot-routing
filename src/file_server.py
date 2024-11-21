file_list_cache = {}

def send(name: str, filename: str):
    print(f'Sending {filename} to {name}...')
    # TODO: implement send

def receive(name: str, filename: str):
    print(f'Receiving {filename} from {name}...')
    # TODO: implement receive

def list(name: str):
    global file_list_cache
    print(f'Retrieving list of files stored by {name}...')
    # TODO: populate l with retrieved file list
    l = {'todo': 53600} # size in bytes
    file_list_cache[name] = l
    return l
