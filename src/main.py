import argparse
import os
from cmd import Cmd

import shallot

class ShallotClient(Cmd):
    """
    Command line handler.
    """
    intro = 'Type help or ? to list commands.\n'
    prompt = 'Shallot > '

    def do_exit(self, arg):
        """Exit the client"""
        print('exiting...')
        shallot.stop_server()
        return True

    def do_EOF(self, arg):
        """Exit the client"""
        return self.do_exit(arg)

def chdir_and_check_permissions(dir):
    """
    Change the current working directory to dir and check if it is writable.
    Args:
        dir: The directory to move to.

    Returns:
        None
    """
    try:
        os.chdir(dir)
    except FileNotFoundError:
        print(f'Directory "{dir}" does not exist!')
        exit(1)
    except PermissionError:
        print(f'Insufficient permissions to access "{dir}"!')
        exit(1)
    except NotADirectoryError:
        print(f'"{dir}" is not a directory!')
        exit(1)

    if not os.access(dir, os.W_OK):
        print(f'"{dir}" is not writable!')
        exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('name', type=str, help='Your name (must be unique in the network)')
    parser.add_argument('-p', '--port', default=53600, type=int,
                        help='Port to listen on (default: %(default)s)')
    parser.add_argument('-d', '--dir', default='.',
                        help='Directory to serve files (default: "%(default)s").\n'
                             'Important: everything in this directory will be made public!')
    args = parser.parse_args()

    chdir_and_check_permissions(args.dir)
    shallot.run_server(args.name, args.port)
    ShallotClient().cmdloop()
