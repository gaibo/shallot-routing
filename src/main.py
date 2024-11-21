import argparse
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

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('name', type=str, help='Your name (must be unique in the network)')
    parser.add_argument('-p', '--port', default=53600, type=int,
                        help='Port to listen on (default: %(default)s)')
    args = parser.parse_args()

    shallot.run_server(args.name, args.port)

    ShallotClient().cmdloop()
