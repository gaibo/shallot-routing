import argparse
from cmd import Cmd

class ShallotClient(Cmd):
    intro = 'Welcome to the Shallot file sharing system. Type help or ? to list commands.\n'
    prompt = 'Shallot > '

    def do_exit(self, arg):
        """Exit the client"""
        print('exiting')
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
    ShallotClient().cmdloop()
