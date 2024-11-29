import argparse
import os
from cmd import Cmd

import file_server
import list_server
import shallot
from config import cc


class ShallotClient(Cmd):
    """
    Command line handler.
    """

    cc.print("[magenta]SHALLOT ROUTING \n\nType help or ? to list commands.\n")
    prompt = ">> "

    def complete_send(self, text, line, begidx, endidx):
        """
        Handle autocompletion for "send" command.
        Args:
            text: String prefix to match.
            line: Current user input.
            begidx: Index of the beginning of text in line.
            endidx: Index of the end of text in line.

        Returns:
            None
        """
        # Divide into tokens, but treat trailing whitespace to be delimiters as well.
        tokens = (line + ".").split()
        match len(tokens):
            case 2:
                return [
                    name for name in list_server.cached_list if name.startswith(text)
                ]
            case 3:
                return [
                    f
                    for f in os.listdir(".")
                    if os.path.isfile(f) and f.startswith(text)
                ]
        return []

    def help_send(self):
        """
        Print help message for "help" command.
        """
        cc.print("[yellow]Send a file to a user.\nUsage: send [name] [filename]")

    def do_send(self, arg):
        """
        Send a file to a user.
        Args:
            arg: String of the format "[name] [filename]".

        Returns:
            None
        """
        tokens = arg.split()
        if len(tokens) != 2:
            self.help_send()
        else:
            file_server.send(*tokens)

    def complete_list(self, text, line, begidx, endidx):
        """
        Handle autocompletion for "list" command.
        """
        # Divide into tokens, but treat trailing whitespace to be delimiters as well.
        tokens = (line + ".").split()
        return (
            [name for name in list_server.cached_list if name.startswith(text)]
            if len(tokens) == 2
            else []
        )

    def complete_receive(self, text, line, begidx, endidx):
        """
        Handle autocompletion for "receive" command.
        """
        # Divide into tokens, but treat trailing whitespace to be delimiters as well.
        tokens = (line + ".").split()
        match len(tokens):
            case 2:
                return [
                    name for name in list_server.cached_list if name.startswith(text)
                ]
            case 3:
                return [
                    f
                    for f in file_server.file_list_cache[tokens[1]].keys()
                    if f.startswith(text)
                ]
        return []

    def do_receive(self, arg):
        """
        Receive a file from a user.
        Args:
            arg: String of the format "[name] [filename]".

        Returns:
            None
        """
        tokens = arg.split()
        if len(tokens) != 2:
            self.help_send()
        else:
            file_server.receive(*tokens)

    def do_list(self, arg):
        """Fetch the list of files stored at [user]."""
        file_server.list(arg)

    def do_exit(self, arg):
        """Exit the client"""
        cc.print("[blue]Exiting...")
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

    if not os.access(".", os.W_OK):
        print(f'"{dir}" is not writable!')
        exit(1)


if __name__ == "__main__":
    cc.print("[magenta]Initializing... (may take a few seconds)")
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "name", type=str, help="Your name (must be unique in the network)"
    )
    parser.add_argument(
        "-p",
        "--port",
        default=53600,
        type=int,
        help="Port to listen on (default: %(default)s)",
    )
    parser.add_argument(
        "-d",
        "--dir",
        default=".",
        help='Directory to serve files (default: "%(default)s").\n'
        "Important: everything in this directory will be made public!",
    )
    args = parser.parse_args()

    chdir_and_check_permissions(args.dir)
    shallot.run_server(args.name, args.port)
    ShallotClient().cmdloop()
