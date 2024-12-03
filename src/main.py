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
        Print help message for "send" command.
        """
        cc.print("[yellow]Send a file to a user.\nUsage: send \[name] \[filename]")

    def spaced_filename_splitter(my_str):
        """
        "gaibo 'requirements - Copy (3).txt'" 
        -> ['gaibo', 'requirements - Copy (3).txt']
        """
        quote_split_list = my_str.split("'")
        if len(quote_split_list) == 1:
            # Perform normal space splitting
            arg = quote_split_list[0]
            tokens = arg.split()
        else:
            # Perform special quote splitting
            tokens = []
            for el in quote_split_list:
                if el != '':
                    tokens.append(el.strip())
        return tokens

    def do_send(self, arg):
        """
        Send a file to a user.
        Args:
            arg: String of the format "[name] [filename]".

        Returns:
            None
        """
        # tokens = arg.split()
        tokens = ShallotClient.spaced_filename_splitter(arg)
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

    def help_receive(self):
        """
        Print help message for "receive" command.
        """
        cc.print("[yellow]Receive a file from a user.\nUsage: receive \[name] \[filename]")

    def do_receive(self, arg):
        """
        Receive a file from a user.
        Args:
            arg: String of the format "[name] [filename]".

        Returns:
            None
        """
        # tokens = arg.split()
        tokens = ShallotClient.spaced_filename_splitter(arg)
        if len(tokens) != 2:
            self.help_receive()
        else:
            file_server.receive(*tokens)

    def help_list(self):
        """
        Print help message for "list" command.
        """
        cc.print("[yellow]Fetch the list of files stored at user.\nUsage: list \[name]")

    def do_list(self, arg):
        """Fetch the list of files stored at [user]."""
        # print(f"here's the arg of 'list':\n{arg}")
        if arg == '':
            arg = shallot.my_name   # To mimic real 'ls'
        tokens = arg.split()
        if len(tokens) != 1:
            self.help_list()
        else:
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
        "name", type=str, help="your username (must be unique in the network)"
    )
    parser.add_argument(
        "-p",
        "--port",
        default=53600,
        type=int,
        help="port to listen on (default: %(default)s)",
    )
    parser.add_argument(
        "-d",
        "--dir",
        default=".",
        help='directory to serve files (default: "%(default)s").\n'
        "IMPORTANT: everything in this directory will be made public!",
    )
    parser.add_argument(
        "-D",
        "--diag_mode",
        action='store_true',
        help='set to print low-level diagnostics; good for demos!'
    )
    args = parser.parse_args()

    chdir_and_check_permissions(args.dir)   # All subsequent operations are from POV inside this selected dir
    if args.diag_mode:
        cc.print("[grey50]Diagnostic/demo mode on!")
    shallot.DIAG_MODE = args.diag_mode
    file_server.DIAG_MODE = args.diag_mode
    shallot.run_server(args.name, args.port)
    ShallotClient().cmdloop()
