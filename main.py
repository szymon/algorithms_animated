import curses
from argparse import ArgumentParser

from sha1 import sha1


@curses.wrapper
def main(stdscr):
    parser = ArgumentParser()
    parser.add_argument("data")

    args = parser.parse_args()
    sha1(stdscr, args.data.encode())
