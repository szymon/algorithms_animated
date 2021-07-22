import curses
from argparse import ArgumentParser

from sha1 import sha1
from sha2 import sha224, sha256


# @curses.wrapper
def main(stdscr=None):
    parser = ArgumentParser()
    parser.add_argument("--algo", choices=["sha1", "sha224", "sha256"], default="sha1")
    parser.add_argument("data")

    args = parser.parse_args()

    if args.algo == "sha1":
        sha1(stdscr, args.data.encode())
    elif args.algo == "sha224":
        print(sha224(args.data.encode()).hex())
    elif args.algo == "sha256":
        print(sha256(args.data.encode()).hex())


main()
