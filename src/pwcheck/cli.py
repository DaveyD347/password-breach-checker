"""Command-line interface.

Passwords are never accepted as command-line arguments, because arguments are
visible to other users via the process list and are saved in shell history.
Use the interactive prompt (input hidden) or pipe passwords on stdin.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from typing import Iterable, List, Optional, TextIO

from . import __version__
from .core import BreachChecker, BreachCheckError, CheckResult, http_fetch, sha1_hex

EXIT_CLEAN = 0
EXIT_PWNED = 1
EXIT_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pwcheck",
        description=(
            "Check passwords against Have I Been Pwned using k-anonymity: only the first "
            "5 characters of each SHA-1 hash are sent over the network."
        ),
        epilog="Exit status: 0 = none found, 1 = at least one found in breaches, 2 = error.",
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument(
        "--stdin",
        action="store_true",
        help="read passwords from stdin, one per line (default when stdin is not a terminal)",
    )
    src.add_argument(
        "--sha1",
        metavar="HASH",
        action="append",
        help="check a pre-computed SHA-1 hash instead of a password (repeatable)",
    )
    p.add_argument("--json", action="store_true", help="emit JSON lines instead of text")
    p.add_argument(
        "--show-request",
        action="store_true",
        help="print the exact prefix sent over the network for each check (to stderr)",
    )
    p.add_argument(
        "--no-padding",
        action="store_true",
        help="do not ask the API to pad responses (padding hides the prefix from size analysis)",
    )
    p.add_argument("--timeout", type=float, default=10.0, help="network timeout in seconds (default: 10)")
    p.add_argument("-q", "--quiet", action="store_true", help="print nothing; rely on the exit status")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _read_stdin_lines(stream: TextIO) -> Iterable[str]:
    for line in stream:
        pw = line.rstrip("\r\n")
        if pw:
            yield pw


def _label(index: int, total: int) -> str:
    return "password" if total == 1 else f"password #{index}"


def _report(result: CheckResult, label: str, args: argparse.Namespace, out: TextIO) -> None:
    if args.quiet:
        return
    if args.json:
        out.write(json.dumps({"item": label, "pwned": result.pwned, "count": result.count}) + "\n")
    elif result.pwned:
        out.write(f"PWNED  {label}: seen {result.count:,} times in data breaches. Do not use it.\n")
    else:
        out.write(f"OK     {label}: not found in any known breach.\n")


def main(argv: Optional[List[str]] = None, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout,
         stderr: TextIO = sys.stderr) -> int:
    args = _build_parser().parse_args(argv)

    def fetcher(prefix: str) -> str:
        if args.show_request:
            stderr.write(f"-> GET https://api.pwnedpasswords.com/range/{prefix}\n")
        return http_fetch(prefix, timeout=args.timeout, padding=not args.no_padding)

    checker = BreachChecker(fetcher)

    # Build the list of SHA-1 hashes up front. Plain-text passwords are hashed
    # immediately and not kept around.
    hashes: List[str] = []
    try:
        if args.sha1:
            hashes = list(args.sha1)
        elif args.stdin or not stdin.isatty():
            hashes = [sha1_hex(pw) for pw in _read_stdin_lines(stdin)]
        else:
            pw = getpass.getpass("Password (input hidden): ")
            if pw:
                hashes = [sha1_hex(pw)]
            del pw
    except (KeyboardInterrupt, EOFError):
        stderr.write("\naborted\n")
        return EXIT_ERROR

    if not hashes:
        stderr.write("pwcheck: no password given\n")
        return EXIT_ERROR

    any_pwned = False
    for i, h in enumerate(hashes, start=1):
        label = f"hash {h.strip()[:5].upper()}..." if args.sha1 else _label(i, len(hashes))
        try:
            result = checker.check_hash(h)
        except ValueError as exc:
            stderr.write(f"pwcheck: {label}: {exc}\n")
            return EXIT_ERROR
        except BreachCheckError as exc:
            stderr.write(f"pwcheck: {exc}\n")
            return EXIT_ERROR
        any_pwned = any_pwned or result.pwned
        _report(result, label, args, stdout)

    return EXIT_PWNED if any_pwned else EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
