# password-breach-checker

[![CI](https://github.com/DaveyD347/password-breach-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/DaveyD347/password-breach-checker/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

A privacy-first command-line tool that checks whether a password has appeared in a known data breach,
using the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) Pwned Passwords API and its
**k-anonymity** model.

Your password never leaves your machine. Neither does its full hash. Only the **first 5 characters of
its SHA-1 hash** are sent over the network.

```console
$ pwcheck
Password (input hidden):
PWNED  password: seen 52,256,179 times in data breaches. Do not use it.
```

## Why you can trust it

Privacy tools only earn trust through transparency, so this one is built to be audited quickly:

- **Zero dependencies.** Python standard library only. Under 300 lines, comments included, across two files:
  [`core.py`](src/pwcheck/core.py) and [`cli.py`](src/pwcheck/cli.py).
- **Zero telemetry.** The only network request goes to `https://api.pwnedpasswords.com/range/<5 hex chars>`.
  There is no logging, analytics, crash reporting or config file.
- **Prefix-only by construction.** The HTTP function validates its argument against `^[0-9A-F]{5}$` and refuses
  to send anything else. Tests assert the exact URL, method, headers and (empty) body of every request.
- **No passwords on the command line.** Arguments show up in `ps` and in shell history, so passwords are only
  read from a hidden prompt or from stdin.
- **Response padding on by default.** The `Add-Padding` header makes the API pad every response with fake
  entries, so someone watching encrypted traffic can't guess your prefix from the response size.
- **See for yourself.** `--show-request` prints every request before it is made.

## How k-anonymity works

```
  your machine                                         api.pwnedpasswords.com
  ────────────                                         ──────────────────────
  "password"
      │ SHA-1 (local)
      ▼
  5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
  └─┬─┘ └───────────────┬─────────────────┘
    │          kept locally (never sent)
    │
    └──────── GET /range/5BAA6 ───────────────────────▶
                                                       returns every breached hash suffix
                                                       that starts with 5BAA6 (~1,000 of them)
    ◀────── 003D68EB55068C33ACE09247EE4C639306B:3 ─────
            1E4C9B93F3F0682250B6CF8331B7EE68FD8:52256179
            ...

  compare locally: is our suffix in the list? ──▶ PWNED (52,256,179)
```

Each 5-character prefix is shared by hundreds of real breached hashes plus every other possible password that
hashes to it, so the API operator learns only that you asked about one of a very large set. SHA-1 is used
because that is what the HIBP corpus is keyed on; here it is a lookup key, not a protection mechanism.

## Install

Requires Python 3.10 or newer.

```bash
pipx install git+https://github.com/DaveyD347/password-breach-checker
# or
pip install git+https://github.com/DaveyD347/password-breach-checker
```

Or run it from a clone with no install at all:

```bash
git clone https://github.com/DaveyD347/password-breach-checker
cd password-breach-checker
PYTHONPATH=src python -m pwcheck
```

## Usage

```console
# Interactive, input hidden
$ pwcheck

# Several passwords from a file, one per line
$ pwcheck < passwords.txt
PWNED  password #1: seen 52,256,179 times in data breaches. Do not use it.
OK     password #2: not found in any known breach.

# Check a SHA-1 you already have (e.g. from a password manager export)
$ pwcheck --sha1 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8

# Show exactly what goes over the wire
$ echo 'hunter2' | pwcheck --show-request
-> GET https://api.pwnedpasswords.com/range/F3BBB
PWNED  password: seen 17,043 times in data breaches. Do not use it.

# Machine-readable output for scripts
$ pwcheck --json < passwords.txt
{"item": "password #1", "pwned": true, "count": 52256179}
{"item": "password #2", "pwned": false, "count": 0}
```

Breach counts change as HIBP adds data, so the numbers above are illustrative.

| Option | Description |
| --- | --- |
| `--stdin` | Read passwords from stdin, one per line (automatic when stdin is piped) |
| `--sha1 HASH` | Check a pre-computed SHA-1 hash instead of a password (repeatable) |
| `--json` | Emit one JSON object per line |
| `--show-request` | Print each request URL to stderr before it is sent |
| `--no-padding` | Don't request padded responses (smaller, slightly less private) |
| `--timeout SECONDS` | Network timeout (default 10) |
| `-q`, `--quiet` | No output; use the exit status |

### Exit status

| Code | Meaning |
| --- | --- |
| `0` | No password was found in a breach |
| `1` | At least one password was found in a breach |
| `2` | Error (bad input, network failure) |

This makes it easy to use in scripts and CI, e.g. `pwcheck -q < secret.txt || echo "rotate it"`.

## Use as a library

```python
from pwcheck import BreachChecker

checker = BreachChecker()          # caches each 5-char range it downloads
result = checker.check_password("correct horse battery staple")
print(result.pwned, result.count)
```

`BreachChecker` accepts a custom `fetcher(prefix) -> str`, which is how the tests run without a network and how
you could route requests through your own proxy or a local mirror of the range data.

## Development

```bash
pip install -e ".[dev]"
pytest          # 39 tests, no network needed
ruff check .
```

CI runs lint and tests on Python 3.10, 3.12 and 3.13.

## Security notes and limits

- A "not found" result means the password is not in HIBP's corpus. It does not mean the password is strong.
- Python strings are immutable, so the password can't be reliably wiped from memory. It is hashed immediately
  and the reference dropped, which is the practical limit for a Python tool.
- The tool trusts the system's TLS certificate store to authenticate `api.pwnedpasswords.com`.

Found a problem? Please open an issue, or for anything sensitive, contact the maintainer privately through GitHub.

## Credits

Breach data from [Have I Been Pwned](https://haveibeenpwned.com) by Troy Hunt, licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The Pwned Passwords range API is free and needs no API
key.

## License

[MIT](LICENSE)
