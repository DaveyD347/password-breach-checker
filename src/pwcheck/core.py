"""Core k-anonymity lookup against the Have I Been Pwned "Pwned Passwords" range API.

Privacy model
-------------
1. The password is hashed locally with SHA-1.
2. Only the first 5 hex characters of that hash (the "prefix") are sent to
   ``https://api.pwnedpasswords.com/range/<prefix>``.
3. The API returns every known hash suffix that shares the prefix (typically
   800-1000 of them, more with padding enabled). The comparison against your
   suffix happens here, on your machine.

The full hash and the password never leave the process. This module has no
logging, no telemetry and no third-party dependencies, so it can be audited in
a single sitting.
"""

from __future__ import annotations

import hashlib
import re
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, Optional

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "password-breach-checker (+https://github.com/DaveyD347/password-breach-checker)"
PREFIX_LEN = 5
DEFAULT_TIMEOUT = 10.0

_SHA1_RE = re.compile(r"^[0-9A-F]{40}$")
_PREFIX_RE = re.compile(r"^[0-9A-F]{5}$")

# A fetcher takes a 5-char prefix and returns the raw response body.
# It is injectable so tests (and auditors) can verify exactly what goes out.
Fetcher = Callable[[str], str]


class BreachCheckError(Exception):
    """Raised when the range API cannot be reached or returns bad data."""


@dataclass(frozen=True)
class CheckResult:
    prefix: str
    count: int

    @property
    def pwned(self) -> bool:
        return self.count > 0


def sha1_hex(password: str) -> str:
    """Return the upper-case SHA-1 hex digest of a UTF-8 encoded password."""
    # usedforsecurity=False: SHA-1 is required by the HIBP protocol and is used
    # here as a lookup key, not as a security primitive.
    return hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()


def normalize_hash(value: str) -> str:
    """Validate and upper-case a user-supplied SHA-1 hex digest."""
    h = value.strip().upper()
    if not _SHA1_RE.match(h):
        raise ValueError("expected a 40-character hexadecimal SHA-1 hash")
    return h


def split_hash(sha1: str) -> tuple[str, str]:
    """Split a SHA-1 hex digest into the 5-char prefix (sent) and the suffix (kept)."""
    return sha1[:PREFIX_LEN], sha1[PREFIX_LEN:]


def parse_range_response(body: str) -> Dict[str, int]:
    """Parse ``SUFFIX:COUNT`` lines into a dict.

    Entries with a count of 0 are padding records (see ``Add-Padding``) and are
    dropped so they can never produce a false positive.
    """
    results: Dict[str, int] = {}
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        suffix, sep, count = line.partition(":")
        if not sep:
            raise BreachCheckError(f"malformed line in API response: {line[:60]!r}")
        try:
            n = int(count)
        except ValueError as exc:
            raise BreachCheckError(f"malformed count in API response: {line[:60]!r}") from exc
        if n > 0:
            results[suffix.strip().upper()] = n
    return results


def http_fetch(prefix: str, timeout: float = DEFAULT_TIMEOUT, padding: bool = True) -> str:
    """Fetch the hash range for ``prefix`` from the HIBP API.

    ``Add-Padding`` asks the API to pad the response with random fake entries so
    that an observer of the (encrypted) response size learns nothing about
    which prefix was requested.
    """
    if not _PREFIX_RE.match(prefix):
        # Defence in depth: refuse to send anything that is not a bare prefix.
        raise ValueError("refusing to send anything other than a 5-char hex prefix")
    headers = {"User-Agent": USER_AGENT}
    if padding:
        headers["Add-Padding"] = "true"
    url = API_URL.format(prefix=prefix)  # fixed https:// URL, prefix validated above
    req = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.read().decode("utf-8")
    except OSError as exc:  # URLError, HTTPError, timeouts and socket errors
        raise BreachCheckError(f"could not reach Pwned Passwords API: {exc}") from exc


class BreachChecker:
    """Looks up hashes by prefix, caching each range so repeated prefixes cost one request."""

    def __init__(self, fetcher: Optional[Fetcher] = None) -> None:
        self._fetch: Fetcher = fetcher or http_fetch
        self._cache: Dict[str, Dict[str, int]] = {}

    def check_hash(self, sha1: str) -> CheckResult:
        sha1 = normalize_hash(sha1)
        prefix, suffix = split_hash(sha1)
        if prefix not in self._cache:
            self._cache[prefix] = parse_range_response(self._fetch(prefix))
        return CheckResult(prefix=prefix, count=self._cache[prefix].get(suffix, 0))

    def check_password(self, password: str) -> CheckResult:
        if password == "":
            raise ValueError("password must not be empty")
        return self.check_hash(sha1_hex(password))


def check_password(password: str, fetcher: Optional[Fetcher] = None) -> CheckResult:
    """Convenience wrapper: check one password."""
    return BreachChecker(fetcher).check_password(password)
