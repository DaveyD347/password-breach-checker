import io
import urllib.request

import pytest

from pwcheck import core
from pwcheck.core import (
    BreachChecker,
    BreachCheckError,
    normalize_hash,
    parse_range_response,
    sha1_hex,
    split_hash,
)

PASSWORD_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"  # sha1("password")


def test_sha1_known_vector():
    assert sha1_hex("password") == PASSWORD_SHA1


def test_sha1_handles_unicode():
    # Passwords are UTF-8 encoded before hashing, matching how HIBP builds its corpus.
    assert sha1_hex("pässwörd") == "F517DDF1D32A112FF1AD55C66D1B12CB38E7E8F7"


def test_split_hash():
    assert split_hash(PASSWORD_SHA1) == ("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8")


def test_normalize_hash_accepts_lowercase_and_whitespace():
    assert normalize_hash("  " + PASSWORD_SHA1.lower() + "\n") == PASSWORD_SHA1


@pytest.mark.parametrize("bad", ["", "abc", "Z" * 40, PASSWORD_SHA1 + "0"])
def test_normalize_hash_rejects_garbage(bad):
    with pytest.raises(ValueError):
        normalize_hash(bad)


def test_parse_range_response_drops_padding_and_blank_lines():
    body = "ABC:3\r\nDEF:0\r\n\r\nghi:12\r\n"
    assert parse_range_response(body) == {"ABC": 3, "GHI": 12}


@pytest.mark.parametrize("body", ["NOCOLON", "ABC:notanumber"])
def test_parse_range_response_rejects_malformed(body):
    with pytest.raises(BreachCheckError):
        parse_range_response(body)


class RecordingFetcher:
    def __init__(self, body):
        self.body = body
        self.calls = []

    def __call__(self, prefix):
        self.calls.append(prefix)
        return self.body


def test_pwned_password_detected():
    fetch = RecordingFetcher(
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n0000000000000000000000000000000000A:1\r\n"
    )
    result = BreachChecker(fetch).check_password("password")
    assert result.pwned
    assert result.count == 9659365


def test_clean_password_not_flagged():
    fetch = RecordingFetcher("0000000000000000000000000000000000A:1\r\n")
    result = BreachChecker(fetch).check_password("password")
    assert not result.pwned
    assert result.count == 0


def test_padding_entry_for_our_suffix_is_not_a_hit():
    fetch = RecordingFetcher("1E4C9B93F3F0682250B6CF8331B7EE68FD8:0\r\n")
    assert not BreachChecker(fetch).check_password("password").pwned


def test_only_the_five_char_prefix_is_given_to_the_network_layer():
    fetch = RecordingFetcher("")
    BreachChecker(fetch).check_password("password")
    assert fetch.calls == ["5BAA6"]
    assert "password" not in fetch.calls[0]


def test_ranges_are_cached_per_prefix():
    fetch = RecordingFetcher("")
    checker = BreachChecker(fetch)
    checker.check_password("password")
    checker.check_hash(PASSWORD_SHA1)
    assert fetch.calls == ["5BAA6"]


def test_empty_password_rejected():
    with pytest.raises(ValueError):
        BreachChecker(RecordingFetcher("")).check_password("")


# --- the real HTTP layer, with urlopen patched out -------------------------------------


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def test_http_fetch_sends_only_prefix_url_and_padding_header(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["headers"] = {k.lower(): v for k, v in req.header_items()}
        seen["data"] = req.data
        seen["method"] = req.get_method()
        return FakeResponse(b"ABC:1\r\n")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    body = core.http_fetch("5BAA6")

    assert body == "ABC:1\r\n"
    assert seen["url"] == "https://api.pwnedpasswords.com/range/5BAA6"
    assert seen["method"] == "GET"
    assert seen["data"] is None
    assert seen["headers"]["add-padding"] == "true"
    assert set(seen["headers"]) == {"add-padding", "user-agent"}


def test_http_fetch_without_padding(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["headers"] = {k.lower() for k, _ in req.header_items()}
        return FakeResponse(b"")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    core.http_fetch("5BAA6", padding=False)
    assert "add-padding" not in seen["headers"]


@pytest.mark.parametrize("bad", ["5BAA61", "5baa6", "", "../x", PASSWORD_SHA1])
def test_http_fetch_refuses_anything_but_a_prefix(bad, monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: pytest.fail("network used"))
    with pytest.raises(ValueError):
        core.http_fetch(bad)


def test_http_fetch_wraps_network_errors(monkeypatch):
    def boom(req, timeout):
        raise OSError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with pytest.raises(BreachCheckError):
        core.http_fetch("5BAA6")
