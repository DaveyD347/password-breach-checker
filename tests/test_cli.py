import io
import json

import pytest

from pwcheck import cli

PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"  # sha1("password")[5:]


class TTYStream(io.StringIO):
    def isatty(self):
        return True


class PipeStream(io.StringIO):
    def isatty(self):
        return False


@pytest.fixture
def fake_api(monkeypatch):
    """Replace the network with a fake range API that knows only "password"."""
    calls = []

    def fake_http_fetch(prefix, timeout=10.0, padding=True):
        calls.append({"prefix": prefix, "padding": padding})
        if prefix == "5BAA6":
            return f"{PASSWORD_SUFFIX}:42\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n"
        return "0000000000000000000000000000000000A:1\r\n"

    monkeypatch.setattr(cli, "http_fetch", fake_http_fetch)
    return calls


def run(argv, stdin_text="", tty=False):
    stdin = (TTYStream if tty else PipeStream)(stdin_text)
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(argv, stdin=stdin, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_stdin_pwned_exit_1(fake_api):
    code, out, _ = run([], "password\n")
    assert code == cli.EXIT_PWNED
    assert "PWNED" in out and "42 times" in out
    assert "password\n" not in out.replace("password:", "").replace("password #", "")


def test_stdin_clean_exit_0(fake_api):
    code, out, _ = run([], "correct horse battery staple zebra 9!\n")
    assert code == cli.EXIT_CLEAN
    assert out.startswith("OK")


def test_multiple_passwords_any_pwned(fake_api):
    code, out, _ = run(["--stdin"], "unique-pass-xyz\npassword\n\n")
    assert code == cli.EXIT_PWNED
    assert "password #1" in out and "password #2" in out
    assert len(out.strip().splitlines()) == 2


def test_password_never_echoed(fake_api):
    secret = "hunter2-super-secret"
    _, out, err = run(["--show-request"], secret + "\n")
    assert secret not in out and secret not in err


def test_show_request_prints_only_prefix(fake_api):
    _, _, err = run(["--show-request"], "password\n")
    assert err.strip() == "-> GET https://api.pwnedpasswords.com/range/5BAA6"


def test_json_output(fake_api):
    code, out, _ = run(["--json"], "password\n")
    assert code == cli.EXIT_PWNED
    assert json.loads(out) == {"item": "password", "pwned": True, "count": 42}


def test_quiet(fake_api):
    code, out, _ = run(["-q"], "password\n")
    assert code == cli.EXIT_PWNED and out == ""


def test_sha1_mode(fake_api):
    code, out, _ = run(["--sha1", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"])
    assert code == cli.EXIT_PWNED
    assert "hash 5BAA6..." in out


def test_bad_sha1_is_error(fake_api):
    code, _, err = run(["--sha1", "nothex"])
    assert code == cli.EXIT_ERROR and "SHA-1" in err


def test_no_padding_flag(fake_api):
    run(["--no-padding"], "password\n")
    assert fake_api == [{"prefix": "5BAA6", "padding": False}]


def test_empty_input_is_error(fake_api):
    code, _, err = run([], "\n\n")
    assert code == cli.EXIT_ERROR and "no password" in err


def test_interactive_prompt_uses_getpass(fake_api, monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "password")
    code, _, _ = run([], tty=True)
    assert code == cli.EXIT_PWNED


def test_network_error_exit_2(monkeypatch):
    def broken(prefix, timeout=10.0, padding=True):
        raise cli.BreachCheckError("could not reach Pwned Passwords API: offline")

    monkeypatch.setattr(cli, "http_fetch", broken)
    code, _, err = run([], "password\n")
    assert code == cli.EXIT_ERROR and "offline" in err


def test_password_argument_not_accepted():
    with pytest.raises(SystemExit):
        run(["password"])
