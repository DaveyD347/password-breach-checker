"""Privacy-first password breach checker using the HIBP k-anonymity range API."""

from .core import BreachChecker, BreachCheckError, CheckResult, check_password, sha1_hex

__all__ = ["BreachChecker", "BreachCheckError", "CheckResult", "check_password", "sha1_hex"]
__version__ = "0.1.0"
