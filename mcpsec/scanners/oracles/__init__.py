"""Detection oracles for confirming vulnerabilities by effect."""

from .command_injection import OracleResult, confirm_command_injection
from .oob_collector import OOBCollector
from .ssrf import confirm_ssrf

__all__ = [
    "OracleResult",
    "OOBCollector",
    "confirm_command_injection",
    "confirm_ssrf",
]
