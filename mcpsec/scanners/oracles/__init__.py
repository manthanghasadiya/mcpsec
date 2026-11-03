"""Detection oracles for confirming vulnerabilities by effect."""

from .command_injection import OracleResult, confirm_command_injection
from .oob_collector import OOBCollector
from .path_traversal import confirm_path_traversal, confirm_path_traversal_sync
from .ssrf import confirm_ssrf

__all__ = [
    "OracleResult",
    "OOBCollector",
    "confirm_command_injection",
    "confirm_path_traversal",
    "confirm_path_traversal_sync",
    "confirm_ssrf",
]
