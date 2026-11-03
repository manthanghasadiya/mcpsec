"""Detection oracles for confirming vulnerabilities by effect."""

from .command_injection import OracleResult, confirm_command_injection
from .deserialization import confirm_deserialization, confirm_deserialization_sync
from .oob_collector import OOBCollector
from .path_traversal import confirm_path_traversal, confirm_path_traversal_sync
from .sql_injection import confirm_sqli, confirm_sqli_sync
from .ssrf import confirm_ssrf

__all__ = [
    "OracleResult",
    "OOBCollector",
    "confirm_command_injection",
    "confirm_deserialization",
    "confirm_deserialization_sync",
    "confirm_path_traversal",
    "confirm_path_traversal_sync",
    "confirm_sqli",
    "confirm_sqli_sync",
    "confirm_ssrf",
]


