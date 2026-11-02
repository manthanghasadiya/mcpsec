"""Detection oracles for confirming vulnerabilities by effect."""

from .command_injection import OracleResult, confirm_command_injection

__all__ = ["OracleResult", "confirm_command_injection"]
