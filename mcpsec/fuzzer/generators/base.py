from dataclasses import dataclass

@dataclass 
class FuzzCase:
    """A single fuzz test case."""
    name: str               # Human-readable name
    generator: str           # Generator that created this
    payload: bytes           # Raw bytes to send
    description: str         # What this tests
    expected_behavior: str   # What a correct server should do
    # New flags for protocol state machine and ID confusion
    skip_init: bool = False
    send_after_init: bool = False
    send_shutdown_first: bool = False
    repeat: int = 1
    delay_between: float = 0.0
    expects_error: bool = False
    crash_indicates_bug: bool = True
