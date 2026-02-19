from dataclasses import dataclass

@dataclass 
class FuzzCase:
    """A single fuzz test case."""
    name: str               # Human-readable name
    generator: str           # Generator that created this
    payload: bytes           # Raw bytes to send
    description: str         # What this tests
    expected_behavior: str   # What a correct server should do
