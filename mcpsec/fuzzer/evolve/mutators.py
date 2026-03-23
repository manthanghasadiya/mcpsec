"""Mutation strategies for evolutionary fuzzing."""

from __future__ import annotations

import json
import random
import struct
from abc import ABC, abstractmethod
from typing import Any


class Mutator(ABC):
    """Base class for mutators."""

    name: str = "base"

    @abstractmethod
    def mutate(self, data: bytes) -> bytes:
        """Mutate input data and return mutated version."""
        pass


class BitFlipMutator(Mutator):
    """Flip random bits in the input."""

    name = "bitflip"

    def mutate(self, data: bytes) -> bytes:
        if not data:
            return data

        data = bytearray(data)
        num_flips = random.randint(1, max(1, len(data) // 10))

        for _ in range(num_flips):
            pos = random.randint(0, len(data) - 1)
            bit = random.randint(0, 7)
            data[pos] ^= (1 << bit)

        return bytes(data)


class ByteFlipMutator(Mutator):
    """Flip entire bytes in the input."""

    name = "byteflip"

    def mutate(self, data: bytes) -> bytes:
        if not data:
            return data

        data = bytearray(data)
        num_flips = random.randint(1, max(1, len(data) // 20))

        for _ in range(num_flips):
            pos = random.randint(0, len(data) - 1)
            data[pos] ^= 0xFF

        return bytes(data)


class ArithmeticMutator(Mutator):
    """Add/subtract small values from bytes."""

    name = "arith"

    def mutate(self, data: bytes) -> bytes:
        if not data:
            return data

        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        delta = random.choice([-35, -1, 1, 35, 127, -128])
        data[pos] = (data[pos] + delta) % 256

        return bytes(data)


class InterestingValuesMutator(Mutator):
    """Replace bytes with interesting values."""

    name = "interesting"

    INTERESTING_8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]
    INTERESTING_16 = [0, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 32768, 65535]
    INTERESTING_32 = [0, 1, 32768, 65535, 65536, 100663045, 2147483647, 4294967295]

    def mutate(self, data: bytes) -> bytes:
        if not data:
            return data

        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)

        choice = random.randint(0, 2)
        if choice == 0:
            data[pos] = random.choice(self.INTERESTING_8)
        elif choice == 1 and pos < len(data) - 1:
            val = random.choice(self.INTERESTING_16)
            data[pos:pos+2] = struct.pack("<H", val % 65536)
        elif choice == 2 and pos < len(data) - 3:
            val = random.choice(self.INTERESTING_32)
            data[pos:pos+4] = struct.pack("<I", val % (2**32))

        return bytes(data)


class DeleteMutator(Mutator):
    """Delete random chunks from input."""

    name = "delete"

    def mutate(self, data: bytes) -> bytes:
        if len(data) < 4:
            return data

        pos = random.randint(0, len(data) - 2)
        length = random.randint(1, min(16, len(data) - pos))

        return data[:pos] + data[pos + length:]


class InsertMutator(Mutator):
    """Insert random bytes into input."""

    name = "insert"

    def mutate(self, data: bytes) -> bytes:
        pos = random.randint(0, len(data))
        length = random.randint(1, 16)
        insert_data = bytes(random.randint(0, 255) for _ in range(length))

        return data[:pos] + insert_data + data[pos:]


class DuplicateMutator(Mutator):
    """Duplicate chunks within input."""

    name = "duplicate"

    def mutate(self, data: bytes) -> bytes:
        if len(data) < 2:
            return data

        pos = random.randint(0, len(data) - 1)
        length = random.randint(1, min(32, len(data) - pos))
        chunk = data[pos:pos + length]

        insert_pos = random.randint(0, len(data))
        return data[:insert_pos] + chunk + data[insert_pos:]


class HavocMutator(Mutator):
    """Apply multiple random mutations (havoc stage)."""

    name = "havoc"

    def __init__(self):
        self.sub_mutators = [
            BitFlipMutator(),
            ByteFlipMutator(),
            ArithmeticMutator(),
            InterestingValuesMutator(),
            DeleteMutator(),
            InsertMutator(),
            DuplicateMutator(),
        ]

    def mutate(self, data: bytes) -> bytes:
        num_mutations = random.randint(1, 8)

        for _ in range(num_mutations):
            mutator = random.choice(self.sub_mutators)
            data = mutator.mutate(data)

        return data


class SpliceMutator(Mutator):
    """Splice two inputs together."""

    name = "splice"

    def __init__(self, corpus_samples: list[bytes] | None = None):
        self.corpus_samples = corpus_samples or []

    def set_corpus(self, samples: list[bytes]):
        """Update corpus samples for splicing."""
        self.corpus_samples = samples

    def mutate(self, data: bytes) -> bytes:
        if not self.corpus_samples or len(data) < 4:
            return data

        other = random.choice(self.corpus_samples)
        if len(other) < 4:
            return data

        pos1 = random.randint(1, len(data) - 1)
        pos2 = random.randint(1, len(other) - 1)

        return data[:pos1] + other[pos2:]


class DictionaryMutator(Mutator):
    """Insert dictionary tokens (JSON/MCP keywords)."""

    name = "dictionary"

    TOKENS = [
        b'"jsonrpc"', b'"2.0"', b'"method"', b'"params"', b'"id"',
        b'"result"', b'"error"', b'"code"', b'"message"',
        b'"initialize"', b'"tools/list"', b'"tools/call"',
        b'"resources/read"', b'"resources/list"', b'"prompts/list"',
        b'"notifications/initialized"', b'"ping"',
        b'"protocolVersion"', b'"capabilities"', b'"clientInfo"',
        b'"name"', b'"version"', b'"arguments"',
        b'null', b'true', b'false', b'{}', b'[]',
        b'":"', b'","', b'":', b'":""', b'":"null"',
        b'-1', b'0', b'1', b'-32700', b'-32600', b'-32601', b'-32603',
        b'\\u0000', b'\\x00', b'\\n', b'\\r\\n',
        b'NaN', b'Infinity', b'-Infinity',
        b'../', b'..\\\\', b'%2e%2e%2f',
        b'; ls', b'| cat /etc/passwd', b'`id`', b'$(whoami)',
        b"' OR '1'='1", b'" OR "1"="1', b'1; DROP TABLE',
    ]

    def mutate(self, data: bytes) -> bytes:
        token = random.choice(self.TOKENS)

        if random.random() < 0.5 and len(data) > 0:
            pos = random.randint(0, len(data) - 1)
            length = random.randint(0, min(len(token), len(data) - pos))
            return data[:pos] + token + data[pos + length:]
        else:
            pos = random.randint(0, len(data))
            return data[:pos] + token + data[pos:]


class MutationEngine:
    """Orchestrates mutation strategies with weighted selection."""

    def __init__(self):
        # Raw byte mutators (20% weight - for parser crashes)
        self.byte_mutators: list[Mutator] = [
            BitFlipMutator(),
            ByteFlipMutator(),
            ArithmeticMutator(),
            InterestingValuesMutator(),
            DeleteMutator(),
            InsertMutator(),
            DuplicateMutator(),
            HavocMutator(),
            SpliceMutator(),
            DictionaryMutator(),
        ]

        # MCP-aware mutators (added later, 80% weight - for logic bugs)
        self.mcp_mutators: list[Mutator] = []

        # Weight for MCP-aware mutations (0.0 to 1.0)
        self.mcp_weight: float = 0.8

    def add_mcp_mutators(self, mutators: list[Mutator]):
        """Add MCP-aware mutators with higher priority."""
        self.mcp_mutators = mutators

    def set_mcp_weight(self, weight: float):
        """Set the weight for MCP-aware mutations (0.0 to 1.0)."""
        self.mcp_weight = max(0.0, min(1.0, weight))

    def mutate(self, data: bytes, num_mutations: int = 1) -> bytes:
        """Apply mutations to data with weighted selection."""
        for _ in range(num_mutations):
            # Use MCP-aware mutators with configured weight
            if self.mcp_mutators and random.random() < self.mcp_weight:
                mutator = random.choice(self.mcp_mutators)
            else:
                mutator = random.choice(self.byte_mutators)

            data = mutator.mutate(data)
        return data

    def update_corpus(self, corpus_samples: list[bytes]):
        """Update splice mutator with corpus samples."""
        for mutator in self.byte_mutators:
            if isinstance(mutator, SpliceMutator):
                mutator.set_corpus(corpus_samples)
