"""Corpus management for coverage-guided fuzzing."""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .feedback import ResponseFingerprint, ResponseType


@dataclass
class CorpusEntry:
    """A single entry in the fuzzing corpus."""

    data: bytes
    fingerprint: ResponseFingerprint
    created_at: float = field(default_factory=time.time)
    executions: int = 0
    children: int = 0
    energy: float = 1.0
    source: str = "seed"
    parent_hash: str | None = None

    @property
    def data_hash(self) -> str:
        """Unique hash of the input data."""
        return hashlib.sha256(self.data).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "data": self.data.hex(),
            "fingerprint_type": self.fingerprint.response_type.name,
            "fingerprint_error_code": self.fingerprint.error_code,
            "fingerprint_stack_hash": self.fingerprint.stack_trace_hash,
            "created_at": self.created_at,
            "executions": self.executions,
            "children": self.children,
            "energy": self.energy,
            "source": self.source,
            "parent_hash": self.parent_hash,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CorpusEntry":
        """Deserialize from dictionary."""
        fingerprint = ResponseFingerprint(
            response_type=ResponseType[d["fingerprint_type"]],
            error_code=d.get("fingerprint_error_code"),
            stack_trace_hash=d.get("fingerprint_stack_hash"),
        )
        return cls(
            data=bytes.fromhex(d["data"]),
            fingerprint=fingerprint,
            created_at=d.get("created_at", time.time()),
            executions=d.get("executions", 0),
            children=d.get("children", 0),
            energy=d.get("energy", 1.0),
            source=d.get("source", "seed"),
            parent_hash=d.get("parent_hash"),
        )


class Corpus:
    """Manages the fuzzing corpus."""

    def __init__(self, corpus_dir: Path | str | None = None):
        self.entries: dict[str, CorpusEntry] = {}
        self.fingerprint_to_entries: dict[ResponseFingerprint, list[str]] = {}
        self.crash_entries: list[str] = []
        self.corpus_dir = Path(corpus_dir) if corpus_dir else None

        if self.corpus_dir:
            self.corpus_dir.mkdir(parents=True, exist_ok=True)

    def add(self, entry: CorpusEntry) -> bool:
        """
        Add entry to corpus if it represents new behavior.

        Returns True if added (new behavior), False if duplicate.
        """
        data_hash = entry.data_hash

        if data_hash in self.entries:
            self.entries[data_hash].executions += 1
            return False

        self.entries[data_hash] = entry

        if entry.fingerprint not in self.fingerprint_to_entries:
            self.fingerprint_to_entries[entry.fingerprint] = []
        self.fingerprint_to_entries[entry.fingerprint].append(data_hash)

        if entry.fingerprint.response_type == ResponseType.CRASH:
            self.crash_entries.append(data_hash)

        if self.corpus_dir:
            self._save_entry(entry)

        return True

    def get_samples(self, n: int | None = None) -> list[bytes]:
        """Get raw data samples from corpus."""
        entries = list(self.entries.values())
        if n:
            entries = entries[:n]
        return [e.data for e in entries]

    def get_entry(self, data_hash: str) -> CorpusEntry | None:
        """Get entry by hash."""
        return self.entries.get(data_hash)

    def select_for_mutation(self) -> CorpusEntry | None:
        """Select an entry for mutation based on energy."""
        if not self.entries:
            return None

        entries = list(self.entries.values())
        weights = [e.energy for e in entries]
        total = sum(weights)

        if total == 0:
            return entries[0] if entries else None

        weights = [w / total for w in weights]

        import random
        return random.choices(entries, weights=weights, k=1)[0]

    def update_energy(self, data_hash: str, produced_new: bool):
        """Update entry energy based on whether it produced new behavior."""
        entry = self.entries.get(data_hash)
        if not entry:
            return

        entry.executions += 1

        if produced_new:
            entry.children += 1
            entry.energy = min(entry.energy * 1.5, 10.0)
        else:
            entry.energy = max(entry.energy * 0.95, 0.1)

    def minimize(self, max_per_fingerprint: int = 3):
        """Minimize corpus by keeping only the smallest inputs per fingerprint."""
        minimized: dict[str, CorpusEntry] = {}

        for fingerprint, hashes in self.fingerprint_to_entries.items():
            entries = [(h, self.entries[h]) for h in hashes if h in self.entries]
            entries.sort(key=lambda x: len(x[1].data))

            for h, entry in entries[:max_per_fingerprint]:
                minimized[h] = entry

        for h in self.crash_entries:
            if h in self.entries:
                minimized[h] = self.entries[h]

        self.entries = minimized

    def _save_entry(self, entry: CorpusEntry):
        """Save entry to disk."""
        if not self.corpus_dir:
            return

        entry_file = self.corpus_dir / f"{entry.data_hash}.json"
        with open(entry_file, "w") as f:
            json.dump(entry.to_dict(), f, indent=2)

        payload_file = self.corpus_dir / f"{entry.data_hash}.bin"
        with open(payload_file, "wb") as f:
            f.write(entry.data)

    def load(self):
        """Load corpus from disk."""
        if not self.corpus_dir or not self.corpus_dir.exists():
            return

        for entry_file in self.corpus_dir.glob("*.json"):
            try:
                with open(entry_file, "r") as f:
                    data = json.load(f)
                entry = CorpusEntry.from_dict(data)
                self.entries[entry.data_hash] = entry

                if entry.fingerprint not in self.fingerprint_to_entries:
                    self.fingerprint_to_entries[entry.fingerprint] = []
                self.fingerprint_to_entries[entry.fingerprint].append(entry.data_hash)

                if entry.fingerprint.response_type == ResponseType.CRASH:
                    self.crash_entries.append(entry.data_hash)
            except Exception:
                continue

    def get_crashes(self) -> list[CorpusEntry]:
        """Get all crash-inducing entries."""
        return [self.entries[h] for h in self.crash_entries if h in self.entries]

    def stats(self) -> dict[str, Any]:
        """Return corpus statistics."""
        return {
            "total_entries": len(self.entries),
            "unique_fingerprints": len(self.fingerprint_to_entries),
            "crash_entries": len(self.crash_entries),
            "avg_entry_size": sum(len(e.data) for e in self.entries.values()) / max(len(self.entries), 1),
        }
