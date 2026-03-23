"""Input scheduling for evolutionary fuzzing."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .corpus import Corpus, CorpusEntry


class Scheduler:
    """Schedules inputs for fuzzing based on various strategies."""

    def __init__(self, corpus: "Corpus"):
        self.corpus = corpus
        self.current_index = 0
        self.cycle_count = 0

    def next(self) -> "CorpusEntry | None":
        """Get next input to fuzz."""
        return self.corpus.select_for_mutation()

    def notify_new_coverage(self, entry: "CorpusEntry"):
        """Called when new coverage is discovered."""
        if entry.parent_hash:
            self.corpus.update_energy(entry.parent_hash, produced_new=True)

    def cycle_complete(self):
        """Called when a full cycle through corpus completes."""
        self.cycle_count += 1

        if self.cycle_count % 10 == 0:
            self.corpus.minimize()
