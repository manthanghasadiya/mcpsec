"""
Sink scanner -- find dangerous sinks in source code.
"""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import re

from mcpsec.static.patterns.base import SinkPattern, SinkMatch
from mcpsec.static.patterns.registry import get_patterns
from mcpsec.static.framework.detector import FrameworkInfo, Language, _map_language


@dataclass
class ScanResult:
    """Result of sink scanning."""
    matches: list[SinkMatch]
    files_scanned: int
    patterns_applied: int


class SinkScanner:
    """
    Scans source code for dangerous sinks using the pattern database.
    """

    def __init__(
        self,
        context_lines: int = 5,
        exclude_dirs: Optional[list[str]] = None,
        exclude_patterns: Optional[list[str]] = None,
    ):
        self.context_lines = context_lines
        self.exclude_dirs = exclude_dirs or [
            "node_modules", "dist", "build", ".git", "__pycache__",
            "venv", ".venv", "vendor", "test", "tests", "__tests__",
            "spec", "docs", "examples", "fixtures",
        ]
        self.exclude_patterns = exclude_patterns or [
            r"\.test\.",
            r"\.spec\.",
            r"_test\.py$",
            r"test_.*\.py$",
        ]

    def scan(
        self,
        project_path: Path,
        framework_info: FrameworkInfo,
    ) -> ScanResult:
        """Scan project for dangerous sinks."""
        # Map detector language to pattern language
        pattern_lang = _map_language(framework_info.language)

        # Get patterns for detected language
        if pattern_lang is not None:
            patterns = get_patterns(language=pattern_lang)
        else:
            # Unknown language -- use all patterns
            patterns = get_patterns()

        matches: list[SinkMatch] = []
        files_scanned = 0

        scan_root = project_path if project_path.is_dir() else project_path.parent

        # Scan files with matching extensions
        for ext in framework_info.extensions:
            for file_path in scan_root.rglob(f"*{ext}"):
                if self._should_exclude(file_path):
                    continue

                file_matches = self._scan_file(file_path, patterns)
                matches.extend(file_matches)
                files_scanned += 1

        return ScanResult(
            matches=matches,
            files_scanned=files_scanned,
            patterns_applied=len(patterns),
        )

    def scan_file(
        self,
        file_path: Path,
        framework_info: Optional[FrameworkInfo] = None,
    ) -> list[SinkMatch]:
        """Scan a single file for sink patterns."""
        pattern_lang = None
        if framework_info:
            pattern_lang = _map_language(framework_info.language)

        if pattern_lang is not None:
            patterns = get_patterns(language=pattern_lang)
        else:
            patterns = get_patterns()

        return self._scan_file(file_path, patterns)

    def _should_exclude(self, path: Path) -> bool:
        """Check if file should be excluded."""
        path_str = str(path).replace("\\", "/")

        for exclude in self.exclude_dirs:
            if f"/{exclude}/" in path_str:
                return True

        for pattern in self.exclude_patterns:
            if re.search(pattern, str(path.name)):
                return True

        return False

    def _scan_file(
        self,
        file_path: Path,
        patterns: list[SinkPattern],
    ) -> list[SinkMatch]:
        """Scan a single file for sink patterns."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            return []

        matches: list[SinkMatch] = []

        for i, line in enumerate(lines, 1):
            # Skip obvious comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                continue
            # Skip blank lines
            if not stripped:
                continue

            for pattern in patterns:
                if pattern.matches(content, line):
                    # Get surrounding context
                    start = max(0, i - 1 - self.context_lines)
                    end = min(len(lines), i + self.context_lines)

                    context_before = lines[start: i - 1]
                    context_after = lines[i:end]

                    # Extract match text
                    match_text = ""
                    if pattern._compiled:
                        m = pattern._compiled.search(line)
                        if m:
                            match_text = m.group(0)

                    matches.append(SinkMatch(
                        pattern=pattern,
                        file_path=str(file_path),
                        line_number=i,
                        code_line=line,
                        context_before=context_before,
                        context_after=context_after,
                        match_text=match_text,
                    ))

        return matches
