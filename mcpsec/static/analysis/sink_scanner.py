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
            "spec", "docs", "examples", "fixtures", "patterns",
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
        explicit: bool = False,
    ) -> ScanResult:
        """Scan project for dangerous sinks.

        Args:
            project_path: File or directory to scan.
            framework_info: Detected framework / language info.
            explicit: When True the caller explicitly pointed at this path
                (e.g. via ``--path``).  Exclusion logic is relaxed:
                - A single FILE is always scanned regardless of its name.
                - The top-level DIRECTORY itself is never excluded; exclusions
                  only apply to files discovered *inside* it.
        """
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

        # ── Single-file path ──────────────────────────────────────────────
        if project_path.is_file():
            # User explicitly pointed at this file; scan it with no exclusions.
            file_matches = self._scan_file(project_path, patterns)
            matches.extend(file_matches)
            files_scanned = 1
            return ScanResult(
                matches=matches,
                files_scanned=files_scanned,
                patterns_applied=len(patterns),
            )

        # ── Directory path ────────────────────────────────────────────────
        scan_root = project_path

        for ext in framework_info.extensions:
            for file_path in scan_root.rglob(f"*{ext}"):
                # When the user explicitly passed this directory, never
                # exclude the root itself -- only filter descendants.
                if explicit and file_path.parent == scan_root:
                    pass  # always include direct children of explicit root
                elif self._should_exclude(file_path):
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
        """Check if a file discovered during recursive scan should be excluded.

        Exclusions match any *directory component* in the path (not the root
        that the user explicitly passed) or filename patterns.
        """
        path_str = str(path).replace("\\", "/")

        for exclude in self.exclude_dirs:
            # Match the segment anywhere except right at the very start
            # so that an explicitly-passed root dir never self-excludes.
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

        for pattern in patterns:
            if not pattern._compiled:
                continue

            for match in pattern._compiled.finditer(content):
                # Verify negative patterns
                skip = False
                for neg in pattern._negative_compiled:
                    if neg.search(content):
                        skip = True
                        break
                if skip:
                    continue

                start_idx = match.start()
                line_idx = content.count('\n', 0, start_idx)
                i = line_idx + 1  # 1-indexed line number
                
                if line_idx >= len(lines):
                    continue
                    
                line = lines[line_idx]
                stripped = line.strip()
                # Skip obvious comments
                if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                    continue

                # Get surrounding context
                start = max(0, i - 1 - self.context_lines)
                end = min(len(lines), i + self.context_lines)

                context_before = lines[start: i - 1]
                context_after = lines[i:end]
                match_text = match.group(0)

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
