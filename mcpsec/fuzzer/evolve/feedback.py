"""Feedback collection and coverage tracking."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class ResponseType(Enum):
    """Categories of server responses."""
    SUCCESS = auto()           # Normal response
    ERROR_PARSE = auto()       # JSON parse error
    ERROR_VALIDATION = auto()  # Schema validation error
    ERROR_METHOD = auto()      # Method not found
    ERROR_INTERNAL = auto()    # Internal server error
    ERROR_UNKNOWN = auto()     # Unclassified error
    TIMEOUT = auto()           # No response in time
    CRASH = auto()             # Server died
    HANG = auto()              # Server unresponsive but alive
    EMPTY = auto()             # Empty response
    UNEXPECTED = auto()        # Unexpected response structure


@dataclass
class ResponseFingerprint:
    """Unique fingerprint of a server response."""
    response_type: ResponseType
    error_code: int | None = None
    error_message_hash: str | None = None
    response_keys: frozenset[str] = field(default_factory=frozenset)
    response_time_bucket: int = 0
    stack_trace_hash: str | None = None

    def __hash__(self) -> int:
        return hash((
            self.response_type,
            self.error_code,
            self.error_message_hash,
            self.response_keys,
            self.response_time_bucket,
            self.stack_trace_hash,
        ))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ResponseFingerprint):
            return False
        return hash(self) == hash(other)


class FeedbackCollector:
    """Collects and analyzes feedback from server responses."""

    def __init__(self):
        self.seen_fingerprints: set[ResponseFingerprint] = set()
        self.fingerprint_counts: dict[ResponseFingerprint, int] = {}
        self.crash_fingerprints: set[ResponseFingerprint] = set()
        self.total_executions: int = 0
        self.unique_behaviors: int = 0
        self.parse_error_count: int = 0

    def analyze_response(
        self,
        response: dict[str, Any] | None,
        response_time: float,
        crashed: bool = False,
        timeout: bool = False,
        stderr: str | None = None,
    ) -> tuple[ResponseFingerprint, bool]:
        """
        Analyze a response and return its fingerprint.

        Returns:
            Tuple of (fingerprint, is_new_behavior)
        """
        self.total_executions += 1

        fingerprint = self._create_fingerprint(
            response, response_time, crashed, timeout, stderr
        )

        # Track parse errors separately for debugging
        if fingerprint.response_type == ResponseType.ERROR_PARSE:
            self.parse_error_count += 1

        is_new = fingerprint not in self.seen_fingerprints

        if is_new:
            self.seen_fingerprints.add(fingerprint)
            self.unique_behaviors += 1
            self.fingerprint_counts[fingerprint] = 1

            if fingerprint.response_type == ResponseType.CRASH:
                self.crash_fingerprints.add(fingerprint)
        else:
            self.fingerprint_counts[fingerprint] = self.fingerprint_counts.get(fingerprint, 0) + 1

        return fingerprint, is_new

    def _create_fingerprint(
        self,
        response: dict[str, Any] | None,
        response_time: float,
        crashed: bool,
        timeout: bool,
        stderr: str | None,
    ) -> ResponseFingerprint:
        """Create a fingerprint from response data."""

        # Determine response type
        if crashed:
            response_type = ResponseType.CRASH
        elif timeout:
            response_type = ResponseType.TIMEOUT
        elif response is None:
            response_type = ResponseType.EMPTY
        elif isinstance(response, dict) and "error" in response:
            response_type = self._classify_error(response.get("error", {}))
        elif isinstance(response, dict) and "result" in response:
            response_type = ResponseType.SUCCESS
        else:
            response_type = ResponseType.UNEXPECTED

        # Extract error details
        error_code = None
        error_message_hash = None
        if isinstance(response, dict) and "error" in response:
            error = response["error"]
            error_code = error.get("code")
            if error.get("message"):
                error_message_hash = hashlib.md5(
                    str(error["message"])[:200].encode()
                ).hexdigest()[:8]

        # Extract response structure
        response_keys = frozenset()
        if response and isinstance(response, dict):
            response_keys = frozenset(response.keys())

        # Bucket response time
        time_bucket = self._bucket_time(response_time)

        # Hash stack trace if present
        stack_hash = None
        if stderr and ("Traceback" in stderr or "panic" in stderr or "Error" in stderr):
            stack_hash = hashlib.md5(stderr[:500].encode()).hexdigest()[:8]

        return ResponseFingerprint(
            response_type=response_type,
            error_code=error_code,
            error_message_hash=error_message_hash,
            response_keys=response_keys,
            response_time_bucket=time_bucket,
            stack_trace_hash=stack_hash,
        )

    def _classify_error(self, error: dict[str, Any]) -> ResponseType:
        """Classify error type from JSON-RPC error object."""
        code = error.get("code", 0)
        message = str(error.get("message", "")).lower()

        if code == -32700:
            return ResponseType.ERROR_PARSE
        elif code == -32600:
            return ResponseType.ERROR_VALIDATION
        elif code == -32601:
            return ResponseType.ERROR_METHOD
        elif code == -32603:
            return ResponseType.ERROR_INTERNAL
        elif "parse" in message or "json" in message:
            return ResponseType.ERROR_PARSE
        elif "valid" in message or "schema" in message:
            return ResponseType.ERROR_VALIDATION
        else:
            return ResponseType.ERROR_UNKNOWN

    def _bucket_time(self, response_time: float) -> int:
        """Bucket response time into categories."""
        ms = response_time * 1000
        if ms < 10:
            return 0
        elif ms < 50:
            return 1
        elif ms < 200:
            return 2
        elif ms < 1000:
            return 3
        else:
            return 4

    def get_stats(self) -> dict[str, Any]:
        """Return fuzzing statistics."""
        return {
            "total_executions": self.total_executions,
            "unique_behaviors": self.unique_behaviors,
            "crash_count": len(self.crash_fingerprints),
            "parse_error_count": self.parse_error_count,
            "parse_error_ratio": self.parse_error_count / max(self.total_executions, 1),
            "coverage_percent": (self.unique_behaviors / max(self.total_executions, 1)) * 100,
        }
