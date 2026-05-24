"""FFmpeg executor types and exceptions (VOD-004).

Dataclasses for execution results, progress tracking, and structured error types
used by the FFmpeg execution layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ProgressSample:
    """A single progress measurement emitted by FFmpeg's -progress protocol."""

    timestamp: float  # Unix time of sample
    out_time_us: int  # FFmpeg's reported output position in microseconds
    frame: int
    fps: float
    speed: float  # e.g. 2.5 means encoding 2.5x faster than real-time


@dataclass
class FFmpegExecutionResult:
    """Structured result from a single rendition FFmpeg execution."""

    success: bool
    returncode: int
    duration_seconds: float
    output_dir: Path
    segments_written: int
    stderr_tail: str  # last 4KB of stderr for error reporting
    progress_samples: list[ProgressSample] = field(default_factory=list)


class RenditionTimeoutError(Exception):
    """Raised when a rendition exceeds its wall-clock timeout."""

    def __init__(self, rendition_name: str, timeout_seconds: int) -> None:
        self.rendition_name = rendition_name
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"Rendition '{rendition_name}' timed out after {timeout_seconds}s"
        )


class RetryableError(Exception):
    """FFmpeg error that is likely transient and can be retried."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


class NonRetryableError(Exception):
    """FFmpeg error that is permanent and should not be retried."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


class OutputValidationError(NonRetryableError):
    """Raised when the output directory does not match expected structure."""

    def __init__(self, message: str) -> None:
        super().__init__("output_validation_failed", message)
