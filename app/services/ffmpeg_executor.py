"""FFmpeg execution layer with progress parsing, error classification, and resource limits (VOD-004).

Wraps asyncio.create_subprocess_exec with:
- Real-time progress parsing from FFmpeg's `-progress pipe:1` protocol
- Structured error classification (retryable vs non-retryable)
- Resource limits (CPU nice, memory cap, file size cap, thread control)
- Wall-clock timeout + cooperative cancellation via asyncio.Event
- Argument augmentation (VOD HLS flags, rate control, thread limits)
- Restricted subprocess environment (no secrets leaked)
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import resource
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

from app.core.settings import S
from app.services.ffmpeg_executor_types import (
    FFmpegExecutionResult,
    NonRetryableError,
    ProgressSample,
    RenditionTimeoutError,
    RetryableError,
)

logger = logging.getLogger(__name__)

# ─── Error classification patterns ───────────────────────────────────────────

_ERROR_PATTERNS: list[tuple[str, str, bool]] = [
    # (stderr_pattern, error_code, is_retryable)
    ("No such file or directory", "source_not_found", False),
    ("Server returned 404", "source_not_found", False),
    ("Invalid data found when processing input", "invalid_input", False),
    ("Invalid data found", "invalid_input", False),
    ("Decoder .* not found", "unsupported_codec", False),
    ("Unknown encoder", "unsupported_codec", False),
    ("No space left on device", "disk_full", True),
    ("Cannot allocate memory", "oom", True),
    ("Connection timed out", "network_timeout", True),
    ("Connection refused", "network_error", True),
    ("End of file", "source_truncated", True),
    ("broken pipe", "broken_pipe", True),
]

# Compiled regex patterns for entries that use regex syntax
_ERROR_REGEX_PATTERNS: list[tuple[re.Pattern[str], str, bool]] = [
    (re.compile(pattern, re.IGNORECASE), code, retryable)
    for pattern, code, retryable in _ERROR_PATTERNS
    if ".*" in pattern or "+" in pattern
]

_ERROR_SIMPLE_PATTERNS: list[tuple[str, str, bool]] = [
    (pattern.lower(), code, retryable)
    for pattern, code, retryable in _ERROR_PATTERNS
    if ".*" not in pattern and "+" not in pattern
]


# ─── Public API ───────────────────────────────────────────────────────────────


async def execute_rendition(
    *,
    args: list[str],
    rendition_name: str,
    expected_duration_us: int,
    timeout_seconds: int,
    on_progress: Callable[[ProgressSample, int], Awaitable[None]] | None = None,
    cancel_event: asyncio.Event | None = None,
) -> FFmpegExecutionResult:
    """Execute a single FFmpeg rendition with progress tracking and resource limits.

    Args:
        args: FFmpeg command-line arguments (from build_rendition_ffmpeg_args)
        rendition_name: Human-readable name (e.g. "720p") for logging
        expected_duration_us: Expected output duration in microseconds for progress %
        timeout_seconds: Wall-clock timeout before SIGTERM
        on_progress: Optional async callback receiving (ProgressSample, overall_pct)
        cancel_event: Optional event that triggers graceful termination when set

    Returns:
        FFmpegExecutionResult with success/failure details

    Raises:
        RenditionTimeoutError: If the process exceeds timeout_seconds
        RetryableError: If cancel_event fires (caller should retry or mark cancelled)
    """
    start_time = time.monotonic()

    # 1. Pre-flight: check disk space
    output_dir = _extract_output_dir(args)
    if output_dir:
        _check_disk_space(output_dir, S.ffmpeg_min_free_disk_gb)

    # 2. Validate and augment args
    validated_args = _validate_and_augment_args(args, expected_duration_us)

    # 3. Construct restricted environment
    env = _build_restricted_env()

    # 4. Launch subprocess
    proc = await asyncio.create_subprocess_exec(
        *validated_args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.DEVNULL,
        env=env,
        preexec_fn=_apply_resource_limits,
    )

    logger.info(
        "FFmpeg started for rendition '%s' (pid=%d, timeout=%ds)",
        rendition_name,
        proc.pid,
        timeout_seconds,
    )

    # 5. Concurrently read stdout (progress) and stderr (errors)
    progress_task = asyncio.create_task(
        _read_progress(proc.stdout, expected_duration_us, on_progress)
    )
    stderr_task = asyncio.create_task(_read_stderr_tail(proc.stderr))

    # 6. Wait with timeout and cancellation
    try:
        await asyncio.wait_for(
            _wait_with_cancel(proc, cancel_event),
            timeout=timeout_seconds,
        )
    except asyncio.TimeoutError:
        await _terminate_gracefully(proc, S.ffmpeg_grace_kill_seconds)
        # Collect what we have
        progress_samples = await progress_task
        stderr_tail = await stderr_task
        raise RenditionTimeoutError(rendition_name, timeout_seconds)

    # 7. Collect results
    progress_samples = await progress_task
    stderr_tail = await stderr_task

    duration_seconds = time.monotonic() - start_time
    segments_written = _count_segments(output_dir) if output_dir else 0

    result = FFmpegExecutionResult(
        success=(proc.returncode == 0),
        returncode=proc.returncode or 0,
        duration_seconds=duration_seconds,
        output_dir=output_dir or Path("."),
        segments_written=segments_written,
        stderr_tail=stderr_tail,
        progress_samples=progress_samples,
    )

    if result.success:
        logger.info(
            "Rendition '%s' completed in %.1fs (%d segments)",
            rendition_name,
            duration_seconds,
            segments_written,
        )
    else:
        logger.warning(
            "Rendition '%s' failed (exit=%d) in %.1fs: %s",
            rendition_name,
            result.returncode,
            duration_seconds,
            stderr_tail[:200],
        )

    return result


# ─── Argument validation and augmentation ─────────────────────────────────────


def _validate_and_augment_args(args: list[str], expected_duration_us: int) -> list[str]:
    """Validate input args and inject progress/VOD/rate-control/thread flags."""
    if not isinstance(args, list) or not all(isinstance(part, str) for part in args):
        raise ValueError("FFmpeg args must be a list[str]")
    if any("\x00" in part for part in args):
        raise ValueError("FFmpeg args contain null byte")

    binary = S.ffmpeg_binary_path or "ffmpeg"
    # Allow the configured binary name or "ffmpeg"
    if args[0] not in (binary, "ffmpeg"):
        raise ValueError(f"Expected 'ffmpeg' or '{binary}' as first arg, got '{args[0]}'")

    augmented = list(args)

    # Replace the binary with the configured path
    augmented[0] = binary

    # 1. Add -nostdin to prevent interactive prompts
    augmented.insert(1, "-nostdin")

    # 2. Add -progress pipe:1 for progress reporting
    augmented.insert(2, "-progress")
    augmented.insert(3, "pipe:1")

    # 3. Patch HLS flags for VOD output
    augmented = _patch_args_for_vod(augmented)

    # 4. Add maxrate/bufsize for quality control
    augmented = _inject_rate_control(augmented)

    # 5. Limit threads
    max_threads = S.ffmpeg_max_threads_per_job
    if max_threads <= 0:
        cpu_count = os.cpu_count() or 4
        max_concurrent = max(1, S.transcode_max_concurrent_jobs)
        max_threads = max(1, cpu_count // max_concurrent)
    augmented = _inject_thread_limit(augmented, max_threads)

    return augmented


def _patch_args_for_vod(args: list[str]) -> list[str]:
    """Replace live-streaming HLS flags with VOD-appropriate flags."""
    patched: list[str] = []
    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg == "-hls_list_size" and i + 1 < len(args):
            patched.extend(["-hls_list_size", "0"])
            skip_next = True
        elif arg == "-hls_flags" and i + 1 < len(args):
            patched.extend(["-hls_flags", "independent_segments"])
            skip_next = True
        else:
            patched.append(arg)

    # Inject VOD playlist type if not present
    if "-hls_playlist_type" not in patched:
        # Insert before output file (last positional arg)
        patched.insert(-1, "-hls_playlist_type")
        patched.insert(-1, "vod")

    return patched


def _inject_rate_control(args: list[str]) -> list[str]:
    """Find -b:v Xk and add -maxrate at 1.2x, -bufsize at 2x."""
    if "-maxrate" in args:
        return args  # already specified

    bitrate_kbps: int | None = None
    bitrate_idx: int | None = None
    for i, arg in enumerate(args):
        if arg == "-b:v" and i + 1 < len(args):
            val = args[i + 1]
            if val.endswith("k"):
                try:
                    bitrate_kbps = int(val[:-1])
                    bitrate_idx = i + 1
                except ValueError:
                    pass
            break

    if bitrate_kbps is None or bitrate_idx is None:
        return args

    maxrate = int(bitrate_kbps * 1.2)
    bufsize = bitrate_kbps * 2
    result = list(args)
    insert_pos = bitrate_idx + 1
    result.insert(insert_pos, "-maxrate")
    result.insert(insert_pos + 1, f"{maxrate}k")
    result.insert(insert_pos + 2, "-bufsize")
    result.insert(insert_pos + 3, f"{bufsize}k")
    return result


def _inject_thread_limit(args: list[str], max_threads: int) -> list[str]:
    """Inject -threads flag after the input specification."""
    if "-threads" in args:
        return args  # already specified

    # Insert after -i <url>
    insert_pos = 2  # fallback: after ffmpeg -nostdin
    for i, arg in enumerate(args):
        if arg == "-i" and i + 1 < len(args):
            insert_pos = i + 2
            break

    result = list(args)
    result.insert(insert_pos, "-threads")
    result.insert(insert_pos + 1, str(max_threads))
    return result


# ─── Subprocess environment ───────────────────────────────────────────────────


def _build_restricted_env() -> dict[str, str]:
    """Construct a minimal environment for the FFmpeg subprocess. No secrets."""
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def _apply_resource_limits() -> None:
    """Called in child process before exec(). Sets rlimits and nice value."""
    # CPU time limit (safety net)
    soft_cpu = 7200  # 2 hours CPU time
    hard_cpu = 7500
    resource.setrlimit(resource.RLIMIT_CPU, (soft_cpu, hard_cpu))

    # Virtual memory limit
    mem_gb = S.ffmpeg_max_memory_gb if S.ffmpeg_max_memory_gb > 0 else 8
    mem_limit = mem_gb * 1024 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))

    # File size limit: 50GB
    file_limit = 50 * 1024 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))

    # Lower priority than API process
    os.nice(10)


# ─── Progress parsing ─────────────────────────────────────────────────────────


async def _read_progress(
    stream: asyncio.StreamReader | None,
    expected_duration_us: int,
    on_progress: Callable[[ProgressSample, int], Awaitable[None]] | None,
) -> list[ProgressSample]:
    """Parse FFmpeg progress protocol from stdout, call on_progress with samples."""
    samples: list[ProgressSample] = []
    if stream is None:
        return samples

    current_frame: dict[str, str] = {}

    async for raw_line in stream:
        line = raw_line.decode("utf-8", errors="replace").strip()
        if not line or "=" not in line:
            continue

        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        current_frame[key] = value

        if key == "progress":
            sample = _parse_progress_frame(current_frame)
            if sample:
                samples.append(sample)
                if on_progress and expected_duration_us > 0:
                    pct = min(100, int((sample.out_time_us / expected_duration_us) * 100))
                    try:
                        await on_progress(sample, pct)
                    except Exception:
                        pass  # Don't let callback errors kill progress reading
            current_frame = {}

    return samples


def _parse_progress_frame(frame: dict[str, str]) -> ProgressSample | None:
    """Extract a ProgressSample from a key-value progress block."""
    try:
        out_time_us = int(frame.get("out_time_us", "0"))
    except (ValueError, TypeError):
        out_time_us = 0

    try:
        frame_num = int(frame.get("frame", "0"))
    except (ValueError, TypeError):
        frame_num = 0

    try:
        fps = float(frame.get("fps", "0"))
    except (ValueError, TypeError):
        fps = 0.0

    speed_str = frame.get("speed", "0x").rstrip("x").strip()
    try:
        speed = float(speed_str) if speed_str and speed_str != "N/A" else 0.0
    except (ValueError, TypeError):
        speed = 0.0

    if out_time_us <= 0 and frame_num <= 0:
        return None

    return ProgressSample(
        timestamp=time.time(),
        out_time_us=out_time_us,
        frame=frame_num,
        fps=fps,
        speed=speed,
    )


# ─── Stderr ring buffer ──────────────────────────────────────────────────────


async def _read_stderr_tail(
    stream: asyncio.StreamReader | None, max_bytes: int = 4096
) -> str:
    """Collect the last max_bytes of stderr output as a string."""
    if stream is None:
        return ""

    buffer = bytearray()
    async for chunk in stream:
        buffer.extend(chunk)
        if len(buffer) > max_bytes * 2:
            # Keep only the last max_bytes to avoid unbounded growth
            buffer = buffer[-max_bytes:]

    # Return only the last max_bytes
    tail = bytes(buffer[-max_bytes:]) if len(buffer) > max_bytes else bytes(buffer)
    return tail.decode("utf-8", errors="replace")


# ─── Process lifecycle ────────────────────────────────────────────────────────


async def _wait_with_cancel(
    proc: asyncio.subprocess.Process,
    cancel_event: asyncio.Event | None,
) -> int:
    """Wait for process to exit, or terminate if cancel_event fires."""
    if cancel_event is None:
        return await proc.wait()

    # Race between process completion and cancellation
    wait_task = asyncio.create_task(proc.wait())
    cancel_task = asyncio.create_task(cancel_event.wait())

    done, pending = await asyncio.wait(
        {wait_task, cancel_task}, return_when=asyncio.FIRST_COMPLETED
    )

    for task in pending:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    if cancel_task in done:
        # Cancellation requested
        await _terminate_gracefully(proc, S.ffmpeg_grace_kill_seconds)
        raise RetryableError("cancelled", "Job cancellation requested")

    return wait_task.result()


async def _terminate_gracefully(
    proc: asyncio.subprocess.Process, grace_seconds: int = 5
) -> None:
    """Send SIGTERM, wait grace period, then SIGKILL if still alive."""
    if proc.returncode is not None:
        return  # already exited

    try:
        proc.terminate()  # SIGTERM
    except ProcessLookupError:
        return

    try:
        await asyncio.wait_for(proc.wait(), timeout=grace_seconds)
    except asyncio.TimeoutError:
        try:
            proc.kill()  # SIGKILL
        except ProcessLookupError:
            return
        await proc.wait()


# ─── Disk space check ─────────────────────────────────────────────────────────


def _check_disk_space(path: Path, min_free_gb: float = 5.0) -> None:
    """Verify sufficient disk space before starting a rendition."""
    try:
        stat = os.statvfs(path if path.exists() else path.parent)
        free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
        if free_gb < min_free_gb:
            raise RetryableError(
                "disk_full",
                f"Only {free_gb:.1f}GB free, need {min_free_gb}GB",
            )
    except OSError:
        pass  # Can't check — proceed anyway


# ─── Error classification ─────────────────────────────────────────────────────


def classify_error(returncode: int, stderr_tail: str) -> tuple[str, bool]:
    """Classify an FFmpeg error from exit code and stderr. Returns (code, is_retryable)."""
    stderr_lower = stderr_tail.lower()

    # Check simple substring patterns first
    for pattern, code, retryable in _ERROR_SIMPLE_PATTERNS:
        if pattern in stderr_lower:
            return code, retryable

    # Check regex patterns
    for regex, code, retryable in _ERROR_REGEX_PATTERNS:
        if regex.search(stderr_tail):
            return code, retryable

    # Default: unknown error, assume retryable (transient)
    return f"ffmpeg_exit_{returncode}", True


# ─── Output validation ────────────────────────────────────────────────────────


def validate_output(output_dir: Path, rendition_names: list[str]) -> None:
    """Verify the output directory has the expected HLS structure.

    Raises OutputValidationError on missing files.
    """
    from app.services.ffmpeg_executor_types import OutputValidationError

    master = output_dir / "master.m3u8"
    if not master.exists():
        raise OutputValidationError("master.m3u8 missing")

    for name in rendition_names:
        playlist = output_dir / name / "index.m3u8"
        if not playlist.exists():
            raise OutputValidationError(f"{name}/index.m3u8 missing")
        segments = list((output_dir / name).glob("seg_*.ts"))
        if not segments:
            raise OutputValidationError(f"{name}/ has no segments")


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _extract_output_dir(args: list[str]) -> Path | None:
    """Try to find the output directory from the args (last arg is the output file)."""
    if not args:
        return None
    # The last arg is typically the output playlist path
    last_arg = args[-1]
    if last_arg.endswith(".m3u8"):
        return Path(last_arg).parent.parent  # e.g. output/720p/index.m3u8 -> output/
    return None


def _count_segments(output_dir: Path) -> int:
    """Count .ts segment files in the output directory tree."""
    if not output_dir or not output_dir.exists():
        return 0
    return len(list(output_dir.rglob("seg_*.ts")))
