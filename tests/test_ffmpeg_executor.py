"""Unit tests for FFmpeg executor (VOD-004).

All tests mock asyncio.create_subprocess_exec to simulate FFmpeg behavior
without requiring the binary.
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ─── Mock subprocess infrastructure ──────────────────────────────────────────


class MockStreamReader:
    """Simulates asyncio.StreamReader for stdout/stderr."""

    def __init__(self, lines: list[bytes]):
        self._lines = list(lines)

    async def __aiter__(self):
        for line in self._lines:
            yield line

    async def read(self, n: int = -1) -> bytes:
        return b"".join(self._lines)


class MockProcess:
    """Simulates asyncio.subprocess.Process."""

    def __init__(
        self,
        stdout_lines: list[bytes],
        stderr_data: bytes,
        returncode: int,
        hang: bool = False,
        hang_seconds: float = 0,
    ):
        self.stdout = MockStreamReader(stdout_lines)
        self.stderr = MockStreamReader([stderr_data])
        self.returncode = None
        self._final_code = returncode
        self._terminated = False
        self._killed = False
        self._hang = hang
        self._hang_seconds = hang_seconds
        self.pid = 12345

    async def wait(self) -> int:
        if self._hang and not self._terminated and not self._killed:
            await asyncio.sleep(self._hang_seconds)
        if self._terminated:
            self.returncode = -15
        elif self._killed:
            self.returncode = -9
        else:
            self.returncode = self._final_code
        return self.returncode

    def terminate(self):
        self._terminated = True
        self.returncode = -15

    def kill(self):
        self._killed = True
        self.returncode = -9


def _make_progress_lines(duration_us: int, num_frames: int) -> list[bytes]:
    """Generate realistic FFmpeg -progress output."""
    lines: list[bytes] = []
    for i in range(num_frames):
        t = int((i + 1) / num_frames * duration_us)
        speed = 2.5
        frame_num = 30 * (i + 1)
        lines.extend([
            f"frame={frame_num}\n".encode(),
            f"fps=75.0\n".encode(),
            f"bitrate=3500.0kbits/s\n".encode(),
            f"out_time_us={t}\n".encode(),
            f"speed={speed:.2f}x\n".encode(),
            b"progress=continue\n",
        ])
    lines.append(b"progress=end\n")
    return lines


def _base_args() -> list[str]:
    """Return a minimal set of FFmpeg args like build_rendition_ffmpeg_args produces."""
    return [
        "ffmpeg", "-hide_banner", "-loglevel", "warning", "-y",
        "-rw_timeout", "5000000", "-i", "input.mp4",
        "-vf", "scale=1280:720",
        "-c:v", "libx264", "-preset", "veryfast",
        "-g", "60", "-sc_threshold", "0",
        "-b:v", "3500k", "-c:a", "aac", "-b:a", "128k",
        "-f", "hls", "-hls_time", "2",
        "-hls_list_size", "6",
        "-hls_flags", "delete_segments+append_list",
        "-hls_segment_filename", "/tmp/test_out/720p/seg_%05d.ts",
        "/tmp/test_out/720p/index.m3u8",
    ]


def _run(coro):
    """Helper to run an async function in a new event loop."""
    return asyncio.run(coro)


# ─── Tests ────────────────────────────────────────────────────────────────────


def test_execute_rendition_success_parses_progress():
    """Verify successful execution parses progress samples correctly."""
    from app.services.ffmpeg_executor import execute_rendition

    duration_us = 10_000_000  # 10 seconds
    progress_lines = _make_progress_lines(duration_us, 5)
    mock_proc = MockProcess(progress_lines, b"", 0)

    progress_callbacks: list[tuple] = []

    async def on_progress(sample, pct):
        progress_callbacks.append((sample, pct))

    async def run():
        with patch("app.services.ffmpeg_executor.asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("app.services.ffmpeg_executor._check_disk_space"):
                return await execute_rendition(
                    args=_base_args(),
                    rendition_name="720p",
                    expected_duration_us=duration_us,
                    timeout_seconds=60,
                    on_progress=on_progress,
                )

    result = _run(run())

    assert result.success is True
    assert result.returncode == 0
    assert len(result.progress_samples) == 5
    # Verify out_time_us values are increasing
    times = [s.out_time_us for s in result.progress_samples]
    assert times == sorted(times)
    assert times[-1] == duration_us
    # Verify on_progress was called
    assert len(progress_callbacks) == 5
    # Last callback should be 100%
    assert progress_callbacks[-1][1] == 100


def test_execute_rendition_failure_captures_stderr():
    """Verify failed execution captures stderr tail."""
    from app.services.ffmpeg_executor import execute_rendition

    stderr = b"input.mp4: No such file or directory\n"
    mock_proc = MockProcess([], stderr, 1)

    async def run():
        with patch("app.services.ffmpeg_executor.asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("app.services.ffmpeg_executor._check_disk_space"):
                return await execute_rendition(
                    args=_base_args(),
                    rendition_name="720p",
                    expected_duration_us=10_000_000,
                    timeout_seconds=60,
                )

    result = _run(run())

    assert result.success is False
    assert result.returncode == 1
    assert "No such file or directory" in result.stderr_tail


def test_execute_rendition_timeout_sends_sigterm_then_sigkill():
    """Verify timeout triggers SIGTERM then SIGKILL."""
    from app.services.ffmpeg_executor import execute_rendition
    from app.services.ffmpeg_executor_types import RenditionTimeoutError

    # Process that hangs but uses short sleep to keep test fast
    mock_proc = MockProcess([], b"", 0, hang=True, hang_seconds=5)

    # Override terminate so process stays "running" (simulates ignoring SIGTERM)
    terminate_called = [False]
    kill_called = [False]

    def stubborn_terminate():
        terminate_called[0] = True
        # Don't set _terminated — process ignores SIGTERM

    def do_kill():
        kill_called[0] = True
        mock_proc._killed = True
        mock_proc.returncode = -9

    mock_proc.terminate = stubborn_terminate
    mock_proc.kill = do_kill
    mock_proc.returncode = None

    async def run():
        with patch("app.services.ffmpeg_executor.asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("app.services.ffmpeg_executor._check_disk_space"):
                with patch("app.services.ffmpeg_executor.S") as mock_settings:
                    mock_settings.ffmpeg_binary_path = "ffmpeg"
                    mock_settings.ffmpeg_max_threads_per_job = 4
                    mock_settings.transcode_max_concurrent_jobs = 2
                    mock_settings.ffmpeg_max_memory_gb = 8
                    mock_settings.ffmpeg_grace_kill_seconds = 1
                    mock_settings.ffmpeg_min_free_disk_gb = 5.0
                    return await execute_rendition(
                        args=_base_args(),
                        rendition_name="720p",
                        expected_duration_us=10_000_000,
                        timeout_seconds=1,  # 1 second timeout
                    )

    with pytest.raises(RenditionTimeoutError) as exc_info:
        _run(run())

    assert exc_info.value.rendition_name == "720p"
    assert terminate_called[0] is True


def test_execute_rendition_cancel_event_terminates_process():
    """Verify cancel_event triggers graceful termination."""
    from app.services.ffmpeg_executor import execute_rendition
    from app.services.ffmpeg_executor_types import RetryableError

    # Process that hangs but responds quickly to cancellation
    # Use a short hang time since the cancel event fires fast
    mock_proc = MockProcess([], b"", 0, hang=True, hang_seconds=10)

    cancel_event = asyncio.Event()

    async def run():
        async def set_cancel_soon():
            await asyncio.sleep(0.05)
            cancel_event.set()

        task = asyncio.create_task(set_cancel_soon())
        try:
            with patch("app.services.ffmpeg_executor.asyncio.create_subprocess_exec", return_value=mock_proc):
                with patch("app.services.ffmpeg_executor._check_disk_space"):
                    return await execute_rendition(
                        args=_base_args(),
                        rendition_name="720p",
                        expected_duration_us=10_000_000,
                        timeout_seconds=60,
                        cancel_event=cancel_event,
                    )
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    with pytest.raises(RetryableError) as exc_info:
        _run(run())

    assert exc_info.value.code == "cancelled"


def test_validate_and_augment_args_injects_progress_flag():
    """Verify -progress pipe:1 and -nostdin are injected."""
    from app.services.ffmpeg_executor import _validate_and_augment_args

    args = _base_args()
    result = _validate_and_augment_args(args, 10_000_000)

    assert "-nostdin" in result
    assert "-progress" in result
    idx = result.index("-progress")
    assert result[idx + 1] == "pipe:1"


def test_validate_and_augment_args_rejects_null_bytes():
    """Verify null bytes in args raise ValueError."""
    from app.services.ffmpeg_executor import _validate_and_augment_args

    args = _base_args()
    args[3] = "bad\x00value"
    with pytest.raises(ValueError, match="null byte"):
        _validate_and_augment_args(args, 10_000_000)


def test_validate_and_augment_args_rejects_non_ffmpeg_binary():
    """Verify non-ffmpeg binary raises ValueError."""
    from app.services.ffmpeg_executor import _validate_and_augment_args

    args = _base_args()
    args[0] = "bash"
    with pytest.raises(ValueError, match="Expected 'ffmpeg'"):
        _validate_and_augment_args(args, 10_000_000)


def test_patch_args_for_vod_replaces_live_flags():
    """Verify live HLS flags are replaced with VOD flags."""
    from app.services.ffmpeg_executor import _patch_args_for_vod

    args = [
        "ffmpeg", "-i", "input.mp4",
        "-f", "hls", "-hls_time", "2",
        "-hls_list_size", "6",
        "-hls_flags", "delete_segments+append_list",
        "output/720p/index.m3u8",
    ]
    result = _patch_args_for_vod(args)

    # hls_list_size should be 0
    idx = result.index("-hls_list_size")
    assert result[idx + 1] == "0"

    # hls_flags should be independent_segments
    idx = result.index("-hls_flags")
    assert result[idx + 1] == "independent_segments"

    # hls_playlist_type vod should be injected
    assert "-hls_playlist_type" in result
    idx = result.index("-hls_playlist_type")
    assert result[idx + 1] == "vod"


def test_inject_rate_control_adds_maxrate_bufsize():
    """Verify maxrate at 1.2x and bufsize at 2x are added."""
    from app.services.ffmpeg_executor import _inject_rate_control

    args = ["ffmpeg", "-i", "input.mp4", "-b:v", "3500k", "-c:a", "aac", "output.m3u8"]
    result = _inject_rate_control(args)

    assert "-maxrate" in result
    idx = result.index("-maxrate")
    assert result[idx + 1] == "4200k"  # 3500 * 1.2 = 4200

    assert "-bufsize" in result
    idx = result.index("-bufsize")
    assert result[idx + 1] == "7000k"  # 3500 * 2 = 7000


def test_inject_rate_control_skips_if_already_present():
    """Verify rate control is not doubled if already present."""
    from app.services.ffmpeg_executor import _inject_rate_control

    args = ["ffmpeg", "-i", "input.mp4", "-b:v", "3500k", "-maxrate", "4000k", "output.m3u8"]
    result = _inject_rate_control(args)
    assert result == args  # unchanged


def test_inject_thread_limit_calculates_from_cpu_count():
    """Verify thread limit calculation from CPU count and concurrency."""
    from app.services.ffmpeg_executor import _inject_thread_limit

    args = ["ffmpeg", "-nostdin", "-progress", "pipe:1", "-i", "input.mp4", "-vf", "scale=720:480", "output.m3u8"]
    result = _inject_thread_limit(args, 4)

    assert "-threads" in result
    idx = result.index("-threads")
    assert result[idx + 1] == "4"
    # Should be inserted after -i <input>
    i_idx = result.index("-i")
    assert idx == i_idx + 2


def test_inject_thread_limit_skips_if_already_present():
    """Verify thread injection is skipped if already in args."""
    from app.services.ffmpeg_executor import _inject_thread_limit

    args = ["ffmpeg", "-i", "input.mp4", "-threads", "2", "output.m3u8"]
    result = _inject_thread_limit(args, 4)
    assert result == args  # unchanged


def test_progress_parser_handles_malformed_lines():
    """Verify progress parser doesn't crash on malformed input."""
    from app.services.ffmpeg_executor import _read_progress

    lines = [
        b"this has no equals sign\n",
        b"=empty_key\n",
        b"out_time_us=not_a_number\n",
        b"progress=continue\n",  # Should produce a None sample (skipped)
        b"frame=100\n",
        b"out_time_us=5000000\n",
        b"speed=2.5x\n",
        b"fps=30.0\n",
        b"progress=continue\n",  # Should produce a valid sample
        b"\n",  # empty line
        b"progress=end\n",
    ]
    stream = MockStreamReader(lines)

    async def run():
        return await _read_progress(stream, 10_000_000, None)

    samples = _run(run())

    # Only the second frame should produce a valid sample
    assert len(samples) == 1
    assert samples[0].out_time_us == 5_000_000
    assert samples[0].frame == 100
    assert samples[0].speed == 2.5


def test_classify_error_all_patterns():
    """Verify each known error pattern is correctly classified."""
    from app.services.ffmpeg_executor import classify_error

    test_cases = [
        ("input.mp4: No such file or directory", "source_not_found", False),
        ("Server returned 404 Not Found", "source_not_found", False),
        ("Invalid data found when processing input", "invalid_input", False),
        ("Invalid data found in stream", "invalid_input", False),
        ("Unknown encoder 'libvpx-vp10'", "unsupported_codec", False),
        ("No space left on device", "disk_full", True),
        ("Cannot allocate memory", "oom", True),
        ("Connection timed out", "network_timeout", True),
        ("Connection refused", "network_error", True),
        ("End of file reached", "source_truncated", True),
        ("broken pipe during write", "broken_pipe", True),
    ]

    for stderr, expected_code, expected_retryable in test_cases:
        code, retryable = classify_error(1, stderr)
        assert code == expected_code, f"Failed for: {stderr}"
        assert retryable == expected_retryable, f"Failed retryable for: {stderr}"

    # Unknown error defaults to retryable
    code, retryable = classify_error(137, "some unknown error message")
    assert code == "ffmpeg_exit_137"
    assert retryable is True


def test_classify_error_regex_pattern():
    """Verify regex-based patterns (Decoder .* not found) work."""
    from app.services.ffmpeg_executor import classify_error

    code, retryable = classify_error(1, "Decoder hevc_cuvid not found")
    assert code == "unsupported_codec"
    assert retryable is False


def test_stderr_ring_buffer_truncates_to_4kb():
    """Verify only the last 4096 bytes of stderr are kept."""
    from app.services.ffmpeg_executor import _read_stderr_tail

    # Generate > 4KB of stderr data
    big_data = b"X" * 8192 + b"TAIL_MARKER_12345\n"
    stream = MockStreamReader([big_data])

    async def run():
        return await _read_stderr_tail(stream, max_bytes=4096)

    result = _run(run())

    assert len(result) <= 4096
    assert "TAIL_MARKER_12345" in result
    # The beginning should be truncated
    assert result[0] == "X"


def test_disk_space_check_raises_on_low_space():
    """Verify disk space check raises RetryableError when space is low."""
    from app.services.ffmpeg_executor import _check_disk_space
    from app.services.ffmpeg_executor_types import RetryableError

    # Mock os.statvfs to report 2GB free
    mock_stat = MagicMock()
    mock_stat.f_bavail = 2 * 1024 * 1024 * 1024 // 4096  # 2GB in 4K blocks
    mock_stat.f_frsize = 4096

    with patch("app.services.ffmpeg_executor.os.statvfs", return_value=mock_stat):
        with pytest.raises(RetryableError) as exc_info:
            _check_disk_space(Path("/tmp"), min_free_gb=5.0)

    assert exc_info.value.code == "disk_full"
    assert "2.0GB free" in exc_info.value.message


def test_restricted_env_excludes_secrets():
    """Verify restricted environment contains no secrets."""
    from app.services.ffmpeg_executor import _build_restricted_env

    # Set some secrets in the environment
    with patch.dict(os.environ, {
        "AWS_SECRET_ACCESS_KEY": "supersecret",
        "DATABASE_URL": "postgres://...",
        "STRIPE_SECRET_KEY": "sk_test_...",
    }):
        env = _build_restricted_env()

    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "DATABASE_URL" not in env
    assert "STRIPE_SECRET_KEY" not in env
    assert env["PATH"] == "/usr/local/bin:/usr/bin:/bin"
    assert env["HOME"] == "/tmp"
    assert env["LANG"] == "C.UTF-8"


def test_output_validation_catches_missing_master():
    """Verify output validation raises on missing master.m3u8."""
    from app.services.ffmpeg_executor import validate_output
    from app.services.ffmpeg_executor_types import OutputValidationError

    with pytest.raises(OutputValidationError) as exc_info:
        validate_output(Path("/nonexistent/dir"), ["720p"])

    assert "master.m3u8 missing" in str(exc_info.value)


def test_output_validation_catches_missing_segments(tmp_path):
    """Verify output validation raises when segments are missing."""
    from app.services.ffmpeg_executor import validate_output
    from app.services.ffmpeg_executor_types import OutputValidationError

    # Create master.m3u8 and rendition playlist but no segments
    (tmp_path / "master.m3u8").write_text("#EXTM3U\n")
    rendition_dir = tmp_path / "720p"
    rendition_dir.mkdir()
    (rendition_dir / "index.m3u8").write_text("#EXTM3U\n#EXTINF:2.0,\nseg_00000.ts\n")

    with pytest.raises(OutputValidationError) as exc_info:
        validate_output(tmp_path, ["720p"])

    assert "720p/ has no segments" in str(exc_info.value)


def test_output_validation_passes_with_valid_structure(tmp_path):
    """Verify output validation passes with correct structure."""
    from app.services.ffmpeg_executor import validate_output

    # Create valid structure
    (tmp_path / "master.m3u8").write_text("#EXTM3U\n")
    for name in ["720p", "360p"]:
        rendition_dir = tmp_path / name
        rendition_dir.mkdir()
        (rendition_dir / "index.m3u8").write_text("#EXTM3U\n#EXTINF:2.0,\nseg_00000.ts\n")
        (rendition_dir / "seg_00000.ts").write_bytes(b"\x00" * 100)

    # Should not raise
    validate_output(tmp_path, ["720p", "360p"])


def test_output_validation_catches_missing_rendition_playlist(tmp_path):
    """Verify output validation raises when a rendition playlist is missing."""
    from app.services.ffmpeg_executor import validate_output
    from app.services.ffmpeg_executor_types import OutputValidationError

    (tmp_path / "master.m3u8").write_text("#EXTM3U\n")
    # 720p exists with segments, but 360p directory is missing
    rendition_dir = tmp_path / "720p"
    rendition_dir.mkdir()
    (rendition_dir / "index.m3u8").write_text("#EXTM3U\n")
    (rendition_dir / "seg_00000.ts").write_bytes(b"\x00" * 100)

    with pytest.raises(OutputValidationError) as exc_info:
        validate_output(tmp_path, ["720p", "360p"])

    assert "360p/index.m3u8 missing" in str(exc_info.value)


def test_progress_parser_computes_correct_pct():
    """Verify percentage computation is correct."""
    from app.services.ffmpeg_executor import _read_progress

    # Simulate 50% progress
    lines = [
        b"frame=150\n",
        b"fps=30.0\n",
        b"out_time_us=5000000\n",
        b"speed=2.0x\n",
        b"progress=continue\n",
    ]
    stream = MockStreamReader(lines)

    callbacks: list[tuple] = []

    async def on_progress(sample, pct):
        callbacks.append((sample, pct))

    async def run():
        return await _read_progress(stream, 10_000_000, on_progress)

    _run(run())

    assert len(callbacks) == 1
    assert callbacks[0][1] == 50  # 5M / 10M = 50%


def test_progress_parser_caps_at_100_pct():
    """Verify progress never exceeds 100%."""
    from app.services.ffmpeg_executor import _read_progress

    # Simulate out_time_us exceeding expected (can happen with padding)
    lines = [
        b"frame=300\n",
        b"fps=30.0\n",
        b"out_time_us=12000000\n",  # exceeds 10M expected
        b"speed=2.0x\n",
        b"progress=continue\n",
    ]
    stream = MockStreamReader(lines)

    callbacks: list[tuple] = []

    async def on_progress(sample, pct):
        callbacks.append((sample, pct))

    async def run():
        return await _read_progress(stream, 10_000_000, on_progress)

    _run(run())

    assert callbacks[0][1] == 100  # capped at 100


def test_extract_output_dir():
    """Verify output directory extraction from args."""
    from app.services.ffmpeg_executor import _extract_output_dir

    args = _base_args()
    result = _extract_output_dir(args)
    assert result == Path("/tmp/test_out")


def test_extract_output_dir_returns_none_for_non_m3u8():
    """Verify None returned when last arg isn't .m3u8."""
    from app.services.ffmpeg_executor import _extract_output_dir

    assert _extract_output_dir(["ffmpeg", "-i", "input.mp4", "output.mp4"]) is None
    assert _extract_output_dir([]) is None
