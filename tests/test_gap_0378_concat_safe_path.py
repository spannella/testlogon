"""Regression test for GAP-0378 (SEC-012): concat demuxer path containment.

Verifies that `_run_concat_demuxer`:
  - rejects any input path that resolves OUTSIDE the owned scratch_dir
    (before fix: any path written to filelist.txt with `-safe 0`;
     after fix: ConcatError raised before ffmpeg is invoked),
  - accepts in-scratch paths and writes them RELATIVE to scratch,
  - invokes ffmpeg with `-safe 1` (not `-safe 0`) and `cwd=scratch_dir`.

Offline: the real ffmpeg subprocess is stubbed; no ffmpeg/network/AWS.
"""
import asyncio
from pathlib import Path
from unittest.mock import patch, AsyncMock

import pytest

from app.services.video_concatenator import _run_concat_demuxer, ConcatError


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_rejects_path_outside_scratch(tmp_path):
    """A path outside scratch_dir must raise ConcatError before ffmpeg runs."""
    valid_input = tmp_path / "input_0.mp4"
    valid_input.touch()
    outside_input = Path("/etc/passwd")

    called = {"subprocess": False}

    async def _spy(*args, **kwargs):  # pragma: no cover - must NOT be reached
        called["subprocess"] = True
        raise AssertionError("ffmpeg should not be invoked for an escaping path")

    with patch("asyncio.create_subprocess_exec", side_effect=_spy):
        with pytest.raises(ConcatError, match="escapes scratch directory"):
            _run(
                _run_concat_demuxer(
                    input_paths=[valid_input, outside_input],
                    output_path=tmp_path / "out.mp4",
                )
            )

    assert called["subprocess"] is False
    # filelist must NOT contain the escaping path (ideally not written at all).
    filelist = tmp_path / "filelist.txt"
    if filelist.exists():
        assert "/etc/passwd" not in filelist.read_text()


def test_rejects_relative_traversal_outside_scratch(tmp_path):
    """A `../../escape` style path must also be rejected."""
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    valid_input = scratch / "input_0.mp4"
    valid_input.touch()
    escape_input = scratch / ".." / ".." / "escape.mp4"

    async def _spy(*args, **kwargs):  # pragma: no cover
        raise AssertionError("ffmpeg should not be invoked")

    with patch("asyncio.create_subprocess_exec", side_effect=_spy):
        with pytest.raises(ConcatError, match="escapes scratch directory"):
            _run(
                _run_concat_demuxer(
                    input_paths=[valid_input, escape_input],
                    output_path=scratch / "out.mp4",
                )
            )


def test_accepts_in_scratch_uses_safe_1_relative_and_cwd(tmp_path):
    """In-scratch inputs: ffmpeg gets -safe 1, relative paths, cwd=scratch."""
    (tmp_path / "input_0.mp4").touch()
    (tmp_path / "input_1.mp4").touch()

    captured = {}

    async def _spy(*args, **kwargs):
        captured["cmd"] = list(args)
        captured["cwd"] = kwargs.get("cwd")
        mock = AsyncMock()
        mock.returncode = 0
        mock.communicate = AsyncMock(return_value=(b"", b""))
        return mock

    with patch("asyncio.create_subprocess_exec", side_effect=_spy):
        _run(
            _run_concat_demuxer(
                input_paths=[tmp_path / "input_0.mp4", tmp_path / "input_1.mp4"],
                output_path=tmp_path / "out.mp4",
            )
        )

    cmd = [str(a) for a in captured["cmd"]]
    assert "-safe" in cmd
    idx = cmd.index("-safe")
    assert cmd[idx + 1] == "1", f"expected '-safe 1', got '-safe {cmd[idx + 1]}'"
    assert "0" not in cmd[idx:idx + 2]

    # ffmpeg must run with cwd set to the scratch/work dir.
    assert captured["cwd"] == str(tmp_path)

    # filelist must contain RELATIVE paths (no absolute scratch prefix).
    filelist = tmp_path / "filelist.txt"
    content = filelist.read_text()
    assert "file 'input_0.mp4'" in content
    assert "file 'input_1.mp4'" in content
    assert str(tmp_path) not in content  # no absolute path leaked
