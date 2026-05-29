# VOD-004: Implement FFmpeg Execution with ABR Output and Watermark

**Ticket**: VOD-004
**Status**: Implemented
**Author**: Platform Engineering
**Date**: 2026-05-24
**Depends on**: VOD-003 (Async Transcode Job Queue and Worker)

---

## 1. Overview & Motivation

### Problem Statement

The video-on-demand pipeline has two critical layers already built: (1) a command-line argument builder (`app/services/ffmpeg_abr_pipeline.py`) that constructs per-rendition FFmpeg invocations with full watermark support, and (2) a job queue design (VOD-003) that defines the orchestration lifecycle for transcode jobs. What is missing is the **executor** — the component that actually runs FFmpeg as a subprocess, parses its progress output in real-time, enforces resource limits, handles failure modes, manages the local scratch filesystem, and produces a well-structured HLS output directory ready for S3 upload.

Today, `build_rendition_ffmpeg_args()` returns a `list[str]` and `write_master_playlist()` writes a static M3U8 file. The only code that executes these arguments is `scripts/video/run_abr_transcoder.py`, which launches all renditions in parallel via bare `subprocess.Popen` with no progress tracking, no error classification, no timeout enforcement, and no cleanup on failure. The broadcast local stack's `scripts/broadcast-local/ffmpeg-worker.sh` demonstrates a production-grade FFmpeg invocation pattern (with `filter_complex`, `maxrate`/`bufsize`, multi-variant HLS output, and a restart loop), but it is a shell script designed for live streaming — not VOD file-based transcoding.

### Why This Matters

1. **No progress visibility**: Without parsing FFmpeg's progress output, the job queue (VOD-003) cannot report `progress_pct` or `eta_seconds` to the API or frontend. Users would see only "running" with no indication of how far along the transcode is.

2. **No resource governance**: Uncontrolled FFmpeg processes can consume all CPU, exhaust disk space with intermediate segments, or run indefinitely on corrupted input files. The executor must enforce per-rendition timeouts, disk quotas, and CPU affinity.

3. **No structured error handling**: FFmpeg exits with code 1 for dozens of reasons (codec incompatibility, corrupted frames, I/O errors, out-of-memory). The executor must parse stderr to classify errors as retryable vs. non-retryable, enabling the VOD-003 retry logic to make correct decisions.

4. **No watermark asset lifecycle management**: The `static_image` watermark mode requires downloading the overlay image from S3 (or the local `app/static/uploads/watermarks/` directory) to a local path before FFmpeg can reference it as a second input. This download, validation, and cleanup are not handled anywhere.

5. **No output structure contract**: Downstream components (CDN origin, playback entitlement service, DRM packager) expect a specific directory layout. The executor must guarantee this layout or the entire pipeline breaks silently.

### Scope

This ticket covers:
- A new `app/services/ffmpeg_executor.py` service that wraps `asyncio.create_subprocess_exec`
- Real-time progress parsing from FFmpeg's `-progress pipe:1` protocol
- Structured output directory creation and validation
- Watermark asset download and filter graph construction
- Error classification and stderr capture
- Resource limits (timeout, disk quota check, nice/ionice)
- Integration points with the VOD-003 `transcode_worker.py`

This ticket does NOT cover:
- The job queue state machine (VOD-003)
- S3 upload of outputs (separate concern, handled by the worker after execution)
- DRM packaging (future ticket)
- Frontend progress UI (separate frontend ticket)

---

## 2. Current State Analysis

### What `ffmpeg_abr_pipeline.py` Generates

The `build_rendition_ffmpeg_args()` function at `app/services/ffmpeg_abr_pipeline.py:48-128` constructs a complete FFmpeg command line for a single rendition. Its output is a `list[str]` suitable for `subprocess` or `asyncio.create_subprocess_exec`. The generated command has these characteristics:

**Base arguments** (lines 68-69):
```
ffmpeg -hide_banner -loglevel warning -y -rw_timeout 5000000 -i <input_url>
```

- `-hide_banner`: Suppresses version/config info on stderr
- `-loglevel warning`: Only warnings and errors on stderr (no per-frame info)
- `-y`: Overwrite output without prompting
- `-rw_timeout 5000000`: 5-second I/O timeout for network sources (RTMP/HTTP)

**Video filter graph** (lines 70-98) — three modes:

| Mode | Filter Graph |
|------|--------------|
| `dynamic_text` | `scale={W}:{H},drawtext=text='{interpolated}':x={pos}:y={pos}:fontcolor=white@{opacity}:fontsize=24` |
| `static_image` | `[0:v]scale={W}:{H}[base];[1:v]format=rgba,colorchannelmixer=aa={opacity}[wm];[base][wm]overlay={x}:{y}[vout]` + `-map [vout] -map 0:a?` |
| `none` | `scale={W}:{H}` |

The `_overlay_xy()` helper (lines 15-22) maps position enums to FFmpeg coordinate expressions (`W-w-{margin}`, `H-h-{margin}`, etc.).

**Encoding parameters** (lines 100-126):
```
-c:v libx264 -preset veryfast -g 60 -sc_threshold 0
-b:v {bitrate}k -c:a aac -b:a {audio_bitrate}k
-f hls -hls_time 2 -hls_list_size 6
-hls_flags delete_segments+append_list
-hls_segment_filename {output_dir}/{name}/seg_%05d.ts
{output_dir}/{name}/index.m3u8
```

**Critical observations about what is MISSING from the generated args:**

1. **No `-progress pipe:1`**: The command uses `-loglevel warning`, which emits nothing to stdout during normal operation. For progress parsing, the executor must inject `-progress pipe:1` (or `-progress pipe:2` for stderr-based tracking) to get periodic `out_time_us`, `frame`, `fps`, `bitrate`, and `speed` fields.

2. **No `-maxrate` / `-bufsize`**: The broadcast worker (`ffmpeg-worker.sh` line 36-38) uses `maxrate` at 1.2x and `bufsize` at 2x the target bitrate to prevent quality spikes. The pipeline builder only sets `-b:v`. The executor should inject these for VOD quality consistency.

3. **No `-threads` control**: FFmpeg defaults to using all available cores per process. When running multiple renditions (even sequentially), the executor should set `-threads` based on available cores / concurrent job count.

4. **No `-nostdin`**: Without this flag, FFmpeg may attempt to read from stdin (e.g., if it encounters an interactive prompt scenario), which would hang the subprocess indefinitely.

5. **No output format for VOD**: The HLS flags `delete_segments+append_list` are designed for live streaming (rotating segment window). For VOD, the correct flags are `independent_segments` with `-hls_playlist_type vod` to produce a complete playlist with all segments retained.

6. **GOP alignment**: `-g 60` sets a fixed 60-frame keyframe interval. For 30fps content this is 2 seconds (matches `-hls_time 2`), but for 24fps or 60fps input, the segments will not align cleanly to keyframe boundaries. The executor should compute `-g` dynamically: `fps * hls_time_seconds`.

### What `watermark_profile_renderers.py` Provides

The `ffmpeg_watermark_filter()` function at `app/services/watermark_profile_renderers.py:51-75` generates standalone FFmpeg filter strings:

- For `dynamic_text`: Returns `drawtext=text='{text}':{position}:fontcolor=white@{alpha}:fontsize=24`
- For `static_image`: Returns `movie={asset_path}[wm];[in][wm]overlay={position}:alpha={alpha}[out]`

This is an alternative filter string format (using the `movie` filter for image input rather than a second `-i` input with `filter_complex`). The executor must reconcile these two approaches — `ffmpeg_abr_pipeline.py` uses the dual-input approach, while `watermark_profile_renderers.py` uses the single-input `movie` filter approach. For VOD, the dual-input approach from `ffmpeg_abr_pipeline.py` is preferred because it supports network-fetched watermark assets (the `movie` filter requires a local file path).

### What `scripts/broadcast-local/ffmpeg-worker.sh` Demonstrates

The shell script (55 lines) shows a production FFmpeg execution pattern for live multi-bitrate streaming:

1. **Restart loop** (line 27): `while true; do ... sleep 3; done` — auto-restart on FFmpeg exit
2. **Segment cleanup before restart** (line 28): `rm -f *.m3u8 *.ts` — prevents stale segments
3. **Watermark via `filter_complex`** (line 33): Scales watermark, overlays at bottom-right
4. **Multi-variant in single process** (lines 36-39): Uses `-b:v:0`, `-s:v:0`, `-var_stream_map` for parallel renditions in one FFmpeg invocation
5. **Rate control** (lines 36-38): `maxrate` = 1.2x target, `bufsize` = 2x target per variant
6. **Archive copy** (lines 49-51): Copies segments to a second directory for recording

For VOD, we diverge: one FFmpeg process per rendition (sequential, not parallel via `-var_stream_map`) to enable per-rendition progress tracking and independent failure/retry.

### What `scripts/video/run_abr_transcoder.py` Does Today

This script (`scripts/video/run_abr_transcoder.py:34-67`) is the only existing code that actually executes the pipeline builder's output:

```python
procs: list[subprocess.Popen] = []
for rendition in CANONICAL_ABR_LADDER:
    args = build_rendition_ffmpeg_args(...)
    procs.append(subprocess.Popen(args))

for p in procs:
    p.wait()
```

Problems:
- All 4 renditions launched simultaneously (CPU contention on dev machines)
- No progress parsing (stdout/stderr ignored)
- No timeout (will run forever on hung input)
- No error handling beyond eventual process exit
- Uses blocking `subprocess.Popen` (cannot integrate with asyncio event loop)
- `terminate()` in `finally` but no `kill()` fallback after grace period

### Existing Subprocess Execution in the Codebase

The `_run_media_tool()` function at `app/services/filemanager.py:1056-1076` is the hardened subprocess runner used for thumbnails and media inspection:

```python
def _run_media_tool(args: list[str], *, timeout_seconds: int | None = None) -> subprocess.CompletedProcess[str]:
    if not isinstance(args, list) or not all(isinstance(part, str) for part in args):
        raise ValueError("media tool args must be a list[str]")
    if any("\x00" in part for part in args):
        raise ValueError("media tool args contain invalid null byte")

    return subprocess.run(
        args, capture_output=True, text=True, check=False, shell=False,
        env=_DEFANGED_MEDIA_TOOL_ENV, stdin=subprocess.DEVNULL,
        close_fds=True, timeout=effective_timeout,
    )
```

Key patterns to adopt:
- Input validation (no null bytes, must be list of strings)
- `shell=False` (no shell injection risk)
- `stdin=subprocess.DEVNULL` (prevent stdin reads)
- `close_fds=True` (prevent FD leakage)
- Restricted environment (`_DEFANGED_MEDIA_TOOL_ENV` strips `PATH` to only FFmpeg-related directories)
- Explicit timeout

Key limitations that make it unsuitable for transcoding:
- `subprocess.run` is **blocking** — cannot be used in asyncio context
- `capture_output=True` buffers ALL stdout/stderr in memory — for a 30-minute transcode, stderr alone could be 100MB+
- No streaming progress output parsing
- 120-second timeout is far too short

---

## 3. Technical Design

### 3.1 Executor Service Architecture

The new `app/services/ffmpeg_executor.py` module exposes a single primary interface:

```python
@dataclass
class FFmpegExecutionResult:
    success: bool
    returncode: int
    duration_seconds: float
    output_dir: Path
    segments_written: int
    stderr_tail: str            # last 4KB of stderr for error reporting
    progress_samples: list[ProgressSample]  # time series for ETA estimation

@dataclass
class ProgressSample:
    timestamp: float            # Unix time of sample
    out_time_us: int            # FFmpeg's reported output position in microseconds
    frame: int
    fps: float
    speed: float                # e.g. 2.5x means encoding 2.5x faster than real-time

async def execute_rendition(
    *,
    args: list[str],
    rendition_name: str,
    expected_duration_us: int,
    timeout_seconds: int,
    on_progress: Callable[[ProgressSample, int], Awaitable[None]] | None = None,
    cancel_event: asyncio.Event | None = None,
) -> FFmpegExecutionResult:
    ...
```

The `on_progress` callback receives a `ProgressSample` and the computed overall percentage (0-100). The VOD-003 worker passes a callback that throttles DynamoDB writes to every 5 seconds.

The `cancel_event` enables cooperative cancellation: if the event is set (e.g., because a user cancelled the job via API), the executor sends SIGTERM to FFmpeg, waits 5 seconds, then SIGKILL if still running.

### 3.2 Subprocess Execution via `asyncio.create_subprocess_exec`

The executor uses `asyncio.create_subprocess_exec` rather than `subprocess.run` or `subprocess.Popen`:

```python
async def execute_rendition(...) -> FFmpegExecutionResult:
    # 1. Validate and augment args
    validated_args = _validate_and_augment_args(args, expected_duration_us)

    # 2. Construct restricted environment
    env = _build_restricted_env()

    # 3. Launch subprocess
    proc = await asyncio.create_subprocess_exec(
        *validated_args,
        stdout=asyncio.subprocess.PIPE,   # progress output
        stderr=asyncio.subprocess.PIPE,   # warnings/errors
        stdin=asyncio.subprocess.DEVNULL,
        env=env,
        preexec_fn=_apply_resource_limits,
    )

    # 4. Concurrently read stdout (progress) and stderr (errors)
    progress_task = asyncio.create_task(_read_progress(proc.stdout, ...))
    stderr_task = asyncio.create_task(_read_stderr_tail(proc.stderr))

    # 5. Wait with timeout and cancellation
    try:
        returncode = await asyncio.wait_for(
            _wait_with_cancel(proc, cancel_event),
            timeout=timeout_seconds,
        )
    except asyncio.TimeoutError:
        await _terminate_gracefully(proc)
        raise RenditionTimeoutError(rendition_name, timeout_seconds)

    # 6. Collect results
    progress_samples = await progress_task
    stderr_tail = await stderr_task

    return FFmpegExecutionResult(
        success=(returncode == 0),
        returncode=returncode,
        ...
    )
```

### 3.3 Progress Parsing from FFmpeg Stderr/Stdout

FFmpeg's `-progress pipe:1` flag causes it to emit key-value pairs to stdout at approximately 1-second intervals:

```
frame=150
fps=47.3
stream_0_0_q=25.0
bitrate=3456.2kbits/s
total_size=2345678
out_time_us=5000000
out_time_ms=5000
out_time=00:00:05.000000
dup_frames=0
drop_frames=0
speed=1.67x
progress=continue
```

The `progress=end` line signals completion. The parser:

```python
async def _read_progress(
    stream: asyncio.StreamReader,
    expected_duration_us: int,
    on_progress: Callable | None,
    rendition_idx: int,
    total_renditions: int,
) -> list[ProgressSample]:
    samples: list[ProgressSample] = []
    current_frame: dict[str, str] = {}

    async for raw_line in stream:
        line = raw_line.decode("utf-8", errors="replace").strip()
        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        current_frame[key] = value

        if key == "progress":
            # End of one progress frame
            sample = _parse_progress_frame(current_frame)
            if sample:
                samples.append(sample)
                if on_progress and expected_duration_us > 0:
                    rendition_pct = min(100, (sample.out_time_us / expected_duration_us) * 100)
                    overall_pct = int(((rendition_idx + rendition_pct / 100) / total_renditions) * 100)
                    await on_progress(sample, overall_pct)
            current_frame = {}

    return samples
```

**ETA estimation**: Using the `speed` field (e.g., `1.67x`), the executor computes:
```
remaining_duration_us = expected_duration_us - out_time_us
eta_seconds = remaining_duration_us / (speed * 1_000_000)
```

For multi-rendition jobs, the overall ETA accounts for remaining renditions using the average speed observed so far.

### 3.4 Output Directory Structure

The executor enforces this directory layout (matching `manifest_variant_path()` from `video_rendition_profiles.py`):

```
{scratch_dir}/
  output/
    master.m3u8                    # Written by write_master_playlist()
    1080p/
      index.m3u8                   # Per-rendition playlist (VOD type, all segments listed)
      seg_00000.ts
      seg_00001.ts
      ...
    720p/
      index.m3u8
      seg_00000.ts
      ...
    540p/
      index.m3u8
      seg_00000.ts
      ...
    360p/
      index.m3u8
      seg_00000.ts
      ...
```

After all renditions complete, the executor validates the output:

```python
def _validate_output(output_dir: Path, rendition_names: list[str]) -> None:
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
```

**VOD playlist correction**: Because `build_rendition_ffmpeg_args()` currently outputs live-style HLS flags (`delete_segments+append_list`, `hls_list_size 6`), the executor must override these for VOD:

```python
def _patch_args_for_vod(args: list[str]) -> list[str]:
    """Replace live-streaming HLS flags with VOD-appropriate flags."""
    patched = []
    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg == "-hls_list_size":
            patched.extend(["-hls_list_size", "0"])  # 0 = keep all segments
            skip_next = True
        elif arg == "-hls_flags":
            patched.extend(["-hls_flags", "independent_segments"])
            skip_next = True
        elif arg == "-hls_time":
            patched.extend(["-hls_time", arg])  # keep existing value
        else:
            patched.append(arg)

    # Inject VOD playlist type if not present
    if "-hls_playlist_type" not in patched:
        # Insert before output file (last positional arg)
        patched.insert(-1, "-hls_playlist_type")
        patched.insert(-1, "vod")

    return patched
```

### 3.5 Watermark Application

The executor handles watermark asset lifecycle for the `static_image` mode:

```python
async def _prepare_watermark_asset(
    policy: WatermarkPolicy,
    tenant_settings: TenantWatermarkSettings | None,
    scratch_dir: Path,
) -> Path | None:
    """Download watermark image to local scratch. Returns local path or None."""
    if policy.mode != "static_image":
        return None

    asset_uri = policy.asset_uri or (tenant_settings.branding_asset_uri if tenant_settings else None)
    if not asset_uri:
        return None

    local_wm_path = scratch_dir / "watermark_asset"

    if asset_uri.startswith("s3://"):
        bucket, key = _parse_s3_uri(asset_uri)
        await _download_from_s3(bucket, key, local_wm_path)
    elif asset_uri.startswith("/") or asset_uri.startswith("file://"):
        # Local path (dev mode) — e.g., app/static/uploads/watermarks/tenant-a_xxx_wm.png
        src = Path(asset_uri.replace("file://", ""))
        if not src.exists():
            raise NonRetryableError("watermark_asset_not_found", f"Local watermark not found: {src}")
        shutil.copy2(src, local_wm_path)
    elif asset_uri.startswith("http://") or asset_uri.startswith("https://"):
        await _download_from_url(asset_uri, local_wm_path)
    else:
        raise NonRetryableError("invalid_watermark_uri", f"Unsupported URI scheme: {asset_uri}")

    # Validate it is a valid image (prevent arbitrary file injection)
    _validate_image_file(local_wm_path)
    return local_wm_path
```

When a local watermark path is resolved, the executor patches the FFmpeg args to reference it:

```python
def _patch_watermark_input(args: list[str], local_wm_path: Path) -> list[str]:
    """Replace the watermark asset URI in the args with the local path."""
    patched = []
    for i, arg in enumerate(args):
        if i > 0 and args[i-1] == "-i" and arg != args[1]:  # second -i is the watermark
            patched.append(str(local_wm_path))
        else:
            patched.append(arg)
    return patched
```

### 3.6 Error Handling and Classification

FFmpeg communicates errors via:
1. **Exit code**: Non-zero (typically 1) on any failure
2. **Stderr**: Human-readable error messages

The executor captures the last 4KB of stderr (ring-buffer approach to avoid memory exhaustion on long runs) and classifies errors:

```python
_ERROR_PATTERNS: list[tuple[str, str, bool]] = [
    # (stderr_pattern, error_code, is_retryable)
    ("No such file or directory", "source_not_found", False),
    ("Server returned 404", "source_not_found", False),
    ("Invalid data found when processing input", "invalid_input", False),
    ("Decoder .* not found", "unsupported_codec", False),
    ("Unknown encoder", "unsupported_codec", False),
    ("No space left on device", "disk_full", True),
    ("Cannot allocate memory", "oom", True),
    ("Connection timed out", "network_timeout", True),
    ("Connection refused", "network_error", True),
    ("End of file", "source_truncated", True),
    ("broken pipe", "broken_pipe", True),
    ("Avi muxer does not support", "muxer_error", False),
]

def _classify_error(returncode: int, stderr_tail: str) -> tuple[str, bool]:
    """Returns (error_code, is_retryable)."""
    stderr_lower = stderr_tail.lower()
    for pattern, code, retryable in _ERROR_PATTERNS:
        if pattern.lower() in stderr_lower:
            return code, retryable
    # Default: unknown error, assume retryable (transient)
    return f"ffmpeg_exit_{returncode}", True
```

The caller (VOD-003 worker) uses this classification to decide whether to retry or fail permanently:

```python
result = await execute_rendition(...)
if not result.success:
    error_code, is_retryable = _classify_error(result.returncode, result.stderr_tail)
    if is_retryable:
        raise RetryableError(error_code, result.stderr_tail[:4096])
    else:
        raise NonRetryableError(error_code, result.stderr_tail[:4096])
```

### 3.7 Resource Limits

The executor applies multiple layers of resource governance:

**1. Process-level limits via `preexec_fn`:**

```python
import resource

def _apply_resource_limits():
    """Called in child process before exec(). Sets rlimits."""
    # CPU time: hard limit at 2x the timeout (safety net)
    # Note: this is CPU seconds, not wall-clock seconds
    soft_cpu = 7200   # 2 hours CPU time
    hard_cpu = 7500
    resource.setrlimit(resource.RLIMIT_CPU, (soft_cpu, hard_cpu))

    # Virtual memory: 8GB (prevents runaway memory from corrupt input)
    mem_limit = 8 * 1024 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))

    # File size: 50GB (prevents infinite segment writing)
    file_limit = 50 * 1024 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))

    # Nice value: lower priority than API process
    os.nice(10)
```

**2. Wall-clock timeout via `asyncio.wait_for`:**

Per-rendition timeout from `S.transcode_rendition_timeout_seconds` (default: 1800 seconds = 30 minutes). Configurable per job for long-form content.

**3. Disk quota pre-check:**

Before starting a rendition, the executor checks available disk space:

```python
def _check_disk_space(scratch_dir: Path, min_free_gb: float = 5.0) -> None:
    stat = os.statvfs(scratch_dir)
    free_gb = (stat.f_bavail * stat.f_frsize) / (1024 ** 3)
    if free_gb < min_free_gb:
        raise RetryableError("disk_full", f"Only {free_gb:.1f}GB free, need {min_free_gb}GB")
```

**4. Restricted environment:**

Following `_DEFANGED_MEDIA_TOOL_ENV` from `filemanager.py`, the executor strips the environment to prevent information leakage and limit attack surface:

```python
def _build_restricted_env() -> dict[str, str]:
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        # No AWS credentials, no database URLs, no secrets
    }
```

**5. Thread control:**

```python
def _inject_thread_limit(args: list[str], max_threads: int) -> list[str]:
    """Inject -threads flag after the input specification."""
    if "-threads" in args:
        return args  # already specified
    # Insert after -i <input>
    for i, arg in enumerate(args):
        if arg == "-i":
            insert_pos = i + 2  # after -i <url>
            break
    else:
        insert_pos = 2  # fallback: after ffmpeg -hide_banner
    return args[:insert_pos] + ["-threads", str(max_threads)] + args[insert_pos:]
```

### 3.8 Graceful Termination

When a job is cancelled or times out:

```python
async def _terminate_gracefully(proc: asyncio.subprocess.Process, grace_seconds: int = 5) -> None:
    """Send SIGTERM, wait grace period, then SIGKILL if still alive."""
    if proc.returncode is not None:
        return  # already exited

    proc.terminate()  # SIGTERM
    try:
        await asyncio.wait_for(proc.wait(), timeout=grace_seconds)
    except asyncio.TimeoutError:
        proc.kill()  # SIGKILL
        await proc.wait()
```

FFmpeg handles SIGTERM cleanly — it finalizes the current segment, writes the playlist, and exits 0. This means a cancelled rendition may still produce a valid (truncated) playlist, which we discard.

### 3.9 Argument Augmentation

The executor augments the args from `build_rendition_ffmpeg_args()` before execution:

```python
def _validate_and_augment_args(args: list[str], expected_duration_us: int) -> list[str]:
    # Validation (same as _run_media_tool)
    if not isinstance(args, list) or not all(isinstance(part, str) for part in args):
        raise ValueError("FFmpeg args must be a list[str]")
    if any("\x00" in part for part in args):
        raise ValueError("FFmpeg args contain null byte")
    if args[0] != "ffmpeg":
        raise ValueError(f"Expected 'ffmpeg' as first arg, got '{args[0]}'")

    augmented = list(args)

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
    max_threads = max(1, os.cpu_count() // max(1, S.transcode_max_concurrent_jobs))
    augmented = _inject_thread_limit(augmented, max_threads)

    return augmented
```

### 3.10 Integration with VOD-003 Worker

The executor is called from `transcode_worker.py`'s `execute_transcode_job()` function (defined in VOD-003 section 4.7). The integration point:

```python
# In app/services/transcode_worker.py

from app.services.ffmpeg_executor import execute_rendition, prepare_watermark_asset

async def _run_ffmpeg_rendition(
    job_id: str,
    worker_id: str,
    args: list[str],
    rendition_name: str,
    rendition_idx: int,
    total_renditions: int,
    expected_duration_us: int,
    cancel_event: asyncio.Event,
) -> FFmpegExecutionResult:
    last_db_write = 0

    async def _on_progress(sample: ProgressSample, overall_pct: int) -> None:
        nonlocal last_db_write
        now = time.time()
        if now - last_db_write >= S.transcode_progress_update_interval_seconds:
            update_progress(
                job_id, worker_id, overall_pct, rendition_name,
                renditions_completed=[], eta_seconds=_compute_eta(sample, expected_duration_us)
            )
            last_db_write = now

    return await execute_rendition(
        args=args,
        rendition_name=rendition_name,
        expected_duration_us=expected_duration_us,
        timeout_seconds=S.transcode_rendition_timeout_seconds,
        on_progress=_on_progress,
        cancel_event=cancel_event,
    )
```

---

## 4. Implementation Plan

### 4.1 Files

<!-- NOTE: Both files below ALREADY EXIST in the codebase. -->

| File | Purpose | Status |
|------|---------|--------|
| `app/services/ffmpeg_executor.py` | Core executor: `execute_rendition()` (line 70), `classify_error()` (line 510), `validate_output()` (line 531), progress parsing, resource limits (565 lines) | **Already exists** |
| `app/services/ffmpeg_executor_types.py` | Dataclasses: `ProgressSample`, error types | **Already exists** |
| `tests/test_ffmpeg_executor.py` | Unit tests (mocked subprocess) | ~300 |
| `tests/test_ffmpeg_executor_integration.py` | Integration tests (real FFmpeg, short fixture) | ~150 |
| `tests/fixtures/test_video_2s.mp4` | 2-second 320x240 test video for integration tests | binary |

### 4.2 Modifications to Existing Files

| File | Change |
|------|--------|
| `app/services/ffmpeg_abr_pipeline.py` | `build_rendition_ffmpeg_args()` at line 50; `write_master_playlist()` at line 145. **Already exists**. |
| `app/services/transcode_worker.py` | Calls `_run_ffmpeg_for_rendition()` at line 234; uses semaphore at line 80. **Already exists**. |
| `app/services/ffmpeg_watermark_lifecycle.py` | `prepare_watermark_asset()` (line 23), `patch_watermark_input()` (line 69). **Already exists**. |
| `app/core/settings.py` | Add `ffmpeg_max_threads_per_job`, `ffmpeg_max_memory_gb`, `ffmpeg_grace_kill_seconds`, `ffmpeg_min_free_disk_gb` |
| `scripts/local-ddb-init.py` | No changes (table creation handled by VOD-003) |

### 4.3 Implementation Phases

**Phase 1: Core Executor (3 days)**

1. Create `app/services/ffmpeg_executor_types.py` with dataclasses
2. Create `app/services/ffmpeg_executor.py` with:
   - `execute_rendition()` main entry point
   - `_validate_and_augment_args()` argument preprocessing
   - `_build_restricted_env()` environment construction
   - `_read_progress()` async stdout parser
   - `_read_stderr_tail()` ring-buffer stderr collector
   - `_terminate_gracefully()` signal handling
   - `_apply_resource_limits()` preexec function
   - `_check_disk_space()` pre-flight check
3. Write unit tests with mocked `asyncio.create_subprocess_exec`

**Phase 2: VOD Argument Patching (1 day)**

1. Add `build_vod_rendition_ffmpeg_args()` to `ffmpeg_abr_pipeline.py`
2. Implement `_patch_args_for_vod()`, `_inject_rate_control()`, `_inject_thread_limit()` in executor
3. Update existing tests in `tests/test_ffmpeg_abr_pipeline.py`

**Phase 3: Watermark Asset Lifecycle (1 day)**

1. Implement `_prepare_watermark_asset()` with S3, local, and HTTP download paths
2. Implement `_validate_image_file()` (check magic bytes: PNG, JPEG, PPM, SVG)
3. Implement `_patch_watermark_input()` to rewrite asset URI in args
4. Handle cleanup in `finally` block

**Phase 4: Error Classification (1 day)**

1. Implement `_classify_error()` with pattern matching
2. Define `RetryableError` and `NonRetryableError` exception hierarchy
3. Write unit tests for each error pattern
4. Add stderr ring-buffer implementation (fixed 4KB circular buffer)

**Phase 5: Integration with VOD-003 Worker (2 days)**

1. Wire `execute_rendition()` into `transcode_worker.py`
2. Implement per-rendition sequential execution with progress aggregation
3. Implement `cancel_event` propagation from job cancellation API
4. Add output validation after all renditions complete
5. Integration test: submit job, verify progress updates in DDB, verify output files

**Phase 6: Integration Tests with Real FFmpeg (1 day)**

1. Generate `tests/fixtures/test_video_2s.mp4`
2. Write integration test that runs full single-rendition transcode
3. Verify output HLS segments are playable (check segment count, playlist structure)
4. Run in CI with FFmpeg installed (add to `scripts/setup_ubuntu.sh` if needed)

### 4.4 Settings Additions

Add to `app/core/settings.py`:

```python
# FFmpeg executor
ffmpeg_max_threads_per_job: int = int(os.environ.get("FFMPEG_MAX_THREADS_PER_JOB", "0"))  # 0 = auto
ffmpeg_max_memory_gb: int = int(os.environ.get("FFMPEG_MAX_MEMORY_GB", "8"))
ffmpeg_grace_kill_seconds: int = int(os.environ.get("FFMPEG_GRACE_KILL_SECONDS", "5"))
ffmpeg_min_free_disk_gb: float = float(os.environ.get("FFMPEG_MIN_FREE_DISK_GB", "5.0"))
ffmpeg_binary_path: str = os.environ.get("FFMPEG_BINARY_PATH", "ffmpeg")
```

### 4.5 Dependency on VOD-003

The executor is designed to be usable independently of the job queue (e.g., for ad-hoc CLI transcoding via `scripts/video/run_abr_transcoder.py`). However, the full integration requires VOD-003's:

- `transcode_worker.py` — calls `execute_rendition()` within the job lifecycle
- `transcode_job_store.py` — provides `update_progress()` for the callback
- `cancel_event` propagation — requires the worker to create an `asyncio.Event` per job and set it when a cancellation is received via DDB polling or SQS message attribute

The executor module has **zero imports from VOD-003** — it communicates purely through the `on_progress` callback and `cancel_event` parameter, making it testable in isolation.

---

## 5. Testing Strategy

### 5.1 Unit Tests with Mocked Subprocess (`tests/test_ffmpeg_executor.py`)

All unit tests mock `asyncio.create_subprocess_exec` to simulate FFmpeg behavior without requiring the binary. This follows the project's standard pattern (tests run via `just test` without the dev stack).

**Test cases:**

1. **`test_execute_rendition_success_parses_progress`**
   - Mock FFmpeg stdout to emit 5 progress frames with increasing `out_time_us`
   - Mock exit code 0
   - Verify `FFmpegExecutionResult.success == True`
   - Verify `progress_samples` has 5 entries with correct `out_time_us` values
   - Verify `on_progress` callback was invoked with increasing percentages

2. **`test_execute_rendition_failure_captures_stderr`**
   - Mock FFmpeg to emit "No such file or directory" on stderr, exit code 1
   - Verify `success == False`, `returncode == 1`
   - Verify `stderr_tail` contains the error message
   - Verify `_classify_error()` returns `("source_not_found", False)`

3. **`test_execute_rendition_timeout_sends_sigterm_then_sigkill`**
   - Mock FFmpeg to never exit (simulate hang)
   - Set `timeout_seconds=1`
   - Verify `terminate()` is called
   - Verify `kill()` is called after grace period
   - Verify `RenditionTimeoutError` is raised

4. **`test_execute_rendition_cancel_event_terminates_process`**
   - Create an `asyncio.Event`, set it after 0.5 seconds via a background task
   - Mock FFmpeg to run for 10 seconds
   - Verify process is terminated when event fires
   - Verify the function returns (not raises) with appropriate error state

5. **`test_validate_and_augment_args_injects_progress_flag`**
   - Pass standard args from `build_rendition_ffmpeg_args()`
   - Verify output contains `-progress pipe:1` and `-nostdin`

6. **`test_validate_and_augment_args_rejects_null_bytes`**
   - Pass args with `\x00` in a value
   - Verify `ValueError` is raised

7. **`test_validate_and_augment_args_rejects_non_ffmpeg_binary`**
   - Pass args starting with `bash` instead of `ffmpeg`
   - Verify `ValueError` is raised

8. **`test_patch_args_for_vod_replaces_live_flags`**
   - Input: args with `-hls_flags delete_segments+append_list -hls_list_size 6`
   - Verify output has `-hls_flags independent_segments -hls_list_size 0 -hls_playlist_type vod`

9. **`test_inject_rate_control_adds_maxrate_bufsize`**
   - Input: args with `-b:v 3500k`
   - Verify output contains `-maxrate 4200k -bufsize 7000k` (1.2x and 2x)

10. **`test_inject_thread_limit_calculates_from_cpu_count`**
    - Mock `os.cpu_count()` to return 8, `S.transcode_max_concurrent_jobs` = 2
    - Verify `-threads 4` is injected

11. **`test_progress_parser_handles_malformed_lines`**
    - Feed progress parser lines with missing `=`, empty values, non-numeric `out_time_us`
    - Verify no crash, malformed lines are skipped

12. **`test_progress_parser_computes_correct_overall_pct`**
    - Simulate rendition_idx=1, total_renditions=4, out_time_us at 50% of expected duration
    - Verify overall_pct = ((1 + 0.5) / 4) * 100 = 37%

13. **`test_classify_error_all_patterns`**
    - For each entry in `_ERROR_PATTERNS`, verify correct code and retryable flag

14. **`test_stderr_ring_buffer_truncates_to_4kb`**
    - Feed 1MB of stderr data
    - Verify only last 4096 bytes are retained

15. **`test_disk_space_check_raises_on_low_space`**
    - Mock `os.statvfs` to report 2GB free
    - Set `min_free_gb=5.0`
    - Verify `RetryableError("disk_full", ...)` is raised

16. **`test_restricted_env_excludes_secrets`**
    - Set `AWS_SECRET_ACCESS_KEY` and `DATABASE_URL` in `os.environ`
    - Verify `_build_restricted_env()` output contains neither

17. **`test_watermark_asset_download_s3`**
    - Mock boto3 S3 download
    - Verify file is written to scratch dir
    - Verify args are patched to reference local path

18. **`test_watermark_asset_local_path_copies_file`**
    - Create temp file, pass its path as `asset_uri`
    - Verify file is copied to scratch dir

19. **`test_watermark_asset_missing_raises_non_retryable`**
    - Pass nonexistent local path
    - Verify `NonRetryableError("watermark_asset_not_found", ...)` is raised

20. **`test_output_validation_catches_missing_segments`**
    - Create output dir with playlist but no `.ts` files
    - Verify `OutputValidationError` is raised

### 5.2 Integration Tests with Real FFmpeg (`tests/test_ffmpeg_executor_integration.py`)

These tests require `ffmpeg` on PATH. They are skipped in environments without it:

```python
import shutil
import pytest

pytestmark = pytest.mark.skipif(
    not shutil.which("ffmpeg"),
    reason="ffmpeg not installed"
)
```

**Test fixture generation** (run once, committed to repo):
```bash
ffmpeg -f lavfi -i "testsrc=duration=2:size=320x240:rate=30" \
       -f lavfi -i "sine=frequency=440:duration=2" \
       -c:v libx264 -preset ultrafast -pix_fmt yuv420p \
       -c:a aac -b:a 64k \
       tests/fixtures/test_video_2s.mp4
```

This produces a ~30KB file with 2 seconds of video (color bars) and audio (440Hz tone).

**Test cases:**

1. **`test_full_single_rendition_360p_produces_valid_hls`**
   - Build args via `build_rendition_ffmpeg_args()` for 360p rendition using `test_video_2s.mp4`
   - Call `execute_rendition()` with real subprocess
   - Verify: exit code 0, `success == True`
   - Verify: `output_dir/360p/index.m3u8` exists and contains `#EXTINF` entries
   - Verify: at least 1 segment file exists
   - Verify: playlist has `#EXT-X-ENDLIST` (VOD mode)
   - Verify: `progress_samples` is non-empty (at least one progress frame received)
   - Assert total execution time < 30 seconds (2s video at veryfast should take < 5s)

2. **`test_full_rendition_with_dynamic_text_watermark`**
   - Build args with `WatermarkPolicy(mode="dynamic_text", text_template="tenant={{tenant_id}}")`
   - Execute and verify success
   - Verify output video duration approximately matches input (within 0.5s tolerance)
   - Optionally: use `ffprobe` to confirm output resolution matches rendition spec

3. **`test_full_rendition_with_static_image_watermark`**
   - Create a small 16x16 PNG in temp dir (single red pixel repeated)
   - Build args with `WatermarkPolicy(mode="static_image", asset_uri=str(png_path))`
   - Execute and verify success
   - Verify the second `-i` in executed args points to the watermark file

4. **`test_invalid_input_returns_nonzero_exit`**
   - Point input to a nonexistent file path
   - Verify `success == False`, `returncode == 1`
   - Verify `stderr_tail` contains error indication
   - Verify error is classified as `source_not_found` (non-retryable)

5. **`test_timeout_kills_process_cleanly`**
   - Use a very long `-re` (real-time) flag with 2-second timeout on 2-second video
   - `-re` makes FFmpeg process at 1x speed (takes 2 real seconds for 2s video)
   - Set `timeout_seconds=1`
   - Verify `RenditionTimeoutError` is raised
   - Verify process is actually dead (no zombie)

6. **`test_progress_callback_receives_increasing_values`**
   - Collect all `on_progress` calls into a list
   - Verify percentages are monotonically non-decreasing
   - Verify final percentage is close to 100 (within 5% tolerance for short videos)

7. **`test_master_playlist_references_correct_renditions`**
   - Run two renditions (360p, 720p) sequentially
   - Call `write_master_playlist()` on output dir
   - Parse `master.m3u8` and verify it contains both `360p/index.m3u8` and `720p/index.m3u8`
   - Verify `BANDWIDTH` values match the rendition profiles

8. **`test_cancel_event_mid_transcode`**
   - Start transcoding 2s video with `-re` flag (will take ~2s)
   - Set cancel event after 0.5 seconds
   - Verify process terminates before completing
   - Verify partial segments may exist but are cleaned up by caller

### 5.3 Mocking Strategy for Unit Tests

The primary mock target is `asyncio.create_subprocess_exec`. The mock must simulate:

```python
@pytest.fixture
def mock_ffmpeg_process():
    """Creates a mock asyncio.subprocess.Process that emits progress."""
    class MockStreamReader:
        def __init__(self, lines: list[bytes]):
            self._lines = iter(lines)

        async def __aiter__(self):
            for line in self._lines:
                yield line

        async def read(self) -> bytes:
            return b"".join(self._lines)

    class MockProcess:
        def __init__(self, stdout_lines: list[bytes], stderr_data: bytes, returncode: int):
            self.stdout = MockStreamReader(stdout_lines)
            self.stderr = MockStreamReader([stderr_data])
            self.returncode = None
            self._final_code = returncode
            self._terminated = False

        async def wait(self) -> int:
            self.returncode = self._final_code
            return self._final_code

        def terminate(self):
            self._terminated = True
            self.returncode = -15  # SIGTERM

        def kill(self):
            self.returncode = -9  # SIGKILL

    return MockProcess
```

For progress emission simulation:
```python
def _make_progress_lines(duration_us: int, num_frames: int) -> list[bytes]:
    """Generate realistic FFmpeg -progress output."""
    lines = []
    for i in range(num_frames):
        t = int((i + 1) / num_frames * duration_us)
        speed = 2.5  # simulated encoding speed
        lines.extend([
            f"frame={30 * (i+1)}\n".encode(),
            f"fps=75.0\n".encode(),
            f"bitrate=3500.0kbits/s\n".encode(),
            f"out_time_us={t}\n".encode(),
            f"speed={speed:.2f}x\n".encode(),
            b"progress=continue\n",
        ])
    lines.append(b"progress=end\n")
    return lines
```

### 5.4 CI/CD Considerations

1. **FFmpeg availability**: The `scripts/setup_ubuntu.sh` already installs FFmpeg (required for `filemanager.py` media tools). Integration tests will run in CI without additional setup.

2. **Test fixture committed to repo**: The 30KB `test_video_2s.mp4` is small enough to commit. Alternatively, generate it in a `conftest.py` fixture (requires FFmpeg in CI).

3. **Timeout handling in CI**: CI runners may be slower than dev machines. Integration test timeouts should be generous (60 seconds for a 2-second transcode that normally takes < 5 seconds).

4. **Parallelism**: Unit tests (mocked) can run in parallel. Integration tests should run sequentially (`@pytest.mark.serial` or in a dedicated test class) to avoid CPU contention affecting timing assertions.

### 5.5 Manual Verification Checklist

For the developer implementing this ticket:

1. Run `scripts/video/run_abr_transcoder.py` with the new executor wired in (replace raw `Popen`) and verify console output shows progress percentages.

2. Submit a job via the VOD-003 API (`POST /ui/transcode-jobs`), poll status, and confirm:
   - `progress_pct` increases over time
   - `current_rendition` reflects the active rendition
   - `eta_seconds` is reasonable
   - Final state is `completed` with valid `output_hls_manifest_uri`

3. Test watermark modes:
   - `dynamic_text`: Verify text overlay visible in output video (play first segment with `ffplay`)
   - `static_image`: Verify overlay positioned correctly (use a visually distinct watermark)
   - `none`: Verify no overlay artifacts

4. Test failure modes:
   - Delete source file mid-transcode: should get `source_not_found` or `broken_pipe`
   - Fill disk: should get `disk_full` (retryable)
   - Kill FFmpeg with `SIGKILL` externally: should get `ffmpeg_exit_-9` (retryable)

5. Test cancellation:
   - Submit a long job, cancel via API after 5 seconds
   - Verify FFmpeg process is terminated
   - Verify scratch directory is cleaned up
   - Verify job status is `cancelled`

6. Verify output playback:
   - Open `master.m3u8` in VLC or `ffplay`
   - Confirm adaptive bitrate switching works (4 renditions available)
   - Confirm segments have correct duration (~2 seconds each)
   - Confirm no gaps or discontinuities at segment boundaries

---

## Appendix A: FFmpeg Progress Protocol Reference

When invoked with `-progress <url>` (where `<url>` is `pipe:1` for stdout), FFmpeg emits a block of key=value lines every ~500ms:

```
frame=450
fps=30.0
stream_0_0_q=28.0
bitrate=3245.7kbits/s
total_size=12345678
out_time_us=15000000
out_time_ms=15000000
out_time=00:00:15.000000
dup_frames=0
drop_frames=0
speed=2.00x
progress=continue
```

Key fields for the executor:
- `out_time_us`: Output stream position in microseconds (primary progress indicator)
- `speed`: Encoding speed relative to real-time (for ETA calculation)
- `frame`: Total frames encoded (secondary progress indicator)
- `fps`: Current encoding frame rate
- `progress`: `continue` during encoding, `end` when complete

The executor MUST handle:
- Fields appearing in any order within a block
- Missing fields (older FFmpeg versions omit some)
- Multiple blocks per read (buffering may concatenate them)
- Non-progress lines interspersed (e.g., filter graph initialization messages)

## Appendix B: HLS Output Differences — Live vs. VOD

| Parameter | Live (current `build_rendition_ffmpeg_args`) | VOD (new executor patching) |
|-----------|----------------------------------------------|------------------------------|
| `hls_list_size` | 6 (sliding window) | 0 (all segments) |
| `hls_flags` | `delete_segments+append_list` | `independent_segments` |
| `hls_playlist_type` | (not set, implies "event" or "live") | `vod` |
| Segment retention | Only last 6 kept on disk | All segments kept |
| `#EXT-X-ENDLIST` | Never written (live stream) | Written at end (signals completion) |

The VOD playlist MUST contain `#EXT-X-ENDLIST` — without it, players treat the stream as live and attempt to poll for new segments indefinitely.

## Appendix C: Relationship to Existing Watermark Assets

The `app/static/uploads/watermarks/` directory contains 67 pre-uploaded watermark assets for `tenant-a`, in both PNG and SVG formats. These follow the naming convention:

```
{tenant_id}_{uuid}_wm.{png|svg}
```

In dev mode, the `asset_uri` field in `WatermarkPolicy` references these files as local paths (e.g., `/home/ubuntu/testlogon/app/static/uploads/watermarks/tenant-a_0516fa73_wm.png`). In production, they would be S3 URIs. The executor's `_prepare_watermark_asset()` function handles both cases transparently.

Note: FFmpeg cannot process SVG files directly as overlay inputs. The executor must detect SVG format and either:
1. Convert to PNG via `rsvg-convert` or ImageMagick before use
2. Reject SVG with a clear error message instructing the tenant to upload a raster format

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/ffmpeg_executor.py` | 70 | `execute_rendition()` — main entry point |
| `app/services/ffmpeg_executor.py` | 184 | `_validate_and_augment_args()` |
| `app/services/ffmpeg_executor.py` | 254 | `_inject_rate_control()` |
| `app/services/ffmpeg_executor.py` | 286 | `_inject_thread_limit()` |
| `app/services/ffmpeg_executor.py` | 307 | `_build_restricted_env()` |
| `app/services/ffmpeg_executor.py` | 317 | `_apply_resource_limits()` |
| `app/services/ffmpeg_executor.py` | 340 | `_read_progress()` |
| `app/services/ffmpeg_executor.py` | 377 | `_parse_progress_frame()` |
| `app/services/ffmpeg_executor.py` | 468 | `_terminate_gracefully()` |
| `app/services/ffmpeg_executor.py` | 493 | `_check_disk_space()` |
| `app/services/ffmpeg_executor.py` | 510 | `classify_error()` |
| `app/services/ffmpeg_executor.py` | 531 | `validate_output()` |
| `app/services/ffmpeg_executor_types.py` | -- | `ProgressSample` and error type dataclasses |
| `app/services/ffmpeg_abr_pipeline.py` | 50 | `build_rendition_ffmpeg_args()` |
| `app/services/ffmpeg_abr_pipeline.py` | 145 | `write_master_playlist()` |
| `app/services/ffmpeg_watermark_lifecycle.py` | 23 | `prepare_watermark_asset()` |
| `app/services/ffmpeg_watermark_lifecycle.py` | 69 | `patch_watermark_input()` |
| `app/services/watermark_profile_renderers.py` | 51 | `ffmpeg_watermark_filter()` |
| `app/services/ffmpeg_manager.py` | 81 | `get_ffmpeg_info()` |
| `app/services/ffmpeg_manager.py` | 116 | `get_ffmpeg_path()` |
| `app/services/transcode_worker.py` | 234 | `_run_ffmpeg_for_rendition()` |
| `app/services/filemanager.py` | 1057 | `_run_media_tool()` (reference subprocess pattern) |
| `app/core/settings.py` | 1120 | `ffmpeg_binary_path` |
| `scripts/video/run_abr_transcoder.py` | -- | Script-based parallel rendition launcher |

The recommended approach is (2) for the initial implementation, with SVG-to-PNG conversion as a future enhancement.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|--------------|
| VOD-003 | `transcode_worker.py` calls `execute_rendition()`; `transcode_job_store.py` provides `update_progress()` for the callback | Implemented | Yes -- executor has zero imports from VOD-003; communicates via callback/event params |
| MEDIA-002 | `ffmpeg_manager.py` for binary path resolution (`get_ffmpeg_path()`) and codec validation | Implemented | Yes -- executor can fall back to `"ffmpeg"` on PATH |

### Depended On By

| Ticket | What It Needs from VOD-004 |
|--------|---------------------------|
| VOD-005 | Completed HLS output directory structure for S3 upload |
| VOD-010 | DRM encryption key injection into FFmpeg args |
| VOD-015 | `execute_rendition()` for clip extraction with resource limits |
| VOD-016 | `execute_rendition()` for concat pre-processing and re-encoding |
| VOD-020 | FFmpeg `drawtext` filter execution for watermark embedding |

### Merge Strategy

**Parallel-safe with VOD-003** -- The executor module has zero imports from VOD-003 and can be developed/tested independently. The integration point is the `on_progress` callback and `cancel_event` parameter, both injected by the caller. Merge after or alongside VOD-003.

### Merge Checklist

- [ ] `ffmpeg` binary available on PATH (installed by `scripts/setup_ubuntu.sh`)
- [ ] `ffmpeg_executor.py` passes all unit tests with mocked subprocess
- [ ] Integration tests pass with real FFmpeg (skipped gracefully if unavailable)
- [ ] `tests/fixtures/test_video_2s.mp4` committed (or generated in conftest.py)
- [ ] Resource limits (`_apply_resource_limits`) do not interfere with CI runners
- [ ] VOD HLS flags patched correctly (`-hls_playlist_type vod`, `-hls_list_size 0`)
- [ ] Error classification covers all patterns in `_ERROR_PATTERNS`
