# MEDIA-002: FFmpeg Binary Management

**Ticket**: MEDIA-002
**Status**: Design
**Author**: Platform Engineering
**Date**: 2026-05-24

---

## 1. Overview & Motivation

### Problem Statement

The platform has grown to depend on FFmpeg in multiple subsystems -- VOD transcoding, broadcast ingest, file manager media previews, and audio waveform generation -- yet there is no centralized mechanism to detect, validate, version-pin, or provision the FFmpeg binary. Each callsite independently calls `shutil.which("ffmpeg")` or hardcodes the string `"ffmpeg"` as the first element of a subprocess argument list. This fragile pattern produces silent degradation (features return `None` or empty results when FFmpeg is absent) and offers no visibility into binary availability at startup or runtime.

### Why Binary Management Matters

1. **Silent feature degradation**: The file manager's `_extract_video_poster_bytes`, `_extract_video_hover_clip_bytes`, `_extract_audio_waveform_bytes`, and `_extract_media_duration_poster` functions all guard with `if not shutil.which("ffmpeg"): return None`. When FFmpeg is missing, video thumbnails, hover clips, and waveforms silently disappear from the UI with no alert or log entry. Users experience broken previews with no indication of the root cause.

2. **Version skew risk**: The ABR pipeline (`app/services/ffmpeg_abr_pipeline.py`) generates command lines that rely on features introduced in FFmpeg 5.0+ (e.g., `hls_flags delete_segments+append_list`). The broadcast worker script (`scripts/broadcast-local/ffmpeg-worker.sh`) uses multi-variant streaming with `-var_stream_map`. Older FFmpeg versions (4.x) may silently produce corrupt output or fail with cryptic errors.

3. **Deployment diversity**: The platform targets four deployment environments:
   - **Local dev** (Ubuntu 24+, installed via apt or direct binary)
   - **Docker** (multi-stage build, binary copied from builder layer)
   - **Lambda** (FFmpeg packaged as a Lambda layer)
   - **ECS Fargate** (same Docker image as standard deployment)

   Each environment requires a different provisioning strategy, but all need the same validation and health-check logic.

4. **Operational observability**: The `just status` / `scripts/dev.sh status` command checks 7 services but has no FFmpeg health indicator. When the transcode worker (VOD-003) starts polling for jobs, it needs confidence that FFmpeg is functional before claiming work.

5. **Codec requirements**: The ticket specifies that FFmpeg must include `libx264`, `libx265`, `libvpx`, and `libopus`. The standard Ubuntu `ffmpeg` package includes these, but custom builds or Alpine-based Docker images may not.

### Deployment Scenarios

| Environment | Binary Source | Validation Timing |
|-------------|--------------|-------------------|
| Local dev (Ubuntu) | `apt install ffmpeg` via `setup_ubuntu.sh` | At stack startup (`dev.sh status`) |
| Local dev (macOS) | `brew install ffmpeg` (manual) | At stack startup |
| Docker | Multi-stage build: `COPY --from=builder /usr/bin/ffmpeg` | At image build + container startup |
| Lambda layer | Pre-built static binary in `/opt/bin/ffmpeg` | At cold start (first invocation) |
| ECS Fargate | Same Docker image | At task startup (health check) |

---

## 2. Current State Analysis

### How FFmpeg Is Referenced Today

The codebase references FFmpeg in five distinct patterns:

**Pattern 1: Hardcoded binary name in argument list** (`app/services/ffmpeg_abr_pipeline.py:68`)
```python
args = ["ffmpeg", "-hide_banner", "-loglevel", "warning", "-y", ...]
```
The string `"ffmpeg"` is hardcoded as the first element of the args list passed to `build_rendition_ffmpeg_args()`. There is no configurable binary path, no version check, and no fallback.

**Pattern 2: Guard-and-skip with `shutil.which`** (`app/services/filemanager.py:1362, 1430, 1481, 1668`)
```python
if not shutil.which("ffmpeg"):
    return None
```
Four separate functions each independently check for FFmpeg availability. If missing, they silently return `None`, causing the caller to skip media preview generation without logging or alerting.

**Pattern 3: Shell script with `command -v` guard** (`scripts/video/package_vod.sh:11`)
```bash
if ! command -v ffmpeg >/dev/null 2>&1; then
  echo "ffmpeg is required for package_vod.sh (not found on PATH)" >&2
  exit 1
fi
```
This exits with an error, which is correct behavior for a CLI tool but provides no structured health signal.

**Pattern 4: Unguarded shell invocation** (`scripts/broadcast-local/ffmpeg-worker.sh:30`)
```bash
ffmpeg -hide_banner -loglevel warning \
  -re -i "${INPUT_URL}" ...
```
No availability check. If FFmpeg is missing, the script fails with a shell error and the `while true` loop retries indefinitely.

**Pattern 5: Log path reference** (`app/core/settings.py:464`)
```python
broadcast_local_ffmpeg_log_path: str = os.environ.get("BROADCAST_LOCAL_FFMPEG_LOG_PATH", "tmp/broadcast-logs/ffmpeg-worker.log")
```
Settings reference FFmpeg log output but not the binary path itself.

### Installation Assumptions

- **`scripts/setup_ubuntu.sh`**: Does NOT install FFmpeg. The system packages block (line 37) installs `build-essential`, `python3-venv`, `openjdk-17-jre-headless`, etc., but FFmpeg is conspicuously absent.
- **No Dockerfile exists yet** for the backend (local dev uses `scripts/run_local_mock_backend.sh` directly).
- **No Lambda layer packaging** exists for FFmpeg.

### Version Requirements

Based on feature usage across the codebase:

| Feature Used | Minimum FFmpeg Version | Where Used |
|-------------|----------------------|------------|
| `-hls_flags delete_segments+append_list` | 4.0 | `ffmpeg_abr_pipeline.py:123` |
| `-var_stream_map` (multi-variant HLS) | 4.0 | `ffmpeg-worker.sh:39` |
| `-master_pl_name` | 4.0 | `ffmpeg-worker.sh:44` |
| `drawtext` filter with alpha | 3.0 | `ffmpeg_abr_pipeline.py:83` |
| `-progress pipe:1` (needed by VOD-003 worker) | 4.0 | Future: `transcode_worker.py` |
| `libx265` encoder | 5.0 (reliable packaging) | Ticket requirement |
| `libvpx` / VP9 encoding | 4.0 | Ticket requirement |
| `libopus` audio codec | 4.0 | Ticket requirement |
| WebP output (`-c:v libwebp`) | 4.3 | `filemanager.py:1380` |

**Conclusion**: Minimum required version is **FFmpeg 5.0** to satisfy all current usage plus the codec requirements specified in the ticket (libx264, libx265, libvpx, libopus). FFmpeg 5.0 was released in January 2022 and is available in Ubuntu 22.04+ repos.

### Existing Settings Pattern

The `Settings` dataclass in `app/core/settings.py` uses a consistent pattern:
```python
some_feature_setting: type = os.environ.get("ENV_VAR_NAME", "default_value")
```
There are currently zero FFmpeg-related settings in the dataclass. The only tangentially related setting is `broadcast_local_ffmpeg_log_path`.

---

## 3. Technical Design

### 3.1 Binary Detection and Validation

Create a new module `app/services/ffmpeg_binary.py` that centralizes all FFmpeg binary management logic:

```python
# app/services/ffmpeg_binary.py

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.core.settings import S

logger = logging.getLogger(__name__)

MINIMUM_FFMPEG_VERSION = (5, 0, 0)
REQUIRED_CODECS = {"libx264", "libx265", "libvpx", "libopus"}
REQUIRED_FORMATS = {"hls", "dash", "mp4", "webm"}

_VERSION_RE = re.compile(r"ffmpeg version (\d+)\.(\d+)(?:\.(\d+))?")


@dataclass(frozen=True)
class FFmpegInfo:
    path: str
    version: tuple[int, int, int]
    version_string: str
    codecs: set[str]
    formats: set[str]
    valid: bool
    errors: list[str]


_cached_info: Optional[FFmpegInfo] = None


def detect_ffmpeg() -> FFmpegInfo:
    """Detect and validate the FFmpeg binary. Result is cached."""
    global _cached_info
    if _cached_info is not None:
        return _cached_info

    errors: list[str] = []

    # 1. Resolve binary path
    binary_path = _resolve_binary_path()
    if not binary_path:
        info = FFmpegInfo(
            path="",
            version=(0, 0, 0),
            version_string="",
            codecs=set(),
            formats=set(),
            valid=False,
            errors=["FFmpeg binary not found on PATH or at configured FFMPEG_BINARY_PATH"],
        )
        _cached_info = info
        return info

    # 2. Parse version
    version, version_string = _parse_version(binary_path)
    if version < MINIMUM_FFMPEG_VERSION:
        errors.append(
            f"FFmpeg version {version_string} is below minimum "
            f"{'.'.join(str(v) for v in MINIMUM_FFMPEG_VERSION)}"
        )

    # 3. Check codecs
    codecs = _detect_codecs(binary_path)
    missing_codecs = REQUIRED_CODECS - codecs
    if missing_codecs:
        errors.append(f"Missing required codecs: {', '.join(sorted(missing_codecs))}")

    # 4. Check formats
    formats = _detect_formats(binary_path)
    missing_formats = REQUIRED_FORMATS - formats
    if missing_formats:
        errors.append(f"Missing required formats: {', '.join(sorted(missing_formats))}")

    info = FFmpegInfo(
        path=binary_path,
        version=version,
        version_string=version_string,
        codecs=codecs,
        formats=formats,
        valid=len(errors) == 0,
        errors=errors,
    )
    _cached_info = info
    return info


def get_ffmpeg_path() -> str:
    """Return the validated FFmpeg binary path. Raises RuntimeError if invalid."""
    info = detect_ffmpeg()
    if not info.valid:
        raise RuntimeError(f"FFmpeg is not available or invalid: {'; '.join(info.errors)}")
    return info.path


def get_ffprobe_path() -> str:
    """Return ffprobe path derived from the FFmpeg binary location."""
    info = detect_ffmpeg()
    if not info.path:
        raise RuntimeError("FFmpeg binary not found; ffprobe unavailable")
    ffmpeg_dir = str(Path(info.path).parent)
    probe_path = shutil.which("ffprobe", path=ffmpeg_dir) or shutil.which("ffprobe")
    if not probe_path:
        raise RuntimeError("ffprobe not found alongside ffmpeg binary")
    return probe_path


def invalidate_cache() -> None:
    """Clear cached detection result. Call after binary install/update."""
    global _cached_info
    _cached_info = None
```

### 3.2 Version Pinning

Version pinning is enforced through two mechanisms:

1. **Hard minimum** (`MINIMUM_FFMPEG_VERSION = (5, 0, 0)`): The `detect_ffmpeg()` function marks the binary as invalid if below this threshold.

2. **Configurable pin** via `FFMPEG_REQUIRED_VERSION` environment variable: Allows operators to pin to a specific major.minor (e.g., `"6.1"`) for fleet consistency. If set, the detected version must match the pinned major.minor.

```python
def _check_version_pin(version: tuple[int, int, int]) -> str | None:
    """Return error string if version does not match pin, or None if OK."""
    pin = S.ffmpeg_required_version
    if not pin:
        return None
    parts = pin.split(".")
    if len(parts) < 2:
        return f"Invalid FFMPEG_REQUIRED_VERSION format: {pin!r} (expected 'major.minor')"
    try:
        pin_major, pin_minor = int(parts[0]), int(parts[1])
    except ValueError:
        return f"Invalid FFMPEG_REQUIRED_VERSION: {pin!r}"
    if version[0] != pin_major or version[1] != pin_minor:
        return (
            f"FFmpeg version {version[0]}.{version[1]} does not match "
            f"pinned version {pin_major}.{pin_minor}"
        )
    return None
```

### 3.3 Auto-Download for Dev Mode

When `S.dev_mode` is True and FFmpeg is not found, the system can optionally auto-download a static build. This is gated by `FFMPEG_AUTO_DOWNLOAD` (default `"0"` -- opt-in).

```python
FFMPEG_STATIC_URL_LINUX_X64 = (
    "https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-amd64-static.tar.xz"
)
FFMPEG_STATIC_URL_LINUX_ARM64 = (
    "https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-arm64-static.tar.xz"
)

def auto_download_ffmpeg(target_dir: str = ".local/tools/ffmpeg") -> str | None:
    """Download a static FFmpeg build to the local tools directory.

    Returns the path to the ffmpeg binary, or None on failure.
    Only runs in dev mode with FFMPEG_AUTO_DOWNLOAD=1.
    """
    if not S.dev_mode or not S.ffmpeg_auto_download:
        return None

    target = Path(target_dir)
    target.mkdir(parents=True, exist_ok=True)
    ffmpeg_bin = target / "ffmpeg"
    if ffmpeg_bin.exists() and ffmpeg_bin.stat().st_size > 0:
        return str(ffmpeg_bin)

    import platform
    import tarfile
    import urllib.request

    arch = platform.machine()
    if arch in ("x86_64", "amd64"):
        url = FFMPEG_STATIC_URL_LINUX_X64
    elif arch in ("aarch64", "arm64"):
        url = FFMPEG_STATIC_URL_LINUX_ARM64
    else:
        logger.warning("ffmpeg_auto_download: unsupported architecture %s", arch)
        return None

    logger.info("Downloading static FFmpeg from %s ...", url)
    archive_path = target / "ffmpeg-static.tar.xz"
    try:
        urllib.request.urlretrieve(url, str(archive_path))
        with tarfile.open(str(archive_path), "r:xz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("/ffmpeg") or member.name.endswith("/ffprobe"):
                    member.name = Path(member.name).name  # flatten path
                    tar.extract(member, path=str(target))
        archive_path.unlink(missing_ok=True)
        ffmpeg_bin.chmod(0o755)
        (target / "ffprobe").chmod(0o755)
        logger.info("FFmpeg downloaded to %s", ffmpeg_bin)
        return str(ffmpeg_bin)
    except Exception as exc:
        logger.error("FFmpeg auto-download failed: %s", exc)
        return None
```

### 3.4 Health Check Endpoint

Add an FFmpeg health check to the existing internal devtools router at `/internal/dev-tools/ffmpeg-health`. This integrates with the existing devtools pattern in `app/routers/internal_devtools.py`.

```python
# Added to app/routers/internal_devtools.py (or a new router registered alongside it)

@router.get("/ffmpeg-health")
def ffmpeg_health_check() -> dict:
    """Return FFmpeg binary status for monitoring and dev-tools UI."""
    from app.services.ffmpeg_binary import detect_ffmpeg
    info = detect_ffmpeg()
    return {
        "available": info.valid,
        "path": info.path,
        "version": info.version_string,
        "version_tuple": list(info.version),
        "codecs_present": sorted(info.codecs & REQUIRED_CODECS),
        "codecs_missing": sorted(REQUIRED_CODECS - info.codecs),
        "formats_present": sorted(info.formats & REQUIRED_FORMATS),
        "formats_missing": sorted(REQUIRED_FORMATS - info.formats),
        "errors": info.errors,
        "minimum_version": ".".join(str(v) for v in MINIMUM_FFMPEG_VERSION),
    }
```

Additionally, add FFmpeg status to `scripts/dev.sh` `cmd_status()`:

```bash
# After existing service checks in cmd_status():
local ffmpeg_ok ffmpeg_ver
if command -v ffmpeg >/dev/null 2>&1; then
  ffmpeg_ver="$(ffmpeg -version 2>/dev/null | head -1 | awk '{print $3}')"
  ffmpeg_ok=true
else
  ffmpeg_ver="not installed"
  ffmpeg_ok=false
fi
printf "  %-34s [%s]  version=%s\n" "FFmpeg" "$(_status_icon $ffmpeg_ok)" "$ffmpeg_ver"
```

### 3.5 Docker Layer Caching

For containerized deployments, the Dockerfile should install FFmpeg in a dedicated early layer to maximize cache reuse:

```dockerfile
# Stage 1: FFmpeg binary (rarely changes, highly cacheable)
FROM ubuntu:24.04 AS ffmpeg-layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/* \
    && ffmpeg -version | head -1

# Stage 2: Python dependencies
FROM python:3.12-slim AS deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 3: Application
FROM python:3.12-slim AS app
COPY --from=ffmpeg-layer /usr/bin/ffmpeg /usr/bin/ffmpeg
COPY --from=ffmpeg-layer /usr/bin/ffprobe /usr/bin/ffprobe
COPY --from=ffmpeg-layer /usr/lib/x86_64-linux-gnu/libav* /usr/lib/x86_64-linux-gnu/
COPY --from=ffmpeg-layer /usr/lib/x86_64-linux-gnu/libsw* /usr/lib/x86_64-linux-gnu/
COPY --from=ffmpeg-layer /usr/lib/x86_64-linux-gnu/libx264* /usr/lib/x86_64-linux-gnu/
COPY --from=ffmpeg-layer /usr/lib/x86_64-linux-gnu/libx265* /usr/lib/x86_64-linux-gnu/
COPY --from=ffmpeg-layer /usr/lib/x86_64-linux-gnu/libvpx* /usr/lib/x86_64-linux-gnu/
COPY --from=ffmpeg-layer /usr/lib/x86_64-linux-gnu/libopus* /usr/lib/x86_64-linux-gnu/
# ... additional shared libs as needed (determined via ldd)
COPY --from=deps /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY . /app
WORKDIR /app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

The key insight: FFmpeg and its shared libraries change infrequently (only on OS upgrades or deliberate version bumps), so placing them in the first build stage means Docker layer caching keeps rebuilds fast during normal development.

### 3.6 Lambda Layer Packaging

For Lambda-based transcode workers, FFmpeg is distributed as a Lambda layer:

```
layers/ffmpeg/
  bin/
    ffmpeg
    ffprobe
  lib/
    libx264.so.164
    libx265.so.199
    libvpx.so.7
    libopus.so.0
    ... (all shared libs from ldd)
```

A packaging script builds this from a static binary or Docker extraction:

```bash
#!/bin/bash
# scripts/lambda/build-ffmpeg-layer.sh
set -euo pipefail

LAYER_DIR="$(mktemp -d)"
mkdir -p "${LAYER_DIR}/bin" "${LAYER_DIR}/lib"

# Use static build for Lambda (no shared lib dependencies)
curl -fSL "https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-amd64-static.tar.xz" \
  | tar -xJ --strip-components=1 -C "${LAYER_DIR}/bin" --wildcards '*/ffmpeg' '*/ffprobe'

chmod +x "${LAYER_DIR}/bin/ffmpeg" "${LAYER_DIR}/bin/ffprobe"

# Validate
"${LAYER_DIR}/bin/ffmpeg" -version | head -1
"${LAYER_DIR}/bin/ffmpeg" -codecs 2>/dev/null | grep -q libx264 || { echo "FAIL: libx264 missing"; exit 1; }

# Package as zip for Lambda layer
cd "${LAYER_DIR}"
zip -r9 /tmp/ffmpeg-lambda-layer.zip bin/ lib/
echo "Layer ready: /tmp/ffmpeg-lambda-layer.zip ($(du -h /tmp/ffmpeg-lambda-layer.zip | cut -f1))"
```

The Lambda handler sets `PATH` to include `/opt/bin` (Lambda layers are mounted at `/opt`):

```python
import os
os.environ.setdefault("FFMPEG_BINARY_PATH", "/opt/bin/ffmpeg")
```

### 3.7 Settings Schema

Add the following to `app/core/settings.py`:

```python
# FFmpeg binary management (MEDIA-002)
ffmpeg_binary_path: str = os.environ.get("FFMPEG_BINARY_PATH", "ffmpeg")
ffmpeg_required_version: str = os.environ.get("FFMPEG_REQUIRED_VERSION", "")
ffmpeg_auto_download: bool = os.environ.get("FFMPEG_AUTO_DOWNLOAD", "0") not in ("0", "false", "False")
ffmpeg_health_check_on_startup: bool = os.environ.get("FFMPEG_HEALTH_CHECK_ON_STARTUP", "1") not in ("0", "false", "False")
ffmpeg_strict_validation: bool = os.environ.get("FFMPEG_STRICT_VALIDATION", "0") not in ("0", "false", "False")
```

| Setting | Env Var | Default | Purpose |
|---------|---------|---------|---------|
| `ffmpeg_binary_path` | `FFMPEG_BINARY_PATH` | `"ffmpeg"` | Absolute path or bare name (resolved via PATH) |
| `ffmpeg_required_version` | `FFMPEG_REQUIRED_VERSION` | `""` (any >= 5.0) | Pin to specific major.minor (e.g., `"6.1"`) |
| `ffmpeg_auto_download` | `FFMPEG_AUTO_DOWNLOAD` | `"0"` | Auto-download static build in dev mode |
| `ffmpeg_health_check_on_startup` | `FFMPEG_HEALTH_CHECK_ON_STARTUP` | `"1"` | Run detection at backend startup and log result |
| `ffmpeg_strict_validation` | `FFMPEG_STRICT_VALIDATION` | `"0"` | If `"1"`, block startup when FFmpeg is invalid |

### 3.8 Startup Integration

Register a startup event handler in `app/main.py` that runs detection and logs the result:

```python
from app.services.ffmpeg_binary import detect_ffmpeg, auto_download_ffmpeg, invalidate_cache

def _ffmpeg_startup_check() -> None:
    if not S.ffmpeg_health_check_on_startup:
        return

    # Attempt auto-download if enabled and binary not found
    if S.ffmpeg_auto_download and S.dev_mode:
        downloaded = auto_download_ffmpeg()
        if downloaded:
            invalidate_cache()

    info = detect_ffmpeg()
    if info.valid:
        logger.info(
            "ffmpeg_available",
            extra={"path": info.path, "version": info.version_string},
        )
    else:
        msg = f"FFmpeg validation failed: {'; '.join(info.errors)}"
        if S.ffmpeg_strict_validation:
            raise RuntimeError(msg)
        logger.warning("ffmpeg_unavailable", extra={"errors": info.errors})

app.add_event_handler("startup", _ffmpeg_startup_check)
```

### 3.9 Integration with Existing Callsites

After MEDIA-002 lands, existing callsites should migrate from hardcoded `"ffmpeg"` to the centralized accessor:

**`app/services/ffmpeg_abr_pipeline.py:68`** -- change:
```python
# Before:
args = ["ffmpeg", "-hide_banner", ...]
# After:
from app.services.ffmpeg_binary import get_ffmpeg_path
args = [get_ffmpeg_path(), "-hide_banner", ...]
```

**`app/services/filemanager.py:1362,1430,1481,1668`** -- change:
```python
# Before:
if not shutil.which("ffmpeg"):
    return None
# After:
from app.services.ffmpeg_binary import detect_ffmpeg
info = detect_ffmpeg()
if not info.valid:
    return None
```

**`app/services/filemanager.py:1093`** -- change:
```python
# Before:
if not shutil.which("ffprobe"):
    return {..., "error": "ffprobe_unavailable"}
# After:
from app.services.ffmpeg_binary import detect_ffmpeg
info = detect_ffmpeg()
if not info.path:
    return {..., "error": "ffprobe_unavailable"}
```

These migrations can be done incrementally. The `detect_ffmpeg()` cache means the overhead is a single subprocess call at first invocation, then free thereafter.

---

## 4. Implementation Plan

### 4.1 New Files

| File | Purpose |
|------|---------|
| `app/services/ffmpeg_binary.py` | Core module: `detect_ffmpeg()`, `get_ffmpeg_path()`, `get_ffprobe_path()`, `auto_download_ffmpeg()`, `invalidate_cache()`, version parsing, codec/format detection |
| `tests/test_ffmpeg_binary.py` | Unit tests for detection, validation, version parsing, error conditions |
| `scripts/lambda/build-ffmpeg-layer.sh` | Lambda layer packaging script |

### 4.2 Modified Files

| File | Change |
|------|--------|
| `app/core/settings.py` | Add 5 FFmpeg settings (section 3.7) |
| `app/main.py` | Add startup event handler `_ffmpeg_startup_check` |
| `app/routers/internal_devtools.py` | Add `GET /internal/dev-tools/ffmpeg-health` endpoint |
| `scripts/setup_ubuntu.sh` | Add `ffmpeg` to the `apt-get install` line (section 1, system packages) |
| `scripts/dev.sh` | Add FFmpeg version display to `cmd_status()` |
| `scripts/verify_ready.sh` | Add FFmpeg availability check |
| `app/services/ffmpeg_abr_pipeline.py` | Replace hardcoded `"ffmpeg"` with `get_ffmpeg_path()` |
| `app/services/filemanager.py` | Replace `shutil.which("ffmpeg")` calls with `detect_ffmpeg()` |

### 4.3 Step-by-Step Implementation Order

**Step 1: Settings** (no dependencies)
- Add the 5 new settings to `app/core/settings.py` in a new `# FFmpeg binary management (MEDIA-002)` section, placed after the existing broadcast settings block (after line 478).

**Step 2: Core detection module** (depends on Step 1)
- Create `app/services/ffmpeg_binary.py` with:
  - `_resolve_binary_path()` -- checks `S.ffmpeg_binary_path`, then `shutil.which()`, then auto-download path
  - `_parse_version(path)` -- runs `ffmpeg -version`, parses with regex
  - `_detect_codecs(path)` -- runs `ffmpeg -codecs`, parses encoder names
  - `_detect_formats(path)` -- runs `ffmpeg -formats`, parses muxer names
  - `_check_version_pin(version)` -- validates against `S.ffmpeg_required_version`
  - `detect_ffmpeg()` -- orchestrates all checks, caches result
  - `get_ffmpeg_path()` / `get_ffprobe_path()` -- convenience accessors
  - `auto_download_ffmpeg()` -- dev-mode auto-provisioning
  - `invalidate_cache()` -- for testing and post-download refresh

**Step 3: Startup hook** (depends on Steps 1-2)
- Add `_ffmpeg_startup_check` to `app/main.py` using `app.add_event_handler("startup", ...)` pattern (matches existing broadcast reconciler, billing dunning, etc.).

**Step 4: Health check endpoint** (depends on Steps 1-2)
- Add `GET /internal/dev-tools/ffmpeg-health` to `app/routers/internal_devtools.py`.

**Step 5: Setup script** (no code dependencies)
- Add `ffmpeg` to the system packages list in `scripts/setup_ubuntu.sh` line 38.
- Add verification block after Node.js section:
  ```bash
  if command -v ffmpeg >/dev/null 2>&1; then
    ok "FFmpeg $(ffmpeg -version 2>&1 | head -1 | awk '{print $3}') installed."
  else
    warn "FFmpeg not found. Install with: sudo apt install ffmpeg"
  fi
  ```

**Step 6: Status integration** (no code dependencies)
- Add FFmpeg check to `scripts/dev.sh` `cmd_status()` (after line 235).
- Add FFmpeg check to `scripts/verify_ready.sh` (after the npm check block).

**Step 7: Migrate callsites** (depends on Step 2)
- Update `app/services/ffmpeg_abr_pipeline.py` to use `get_ffmpeg_path()`.
- Update `app/services/filemanager.py` to use `detect_ffmpeg()`.
- This step can be done as a follow-up PR to keep the initial PR small.

**Step 8: Lambda layer script** (independent)
- Create `scripts/lambda/build-ffmpeg-layer.sh`.
- Document in `docs/run-deploy.md`.

### 4.4 Dependencies

- **No blocking dependencies**: MEDIA-002 can be built in parallel with all other tickets.
- **Downstream consumers**: VOD-003 (transcode job queue) will call `get_ffmpeg_path()` in its worker. BCAST-007 can use the health check to validate broadcast worker readiness.

---

## 5. Testing Strategy

### 5.1 Unit Tests for Detection and Validation (`tests/test_ffmpeg_binary.py`)

Tests run without requiring FFmpeg on the system by mocking `subprocess.run` and `shutil.which`.

**Version parsing tests:**

1. `test_parse_version_standard_format` -- Input: `"ffmpeg version 6.1.1 Copyright (c) ..."` -> `(6, 1, 1)`
2. `test_parse_version_two_part` -- Input: `"ffmpeg version 7.0 ..."` -> `(7, 0, 0)`
3. `test_parse_version_with_suffix` -- Input: `"ffmpeg version 5.1.4-ubuntu22.04 ..."` -> `(5, 1, 4)`
4. `test_parse_version_git_build` -- Input: `"ffmpeg version N-112345-g1234abc ..."` -> graceful fallback `(0, 0, 0)` with error
5. `test_parse_version_empty_output` -- Input: `""` -> `(0, 0, 0)` with error

**Binary resolution tests:**

6. `test_resolve_explicit_path` -- Set `S.ffmpeg_binary_path = "/usr/local/bin/ffmpeg"` -> returns that path if exists
7. `test_resolve_from_path_fallback` -- Set `S.ffmpeg_binary_path = "ffmpeg"` -> delegates to `shutil.which("ffmpeg")`
8. `test_resolve_not_found` -- Neither explicit path nor PATH resolution finds binary -> returns `None`
9. `test_resolve_auto_download_path` -- When auto-downloaded, checks `.local/tools/ffmpeg/ffmpeg`

**Validation tests:**

10. `test_detect_valid_ffmpeg` -- Mock version 6.1.1, all codecs present -> `info.valid == True`
11. `test_detect_version_too_old` -- Mock version 4.2.0 -> `info.valid == False`, error mentions minimum
12. `test_detect_missing_codec` -- Mock version OK but `libx265` missing -> `info.valid == False`
13. `test_detect_missing_format` -- Mock version OK but `hls` not in formats -> `info.valid == False`
14. `test_detect_version_pin_match` -- Pin `"6.1"`, detected `6.1.2` -> valid
15. `test_detect_version_pin_mismatch` -- Pin `"6.1"`, detected `6.0.1` -> invalid with pin error
16. `test_detect_caches_result` -- Call `detect_ffmpeg()` twice, `subprocess.run` called only once
17. `test_invalidate_cache_clears` -- After `invalidate_cache()`, next `detect_ffmpeg()` re-runs subprocess

**Error handling tests:**

18. `test_subprocess_timeout` -- `subprocess.run` raises `TimeoutExpired` -> graceful failure
19. `test_subprocess_permission_denied` -- Binary exists but not executable -> error
20. `test_malformed_codec_output` -- FFmpeg returns unexpected format -> empty codec set, error logged

### 5.2 Unit Tests for Auto-Download (`tests/test_ffmpeg_binary.py`)

21. `test_auto_download_skipped_when_disabled` -- `S.ffmpeg_auto_download = False` -> returns None immediately
22. `test_auto_download_skipped_in_prod` -- `S.dev_mode = False` -> returns None
23. `test_auto_download_skipped_when_binary_exists` -- Target file already exists -> returns existing path
24. `test_auto_download_network_failure` -- Mock `urllib.request.urlretrieve` raising -> returns None, logs error
25. `test_auto_download_success` -- Mock download + extraction -> returns path, file is executable

### 5.3 Integration Tests (require FFmpeg on system)

These tests are gated with `@pytest.mark.skipif(not shutil.which("ffmpeg"), reason="FFmpeg not installed")`:

26. `test_detect_ffmpeg_real` -- Run `detect_ffmpeg()` against the real system binary. Verify `info.valid == True` (on CI where FFmpeg is installed), version >= 5.0.
27. `test_get_ffmpeg_path_real` -- Verify `get_ffmpeg_path()` returns a string that resolves to an executable.
28. `test_get_ffprobe_path_real` -- Verify `get_ffprobe_path()` returns a path to a working ffprobe.
29. `test_ffmpeg_can_produce_output` -- Run a trivial transcode (2-second testsrc to null output):
    ```python
    result = subprocess.run(
        [get_ffmpeg_path(), "-f", "lavfi", "-i", "testsrc=duration=1:size=64x64:rate=1",
         "-frames:v", "1", "-f", "null", "-"],
        capture_output=True, timeout=10,
    )
    assert result.returncode == 0
    ```
30. `test_codec_detection_matches_reality` -- Verify that `detect_ffmpeg().codecs` includes `libx264` (which is always present in standard Ubuntu FFmpeg packages).

### 5.4 Health Check Endpoint Tests

31. `test_ffmpeg_health_endpoint_available` -- `GET /internal/dev-tools/ffmpeg-health` returns 200 with expected JSON schema.
32. `test_ffmpeg_health_endpoint_reports_missing` -- Mock `detect_ffmpeg()` to return invalid info -> response has `"available": false`.
33. `test_ffmpeg_health_endpoint_requires_dev_mode` -- When `S.dev_mode = False`, endpoint returns 404 (existing `_require_devtools_enabled()` guard).

### 5.5 Startup Hook Tests

34. `test_startup_logs_ffmpeg_available` -- Mock valid FFmpeg -> no exception, info-level log emitted.
35. `test_startup_logs_ffmpeg_missing` -- Mock missing FFmpeg with `ffmpeg_strict_validation=False` -> warning log, no exception.
36. `test_startup_strict_mode_raises` -- Mock missing FFmpeg with `ffmpeg_strict_validation=True` -> `RuntimeError` raised.
37. `test_startup_auto_download_triggers` -- Mock `S.ffmpeg_auto_download=True`, no binary found -> `auto_download_ffmpeg()` is called.

### 5.6 CI Pipeline Considerations

**GitHub Actions / CI configuration:**

```yaml
# .github/workflows/test.yml (relevant section)
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install FFmpeg
        run: sudo apt-get update && sudo apt-get install -y ffmpeg
      - name: Verify FFmpeg
        run: |
          ffmpeg -version | head -1
          ffmpeg -codecs 2>/dev/null | grep -q libx264
          ffmpeg -codecs 2>/dev/null | grep -q libx265
      - name: Run tests
        run: .venv/bin/pytest tests/test_ffmpeg_binary.py -v
```

**Test isolation**: Unit tests (5.1, 5.2) mock all subprocess calls and run without FFmpeg. Integration tests (5.3) are skipped on systems without FFmpeg. This ensures the test suite passes in environments where FFmpeg is deliberately not installed (e.g., lightweight lint-only CI jobs).

**E2E test coverage**: The existing file manager E2E tests that exercise video upload + thumbnail generation implicitly validate FFmpeg availability. No additional E2E spec file is needed for MEDIA-002 specifically, but the `just status` output should be verified manually after implementation.

---

## Appendix A: Internal Helper Functions

```python
def _resolve_binary_path() -> str | None:
    """Resolve the FFmpeg binary path from settings, PATH, or auto-download location."""
    configured = S.ffmpeg_binary_path.strip()

    # Absolute path specified
    if configured.startswith("/"):
        return configured if Path(configured).is_file() else None

    # Bare name -- resolve via PATH
    found = shutil.which(configured)
    if found:
        return found

    # Check auto-download location
    auto_path = Path(".local/tools/ffmpeg") / configured
    if auto_path.is_file():
        return str(auto_path.resolve())

    return None


def _parse_version(binary_path: str) -> tuple[tuple[int, int, int], str]:
    """Run ffmpeg -version and parse the version tuple."""
    try:
        result = subprocess.run(
            [binary_path, "-version"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout or result.stderr or ""
        match = _VERSION_RE.search(output)
        if match:
            major, minor = int(match.group(1)), int(match.group(2))
            patch = int(match.group(3)) if match.group(3) else 0
            version_str = output.split("\n")[0].strip()
            return (major, minor, patch), version_str
    except (subprocess.TimeoutExpired, OSError, ValueError):
        pass
    return (0, 0, 0), ""


def _detect_codecs(binary_path: str) -> set[str]:
    """Run ffmpeg -codecs and return the set of available encoder names."""
    try:
        result = subprocess.run(
            [binary_path, "-codecs", "-hide_banner"],
            capture_output=True, text=True, timeout=10,
        )
        codecs = set()
        for line in (result.stdout or "").splitlines():
            # Format: " DEV.L. libx264  ..."
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0] != "------":
                codecs.add(parts[1])
        return codecs
    except (subprocess.TimeoutExpired, OSError):
        return set()


def _detect_formats(binary_path: str) -> set[str]:
    """Run ffmpeg -formats and return the set of available format names."""
    try:
        result = subprocess.run(
            [binary_path, "-formats", "-hide_banner"],
            capture_output=True, text=True, timeout=10,
        )
        formats = set()
        for line in (result.stdout or "").splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0] != "---":
                formats.add(parts[1])
        return formats
    except (subprocess.TimeoutExpired, OSError):
        return set()
```

## Appendix B: Environment Variable Reference

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `FFMPEG_BINARY_PATH` | `ffmpeg` | Path to FFmpeg binary (absolute or bare name resolved via PATH) |
| `FFMPEG_REQUIRED_VERSION` | `""` | Pin to major.minor (e.g., `"6.1"`); empty = any >= 5.0 |
| `FFMPEG_AUTO_DOWNLOAD` | `0` | Auto-download static FFmpeg in dev mode when not found |
| `FFMPEG_HEALTH_CHECK_ON_STARTUP` | `1` | Run validation at backend startup |
| `FFMPEG_STRICT_VALIDATION` | `0` | Block startup if FFmpeg is missing/invalid |

## Appendix C: Migration Path for Existing Callsites

| File | Line(s) | Current Pattern | Target Pattern |
|------|---------|----------------|----------------|
| `app/services/ffmpeg_abr_pipeline.py` | 68 | `["ffmpeg", ...]` | `[get_ffmpeg_path(), ...]` |
| `app/services/filemanager.py` | 1362, 1430, 1481, 1668 | `shutil.which("ffmpeg")` | `detect_ffmpeg().valid` |
| `app/services/filemanager.py` | 1093 | `shutil.which("ffprobe")` | `detect_ffmpeg().path` (derive ffprobe) |
| `scripts/broadcast-local/ffmpeg-worker.sh` | 30 | bare `ffmpeg` | `${FFMPEG_BINARY_PATH:-ffmpeg}` |
| `scripts/video/package_vod.sh` | 11 | `command -v ffmpeg` | `${FFMPEG_BINARY_PATH:-ffmpeg}` |
