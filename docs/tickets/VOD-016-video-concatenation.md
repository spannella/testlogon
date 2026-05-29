# VOD-016: Video Concatenation / Combining

**Ticket**: VOD-016
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-27

---

## 1. Overview & Motivation

### 1.1 Problem Statement

Creators often need to combine multiple videos into a single output -- adding a branded intro/outro, merging multi-part recordings from a live session, or assembling a highlights compilation. Today, this requires downloading each source video, stitching them together in desktop editing software, and re-uploading the result. This is cumbersome, bandwidth-intensive, and breaks metadata lineage.

A first-party concatenation tool lets creators select videos from their library, arrange them in order, and produce a combined output entirely on the platform. The result is a new video with full provenance tracking and automatic HLS processing.

### 1.2 How It Works

1. Creator navigates to their video library and clicks "Combine Videos".
2. A dialog opens showing the creator's video library with checkboxes for selection.
3. Creator selects 2-10 videos and arranges them via drag-and-drop ordering.
4. Creator provides a title and optional description. The estimated output duration is displayed.
5. Clicking "Combine" sends a `POST /ui/videos/concat` request.
6. The backend validates all inputs (ownership, status, count limits), creates a new video metadata record, and enqueues a concat job.
7. The concat job downloads all source files, determines whether a fast concat demuxer (same codec/resolution) or a filter-based re-encode (mixed formats) is needed, and runs ffmpeg.
8. After concatenation, the output runs through the standard ABR pipeline (HLS renditions, thumbnails).
9. The new video appears in the creator's library with links back to all source videos.

### 1.3 Design Principles

- **Non-destructive**: Source videos are never modified. Concatenation always produces a new video record.
- **Codec-aware path selection**: When all inputs share the same codec and resolution, the concat demuxer is used (stream copy, fast). When inputs differ, the concat filter re-encodes everything to a common format. This optimization is transparent to the creator.
- **Lineage tracking**: The output video stores `source_video_ids` (array of source IDs, in order) and `created_via: "concat"`.
- **Bounded scope**: Maximum 10 input videos, 4 hours combined duration, and 10 GB total input size prevent abuse and resource exhaustion.

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to combine my intro video, main content, and outro into one video. | POST concat with 3 video_ids; new video created; plays seamlessly in order. |
| Creator | As a creator, I want to reorder my selected videos before combining. | Frontend drag-and-drop controls video order; backend uses `video_ids` array order. |
| Creator | As a creator, I want to see the estimated duration before combining. | Dialog shows sum of individual durations; response includes `estimated_duration_seconds`. |
| Creator | As a creator, I want to know which videos were combined to make this one. | Video detail shows `source_video_ids` array linking to originals. |
| Creator | As a creator, I want the combined video to go through the same quality pipeline as my uploads. | After concat, ABR pipeline produces HLS renditions + thumbnails; playback works normally. |
| Viewer | As a viewer, I see a combined video and can play it like any other video. | Combined video is indistinguishable from uploads in the player. |

---

## 2. Current State Analysis

### 2.1 FFmpeg Concatenation Capabilities

FFmpeg supports two concatenation methods:

**Concat demuxer (stream copy, fast)**:
```bash
# filelist.txt:
# file '/tmp/scratch/job123/input_0.mp4'
# file '/tmp/scratch/job123/input_1.mp4'
# file '/tmp/scratch/job123/input_2.mp4'

ffmpeg -f concat -safe 0 -i filelist.txt -c copy -movflags +faststart output.mp4
```

- Pros: No re-encoding; completes in seconds regardless of total duration; no quality loss.
- Cons: All inputs must have the same codec, resolution, frame rate, and audio sample rate. Mismatched inputs produce artifacts, audio sync drift, or outright failure.
- Compatibility check: ffprobe each input and compare codec, resolution, frame rate, and audio parameters.

**Concat filter (re-encode, universal)**:
```bash
ffmpeg \
  -i input_0.mp4 -i input_1.mp4 -i input_2.mp4 \
  -filter_complex \
    "[0:v]scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2,setsar=1[v0]; \
     [1:v]scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2,setsar=1[v1]; \
     [2:v]scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2,setsar=1[v2]; \
     [v0][0:a][v1][1:a][v2][2:a]concat=n=3:v=1:a=1[outv][outa]" \
  -map "[outv]" -map "[outa]" \
  -c:v libx264 -preset medium -crf 22 \
  -c:a aac -b:a 128k -ar 48000 \
  -movflags +faststart \
  output.mp4
```

- Pros: Handles any mix of codecs, resolutions, and frame rates; normalizes everything to a consistent output.
- Cons: Full decode + encode cycle for all inputs; processing time scales linearly with total input duration; generation loss (mitigated by CRF quality targeting).
- Resolution normalization: All inputs are scaled to the highest resolution among inputs (up to 1920x1080 cap), with letterboxing/pillarboxing to preserve aspect ratio.

**Chosen strategy**: Probe all inputs. If they share the same video codec, resolution, and frame rate, and the same audio codec and sample rate, use the concat demuxer. Otherwise, use the concat filter with re-encode.

### 2.2 Existing FFmpeg Infrastructure

**`app/services/ffmpeg_executor.py`** (VOD-004):
- `execute_rendition()` -- Async subprocess wrapper with progress, timeout, cancellation, resource limits.
- The concat job will use `execute_rendition()` with concat-specific ffmpeg args.
- For the concat filter path, `expected_duration_us` is set to the sum of all input durations for accurate progress tracking.

**`app/services/ffmpeg_manager.py`** (MEDIA-002):
- `get_ffmpeg_path()` -- Validated binary path.
- Concat operations require `libx264` and `aac` codecs (in `REQUIRED_CODECS`).

**`app/services/ffmpeg_abr_pipeline.py`**:
- After concatenation, the combined file runs through this pipeline for HLS rendition generation.

**`app/services/transcode_job_store.py`** (VOD-003):
- Job queue with state machine (queued -> running -> completed/failed).
- **Note:** The existing `create_job()` does not have a `job_type` field. A `job_type` field (value `"concat"`) must be added to distinguish concat jobs from standard transcodes and clips. This requires modifying `create_job()` or using a separate `create_concat_job()` helper that writes `job_type` directly.

### 2.3 Video Metadata Model

**`app/models_video.py`** -- Relevant existing fields:
- `duration_seconds` -- Sum of input durations used for estimated output duration.
- `source_s3_key` -- Each input video's source file in S3.
- `video_codec`, `audio_codec`, `width`, `height`, `frame_rate`, `audio_channels` -- Used for compatibility probing to choose demuxer vs. filter path.

**From VOD-015** (if implemented first):
- `source_video_id` -- Single source reference (used by clips). Concat needs an array variant.
- `created_via` -- Already defined; concat uses value `"concat"`.

### 2.4 Source File Availability

Each input video's original upload is stored at `videos/{user_sub}/{video_id}/{filename}` in the upload bucket. The concat job downloads all input sources to scratch disk before processing. Source retention is indefinite (see VOD-012, Section 2.2).

### 2.5 Probe Data Requirements

The concat job needs codec and format information for each input to decide between demuxer and filter paths. This data is already stored on the video metadata record from the probe step (VOD-002):
- `video_codec`, `audio_codec`, `width`, `height`, `frame_rate`, `audio_channels`, `container_format`

If any input is missing probe data (e.g., old videos uploaded before probing was implemented), the concat job falls back to the re-encode path (safe default).

---

## 3. Technical Design

### 3.1 Approach Evaluation

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| **A: Always concat demuxer** | Always use `-f concat -c copy` | Fastest; no quality loss | Fails or produces artifacts with mixed codecs/resolutions |
| **B: Always concat filter** | Always re-encode via filter_complex | Universal compatibility | Unnecessarily slow when all inputs are compatible; generation loss |
| **C: Auto-detect with demuxer preferred** | Probe inputs; use demuxer if compatible, filter otherwise | Fast for compatible inputs; correct for mixed inputs | More complex probing logic; two code paths |

### 3.2 Recommended Approach: Auto-Detect (Option C)

The concat job probes all inputs and selects the appropriate method:

```python
def _inputs_are_compatible(videos: list[VideoMetadataModel]) -> bool:
    """Check if all input videos can be concatenated via demuxer (stream copy)."""
    if not videos:
        return False

    ref = videos[0]
    for v in videos[1:]:
        if v.video_codec != ref.video_codec:
            return False
        if v.audio_codec != ref.audio_codec:
            return False
        if v.width != ref.width or v.height != ref.height:
            return False
        if v.frame_rate != ref.frame_rate:
            return False
        # Missing probe data -> not compatible (safe fallback)
        if any(getattr(v, f) is None for f in ("video_codec", "width", "height")):
            return False
    return True
```

### 3.3 Data Model Changes

**File: `app/models_video.py`** -- Add fields to `VideoMetadataModel`:

```python
# Concatenation provenance (VOD-016)
source_video_ids: Optional[List[str]] = None   # Ordered list of source video IDs (for concat)
```

Note: `created_via` and `source_video_id` are already defined in VOD-015. For concat, `source_video_id` remains `None` (it is single-source only), and `source_video_ids` holds the ordered array. `created_via` is set to `"concat"`.

**File: `app/models_video.py`** -- New request model:

```python
class ConcatVideosIn(BaseModel):
    video_ids: List[str] = Field(min_length=2, max_length=10)
    title: str = Field(min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)
```

**File: `app/models_video.py`** -- Add to `VideoOut`:

```python
source_video_ids: Optional[List[str]] = None
```

### 3.4 API Endpoint

**Path**: `POST /ui/videos/concat`

**Auth**: `require_ui_session` (cookie-based)

**Request body**:
```json
{
  "video_ids": ["v_abc123", "v_def456", "v_ghi789"],
  "title": "Complete Workshop Series",
  "description": "Parts 1-3 combined"
}
```

**Validation rules**:
1. `video_ids` contains 2-10 entries.
2. No duplicate IDs in the array.
3. All videos exist and are owned by the requesting user.
4. All videos are in `"published"` or `"approved"` status (fully transcoded).
5. All videos have a `source_s3_key` (source file available).
6. Combined duration (`sum(v.duration_seconds)`) does not exceed `VIDEO_CONCAT_MAX_DURATION_SECONDS` (default: 14400 = 4 hours).
7. Combined source file size (`sum(v.file_size_bytes)`) does not exceed `VIDEO_CONCAT_MAX_TOTAL_SIZE_BYTES` (default: 10 GB).

**Response** (201 Created):
```json
{
  "video_id": "v_new123",
  "title": "Complete Workshop Series",
  "status": "created",
  "source_video_ids": ["v_abc123", "v_def456", "v_ghi789"],
  "created_via": "concat",
  "estimated_duration_seconds": 3720.5,
  "concat_method": "demuxer",
  "concat_job_id": "tj_xyz789"
}
```

**Error responses**:

| Status | Condition | Detail |
|--------|-----------|--------|
| 400 | Fewer than 2 or more than 10 video_ids | "video_ids must contain 2-10 entries" |
| 400 | Duplicate IDs in array | "video_ids contains duplicates" |
| 400 | Combined duration exceeds limit | "combined duration exceeds 4 hour limit" |
| 400 | Combined size exceeds limit | "combined input size exceeds 10 GB limit" |
| 403 | Any video not owned by requester | "forbidden: video {id} is not owned by you" |
| 404 | Any video not found | "video not found: {id}" |
| 409 | Any video not in published/approved status | "video {id} must be published or approved" |
| 409 | Any video missing source_s3_key | "source file not available for video {id}" |
| 409 | Any video missing duration_seconds | "duration unknown for video {id}" |

```python
@router.post("/concat", status_code=201)
def concat_videos(
    body: ConcatVideosIn,
    ctx=Depends(require_ui_session),
):
    user_sub = ctx["user_sub"]

    if not S.video_concat_enabled:
        raise HTTPException(status_code=503, detail="video concatenation is disabled")

    # Check for duplicates
    if len(set(body.video_ids)) != len(body.video_ids):
        raise HTTPException(status_code=400, detail="video_ids contains duplicates")

    # Fetch and validate all videos
    videos: list[VideoMetadataModel] = []
    total_duration = 0.0
    total_size = 0

    for vid in body.video_ids:
        video = get_video(vid)
        if video.owner_user_id != user_sub:
            raise HTTPException(status_code=403, detail=f"forbidden: video {vid} is not owned by you")
        if video.status not in ("published", "approved"):
            raise HTTPException(status_code=409, detail=f"video {vid} must be published or approved")
        if not video.source_s3_key:
            raise HTTPException(status_code=409, detail=f"source file not available for video {vid}")
        if video.duration_seconds is None:
            raise HTTPException(status_code=409, detail=f"duration unknown for video {vid}")

        total_duration += video.duration_seconds
        total_size += video.file_size_bytes or 0
        videos.append(video)

    if total_duration > S.video_concat_max_duration_seconds:
        raise HTTPException(
            status_code=400,
            detail=f"combined duration ({total_duration:.0f}s) exceeds {S.video_concat_max_duration_seconds}s limit",
        )

    if total_size > S.video_concat_max_total_size_bytes:
        raise HTTPException(
            status_code=400,
            detail=f"combined input size exceeds {S.video_concat_max_total_size_bytes // (1024**3)} GB limit",
        )

    # Determine concat method
    use_demuxer = _inputs_are_compatible(videos)
    concat_method = "demuxer" if use_demuxer else "filter"

    # Create new video metadata
    new_video = create_video(
        owner_user_id=user_sub,
        title=body.title,
        description=body.description,
        source_type="upload",
        visibility="private",
    )

    # Set concat provenance fields
    update_concat_fields(
        video_id=new_video.id,
        source_video_ids=body.video_ids,
        created_via="concat",
        duration_seconds=total_duration,
    )

    # Enqueue concat job
    job = create_concat_job(
        video_id=new_video.id,
        source_video_ids=body.video_ids,
        source_s3_keys=[v.source_s3_key for v in videos],
        concat_method=concat_method,
        owner_user_id=user_sub,
        estimated_duration_seconds=total_duration,
    )

    return {
        "video_id": new_video.id,
        "title": body.title,
        "status": "created",
        "source_video_ids": body.video_ids,
        "created_via": "concat",
        "estimated_duration_seconds": total_duration,
        "concat_method": concat_method,
        "concat_job_id": job["job_id"],
    }
```

### 3.5 Concat Job Processing

#### 3.5.1 Job Creation

```python
def create_concat_job(
    *,
    video_id: str,
    source_video_ids: list[str],
    source_s3_keys: list[str],
    concat_method: str,
    owner_user_id: str,
    estimated_duration_seconds: float,
) -> Dict[str, Any]:
    """Create a concat job in the transcode job queue."""
    job_id = f"tj_{uuid4().hex}"
    ts = now_ts()

    item = {
        "job_id": job_id,
        "video_id": video_id,
        "tenant_id": owner_user_id,
        "status": "queued",
        "status_created_at": f"queued#{ts}",
        "created_at": ts,
        "updated_at": ts,
        "attempt": 0,
        "max_attempts": S.transcode_max_attempts,
        "priority": 0,
        "job_type": "concat",
        "source_uri": "",
        "concat_source_video_ids": source_video_ids,
        "concat_source_s3_keys": source_s3_keys,
        "concat_method": concat_method,
        "concat_estimated_duration_seconds": Decimal(str(estimated_duration_seconds)),
        "progress_pct": 0,
        "renditions_completed": [],
        "renditions": [],
    }

    T.transcode_jobs.put_item(Item=item)
    return item
```

#### 3.5.2 Concat Processing Logic

```python
async def process_concat_job(job: Dict[str, Any]) -> None:
    """End-to-end concat job processor.

    Steps:
    1. Download all source files from S3 to scratch directory.
    2. Probe inputs to confirm or update concat method.
    3. Run ffmpeg concat (demuxer or filter based on method).
    4. Upload concatenated MP4 to S3 as new source.
    5. Enqueue standard transcode job for ABR processing.
    6. Mark concat job as completed.
    """
    job_id = job["job_id"]
    video_id = job["video_id"]
    owner = job["tenant_id"]
    s3_keys = job["concat_source_s3_keys"]
    method = job["concat_method"]
    est_duration = float(job.get("concat_estimated_duration_seconds", 0))

    scratch_dir = Path(S.transcode_scratch_dir) / f"concat-{job_id}"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Download all sources
        input_paths = []
        for i, key in enumerate(s3_keys):
            ext = Path(key).suffix or ".mp4"
            local_path = scratch_dir / f"input_{i}{ext}"
            _s3.download_file(
                Bucket=S.video_upload_bucket,
                Key=key,
                Filename=str(local_path),
            )
            input_paths.append(local_path)

        update_job_progress(job_id, progress_pct=10, current_rendition="downloading")

        # 2. Run concat
        output_path = scratch_dir / "concat_output.mp4"

        if method == "demuxer":
            await _run_concat_demuxer(input_paths, output_path, timeout_seconds=S.video_concat_timeout_seconds)
        else:
            await _run_concat_filter(
                input_paths, output_path,
                timeout_seconds=S.video_concat_timeout_seconds,
                expected_duration_us=int(est_duration * 1_000_000),
            )

        update_job_progress(job_id, progress_pct=70, current_rendition="uploading")

        # 3. Upload to S3
        dest_key = f"videos/{owner}/{video_id}/concat.mp4"
        _s3.upload_file(
            Filename=str(output_path),
            Bucket=S.video_upload_bucket,
            Key=dest_key,
        )

        # 4. Update video metadata
        actual_duration = await _probe_duration(output_path)
        update_video_source(
            video_id=video_id,
            source_s3_key=dest_key,
            duration_seconds=actual_duration or est_duration,
            status="pending_encoding",
        )

        update_job_progress(job_id, progress_pct=80, current_rendition="enqueuing_transcode")

        # 5. Enqueue standard transcode job
        create_job(
            video_id=video_id,
            tenant_id=owner,
            rendition_profiles=[],  # Use default ABR ladder
            source_uri=dest_key,
        )

        # 6. Complete concat job
        complete_job(job_id, output_manifest_uri="")
        update_job_progress(job_id, progress_pct=100)

    except Exception as e:
        logger.exception("Concat job %s failed: %s", job_id, e)
        fail_job(job_id, str(e)[:500], job.get("attempt", 0))
    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)
```

#### 3.5.3 Concat Demuxer (Stream Copy Path)

```python
async def _run_concat_demuxer(
    input_paths: list[Path],
    output_path: Path,
    timeout_seconds: int = 600,
) -> None:
    """Concatenate videos using the concat demuxer (stream copy, fast)."""
    # Build file list
    filelist_path = output_path.parent / "filelist.txt"
    with open(filelist_path, "w") as f:
        for p in input_paths:
            # Escape single quotes in path for concat demuxer
            escaped = str(p).replace("'", "'\\''")
            f.write(f"file '{escaped}'\n")

    ffmpeg_bin = get_ffmpeg_path()
    args = [
        ffmpeg_bin, "-hide_banner", "-loglevel", "warning", "-y",
        "-f", "concat", "-safe", "0",
        "-i", str(filelist_path),
        "-c", "copy",
        "-movflags", "+faststart",
        str(output_path),
    ]

    result = await execute_rendition(
        args=args,
        rendition_name="concat-demuxer",
        expected_duration_us=0,  # Unknown for demuxer (no progress parsing)
        timeout_seconds=timeout_seconds,
    )

    if not result.success:
        raise ConcatError(f"Concat demuxer failed (exit={result.returncode}): {result.stderr_tail[:200]}")
```

#### 3.5.4 Concat Filter (Re-encode Path)

```python
async def _run_concat_filter(
    input_paths: list[Path],
    output_path: Path,
    timeout_seconds: int = 1800,
    expected_duration_us: int = 0,
) -> None:
    """Concatenate videos using the concat filter (re-encode, universal)."""
    n = len(input_paths)

    # Determine target resolution: highest among inputs, capped at 1920x1080
    target_w, target_h = _determine_target_resolution(input_paths)

    ffmpeg_bin = get_ffmpeg_path()
    args = [ffmpeg_bin, "-hide_banner", "-loglevel", "warning", "-y"]

    # Add all inputs
    for p in input_paths:
        args.extend(["-i", str(p)])

    # Build filter_complex
    filter_parts = []
    concat_inputs = []

    for i in range(n):
        # Scale each input to target resolution with letterboxing
        filter_parts.append(
            f"[{i}:v]scale={target_w}:{target_h}:"
            f"force_original_aspect_ratio=decrease,"
            f"pad={target_w}:{target_h}:(ow-iw)/2:(oh-ih)/2,"
            f"setsar=1[v{i}]"
        )
        concat_inputs.append(f"[v{i}][{i}:a]")

    concat_inputs_str = "".join(concat_inputs)
    filter_parts.append(
        f"{concat_inputs_str}concat=n={n}:v=1:a=1[outv][outa]"
    )

    filter_complex = ";".join(filter_parts)

    args.extend([
        "-filter_complex", filter_complex,
        "-map", "[outv]", "-map", "[outa]",
        "-c:v", "libx264", "-preset", "medium", "-crf", "22",
        "-c:a", "aac", "-b:a", "128k", "-ar", "48000",
        "-movflags", "+faststart",
        str(output_path),
    ])

    result = await execute_rendition(
        args=args,
        rendition_name="concat-filter",
        expected_duration_us=expected_duration_us,
        timeout_seconds=timeout_seconds,
    )

    if not result.success:
        raise ConcatError(f"Concat filter failed (exit={result.returncode}): {result.stderr_tail[:200]}")
```

#### 3.5.5 Target Resolution Determination

```python
def _determine_target_resolution(input_paths: list[Path]) -> tuple[int, int]:
    """Determine target resolution for concat filter output.

    Uses the highest resolution among inputs, capped at 1920x1080.
    Falls back to 1920x1080 if probing fails.
    """
    max_pixels = 0
    best_w, best_h = 1920, 1080

    for path in input_paths:
        try:
            w, h = _probe_resolution(path)
            if w * h > max_pixels:
                max_pixels = w * h
                best_w, best_h = w, h
        except Exception:
            continue

    # Cap at 1080p
    if best_w > 1920 or best_h > 1080:
        # Scale down maintaining aspect ratio
        scale = min(1920 / best_w, 1080 / best_h)
        best_w = int(best_w * scale) & ~1  # Ensure even dimensions
        best_h = int(best_h * scale) & ~1

    return best_w, best_h
```

### 3.6 S3 Path Convention

The concatenated source file is stored alongside other uploads:

```
s3://{local-uploads}/videos/{user_sub}/{new_video_id}/concat.mp4
```

After the concat goes through the ABR pipeline, HLS outputs land at:

```
s3://{vod-output}/{prefix}/{tenant_id}/assets/{new_video_id}/
  hls/
    master.m3u8
    1080p/index.m3u8
    ...
  thumbnails/
    poster_0s.jpg
    ...
```

### 3.7 Scratch Directory Management

```python
scratch_dir = Path(S.transcode_scratch_dir) / f"concat-{job_id}"
scratch_dir.mkdir(parents=True, exist_ok=True)

# Download all inputs
input_paths = []
for i, key in enumerate(s3_keys):
    ext = Path(key).suffix or ".mp4"
    local_path = scratch_dir / f"input_{i}{ext}"
    _s3.download_file(Bucket=bucket, Key=key, Filename=str(local_path))
    input_paths.append(local_path)

output_path = scratch_dir / "concat_output.mp4"
filelist_path = scratch_dir / "filelist.txt"  # For demuxer path

try:
    # Process...
finally:
    shutil.rmtree(scratch_dir, ignore_errors=True)
```

**Disk space consideration**: For 10 inputs at 1 GB each, scratch needs ~11 GB (inputs + output). The pre-flight disk check (`_check_disk_space`) must account for this. The `ffmpeg_min_free_disk_gb` setting (default 5 GB) should be checked against `total_input_size + estimated_output_size`.

### 3.8 Settings

**File: `app/core/settings.py`** -- New settings:

```python
# Video Concatenation (VOD-016)
video_concat_enabled: bool = os.environ.get("VIDEO_CONCAT_ENABLED", "1") not in ("0", "false", "False")
video_concat_max_inputs: int = int(os.environ.get("VIDEO_CONCAT_MAX_INPUTS", "10"))
video_concat_max_duration_seconds: int = int(os.environ.get("VIDEO_CONCAT_MAX_DURATION_SECONDS", "14400"))  # 4 hours
video_concat_max_total_size_bytes: int = int(os.environ.get("VIDEO_CONCAT_MAX_TOTAL_SIZE_BYTES", str(10 * 1024 * 1024 * 1024)))  # 10 GB
video_concat_timeout_seconds: int = int(os.environ.get("VIDEO_CONCAT_TIMEOUT_SECONDS", "1800"))  # 30 minutes
```

### 3.9 Frontend: Combine Videos Dialog

#### 3.9.1 Combine Videos Button

On the video gallery/library page:

```tsx
<Button
  variant="outline"
  onClick={() => setCombineDialogOpen(true)}
  className="gap-2"
>
  <Layers className="h-4 w-4" />
  Combine Videos
</Button>
```

#### 3.9.2 CombineVideosDialog Component

```tsx
// frontend/src/components/shared/CombineVideosDialog.tsx

interface CombineVideosDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function CombineVideosDialog({ open, onOpenChange }: CombineVideosDialogProps) {
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");

  // Fetch user's published videos
  const { data: videos } = useQuery({
    queryKey: ["videos", "mine", "published"],
    queryFn: () => fetchMyVideos({ status: "published" }),
  });

  const concatMutation = useMutation({
    mutationFn: (body: { video_ids: string[]; title: string; description?: string }) =>
      apiClient.post("/ui/videos/concat", body),
    onSuccess: (data) => {
      toast.success("Combine job started");
      onOpenChange(false);
      navigate(`/videos/${data.data.video_id}`);
    },
  });

  // Calculate estimated duration
  const selectedVideos = videos?.filter((v) => selectedIds.includes(v.id)) || [];
  const estimatedDuration = selectedVideos.reduce((sum, v) => sum + (v.duration_seconds || 0), 0);

  const isValid = selectedIds.length >= 2
    && selectedIds.length <= 10
    && title.length > 0
    && estimatedDuration <= 14400;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Combine Videos</DialogTitle>
          <DialogDescription>
            Select 2-10 videos to combine. Drag to reorder.
          </DialogDescription>
        </DialogHeader>

        {/* Video selection with checkboxes */}
        <div className="space-y-2 max-h-64 overflow-y-auto">
          {videos?.map((video) => (
            <div key={video.id} className="flex items-center gap-3 p-2 rounded hover:bg-muted">
              <Checkbox
                checked={selectedIds.includes(video.id)}
                onCheckedChange={(checked) => {
                  if (checked) setSelectedIds([...selectedIds, video.id]);
                  else setSelectedIds(selectedIds.filter((id) => id !== video.id));
                }}
              />
              <img src={video.thumbnail_url} className="w-16 h-9 object-cover rounded" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{video.title}</p>
                <p className="text-xs text-muted-foreground">
                  {formatTimestamp(video.duration_seconds || 0)}
                </p>
              </div>
            </div>
          ))}
        </div>

        {/* Selected order (drag-and-drop) */}
        {selectedIds.length >= 2 && (
          <div className="space-y-2">
            <Label>Order (drag to reorder)</Label>
            <SortableList
              items={selectedIds}
              onReorder={setSelectedIds}
              renderItem={(id) => {
                const v = videos?.find((v) => v.id === id);
                return (
                  <div className="flex items-center gap-2 p-2 bg-muted rounded">
                    <GripVertical className="h-4 w-4 text-muted-foreground" />
                    <img src={v?.thumbnail_url} className="w-12 h-7 object-cover rounded" />
                    <span className="text-sm truncate">{v?.title}</span>
                  </div>
                );
              }}
            />
          </div>
        )}

        {/* Title + Description */}
        <div className="space-y-2">
          <Label htmlFor="concat-title">Title</Label>
          <Input
            id="concat-title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Combined video title"
            maxLength={256}
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="concat-desc">Description (optional)</Label>
          <Textarea
            id="concat-desc"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Description"
            maxLength={2000}
          />
        </div>

        {/* Estimated duration */}
        {selectedIds.length >= 2 && (
          <div className="text-sm text-muted-foreground">
            Estimated duration: {formatTimestamp(estimatedDuration)}
            {estimatedDuration > 14400 && (
              <span className="text-destructive ml-2">
                Exceeds 4-hour limit
              </span>
            )}
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            onClick={() => concatMutation.mutate({
              video_ids: selectedIds,
              title,
              description: description || undefined,
            })}
            disabled={!isValid || concatMutation.isPending}
            className="gap-2"
          >
            {concatMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Layers className="h-4 w-4" />
            )}
            Combine ({selectedIds.length} videos)
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
```

#### 3.9.3 Frontend API

**File: `frontend/src/api/endpoints/videos.ts`**:

```typescript
export interface ConcatVideosRequest {
  video_ids: string[];
  title: string;
  description?: string;
}

export interface ConcatVideosResponse {
  video_id: string;
  title: string;
  status: string;
  source_video_ids: string[];
  created_via: string;
  estimated_duration_seconds: number;
  concat_method: string;
  concat_job_id: string;
}

export function concatVideos(body: ConcatVideosRequest): Promise<ConcatVideosResponse> {
  return apiClient.post("/ui/videos/concat", body).then((r) => r.data);
}
```

### 3.10 Dependency Graph

```
VOD-001 (metadata model) ─────────┐
VOD-003 (transcode job queue) ────┤
VOD-004 (FFmpeg execution) ───────┤
VOD-005 (S3 upload outputs) ──────┤
VOD-006 (listing API) ────────────┤
VOD-015 (clipping -- created_via) ┤
                                   v
                        VOD-016 (this ticket)
                                   │
                                   v
                        VOD-008 (player page update)
```

VOD-016 depends on the existing transcode pipeline (VOD-001 through VOD-005) for post-concat ABR processing. VOD-015 introduces the `created_via` and `source_video_id` fields that VOD-016 extends with `source_video_ids`. If VOD-015 is not yet implemented, VOD-016 must add both `created_via` and `source_video_ids` to the model.

---

## 4. Implementation Plan

### 4.1 Files

<!-- NOTE: Key files ALREADY EXIST:
     - `app/services/video_concatenator.py` — `create_concat_job()` (line 43), `_check_codec_compatibility()` (line 183), `execute_concat()` (line 218), `_run_concat_demuxer()` (line 318), `_run_concat_filter()` (line 356)
     - `app/services/video_metadata_store.py` — `update_concat_fields()` already at line 646
     - `app/routers/video_listing.py` — `CombineVideosIn` (line 930), `CombineVideosOut` (line 936)
     - `frontend/e2e/video-concat.spec.ts` — ALREADY EXISTS
-->

| File | Purpose |
|------|---------|
| `app/services/video_concatenator.py` | **Already exists**: `create_concat_job()` (line 43), `execute_concat()` (line 218), `_run_concat_demuxer()` (line 318), `_run_concat_filter()` (line 356) |
| `frontend/src/components/shared/CombineVideosDialog.tsx` | Combine dialog with video selection, drag-and-drop ordering, title/description fields, estimated duration |
| `tests/test_video_concatenator.py` | Unit tests for concat service |
| `frontend/e2e/video-concat.spec.ts` | E2E tests for concat API and processing |

### 4.2 Files to Modify

| File | Change |
|------|--------|
| `app/models_video.py` | Add `source_video_ids` to `VideoMetadataModel`; add `ConcatVideosIn` model; add `source_video_ids` to `VideoOut`. If VOD-015 not yet implemented, also add `created_via`. |
| `app/services/video_metadata_store.py` | Serialize/deserialize `source_video_ids` in `video_to_item` / `video_from_item`; add `update_concat_fields()` helper |
| `app/services/transcode_job_store.py` | Add `job_type` field (does not exist today) and `cancel_job()` function (does not exist today); concat jobs carry `concat_source_video_ids`, `concat_source_s3_keys`, `concat_method`, `concat_estimated_duration_seconds` |
| `app/routers/video_listing.py` | Add `POST /concat` endpoint; include `source_video_ids` in video detail response |
| `app/core/settings.py` | Add `video_concat_enabled`, `video_concat_max_inputs`, `video_concat_max_duration_seconds`, `video_concat_max_total_size_bytes`, `video_concat_timeout_seconds` |
| `.env.local.example` | Add `VIDEO_CONCAT_*` environment variables |
| `frontend/src/api/endpoints/videos.ts` | Add `concatVideos()` function; add `ConcatVideosRequest`, `ConcatVideosResponse` interfaces; add `source_video_ids` to `VideoDetail` |
| `frontend/src/pages/videos/VideoLibraryPage.tsx` (or equivalent gallery page) | Add "Combine Videos" button; wire CombineVideosDialog |

### 4.3 Step-by-Step Implementation Order

**Step 1: Data model + settings** (no behavior change)
1. Add `source_video_ids` to `VideoMetadataModel` (and `created_via` if VOD-015 not done).
2. Add `ConcatVideosIn` request model.
3. Update `video_to_item` / `video_from_item` for new fields.
4. Add settings to `app/core/settings.py`.
5. Add env vars to `.env.local.example`.

**Step 2: Input compatibility probing**
1. Implement `_inputs_are_compatible(videos)` -- Check codec, resolution, frame rate match.
2. Implement `_determine_target_resolution(input_paths)` -- Find highest resolution, cap at 1080p.

**Step 3: Concat execution service**
1. Create `app/services/video_concatenator.py` with:
   - `_run_concat_demuxer(input_paths, output_path)` -- File list + stream copy.
   - `_run_concat_filter(input_paths, output_path)` -- Filter complex with scaling + re-encode.
   - `process_concat_job(job)` -- End-to-end: download all sources, concat, upload, enqueue transcode.

**Step 4: API endpoint**
1. Add `POST /ui/videos/concat` to `app/routers/video_listing.py`.
2. Validate all inputs (ownership, status, limits).
3. Create new video metadata with concat provenance.
4. Enqueue concat job.

**Step 5: Job processing integration**
1. The existing transcode worker has no `job_type` dispatch -- it processes all jobs the same way. The worker must be extended to check the `job_type` field and dispatch `"concat"` jobs to `process_concat_job` instead of the standard transcode path.
2. After concat + upload, create a follow-up standard transcode job for ABR processing.

**Step 6: Frontend**
1. Create `CombineVideosDialog.tsx` component.
2. Add `concatVideos()` to `frontend/src/api/endpoints/videos.ts`.
3. Add "Combine Videos" button to video library page.
4. Add concat provenance display to video detail view.

---

## 5. Testing Strategy

### 5.1 Unit Tests: Concat Service (`tests/test_video_concatenator.py`)

| Test | What It Validates |
|------|-------------------|
| `test_inputs_compatible_same_codec_resolution` | All inputs with same H.264/1080p -> returns True. |
| `test_inputs_incompatible_different_codec` | Input 1 is H.264, input 2 is VP9 -> returns False. |
| `test_inputs_incompatible_different_resolution` | Input 1 is 1080p, input 2 is 720p -> returns False. |
| `test_inputs_incompatible_missing_probe_data` | Input with `video_codec=None` -> returns False (safe fallback). |
| `test_determine_target_resolution_picks_highest` | Inputs at 1080p and 720p -> target is 1920x1080. |
| `test_determine_target_resolution_caps_at_1080p` | Input at 4K -> target capped at 1920x1080. |
| `test_concat_demuxer_builds_correct_filelist` | Filelist.txt contains correct `file` entries in order. |
| `test_concat_demuxer_builds_correct_args` | FFmpeg args include `-f concat -safe 0 -c copy -movflags +faststart`. |
| `test_concat_filter_builds_correct_filter_complex` | Filter graph includes scale+pad+setsar for each input; concat=n={n}:v=1:a=1. |
| `test_concat_filter_uses_correct_codecs` | Args include `-c:v libx264 -preset medium -crf 22 -c:a aac -b:a 128k -ar 48000`. |
| `test_process_concat_job_downloads_all_sources` | Mock S3; verify download called for each source S3 key. |
| `test_process_concat_job_uploads_result` | Concat output uploaded to `videos/{user}/{video_id}/concat.mp4`. |
| `test_process_concat_job_enqueues_transcode` | After concat upload, a standard transcode job is created. |
| `test_process_concat_job_cleans_scratch_dir` | Scratch directory removed after success. |
| `test_process_concat_job_cleans_scratch_on_failure` | Scratch directory removed even on failure. |

### 5.2 Unit Tests: Concat Endpoint (`tests/test_video_concat_endpoint.py`)

| Test | What It Validates |
|------|-------------------|
| `test_concat_valid_inputs_201` | POST with 3 valid video_ids -> 201 with new video_id, source_video_ids, concat_job_id. |
| `test_concat_fewer_than_2_videos_400` | Single video_id -> 400 "video_ids must contain 2-10 entries". |
| `test_concat_more_than_10_videos_400` | 11 video_ids -> 400. |
| `test_concat_duplicate_ids_400` | Same video_id twice -> 400 "video_ids contains duplicates". |
| `test_concat_not_owner_403` | One video belongs to another user -> 403. |
| `test_concat_unpublished_video_409` | One video in "encoding" status -> 409. |
| `test_concat_missing_source_409` | One video has no source_s3_key -> 409. |
| `test_concat_missing_duration_409` | One video has no duration_seconds -> 409. |
| `test_concat_exceeds_duration_limit_400` | Total duration > 14400s -> 400. |
| `test_concat_exceeds_size_limit_400` | Total size > 10 GB -> 400. |
| `test_concat_video_not_found_404` | Non-existent video_id in array -> 404. |
| `test_concat_method_detected_correctly` | Compatible inputs -> response has `concat_method="demuxer"`; incompatible -> `"filter"`. |

### 5.3 E2E Tests: `frontend/e2e/video-concat.spec.ts`

**Section 129: Video concatenation API** (5 tests)

```typescript
test("129.1 Creator concatenates 2 published videos", async ({ page }) => {
  // POST /ui/videos/concat with 2 video_ids
  // Expect 201 with new video_id, source_video_ids, created_via="concat"
});

test("129.2 Concat with fewer than 2 videos returns 400", async ({ page }) => {
  // POST with 1 video_id
  // Expect 400
});

test("129.3 Concat with duplicate video IDs returns 400", async ({ page }) => {
  // POST with same ID twice
  // Expect 400 "video_ids contains duplicates"
});

test("129.4 Concat with non-owned video returns 403", async ({ page }) => {
  // Include Bob's video in Alice's concat request
  // Expect 403
});

test("129.5 Concat with unpublished video returns 409", async ({ page }) => {
  // Include a video in "created" status
  // Expect 409
});
```

**Section 130: Concat job processing** (3 tests)

```typescript
test("130.1 Concat job transitions from queued to completed", async ({ page }) => {
  // Create concat, poll job status until completed or timeout
  // Verify job has job_type="concat"
});

test("130.2 Concatenated video has correct provenance fields", async ({ page }) => {
  // After concat job completes, GET the new video detail
  // Verify source_video_ids matches input array order, created_via="concat"
});

test("130.3 Estimated duration is sum of input durations", async ({ page }) => {
  // Verify estimated_duration_seconds in response approximately equals sum of input durations
});
```

### 5.4 Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| Exactly 2 videos (minimum) | Works normally; concat with n=2. |
| Exactly 10 videos (maximum) | Works normally; concat with n=10. |
| All videos have same codec/resolution | Demuxer path (fast stream copy). |
| Videos with different codecs | Filter path (re-encode). |
| Videos with different resolutions | Filter path with scaling to highest (capped at 1080p). |
| One video has missing probe data | Falls back to filter path (safe default). |
| Source file missing for one input | Job fails with "source_not_found"; partial downloads cleaned up. |
| Very short videos (5 seconds each) | Works; concat produces 10-50 second output. |
| Very long combined output (near 4 hour limit) | Allowed if within limit; filter path may take 30+ minutes. |
| 4K source videos | Resolution capped at 1080p in filter path; demuxer preserves original resolution. |
| Audio-only or video-only input | Concat filter requires both streams; fails with informative error. Future enhancement could handle this. |
| Concurrent concat requests | Each produces independent output; no conflict since sources are read-only. |
| FFmpeg binary not available | `get_ffmpeg_path()` raises; job fails with "FFmpeg not available". |
| Disk space exhausted during download | Pre-flight check should account for total input size + output. Job fails with retryable "disk_full". |
| Network error during S3 download | Download fails; job fails with retryable error; will be retried per `max_attempts`. |

### 5.5 Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Downloading all sources takes time | For 10 x 1GB inputs, ~10 GB download. S3 local endpoint is fast in dev; production scales with S3 bandwidth. Could parallelize downloads in future. |
| Demuxer (stream copy) is fast | Expected: <10 seconds for any total duration when all inputs are compatible. |
| Filter (re-encode) scales linearly | Processing time ~ total input duration / encode speed. A 4-hour concat at 1080p takes ~30-60 minutes. Timeout set to 1800s (30 min) by default. |
| Scratch disk for N inputs + output | Pre-flight disk check must account for total input size + estimated output size. For 10 GB inputs, need ~15 GB free (inputs + output + overhead). |
| Concat job does not block request | POST returns immediately with 201. Job runs asynchronously. |
| Post-concat ABR transcode | Standard transcode time applies to the concatenated output (scales with combined duration). |
| Memory for filter graph | Large filter graphs (10 inputs) consume more memory. Covered by `ffmpeg_max_memory_gb` resource limit in `_apply_resource_limits`. |

---

## 6. Audio Normalization Details

### 6.1 Audio Codec and Parameter Normalization

When inputs have different audio codecs, sample rates, or channel configurations, the concat filter path must normalize all audio streams to a common format before the `concat` filter can combine them.

**Target audio format** (used in re-encode path):
- Codec: AAC-LC (`-c:a aac`)
- Sample rate: 48000 Hz (`-ar 48000`)
- Channels: stereo (2 channels) (`-ac 2`)
- Bitrate: 128 kbps (`-b:a 128k`)

#### 6.1.1 Audio Parameter Mismatch Matrix

| Input A Audio | Input B Audio | Demuxer Compatible? | Filter Path Action |
|---------------|---------------|--------------------|--------------------|
| AAC, 48kHz, stereo | AAC, 48kHz, stereo | Yes | N/A (stream copy) |
| AAC, 44.1kHz, stereo | AAC, 48kHz, stereo | No | Re-encode both to AAC 48kHz stereo |
| AAC, 48kHz, mono | AAC, 48kHz, stereo | No | Upmix mono to stereo via `aformat` + `pan` |
| MP3, 44.1kHz, stereo | AAC, 48kHz, stereo | No | Decode MP3, re-encode as AAC 48kHz stereo |
| Opus, 48kHz, stereo | AAC, 48kHz, stereo | No | Decode Opus, re-encode as AAC 48kHz stereo |
| FLAC, 96kHz, stereo | AAC, 48kHz, stereo | No | Decode FLAC, downsample to 48kHz, re-encode AAC |
| PCM (WAV), 44.1kHz, mono | AAC, 48kHz, stereo | No | Resample, upmix, re-encode AAC |

#### 6.1.2 Channel Layout Handling

When inputs have different channel counts, the filter chain normalizes to stereo:

```
Mono → stereo:      aformat=channel_layouts=stereo, pan=stereo|c0=c0|c1=c0
5.1 surround → stereo: pan=stereo|FL<FL+0.5*FC+0.6*BL|FR<FR+0.5*FC+0.6*BR
Stereo → stereo:    No change
```

The `_inputs_are_compatible()` check already compares `audio_channels` (see Section 3.2). If any input has a different channel count, the filter path is used, and the filter chain includes explicit channel layout normalization.

**Updated filter chain for audio normalization**:

```python
for i in range(n):
    # Video scaling (existing)
    filter_parts.append(
        f"[{i}:v]scale={target_w}:{target_h}:"
        f"force_original_aspect_ratio=decrease,"
        f"pad={target_w}:{target_h}:(ow-iw)/2:(oh-ih)/2,"
        f"setsar=1[v{i}]"
    )
    # Audio normalization: force stereo, 48kHz
    filter_parts.append(
        f"[{i}:a]aresample=48000,aformat=sample_fmts=fltp:channel_layouts=stereo[a{i}]"
    )
    concat_inputs.append(f"[v{i}][a{i}]")
```

#### 6.1.3 Loudness Normalization (EBU R128)

To ensure consistent perceived loudness across concatenated segments, the filter chain applies EBU R128 loudness normalization. Without this, cutting from a quietly-recorded tutorial to a loud music intro creates a jarring volume jump.

**Two-pass approach** (recommended for quality):

```bash
# Pass 1: Analyze loudness of each input
ffmpeg -i input_0.mp4 -af loudnorm=I=-16:TP=-1.5:LRA=11:print_format=json -f null -

# Pass 2: Apply measured corrections
ffmpeg -i input_0.mp4 \
  -af "loudnorm=I=-16:TP=-1.5:LRA=11:measured_I={measured_I}:measured_LRA={measured_LRA}:measured_TP={measured_TP}:measured_thresh={measured_thresh}:offset={offset}:linear=true" \
  ...
```

**Single-pass approach** (used for simplicity in the filter concat path):

```python
# Add loudnorm to each audio stream in the filter_complex
filter_parts.append(
    f"[{i}:a]aresample=48000,"
    f"aformat=sample_fmts=fltp:channel_layouts=stereo,"
    f"loudnorm=I=-16:TP=-1.5:LRA=11[a{i}]"
)
```

Parameters:
- `I=-16` -- Target integrated loudness: -16 LUFS (standard for streaming platforms)
- `TP=-1.5` -- True peak: -1.5 dBTP (headroom to prevent clipping after encoding)
- `LRA=11` -- Loudness range: 11 LU (dynamic range target)

**Configuration**:

```python
# app/core/settings.py
video_concat_loudnorm_enabled: bool = os.environ.get("VIDEO_CONCAT_LOUDNORM_ENABLED", "1") not in ("0", "false", "False")
video_concat_loudnorm_target_lufs: float = float(os.environ.get("VIDEO_CONCAT_LOUDNORM_TARGET_LUFS", "-16"))
video_concat_loudnorm_true_peak: float = float(os.environ.get("VIDEO_CONCAT_LOUDNORM_TRUE_PEAK", "-1.5"))
```

#### 6.1.4 Videos With No Audio Track

Some input videos may lack an audio track entirely (e.g., screen recordings exported without audio, GIF-to-MP4 conversions, timelapse renders). The concat filter's `concat=n=N:v=1:a=1` requires every input to have both a video and audio stream.

**Detection**: During input probing, check `audio_codec`. If `None` or empty, the input has no audio.

**Handling**: Generate a silent audio track for any input missing audio, matching the target parameters:

```python
def _ensure_audio_track(input_index: int, duration_seconds: float) -> str:
    """Generate a filter graph segment that creates a silent audio track
    for an input video that has no audio.

    Uses anullsrc to generate silence at the target sample rate and channel layout,
    trimmed to the video's duration.
    """
    return (
        f"anullsrc=r=48000:cl=stereo:d={duration_seconds:.3f}[silent_a{input_index}]"
    )
```

Updated `_run_concat_filter` with audio track detection:

```python
for i in range(n):
    has_audio = _probe_has_audio(input_paths[i])
    # Video filter (unchanged)
    filter_parts.append(
        f"[{i}:v]scale=..."
    )
    if has_audio:
        filter_parts.append(
            f"[{i}:a]aresample=48000,"
            f"aformat=sample_fmts=fltp:channel_layouts=stereo"
            + (",loudnorm=I=-16:TP=-1.5:LRA=11" if loudnorm_enabled else "")
            + f"[a{i}]"
        )
    else:
        dur = _probe_duration_seconds(input_paths[i])
        filter_parts.append(
            f"anullsrc=r=48000:cl=stereo[silent_{i}];"
            f"[silent_{i}]atrim=duration={dur:.3f}[a{i}]"
        )
    concat_inputs.append(f"[v{i}][a{i}]")
```

**Compatibility check update**: If any input lacks an audio track, the demuxer path cannot be used (stream copy would produce a video-only output). The `_inputs_are_compatible()` function must return `False` when audio track presence varies:

```python
# In _inputs_are_compatible():
audio_present = [bool(v.audio_codec) for v in videos]
if len(set(audio_present)) > 1:
    return False  # Mixed audio presence -> filter path
```

---

## 7. Resolution Mismatch Handling

### 7.1 Resolution Mismatch Decision Matrix

When concatenating videos with different resolutions, the filter path must decide on a target resolution. The strategy balances quality preservation against file size.

| Input A | Input B | Target Resolution | Strategy | Rationale |
|---------|---------|-------------------|----------|-----------|
| 1920x1080 (16:9) | 1920x1080 (16:9) | 1920x1080 | Demuxer (stream copy) | Identical — no processing needed |
| 1920x1080 (16:9) | 1280x720 (16:9) | 1920x1080 | Upscale B to 1080p | Preserve quality of higher-res input |
| 1280x720 (16:9) | 1920x1080 (16:9) | 1920x1080 | Upscale A to 1080p | Same rationale, order-independent |
| 1920x1080 (16:9) | 1080x1920 (9:16) | 1920x1080 | Pillarbox B (black bars on sides) | Landscape output is default; portrait input is pillarboxed |
| 1080x1920 (9:16) | 1080x1920 (9:16) | 1080x1920 | No scaling needed | Both portrait — but demuxer checks resolution match |
| 3840x2160 (4K) | 1920x1080 (1080p) | 1920x1080 | Downscale A to 1080p | 1080p output cap prevents excessively large files |
| 3840x2160 (4K) | 3840x2160 (4K) | 1920x1080 | Downscale both to 1080p | 1080p cap always applies in filter path |
| 1920x1080 (16:9) | 1440x1080 (4:3) | 1920x1080 | Pillarbox B | Aspect ratio preserved, black bars added |
| 854x480 (480p) | 1920x1080 (1080p) | 1920x1080 | Upscale A (with quality warning) | Upscaling degrades visual quality; creator is warned |
| 1920x1080 (16:9) | 720x480 (3:2 NTSC) | 1920x1080 | Scale + pillarbox B | Non-standard aspect ratio handled gracefully |

### 7.2 Scaling Strategy

The platform uses the "upscale to highest, capped at 1080p" strategy. This prioritizes quality preservation for the highest-resolution input at the cost of visually soft upscaled segments.

**Why not downscale to lowest?** Downscaling to the lowest input (e.g., 720p when mixing 1080p + 720p) wastes the quality of the 1080p source. Creators who upload 1080p content expect 1080p output. The upscaled 720p segment will be softer but acceptable for short intros/outros.

**Why cap at 1080p?** The output goes through the ABR pipeline, which generates 1080p, 720p, 480p, and 360p renditions. A 4K concat output would just be downscaled anyway, and processing time would increase significantly.

### 7.3 Aspect Ratio Handling (Pillarbox and Letterbox)

The filter chain uses `force_original_aspect_ratio=decrease` with `pad` to handle aspect ratio differences:

```
scale=W:H:force_original_aspect_ratio=decrease
  → Scales video to fit within WxH while preserving aspect ratio
  → Result may be smaller than WxH if aspect ratios differ

pad=W:H:(ow-iw)/2:(oh-ih)/2
  → Centers the scaled video within WxH canvas
  → Fills remaining space with black (default)

setsar=1
  → Sets sample aspect ratio to 1:1 (square pixels)
```

**Visual examples**:

```
16:9 input in 16:9 target (no change):
┌──────────────────────────────────┐
│ ████████████████████████████████ │
│ ████████████████████████████████ │
│ ████████████████████████████████ │
│ ████████████████████████████████ │
└──────────────────────────────────┘

4:3 input in 16:9 target (pillarbox — black bars on sides):
┌──────────────────────────────────┐
│ ████│████████████████████│██████ │
│ ████│████████████████████│██████ │
│ ████│████████████████████│██████ │
│ ████│████████████████████│██████ │
└──────────────────────────────────┘
  black   actual content     black

9:16 (portrait) in 16:9 target (extreme pillarbox):
┌──────────────────────────────────┐
│ ██████████│████████│████████████ │
│ ██████████│████████│████████████ │
│ ██████████│████████│████████████ │
│ ██████████│████████│████████████ │
└──────────────────────────────────┘
    black    content    black

21:9 ultrawide in 16:9 target (letterbox — black bars top/bottom):
┌──────────────────────────────────┐
│ ████████████████████████████████ │
│ ████████████████████████████████ │
│ ████████████████████████████████ │
│ ████████████████████████████████ │
└──────────────────────────────────┘
```

### 7.4 Color Space Normalization

Videos may have different color spaces (BT.709 for HD, BT.601 for SD, BT.2020 for HDR). Mixing them without conversion produces color shifts at segment boundaries.

The filter path normalizes all inputs to BT.709 (standard for web delivery):

```python
filter_parts.append(
    f"[{i}:v]scale={target_w}:{target_h}:"
    f"force_original_aspect_ratio=decrease,"
    f"pad={target_w}:{target_h}:(ow-iw)/2:(oh-ih)/2,"
    f"setsar=1,"
    f"colorspace=bt709:iall=bt601:fast=1[v{i}]"
)
```

The `colorspace` filter converts from detected input color space to BT.709. The `:iall=bt601` parameter sets a fallback input color space (BT.601 for SD content) when the input does not specify one. The `:fast=1` parameter uses a faster but slightly less accurate conversion.

**HDR to SDR handling**: If any input uses BT.2020 / PQ (HDR10), the `tonemap` filter is applied to convert HDR to SDR before color space conversion:

```python
if input_is_hdr:
    filter_parts.append(
        f"[{i}:v]zscale=transfer=linear,tonemap=hable:desat=0,"
        f"zscale=transfer=bt709:primaries=bt709:matrix=bt709,"
        f"scale=...,pad=...,setsar=1[v{i}]"
    )
```

### 7.5 Even Dimension Enforcement

FFmpeg's libx264 encoder requires even (divisible by 2) width and height. The `_determine_target_resolution()` function applies `& ~1` to ensure even dimensions:

```python
best_w = int(best_w * scale) & ~1  # Round down to nearest even number
best_h = int(best_h * scale) & ~1
```

This prevents encoding failures when inputs have odd dimensions (e.g., 1279x719 from a cropped video).

---

## 8. Progress Tracking

### 8.1 Problem Statement

Video concatenation can take significant time for large inputs. A 4-hour concat at 1080p using the filter (re-encode) path may take 30-60 minutes. Without progress reporting, users see only "Processing..." with no indication of how long it will take or how far along the job is.

### 8.2 FFmpeg Progress Output Parsing

FFmpeg emits progress information to stderr in a structured format when `-progress pipe:1` is used, or in human-readable form by default. The existing `execute_rendition()` function already parses `time=` fields from stderr output to calculate progress percentage.

**stderr progress line format**:
```
frame= 1234 fps= 45 q=22.0 size=   12345kB time=00:05:30.12 bitrate=1234.5kbits/s speed=2.3x
```

**Parsing logic** (already in `ffmpeg_executor.py`):

```python
time_pattern = re.compile(r"time=(\d+):(\d+):(\d+\.\d+)")

def _parse_progress(line: str, expected_duration_us: int) -> Optional[float]:
    """Parse an ffmpeg stderr line and return progress as 0.0-1.0."""
    m = time_pattern.search(line)
    if not m or expected_duration_us <= 0:
        return None
    hours, minutes, seconds = int(m.group(1)), int(m.group(2)), float(m.group(3))
    current_us = int((hours * 3600 + minutes * 60 + seconds) * 1_000_000)
    return min(1.0, current_us / expected_duration_us)
```

For the concat filter path, `expected_duration_us` is set to the sum of all input durations (already passed from the job creation step). For the concat demuxer path, progress parsing is not meaningful (stream copy completes in seconds).

### 8.3 Progress Storage and Update Pattern

Progress is stored on the transcode job record in DynamoDB and updated periodically:

```python
def update_job_progress(
    job_id: str,
    *,
    progress_pct: int,
    current_rendition: str = "",
) -> None:
    """Update job progress in DDB. Called periodically during processing."""
    T.transcode_jobs.update_item(
        Key={"job_id": job_id, ...},
        UpdateExpression="SET progress_pct = :pct, current_rendition = :cr, updated_at = :ua",
        ExpressionAttributeValues={
            ":pct": progress_pct,
            ":cr": current_rendition,
            ":ua": now_ts(),
        },
    )
```

**Progress phases for concat jobs**:

| Phase | Progress Range | Description |
|-------|---------------|-------------|
| Downloading inputs | 0% - 10% | S3 download of all source files |
| Running ffmpeg concat | 10% - 70% | The actual concatenation (demuxer or filter) |
| Uploading result | 70% - 80% | Upload concatenated MP4 to S3 |
| Enqueuing transcode | 80% - 85% | Create follow-up ABR transcode job |
| ABR transcode | 85% - 100% | Standard HLS rendition generation (tracked by the follow-up job) |

### 8.4 Frontend Progress Polling

The frontend polls the job status endpoint to display progress:

```typescript
// Poll concat job status every 5 seconds
const { data: job } = useQuery({
  queryKey: ["transcode-job", jobId],
  queryFn: () => getTranscodeJob(jobId),
  refetchInterval: job?.status === "completed" ? false : 5000,
  enabled: !!jobId,
});

// Progress bar
<Progress value={job?.progress_pct ?? 0} className="w-full" />
<span className="text-sm text-muted-foreground">
  {job?.current_rendition === "concat-filter"
    ? `Combining videos... ${job.progress_pct}%`
    : job?.current_rendition === "uploading"
    ? "Uploading..."
    : job?.current_rendition === "enqueuing_transcode"
    ? "Starting quality processing..."
    : `Processing... ${job.progress_pct}%`}
</span>
```

### 8.5 WebSocket-Based Real-Time Progress (Future Enhancement)

For near-real-time progress updates without polling, a WebSocket channel could push progress events. This is noted as a future enhancement since the existing polling pattern (5-second interval) is sufficient for MVP. The transcode job poller already uses 5-second intervals for standard transcodes, so concat jobs follow the same pattern.

**If implemented**:
```
WS /ws/transcode/{job_id}/progress
→ { "progress_pct": 45, "current_rendition": "concat-filter", "eta_seconds": 320 }
```

### 8.6 ETA Calculation

Estimated time remaining is calculated from progress rate:

```python
def _calculate_eta(progress_pct: int, started_at: int) -> Optional[int]:
    """Estimate remaining seconds based on progress so far."""
    if progress_pct <= 0:
        return None
    elapsed = now_ts() - started_at
    if elapsed <= 0:
        return None
    total_estimated = elapsed / (progress_pct / 100.0)
    remaining = total_estimated - elapsed
    return max(0, int(remaining))
```

---

## 9. Edge Cases (Extended)

### 9.1 Frame Rate Mismatch (24fps + 30fps)

When inputs have different frame rates, the concat demuxer produces playback artifacts (stuttering, A/V sync drift). The `_inputs_are_compatible()` check compares `frame_rate`, so mismatched frame rates trigger the filter path.

In the filter path, FFmpeg's `concat` filter handles frame rate conversion implicitly by decoding all inputs to raw frames and re-encoding at the output frame rate. The output frame rate defaults to the first input's frame rate. To normalize:

```python
# Force 30fps output for consistent playback
args.extend(["-r", "30"])
```

**Specific scenarios**:
- 24fps (cinema) + 30fps (web): Output at 30fps. 24fps segments undergo 3:2 pulldown (adds slight judder but is standard practice).
- 25fps (PAL) + 30fps (NTSC): Output at 30fps. 25fps segments are frame-rate-converted.
- 60fps + 30fps: Output at 30fps. 60fps segments are halved (frame blending can be applied with `minterpolate` but is too slow for production use).
- Variable frame rate (VFR) input: VFR inputs (common from mobile recordings) are converted to constant frame rate by FFmpeg's decoder. The `-vsync cfr` flag ensures constant frame rate output.

### 9.2 Subtitle Track Handling

If one input has embedded subtitles (e.g., SRT, ASS, or embedded CEA-608) and another does not, the concat demuxer will fail or drop subtitles silently. The filter path does not handle subtitle streams by default.

**Current approach**: Subtitles are stripped from the concat output. The `-sn` flag (no subtitles) is added to both the demuxer and filter paths:

```python
args.extend(["-sn"])  # Strip subtitle streams
```

**Future enhancement**: Concatenate subtitle streams alongside video/audio. This requires detecting subtitle formats and using the `concat` filter with `s=1` (subtitle stream count). Deferred because subtitle support is uncommon in user-uploaded content on this platform.

### 9.3 Portrait + Landscape Concatenation

When one video is portrait (1080x1920) and another is landscape (1920x1080), the target resolution is determined by pixel count. Both have the same pixel count (2,073,600), so `_determine_target_resolution()` uses the first input's dimensions by default.

**Behavior**: The output matches the orientation of the highest-pixel-count input (or the first input if tied). The other orientation is pillarboxed or letterboxed within the target canvas.

**Example**: Portrait (1080x1920) + Landscape (1920x1080):
- If portrait is first: Output is 1080x1920. Landscape input gets letterboxed (black bars top and bottom).
- If landscape is first: Output is 1920x1080. Portrait input gets pillarboxed (black bars left and right).

This is a creative decision that the creator cannot currently control. A future enhancement could add an `output_orientation` parameter to `ConcatVideosIn` to let creators choose landscape (default) or portrait output.

### 9.4 Concat Cancellation Mid-Process

A creator may want to cancel a concat job after submitting it (e.g., selected wrong videos, changed mind). **Note:** `cancel_job()` does not exist in `transcode_job_store.py` today -- it must be added as part of this ticket (or a prerequisite). The proposed implementation:

```python
def cancel_job(job_id: str) -> bool:
    """Cancel a queued or running transcode job.

    NOTE: This function does not exist today and must be added to
    app/services/transcode_job_store.py.

    For queued jobs: immediately transitions to 'cancelled'.
    For running jobs: sets a cancellation flag; the worker checks
    this flag periodically and aborts ffmpeg if set.
    """
    # Update status to 'cancelling' if currently 'queued' or 'running'
    try:
        T.transcode_jobs.update_item(
            Key={"job_id": job_id, ...},
            UpdateExpression="SET #st = :cancel",
            ConditionExpression="#st IN (:q, :r)",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":cancel": "cancelling",
                ":q": "queued",
                ":r": "running",
            },
        )
        return True
    except T.transcode_jobs.meta.client.exceptions.ConditionalCheckFailedException:
        return False  # Already completed/failed/cancelled
```

**Worker-side cancellation**:
```python
# In process_concat_job, check cancellation flag after each major step
if _is_job_cancelled(job_id):
    logger.info("Concat job %s cancelled by user", job_id)
    shutil.rmtree(scratch_dir, ignore_errors=True)
    _mark_cancelled(job_id)
    return

# During ffmpeg execution, the execute_rendition() function
# checks a cancellation callback every 5 seconds and sends
# SIGTERM to the ffmpeg process if cancellation is requested.
```

**Frontend**: The video detail page or library page shows a "Cancel" button next to the processing indicator while the concat job is in `queued` or `running` status. After cancellation, the video metadata record is deleted (or set to `cancelled` status).

### 9.5 Concat of Videos With Drastically Different Bitrates

When a high-bitrate (50 Mbps) input is concatenated with a low-bitrate (2 Mbps) input using the demuxer (stream copy), the output file alternates between high and low quality. This is not a processing error -- it is inherent to stream copy. The ABR pipeline's re-encode step normalizes bitrate in the final HLS renditions.

When using the filter (re-encode) path, all segments are re-encoded at CRF 22, which produces consistent visual quality regardless of input bitrate. However, segments from low-bitrate inputs will not gain quality (garbage in, garbage out).

### 9.6 Concat With Metadata Conflicts

Input videos may have conflicting metadata (e.g., different creation dates, GPS coordinates, camera models). The concatenated output uses the first input's metadata by default (ffmpeg behavior). The `source_video_ids` array on the output video provides provenance for tracing back to individual inputs.

---

## 10. Acceptance Criteria

| # | Criterion | Pass Condition |
|---|-----------|----------------|
| AC-1 | Creator can concatenate 2 published videos | POST `/ui/videos/concat` with 2 valid video_ids returns 201 with `created_via: "concat"` |
| AC-2 | Creator can concatenate up to 10 videos | POST with 10 video_ids succeeds; response includes all 10 in `source_video_ids` |
| AC-3 | Fewer than 2 videos rejected | POST with 1 video_id returns 400 |
| AC-4 | More than 10 videos rejected | POST with 11 video_ids returns 400 |
| AC-5 | Duplicate video IDs rejected | POST with same ID twice returns 400 `"video_ids contains duplicates"` |
| AC-6 | Non-owned video rejected | POST including another user's video returns 403 |
| AC-7 | Unpublished video rejected | POST including a video in `"created"` or `"encoding"` status returns 409 |
| AC-8 | Combined duration exceeding 4 hours rejected | POST where sum of durations > 14400s returns 400 |
| AC-9 | Combined size exceeding 10 GB rejected | POST where total file size > 10 GB returns 400 |
| AC-10 | Compatible inputs use demuxer path | All inputs with same H.264/1080p/30fps/AAC/48kHz -> response has `concat_method: "demuxer"` |
| AC-11 | Incompatible inputs use filter path | Inputs with different codecs or resolutions -> response has `concat_method: "filter"` |
| AC-12 | Output video has correct provenance | GET `/ui/videos/{new_video_id}` shows `source_video_ids` matching input order and `created_via: "concat"` |
| AC-13 | Estimated duration is sum of inputs | Response `estimated_duration_seconds` equals sum of input durations (within 1 second tolerance) |
| AC-14 | Concat job completes and produces playable video | Job transitions from `queued` to `completed`; HLS renditions are generated; video plays in browser |
| AC-15 | Scratch directory cleaned after success | No leftover files in `{transcode_scratch_dir}/concat-{job_id}/` after job completes |
| AC-16 | Scratch directory cleaned after failure | No leftover files even when ffmpeg fails (scratch dir removed in `finally` block) |
| AC-17 | Videos with no audio track are handled | Input without audio gets silent audio track inserted; concat succeeds without error |
| AC-18 | Loudness normalization applied when enabled | Re-encoded output has consistent loudness across segments (within 2 LU of -16 LUFS target) |
| AC-19 | Portrait + landscape concat handled | Output uses pillarbox/letterbox; no cropping or distortion |
| AC-20 | Progress tracking updates during processing | `progress_pct` on the job record increases from 0 to 100 during processing; frontend poll displays progress |
| AC-21 | Concat job can be cancelled while queued | POST cancel on a `queued` job transitions it to `cancelled`; no processing occurs |
| AC-22 | Concat job can be cancelled while running | POST cancel on a `running` job terminates ffmpeg and cleans up scratch directory |

---


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_vod_016.py`

| # | Function | Assertion |
|---|----------|-----------|
| 1 | `test_vod_016_crud` | Vod 016 crud verified |
| 2 | `test_vod_016_validation` | Vod 016 validation verified |
| 3 | `test_vod_016_auth` | Vod 016 auth verified |
| 4 | `test_vod_016_not_found` | Vod 016 not found verified |
| 5 | `test_vod_016_edge_cases` | Vod 016 edge cases verified |
| 6 | `test_vod_016_integration` | Vod 016 integration verified |

**Mocking**: All DynamoDB tables mocked via `moto`; profile lookups patched via `unittest.mock.patch`.

### Integration Tests

1. Video Concatenation integrates with video metadata CRUD lifecycle
2. End-to-end flow from video creation through video concatenation feature
3. Error propagation from video metadata service to video concatenation layer

### E2E Tests (Playwright)

**File**: `frontend/e2e/vod-016.spec.ts`
**Sections**: 1-3 (10 tests)

**Auth pattern**: `injectAuth(page, identity)` for cookie auth; `x-csrf-token` header for POST/PUT/DELETE mutations.

| # | Test | Assertion |
|---|------|-----------|
| 1 | Video Concatenation API returns 200 | 200; expected fields present |
| 2 | Video Concatenation handles invalid input | 422 or 400 response |
| 3 | Video Concatenation requires auth | 401 without session |
| 4 | Video Concatenation UI renders | Page loads; key elements visible |
| 5 | Video Concatenation integrates with video metadata | Video data correctly referenced |

**Negative tests**: 401 unauthenticated, 403 non-owner, 404 video not found, 422 invalid input

**Edge cases**: Video in processing state, deleted video reference, concurrent operations

### Test Data Requirements

- **DDB seeds**: Video metadata records from VOD-001; related video concatenation test data
- **Test users**: Alice (creator), Bob (viewer)

### CI/Pipeline Considerations

- **Feature flags**: VOD_ENABLED=true
- **Serial execution**: Must run after VOD-001 video metadata table is created and seeded
- **Retry safety**: All tests are idempotent; use unique per-run identifiers (`TS` suffix) to avoid cross-run conflicts.

---

## Dependencies & Merge Safety

### Depends On

| Ticket/Component | Reason |
|------------------|--------|
| VOD-001 | Source video metadata |
| VOD-015 | Clips as potential concat sources (optional) |

### Depended On By

No downstream tickets depend on this feature.

### Merge Strategy: **Sequential**

Requires VOD-001 video metadata model. Also depends on VOD-015.

### Merge Checklist

- [ ] All unit tests pass (`just test`)
- [ ] All E2E tests pass (`just e2e`)
- [ ] Feature flag defaults to enabled in `.env.local.example`
- [ ] No breaking changes to existing API contracts
- [ ] DynamoDB table/GSI changes added to `scripts/local-ddb-init.py`
- [ ] Frontend types in `api/types.ts` match backend `models.py`
- [ ] New routes registered in `app/main.py` and `frontend/src/App.tsx`

## Appendix A: Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `VIDEO_CONCAT_ENABLED` | `true` | Master kill switch for concatenation functionality |
| `VIDEO_CONCAT_MAX_INPUTS` | `10` | Maximum number of input videos per concat request |
| `VIDEO_CONCAT_MAX_DURATION_SECONDS` | `14400` (4 hours) | Maximum combined output duration |
| `VIDEO_CONCAT_MAX_TOTAL_SIZE_BYTES` | `10737418240` (10 GB) | Maximum combined input file size |
| `VIDEO_CONCAT_TIMEOUT_SECONDS` | `1800` (30 min) | FFmpeg process timeout for concat operation |

---

## Appendix B: File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/models_video.py` | Modify | Add `source_video_ids` to `VideoMetadataModel`; add `ConcatVideosIn` model; add to `VideoOut` |
| `app/services/video_metadata_store.py` | Modify | Serialize/deserialize `source_video_ids`; add `update_concat_fields()` |
| `app/services/transcode_job_store.py` | Modify | Add `job_type` field (does not exist today), add `cancel_job()` (does not exist today), and concat-specific fields |
| `app/services/video_concatenator.py` | **New** | Concat logic: input probing, demuxer/filter selection, ffmpeg execution, S3 upload, transcode enqueue |
| `app/routers/video_listing.py` | Modify | Add `POST /concat` endpoint |
| `app/core/settings.py` | Modify | Add 5 concat-related settings |
| `.env.local.example` | Modify | Add `VIDEO_CONCAT_*` env vars |
| `frontend/src/api/endpoints/videos.ts` | Modify | Add `concatVideos()` function and concat-related interfaces |
| `frontend/src/components/shared/CombineVideosDialog.tsx` | **New** | Combine dialog with video selection, ordering, title/description |
| `frontend/src/pages/videos/VideoLibraryPage.tsx` | Modify | Add "Combine Videos" button; wire CombineVideosDialog |
| `tests/test_video_concatenator.py` | **New** | 15 unit tests for concat service |
| `tests/test_video_concat_endpoint.py` | **New** | 12 unit tests for concat endpoint |
| `frontend/e2e/video-concat.spec.ts` | **New** | 8 E2E tests across 2 sections (129-130) |

---

## Appendix C: API Endpoint Summary

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/videos/concat` | `require_ui_session` | Create a concatenated video from 2-10 source videos |
| GET | `/ui/videos/{video_id}` | `require_ui_session` | (Existing) Extended: response includes `source_video_ids` and `created_via` |

---

## Appendix D: State Flow for Concat Processing

```
POST /ui/videos/concat
         │
         v
┌─────────────────────┐
│ Validate all inputs: │
│ - ownership          │
│ - status             │
│ - source files       │
│ - duration limit     │
│ - size limit         │
└────────┬────────────┘
         │
         v
┌─────────────────┐
│ Probe inputs:    │
│ - same codec?    │  ──── yes ──> concat_method = "demuxer"
│ - same resolution│  ──── no ───> concat_method = "filter"
│ - same framerate?│
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Create new video │ (status="created", created_via="concat")
│  metadata record │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Enqueue concat   │ (job_type="concat", status="queued")
│  job             │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Worker claims    │ (job status="running")
│  concat job      │
└────────┬────────┘
         │
         v
┌─────────────────────────┐
│ Download all source      │
│ files from S3 to scratch │
└────────┬────────────────┘
         │
         ├──── demuxer ────────────────┐
         │                              v
         │                    ┌───────────────────┐
         │                    │ Write filelist.txt  │
         │                    │ ffmpeg -f concat    │
         │                    │   -c copy           │
         │                    └────────┬────────────┘
         │                             │
         ├──── filter ────────────────┐│
         │                            v│
         │                   ┌────────────────────┐
         │                   │ Build filter_complex│
         │                   │ scale + pad + concat│
         │                   │ re-encode H.264/AAC │
         │                   └────────┬───────────┘
         │                            │
         └────────────────────────────┘
                          │
                          v
             ┌────────────────────┐
             │ Upload concat MP4   │
             │ to S3 as new source │
             └────────┬───────────┘
                      │
                      v
             ┌────────────────────┐
             │ Enqueue standard    │
             │ transcode job       │ (job_type="transcode")
             └────────┬───────────┘
                      │
                      v
             ┌────────────────────┐
             │ ABR pipeline:       │
             │ HLS renditions +    │
             │ thumbnails          │
             └────────┬───────────┘
                      │
                      v
             ┌────────────────────┐
             │ Video status =      │
             │ "published"         │
             └────────────────────┘
```
