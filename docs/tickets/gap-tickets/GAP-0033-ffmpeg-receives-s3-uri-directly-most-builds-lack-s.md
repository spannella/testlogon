# GAP-0033: FFmpeg receives s3:// URI directly; most builds lack S3 protocol support

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: VOD-004 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/VOD-004.md`); see also `docs/tickets/writeups/VOD-004.md`

## Location
`app/services/transcode_worker.py:234`

## Problem / Impact
FFmpeg receives s3:// URI directly; most builds lack S3 protocol support

## Fix
create `app/services/vod_s3_downloader.py`; download source to `scratch_dir/source.<ext>` before rendition loop and pass local path as input

## Notes
This gap was identified by the second-pass as-built review of VOD-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
