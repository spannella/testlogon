#!/usr/bin/env python3
"""Render the demo voiceover from docs/demo-video-script.md via ElevenLabs.

For each `## SEGMENT NN — Title` block (excluding HTML-comment TODO placeholders),
synthesize speech to frontend/e2e/demo/out/voiceNN.mp3, then concatenate the rendered
segments (numeric order) into out/voiceover.mp3.

The API key is read from the ELEVENLABS_API_KEY environment variable (never hard-coded,
never logged, never committed). Optional: ELEVENLABS_VOICE_ID, ELEVENLABS_MODEL_ID.

Usage:
    export ELEVENLABS_API_KEY=...      # provided by the user at render time
    .venv/bin/python scripts/render_voiceover.py            # all ready segments
    .venv/bin/python scripts/render_voiceover.py --only 01  # one segment

Then mux onto the video:
    ffmpeg -i out/demo_walkthrough.mp4 -i out/voiceover.mp3 -map 0:v -map 1:a \
           -c:v copy -c:a aac -shortest out/demo_walkthrough_voiced.mp4
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_MD = ROOT / "docs" / "demo-video-script.md"
OUT = ROOT / "frontend" / "e2e" / "demo" / "out"

# Default voice: "Rachel" (a stock ElevenLabs voice). Override via env.
DEFAULT_VOICE_ID = os.environ.get("ELEVENLABS_VOICE_ID", "21m00Tcm4TlvDq8ikWAM")
DEFAULT_MODEL_ID = os.environ.get("ELEVENLABS_MODEL_ID", "eleven_multilingual_v2")

SEG_RE = re.compile(r"^##\s+SEGMENT\s+(\d+)\b.*$", re.MULTILINE)


def parse_segments() -> dict[str, str]:
    """Return {seg_number_2digit: narration_text} for blocks with real prose."""
    text = SCRIPT_MD.read_text()
    out: dict[str, str] = {}
    matches = list(SEG_RE.finditer(text))
    for i, m in enumerate(matches):
        num = m.group(1).zfill(2)
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end]
        # strip HTML comments (TODO placeholders) and markdown rules
        body = re.sub(r"<!--.*?-->", "", body, flags=re.DOTALL)
        body = body.replace("---", " ").strip()
        if body:
            out[num] = body
    return out


def synth(text: str, dest: Path, api_key: str) -> None:
    url = f"https://api.elevenlabs.io/v1/text-to-speech/{DEFAULT_VOICE_ID}"
    payload = {
        "text": text,
        "model_id": DEFAULT_MODEL_ID,
        "voice_settings": {"stability": 0.45, "similarity_boost": 0.8, "style": 0.0},
    }
    import json as _json

    req = urllib.request.Request(
        url,
        data=_json.dumps(payload).encode(),
        headers={
            "xi-api-key": api_key,
            "Content-Type": "application/json",
            "Accept": "audio/mpeg",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        dest.write_bytes(resp.read())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="render just this 2-digit segment number, e.g. 01")
    args = ap.parse_args()

    api_key = os.environ.get("ELEVENLABS_API_KEY", "").strip()
    if not api_key:
        print(
            "ERROR: set ELEVENLABS_API_KEY (export it; do not paste into any file).",
            file=sys.stderr,
        )
        return 2

    OUT.mkdir(parents=True, exist_ok=True)
    segments = parse_segments()
    if args.only:
        segments = {k: v for k, v in segments.items() if k == args.only.zfill(2)}
    if not segments:
        print("No ready narration blocks found in docs/demo-video-script.md", file=sys.stderr)
        return 1

    rendered: list[Path] = []
    for num in sorted(segments):
        dest = OUT / f"voice{num}.mp3"
        print(f"  rendering segment {num} ({len(segments[num])} chars) -> {dest.name}")
        synth(segments[num], dest, api_key)
        rendered.append(dest)

    # Concatenate in order into voiceover.mp3 (re-encode for safe concat).
    listfile = OUT / "_voice_concat.txt"
    listfile.write_text("".join(f"file '{p}'\n" for p in sorted(rendered)))
    combined = OUT / "voiceover.mp3"
    subprocess.run(
        ["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0",
         "-i", str(listfile), "-c:a", "libmp3lame", "-q:a", "3", str(combined)],
        check=True,
    )
    print(f"\nWrote {combined}")
    print("Mux onto video:\n  ffmpeg -i out/demo_walkthrough.mp4 -i out/voiceover.mp3 "
          "-map 0:v -map 1:a -c:v copy -c:a aac -shortest out/demo_walkthrough_voiced.mp4")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
