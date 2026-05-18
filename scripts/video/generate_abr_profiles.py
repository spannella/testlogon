#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.video_abr_profile_exports import ffmpeg_abr_profiles, medialive_abr_profiles
OUT_DIR = ROOT / "config" / "video"


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ffmpeg_out = OUT_DIR / "ffmpeg_abr_profiles.json"
    medialive_out = OUT_DIR / "medialive_abr_profiles.json"

    ffmpeg_out.write_text(json.dumps(ffmpeg_abr_profiles(), indent=2) + "\n")
    medialive_out.write_text(json.dumps(medialive_abr_profiles(), indent=2) + "\n")

    print(f"Wrote {ffmpeg_out}")
    print(f"Wrote {medialive_out}")


if __name__ == "__main__":
    main()
