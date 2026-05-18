#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.contracts.video_rendition_profiles import CANONICAL_ABR_LADDER
from app.contracts.watermark_policy import TenantWatermarkSettings, WatermarkPolicy
from app.services.ffmpeg_abr_pipeline import build_rendition_ffmpeg_args, write_master_playlist


def _policy_from_env() -> WatermarkPolicy:
    mode = os.getenv("WATERMARK_MODE", "dynamic_text")
    text_template = os.getenv("WATERMARK_TEXT_TEMPLATE", "tenant={{tenant_id}}")
    asset_uri = os.getenv("WATERMARK_ASSET_URI") or None
    return WatermarkPolicy(
        mode=mode,
        position=os.getenv("WATERMARK_POSITION", "top_right"),
        opacity=float(os.getenv("WATERMARK_OPACITY", "0.7")),
        margin_x=int(os.getenv("WATERMARK_MARGIN_X", "24")),
        margin_y=int(os.getenv("WATERMARK_MARGIN_Y", "24")),
        text_template=text_template if mode == "dynamic_text" else None,
        asset_uri=asset_uri,
    )


def main() -> None:
    input_url = os.getenv("INPUT_URL", "rtmp://ingest/live/localdemo")
    output_dir = Path(os.getenv("OUTPUT_DIR", "/workspace/video-data/hls"))
    tenant_settings = TenantWatermarkSettings(
        tenant_id=os.getenv("TENANT_ID", "dev-tenant"),
        branding_asset_uri=os.getenv("TENANT_BRANDING_ASSET_URI") or None,
    )
    policy = _policy_from_env()

    write_master_playlist(output_dir)

    procs: list[subprocess.Popen] = []
    for rendition in CANONICAL_ABR_LADDER:
        args = build_rendition_ffmpeg_args(
            input_url=input_url,
            output_dir=output_dir,
            rendition=rendition,
            watermark_policy=policy,
            tenant_settings=tenant_settings,
        )
        print(json.dumps({"rendition": rendition["name"], "cmd": args}))
        procs.append(subprocess.Popen(args))

    try:
        for p in procs:
            p.wait()
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()


if __name__ == "__main__":
    main()
