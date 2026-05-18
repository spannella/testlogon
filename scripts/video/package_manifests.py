#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.local_packaging import write_local_manifests, write_shaka_packager_config


def main() -> None:
    output_root = Path(os.getenv("OUTPUT_ROOT", str(ROOT / "video-data")))
    config_path = Path(os.getenv("SHAKA_CONFIG_PATH", str(ROOT / "config" / "video" / "shaka_packager_config.json")))
    write_local_manifests(output_root)
    write_shaka_packager_config(config_path, output_root=str(output_root))
    print(f"wrote manifests under {output_root}")
    print(f"wrote shaka config at {config_path}")


if __name__ == "__main__":
    main()
