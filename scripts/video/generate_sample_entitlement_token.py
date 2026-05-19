#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.drm_mock_license import issue_entitlement_token


def main() -> None:
    payload = issue_entitlement_token(
        asset_id=os.getenv("ASSET_ID", "asset_local_demo_001"),
        tenant_id=os.getenv("TENANT_ID", "dev-tenant"),
        session_id=os.getenv("SESSION_ID", "session-1"),
        device_id=os.getenv("DEVICE_ID", "device-1"),
        profile=os.getenv("PROFILE", "multi_drm"),
        key_id=os.getenv("KEY_ID", "local-dev-key"),
        ttl_seconds=int(os.getenv("TTL_SECONDS", "300")),
        secret=os.getenv("DRM_MOCK_SECRET", "local-dev-secret"),
    )
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
