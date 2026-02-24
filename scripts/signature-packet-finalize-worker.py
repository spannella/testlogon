#!/usr/bin/env python3
from __future__ import annotations

import json

from app.services.signature_packet_renderer import process_completed_packet_finalization_jobs


if __name__ == "__main__":
    print(json.dumps(process_completed_packet_finalization_jobs(), sort_keys=True))
