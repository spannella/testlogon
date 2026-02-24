#!/usr/bin/env python3
from __future__ import annotations

import json

from app.services.signature_packet_reminders import process_signature_packet_reminders


def main() -> int:
    summary = process_signature_packet_reminders()
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
