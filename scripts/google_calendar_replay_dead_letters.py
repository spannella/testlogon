#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from app.services.google_calendar_sync_outbound import replay_google_calendar_dead_letters


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay Google Calendar outbound dead-letter jobs.")
    parser.add_argument("--owner-user-sub", required=True, help="Owner user_sub for outbox partition")
    parser.add_argument("--limit", type=int, default=100, help="Max dead-letter jobs to replay")
    args = parser.parse_args()

    result = replay_google_calendar_dead_letters(
        owner_user_sub=str(args.owner_user_sub),
        limit=max(1, int(args.limit)),
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
