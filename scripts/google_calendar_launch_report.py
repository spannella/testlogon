#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a lightweight Google Calendar launch report markdown block.")
    parser.add_argument("--cohort", required=True, help="Cohort name (internal/pilot/broad)")
    parser.add_argument("--sync-sla", required=True, help="SLA result (met/not_met)")
    parser.add_argument("--error-budget", required=True, help="Error budget status")
    parser.add_argument("--sev-open", type=int, default=0, help="Open Sev1/Sev2 count")
    parser.add_argument("--notes", default="", help="Short release notes")
    args = parser.parse_args()

    ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    print("## GCAL Launch Check")
    print(f"- timestamp: {ts}")
    print(f"- cohort: {args.cohort}")
    print(f"- sync_sla: {args.sync_sla}")
    print(f"- error_budget: {args.error_budget}")
    print(f"- open_sev1_sev2: {args.sev_open}")
    print(f"- notes: {args.notes}")
    print(f"- go_no_go: {'go' if args.sync_sla == 'met' and args.sev_open == 0 else 'no_go'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
