from __future__ import annotations

from pathlib import Path

from app.services.devtools.sms_log_parser import parse_sms_log


def test_sms_parser_handles_plain_json_invalid_and_groups_conversations(tmp_path: Path) -> None:
    log = tmp_path / "sms.log"
    log.write_text(
        "\n".join(
            [
                "[2026-03-01T10:00:00Z] SMS TO=+14155550123 Code: 123456",
                "",
                "[2026-03-01T10:03:00Z] ALERT_SMS TO=+14155550123",
                "  Body: Payment failed",
                "",
                '{"timestamp":"2026-03-01T10:04:00Z","from":"+14155550124","to":"+14155550199","body_text":"hello","status":"delivered","message_id":"mid_1","event_kind":"alert_sms"}',
                "",
                "{bad json}",
                "",
                "[bad-ts] SMS TO=+14155550123 Code: 111111",
            ]
        ),
        encoding="utf-8",
    )

    out = parse_sms_log(str(log), limit=10)

    assert len(out.messages) == 3
    assert len(out.conversations) == 2
    # conversations sorted by latest activity desc
    assert out.conversations[0].latest_message_at >= out.conversations[1].latest_message_at
    warning_codes = {w.code for w in out.parse_warnings}
    assert "invalid_json" in warning_codes
    assert "invalid_timestamp" in warning_codes


def test_sms_parser_deterministic_message_ordering_and_filtering(tmp_path: Path) -> None:
    log = tmp_path / "sms.log"
    log.write_text(
        "\n".join(
            [
                "[2026-03-01T10:00:00Z] SMS TO=+14155550123 Code: 111111",
                "",
                "[2026-03-01T10:01:00Z] SMS TO=+14155550123 Code: 222222",
                "",
                "[2026-03-01T10:02:00Z] SMS TO=+14155550000 Code: 333333",
                "",
            ]
        ),
        encoding="utf-8",
    )

    first = parse_sms_log(str(log), participant="+14155550123", limit=10)
    second = parse_sms_log(str(log), participant="+14155550123", limit=10)

    assert first.model_dump() == second.model_dump()
    assert len(first.messages) == 2
    assert all(m.to_number == "+14155550123" for m in first.messages)
    assert first.messages[0].sent_at >= first.messages[1].sent_at


def test_sms_parser_pagination_and_missing_file_warning(tmp_path: Path) -> None:
    log = tmp_path / "sms.log"
    lines = []
    for i in range(3):
        lines.extend([f"[2026-03-01T10:0{i}:00Z] SMS TO=+14155550123 Code: 99999{i}", ""])
    log.write_text("\n".join(lines), encoding="utf-8")

    paged = parse_sms_log(str(log), limit=2, offset=0)
    assert len(paged.messages) == 2
    assert paged.next_cursor is not None

    missing = parse_sms_log(str(tmp_path / "missing.log"))
    assert missing.messages == []
    assert missing.conversations == []
    assert any(w.code == "missing_log_file" for w in missing.parse_warnings)
