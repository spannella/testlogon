from __future__ import annotations

from pathlib import Path

from app.services.devtools.email_log_parser import parse_email_log


def test_parser_handles_mixed_plaintext_json_and_invalid_entries(tmp_path: Path) -> None:
    log = tmp_path / "emails.log"
    log.write_text(
        "\n".join(
            [
                "[2026-03-01T10:00:00Z] TO=alice@example.com PURPOSE=login",
                "  Subject: Your verification code (login)",
                "  Code: 123456",
                "  Body: Your verification code is: 123456",
                "",
                '{"timestamp":"2026-03-01T10:02:00Z","to":["bob@example.com"],"subject":"Alert","body_text":"Device sign in","event_kind":"alert_email"}',
                "",
                "{not valid json}",
                "",
                "[bad-ts] TO=alice@example.com PURPOSE=login",
                "  Subject: broken",
                "",
            ]
        ),
        encoding="utf-8",
    )

    out = parse_email_log(str(log), limit=10)

    assert [m.mailbox for m in out.mailboxes] == ["alice@example.com", "bob@example.com"]
    assert len(out.messages) == 2
    assert len(out.threads) == 2
    codes = {w.code for w in out.parse_warnings}
    assert "invalid_json" in codes
    assert "invalid_timestamp" in codes


def test_parser_deterministic_and_supports_mailbox_filter(tmp_path: Path) -> None:
    log = tmp_path / "emails.log"
    log.write_text(
        "\n".join(
            [
                "[2026-03-01T10:00:00Z] TO=alice@example.com PURPOSE=login",
                "  Subject: Login code",
                "  Code: 111111",
                "  Body: Code",
                "",
                "[2026-03-01T10:01:00Z] TO=bob@example.com PURPOSE=login",
                "  Subject: Login code",
                "  Code: 222222",
                "  Body: Code",
                "",
            ]
        ),
        encoding="utf-8",
    )

    first = parse_email_log(str(log), mailbox="alice@example.com", limit=10)
    second = parse_email_log(str(log), mailbox="alice@example.com", limit=10)

    assert first.model_dump() == second.model_dump()
    assert len(first.messages) == 1
    assert first.messages[0].mailbox == "alice@example.com"


def test_parser_paginates_and_returns_next_cursor(tmp_path: Path) -> None:
    log = tmp_path / "emails.log"
    blocks = []
    for i in range(3):
        blocks.extend(
            [
                f"[2026-03-01T10:0{i}:00Z] TO=user@example.com PURPOSE=login",
                f"  Subject: Code {i}",
                f"  Code: 10000{i}",
                "  Body: code body",
                "",
            ]
        )
    log.write_text("\n".join(blocks), encoding="utf-8")

    out = parse_email_log(str(log), limit=2, offset=0)
    assert len(out.messages) == 2
    assert out.next_cursor is not None


def test_parser_missing_file_returns_warning_not_exception(tmp_path: Path) -> None:
    out = parse_email_log(str(tmp_path / "missing.log"))
    assert out.messages == []
    assert out.threads == []
    assert out.mailboxes == []
    assert any(w.code == "missing_log_file" for w in out.parse_warnings)
