from app.models import (
    DevtoolsBillingLedgerEntryOut,
    DevtoolsEmailMessageOut,
    DevtoolsParseWarningOut,
    DevtoolsSmsMessageOut,
)


def test_devtools_email_message_normalizes_timestamp_and_keeps_stable_id_fields() -> None:
    model = DevtoolsEmailMessageOut(
        id="email#e6a9a5",
        id_strategy="sha256(mailbox|timestamp|subject|body)",
        thread_id="thread#123",
        mailbox="user@example.com",
        sent_at="2026-03-01T12:34:56+02:00",
        event_kind="mfa_email_code",
        to_emails=["user@example.com"],
        subject="Your verification code",
        body_text="Code is 123456",
        code="123456",
        parse_warnings=[
            DevtoolsParseWarningOut(source="email", line_number=10, code="missing_subject", message="subject missing")
        ],
    )

    assert model.sent_at == "2026-03-01T10:34:56Z"
    assert model.id == "email#e6a9a5"
    assert model.id_strategy.startswith("sha256(")
    assert model.parse_warnings[0].code == "missing_subject"


def test_devtools_sms_message_requires_timezone_aware_timestamp() -> None:
    try:
        DevtoolsSmsMessageOut(
            id="sms#abc",
            id_strategy="sha256(participants|timestamp|body)",
            conversation_id="conv#1",
            sent_at="2026-03-01T12:00:00",
        )
    except ValueError as exc:
        assert "timestamp must include timezone" in str(exc)
    else:
        raise AssertionError("Expected timezone validation error")


def test_devtools_billing_entry_normalizes_currency_and_timestamp() -> None:
    model = DevtoolsBillingLedgerEntryOut(
        id="bill#1",
        id_strategy="sha256(provider|external_id|occurred_at|amount)",
        provider="paypal",
        event_type="capture",
        status="completed",
        occurred_at="2026-03-01T12:00:30+00:00",
        amount=9.99,
        fee=0.59,
        net=9.40,
        currency="USD",
    )

    assert model.occurred_at == "2026-03-01T12:00:30Z"
    assert model.currency == "usd"
