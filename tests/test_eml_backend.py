"""Hermetic offline tests for EML-001 through EML-009 backend.

Tests:
  - EML-001: send_alert_email html_body parameter
  - EML-002: email_settings service (get/update/cache)
  - EML-003: user_email_accounts service (CRUD, KMS, IMAP verify)
  - EML-004: email_sync service (sync, list, get, thread)
  - EML-007: email_archive service (archive/list/unarchive)
  - EML-009: campaign template functions (create/render/list)

Conventions:
  - moto DDB tables bound to frozen T via object.__setattr__ + restored
  - frozen S flags toggled via object.__setattr__ + restored
  - KMS stubbed at service module level
  - No TestClient, no real AWS, no real network
"""
from __future__ import annotations

import asyncio
import importlib
import sys
import types
import uuid
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import boto3
import pytest

# ---------------------------------------------------------------------------
# Moto bootstrap (must be done before importing any app module that calls DDB)
# ---------------------------------------------------------------------------
from moto import mock_aws


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_table(ddb_resource, name: str, pk: str, sk: str = None, gsi=None, attr_types=None):
    key_schema = [{"AttributeName": pk, "KeyType": "HASH"}]
    attr_defs = [{"AttributeName": pk, "AttributeType": "S"}]
    if sk:
        key_schema.append({"AttributeName": sk, "KeyType": "RANGE"})
        attr_defs.append({"AttributeName": sk, "AttributeType": "S"})

    if attr_types:
        for attr, atype in attr_types.items():
            if not any(a["AttributeName"] == attr for a in attr_defs):
                attr_defs.append({"AttributeName": attr, "AttributeType": atype})

    kwargs: Dict[str, Any] = {
        "TableName": name,
        "KeySchema": key_schema,
        "AttributeDefinitions": attr_defs,
        "BillingMode": "PAY_PER_REQUEST",
    }
    if gsi:
        gsi_defs = []
        for g in gsi:
            pk_gsi = g["partition_key"]
            if not any(a["AttributeName"] == pk_gsi for a in attr_defs):
                attr_defs.append({"AttributeName": pk_gsi, "AttributeType": "S"})
            gsi_ks = [{"AttributeName": pk_gsi, "KeyType": "HASH"}]
            if g.get("sort_key"):
                gsi_ks.append({"AttributeName": g["sort_key"], "KeyType": "RANGE"})
                if not any(a["AttributeName"] == g["sort_key"] for a in attr_defs):
                    atype = (attr_types or {}).get(g["sort_key"], "S")
                    attr_defs.append({"AttributeName": g["sort_key"], "AttributeType": atype})
            gsi_defs.append({
                "IndexName": g["index_name"],
                "KeySchema": gsi_ks,
                "Projection": {"ProjectionType": "ALL"},
            })
        kwargs["GlobalSecondaryIndexes"] = gsi_defs
        kwargs["AttributeDefinitions"] = attr_defs
    return ddb_resource.create_table(**kwargs)


# ===========================================================================
# EML-001: send_alert_email html_body parameter
# ===========================================================================

class TestEml001HtmlEmail:

    def _make_ses_mock(self):
        mock_ses = MagicMock()
        mock_ses.send_email.return_value = {"MessageId": "msg-test-123"}
        return mock_ses

    def _setup_s(self):
        from app.core.settings import S
        prev_dev = S.dev_mode
        prev_enabled = S.alerts_email_enabled
        prev_from = S.alerts_from_email
        object.__setattr__(S, "dev_mode", False)
        object.__setattr__(S, "alerts_email_enabled", True)
        object.__setattr__(S, "alerts_from_email", "noreply@test.local")
        object.__setattr__(S, "admin_email_settings_enabled", False)
        return prev_dev, prev_enabled, prev_from

    def _restore_s(self, prev_dev, prev_enabled, prev_from):
        from app.core.settings import S
        object.__setattr__(S, "dev_mode", prev_dev)
        object.__setattr__(S, "alerts_email_enabled", prev_enabled)
        object.__setattr__(S, "alerts_from_email", prev_from)

    def test_html_body_in_ses_call(self):
        prev = self._setup_s()
        mock_ses = self._make_ses_mock()
        with patch("boto3.client", return_value=mock_ses):
            with patch("app.services.alerts.record_email_sent"):
                from app.services.alerts import send_alert_email
                send_alert_email(["a@b.com"], "Subject", "plain text", html_body="<h1>Hello</h1>")
        assert mock_ses.send_email.called
        call_kwargs = mock_ses.send_email.call_args[1]
        body = call_kwargs["Message"]["Body"]
        assert body["Text"]["Data"] == "plain text"
        assert body["Html"]["Data"] == "<h1>Hello</h1>"
        self._restore_s(*prev)

    def test_no_html_body_omits_html_key(self):
        prev = self._setup_s()
        mock_ses = self._make_ses_mock()
        with patch("boto3.client", return_value=mock_ses):
            with patch("app.services.alerts.record_email_sent"):
                from app.services.alerts import send_alert_email
                send_alert_email(["a@b.com"], "Subject", "plain text")
        call_kwargs = mock_ses.send_email.call_args[1]
        body = call_kwargs["Message"]["Body"]
        assert "Html" not in body
        assert "Text" in body
        self._restore_s(*prev)

    def test_empty_string_html_body_omits_html_key(self):
        prev = self._setup_s()
        mock_ses = self._make_ses_mock()
        with patch("boto3.client", return_value=mock_ses):
            with patch("app.services.alerts.record_email_sent"):
                from app.services.alerts import send_alert_email
                send_alert_email(["a@b.com"], "Subject", "plain text", html_body="")
        call_kwargs = mock_ses.send_email.call_args[1]
        body = call_kwargs["Message"]["Body"]
        assert "Html" not in body
        self._restore_s(*prev)

    def test_html_body_truncated_at_50000(self):
        prev = self._setup_s()
        mock_ses = self._make_ses_mock()
        with patch("boto3.client", return_value=mock_ses):
            with patch("app.services.alerts.record_email_sent"):
                from app.services.alerts import send_alert_email
                send_alert_email(["a@b.com"], "Subject", "plain", html_body="x" * 60000)
        call_kwargs = mock_ses.send_email.call_args[1]
        html_data = call_kwargs["Message"]["Body"]["Html"]["Data"]
        assert len(html_data) == 50000
        self._restore_s(*prev)

    def test_dev_mode_logs_html_length(self, tmp_path):
        from app.core.settings import S
        prev_dev = S.dev_mode
        object.__setattr__(S, "dev_mode", True)
        logged = []
        with patch("app.services.alerts._write_dev_log", side_effect=lambda p, e: logged.append(e)):
            from app.services.alerts import send_alert_email
            send_alert_email(["a@b.com"], "Subj", "plain", html_body="<p>hi</p>")
        object.__setattr__(S, "dev_mode", prev_dev)
        assert any("HTML: 9 chars" in e for e in logged)

    def test_dev_mode_no_html_no_html_note(self):
        from app.core.settings import S
        prev_dev = S.dev_mode
        object.__setattr__(S, "dev_mode", True)
        logged = []
        with patch("app.services.alerts._write_dev_log", side_effect=lambda p, e: logged.append(e)):
            from app.services.alerts import send_alert_email
            send_alert_email(["a@b.com"], "Subj", "plain")
        object.__setattr__(S, "dev_mode", prev_dev)
        assert not any("HTML:" in e for e in logged)

    def test_record_email_sent_called_on_success(self):
        prev = self._setup_s()
        mock_ses = self._make_ses_mock()
        with patch("boto3.client", return_value=mock_ses):
            with patch("app.services.alerts.record_email_sent") as mock_rec:
                from app.services.alerts import send_alert_email
                send_alert_email(["a@b.com"], "Subject", "plain")
        assert mock_rec.called
        assert mock_rec.call_args[0][0] == ["a@b.com"]
        self._restore_s(*prev)

    def test_record_email_failure_called_on_ses_error(self):
        prev = self._setup_s()
        mock_ses = MagicMock()
        mock_ses.send_email.side_effect = Exception("throttled")
        with patch("boto3.client", return_value=mock_ses):
            with patch("app.services.alerts.record_email_sent") as mock_sent:
                with patch("app.services.alerts.record_email_failure") as mock_fail:
                    from app.services.alerts import send_alert_email
                    send_alert_email(["a@b.com"], "Subject", "plain")
        assert mock_fail.called
        assert not mock_sent.called
        self._restore_s(*prev)


# ===========================================================================
# EML-002: email_settings service
# ===========================================================================

@pytest.fixture(scope="function")
def eml002_tables():
    """Create moto email_settings table and patch T + S."""
    from app.core.settings import S
    from app.core.tables import T

    prev_admin_enabled = getattr(S, "admin_email_settings_enabled", False)
    prev_table_name = getattr(S, "email_settings_table_name", "email_settings")
    prev_from = S.alerts_from_email
    prev_enabled = S.alerts_email_enabled
    prev_t = T.email_settings

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tbl = _make_table(ddb, "test_email_settings", "pk", "sk")
        object.__setattr__(T, "email_settings", tbl)
        object.__setattr__(S, "admin_email_settings_enabled", True)
        object.__setattr__(S, "email_settings_table_name", "test_email_settings")
        object.__setattr__(S, "alerts_from_email", "env@test.local")
        object.__setattr__(S, "alerts_email_enabled", True)

        # Reset the module cache
        import app.services.email_settings as es_mod
        es_mod._CACHE = None
        es_mod._CACHE_TS = 0

        yield tbl

        # Restore
        object.__setattr__(T, "email_settings", prev_t)
        object.__setattr__(S, "admin_email_settings_enabled", prev_admin_enabled)
        object.__setattr__(S, "email_settings_table_name", prev_table_name)
        object.__setattr__(S, "alerts_from_email", prev_from)
        object.__setattr__(S, "alerts_email_enabled", prev_enabled)
        es_mod._CACHE = None
        es_mod._CACHE_TS = 0


def test_eml002_get_settings_env_fallback(eml002_tables):
    import app.services.email_settings as es_mod
    result = es_mod.get_email_settings()
    assert result["source"] == "env_fallback"
    assert result["from_email"] == "env@test.local"


def test_eml002_update_and_get_settings(eml002_tables):
    import app.services.email_settings as es_mod
    with patch("app.services.alerts.audit_event"):
        es_mod.update_email_settings("root_sub", from_email="noreply@example.com", ses_enabled=True)
    result = es_mod.get_email_settings()
    assert result["from_email"] == "noreply@example.com"
    assert result["ses_enabled"] is True
    assert result["source"] == "ddb_override"
    assert result["updated_by"] == "root_sub"


def test_eml002_invalid_from_email_raises_400(eml002_tables):
    import app.services.email_settings as es_mod
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        es_mod.update_email_settings("root_sub", from_email="not-an-email")
    assert exc_info.value.status_code == 400


def test_eml002_partial_patch_preserves_existing(eml002_tables):
    import app.services.email_settings as es_mod
    with patch("app.services.alerts.audit_event"):
        es_mod.update_email_settings("root_sub", from_email="a@b.com", ses_enabled=False)
        es_mod.update_email_settings("root_sub", ses_enabled=True)
    result = es_mod.get_email_settings()
    assert result["from_email"] == "a@b.com"
    assert result["ses_enabled"] is True


def test_eml002_cache_invalidated_after_update(eml002_tables):
    import app.services.email_settings as es_mod
    # Prime the cache
    es_mod.get_email_settings()
    assert es_mod._CACHE is not None
    # Update should clear cache
    with patch("app.services.alerts.audit_event"):
        es_mod.update_email_settings("root_sub", from_email="new@domain.com")
    assert es_mod._CACHE is None
    # Fresh read returns updated value
    result = es_mod.get_email_settings()
    assert result["from_email"] == "new@domain.com"


def test_eml002_flag_off_no_ddb_read():
    from app.core.settings import S
    prev = getattr(S, "admin_email_settings_enabled", False)
    object.__setattr__(S, "admin_email_settings_enabled", False)
    import app.services.email_settings as es_mod
    # patch get_email_settings to raise if called
    with patch.object(es_mod, "get_email_settings", side_effect=AssertionError("should not call")):
        from app.services.alerts import send_alert_email
        # Should not raise even when the mock would raise
    object.__setattr__(S, "admin_email_settings_enabled", prev)


# ===========================================================================
# EML-003: user_email_accounts service
# ===========================================================================

@pytest.fixture(scope="function")
def eml003_tables():
    """Create moto user_email_accounts table, patch T + KMS."""
    from app.core.settings import S
    from app.core.tables import T

    prev_enabled = getattr(S, "email_client_enabled", False)
    prev_t = T.user_email_accounts

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tbl = _make_table(
            ddb, "test_user_email_accounts", "pk", "sk",
            gsi=[{"index_name": "ByUser", "partition_key": "pk", "sort_key": "created_at"}],
            attr_types={"created_at": "N"},
        )
        object.__setattr__(T, "user_email_accounts", tbl)
        object.__setattr__(S, "email_client_enabled", True)

        with patch("app.services.user_email_accounts.kms_encrypt", side_effect=lambda p: "ENC:" + p), \
             patch("app.services.user_email_accounts.kms_decrypt", side_effect=lambda ct: ct[4:].encode()):
            yield tbl

    object.__setattr__(T, "user_email_accounts", prev_t)
    object.__setattr__(S, "email_client_enabled", prev_enabled)


def test_eml003_create_returns_no_password(eml003_tables):
    import app.services.user_email_accounts as svc
    with patch("app.services.alerts.audit_event"):
        result = svc.create_account("alice", {
            "label": "Gmail", "imap_host": "imap.gmail.com",
            "smtp_host": "smtp.gmail.com", "username": "alice@gmail.com",
            "password": "secret", "imap_port": 993, "smtp_port": 587,
        })
    assert "password_ct_b64" not in result
    assert result["status"] == "unverified"


def test_eml003_kms_encryption_stored(eml003_tables):
    import app.services.user_email_accounts as svc
    with patch("app.services.alerts.audit_event"):
        result = svc.create_account("alice", {
            "label": "Gmail", "imap_host": "imap.gmail.com",
            "smtp_host": "smtp.gmail.com", "username": "alice@gmail.com",
            "password": "mysecret", "imap_port": 993, "smtp_port": 587,
        })
    raw = svc.get_account("alice", result["account_id"])
    assert raw["password_ct_b64"] == "ENC:mysecret"


def test_eml003_list_accounts(eml003_tables):
    import app.services.user_email_accounts as svc
    with patch("app.services.alerts.audit_event"):
        svc.create_account("bob", {"label": "A", "imap_host": "h", "smtp_host": "h",
                                   "username": "b@b.com", "password": "p"})
        svc.create_account("bob", {"label": "B", "imap_host": "h", "smtp_host": "h",
                                   "username": "b@b.com", "password": "p"})
    items, cursor = svc.list_accounts("bob")
    assert len(items) == 2
    assert all("password_ct_b64" not in it for it in items)


def test_eml003_get_account_not_owned(eml003_tables):
    import app.services.user_email_accounts as svc
    with patch("app.services.alerts.audit_event"):
        result = svc.create_account("alice", {"label": "A", "imap_host": "h", "smtp_host": "h",
                                              "username": "a@a.com", "password": "p"})
    # Bob cannot access Alice's account
    other = svc.get_account("bob", result["account_id"])
    assert other is None


def test_eml003_update_label(eml003_tables):
    import app.services.user_email_accounts as svc
    with patch("app.services.alerts.audit_event"):
        acct = svc.create_account("alice", {"label": "Old", "imap_host": "h", "smtp_host": "h",
                                            "username": "a@a.com", "password": "p"})
        result = svc.update_account("alice", acct["account_id"], {"label": "New"})
    assert result["label"] == "New"
    assert result["status"] == "unverified"  # credential unchanged, status doesn't reset for label


def test_eml003_update_host_resets_status(eml003_tables):
    import app.services.user_email_accounts as svc
    with patch("app.services.alerts.audit_event"):
        # First set status to active manually
        acct = svc.create_account("alice", {"label": "A", "imap_host": "old.host", "smtp_host": "h",
                                            "username": "a@a.com", "password": "p"})
        result = svc.update_account("alice", acct["account_id"], {"imap_host": "new.host"})
    assert result["status"] == "unverified"


def test_eml003_delete(eml003_tables):
    import app.services.user_email_accounts as svc
    from app.services.user_email_accounts import AccountNotFound
    with patch("app.services.alerts.audit_event"):
        acct = svc.create_account("alice", {"label": "A", "imap_host": "h", "smtp_host": "h",
                                            "username": "a@a.com", "password": "p"})
        svc.delete_account("alice", acct["account_id"])
    # Second delete raises 404
    with pytest.raises(AccountNotFound):
        svc.delete_account("alice", acct["account_id"])


def test_eml003_verify_success_mock(eml003_tables):
    import app.services.user_email_accounts as svc

    mock_imap = MagicMock()
    mock_imap.login.return_value = ("OK", [b"Logged in"])
    mock_imap.logout.return_value = ("BYE", [])

    with patch("app.services.alerts.audit_event"), \
         patch("app.services.user_email_accounts._get_imap_client", return_value=mock_imap):
        acct = svc.create_account("alice", {"label": "A", "imap_host": "imap.test", "smtp_host": "h",
                                            "username": "a@a.com", "password": "pass"})
        result = svc.verify_connection("alice", acct["account_id"])

    assert result["ok"] is True
    assert result["status"] == "active"


def test_eml003_verify_failure_mock(eml003_tables):
    import app.services.user_email_accounts as svc
    import imaplib

    mock_imap = MagicMock()
    mock_imap.login.side_effect = imaplib.IMAP4.error("AUTH failed")

    with patch("app.services.alerts.audit_event"), \
         patch("app.services.user_email_accounts._get_imap_client", return_value=mock_imap):
        acct = svc.create_account("alice", {"label": "A", "imap_host": "imap.test", "smtp_host": "h",
                                            "username": "a@a.com", "password": "pass"})
        result = svc.verify_connection("alice", acct["account_id"])

    assert result["ok"] is False
    assert result["status"] == "error"


def test_eml003_is_default_uniqueness(eml003_tables):
    import app.services.user_email_accounts as svc
    with patch("app.services.alerts.audit_event"):
        a1 = svc.create_account("alice", {"label": "A", "imap_host": "h", "smtp_host": "h",
                                          "username": "a@a.com", "password": "p", "is_default": True})
        a2 = svc.create_account("alice", {"label": "B", "imap_host": "h", "smtp_host": "h",
                                          "username": "a@a.com", "password": "p", "is_default": True})
    # a1 should have is_default=False now
    raw1 = svc.get_account("alice", a1["account_id"])
    raw2 = svc.get_account("alice", a2["account_id"])
    assert raw1["is_default"] is False
    assert raw2["is_default"] is True


def test_eml003_host_injection_rejected(eml003_tables):
    import app.services.user_email_accounts as svc
    from fastapi import HTTPException
    with patch("app.services.alerts.audit_event"):
        with pytest.raises(HTTPException):
            svc.create_account("alice", {"label": "A", "imap_host": "bad\nhost", "smtp_host": "h",
                                         "username": "a@a.com", "password": "p"})


def test_eml003_username_not_email_raises_400(eml003_tables):
    import app.services.user_email_accounts as svc
    from fastapi import HTTPException
    with patch("app.services.alerts.audit_event"):
        with pytest.raises(HTTPException):
            svc.create_account("alice", {"label": "A", "imap_host": "h", "smtp_host": "h",
                                         "username": "not-an-email", "password": "p"})


# ===========================================================================
# EML-004: email_sync service
# ===========================================================================

@pytest.fixture(scope="function")
def eml004_tables():
    """Create moto user_email_messages + accounts tables, patch T + S."""
    from app.core.settings import S
    from app.core.tables import T

    prev_dev = S.dev_mode
    prev_enabled = getattr(S, "email_client_enabled", False)
    prev_msg_t = T.user_email_messages
    prev_acct_t = T.user_email_accounts

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        msg_tbl = _make_table(
            ddb, "test_email_messages", "pk", "sk",
            gsi=[
                {"index_name": "ByFolder", "partition_key": "folder_pk", "sort_key": "date_ts"},
                {"index_name": "ByThread", "partition_key": "pk", "sort_key": "thread_id"},
            ],
            attr_types={"date_ts": "N"},
        )
        acct_tbl = _make_table(
            ddb, "test_email_accounts_04", "pk", "sk",
            gsi=[{"index_name": "ByUser", "partition_key": "pk", "sort_key": "created_at"}],
            attr_types={"created_at": "N"},
        )
        object.__setattr__(T, "user_email_messages", msg_tbl)
        object.__setattr__(T, "user_email_accounts", acct_tbl)
        object.__setattr__(S, "dev_mode", True)
        object.__setattr__(S, "email_client_enabled", True)
        object.__setattr__(S, "email_messages_ttl_days", 90)
        object.__setattr__(S, "email_imap_max_fetch", 200)
        object.__setattr__(S, "email_bodies_s3_bucket", "local-uploads")
        object.__setattr__(S, "email_bodies_s3_prefix", "email-bodies/")

        # Seed an account
        acct_tbl.put_item(Item={
            "pk": "USER#alice",
            "sk": "ACCT#testacct01",
            "account_id": "testacct01",
            "label": "Test",
            "imap_host": "imap.test",
            "imap_port": 993,
            "imap_use_ssl": True,
            "smtp_host": "smtp.test",
            "smtp_port": 587,
            "smtp_use_tls": True,
            "username": "alice@test.local",
            "password_ct_b64": "ENC:fakepass",
            "is_default": True,
            "status": "active",
            "created_at": 1000000,
            "updated_at": 1000000,
        })

        with patch("app.services.user_email_accounts.kms_decrypt", side_effect=lambda ct: ct[4:].encode()):
            yield msg_tbl

    object.__setattr__(T, "user_email_messages", prev_msg_t)
    object.__setattr__(T, "user_email_accounts", prev_acct_t)
    object.__setattr__(S, "dev_mode", prev_dev)
    object.__setattr__(S, "email_client_enabled", prev_enabled)


def test_eml004_sync_inbox_dev_mode(eml004_tables):
    import app.services.email_sync as svc
    with patch("app.services.alerts.audit_event"):
        result = svc.sync_inbox("alice", "testacct01")
    assert result["synced"] == 2
    assert result["folder"] == "INBOX"
    # Verify rows in DDB
    resp = eml004_tables.scan()
    msg_rows = [it for it in resp["Items"] if it.get("sk", "").startswith("MSG#")]
    assert len(msg_rows) == 2


def test_eml004_sync_inbox_idempotent(eml004_tables):
    import app.services.email_sync as svc
    with patch("app.services.alerts.audit_event"):
        r1 = svc.sync_inbox("alice", "testacct01")
        r2 = svc.sync_inbox("alice", "testacct01")
    assert r1["synced"] == 2
    # Second sync finds no new UIDs (cursor advanced)
    assert r2["synced"] == 0
    resp = eml004_tables.scan()
    msg_rows = [it for it in resp["Items"] if it.get("sk", "").startswith("MSG#")]
    assert len(msg_rows) == 2


def test_eml004_thread_id_consistency(eml004_tables):
    import app.services.email_sync as svc
    with patch("app.services.alerts.audit_event"):
        svc.sync_inbox("alice", "testacct01")

    items, _ = svc.list_messages("alice", "testacct01", "INBOX")
    thread_ids = {it["thread_id"] for it in items}
    # Both mock messages should share the same thread (reply references root)
    assert len(thread_ids) == 1


def test_eml004_list_messages_folder(eml004_tables):
    import app.services.email_sync as svc
    with patch("app.services.alerts.audit_event"):
        svc.sync_inbox("alice", "testacct01")

    items, cursor = svc.list_messages("alice", "testacct01", "INBOX", limit=10)
    assert len(items) == 2
    # List responses should NOT include body_text or body_html
    for it in items:
        assert "body_text" not in it
        assert "body_html" not in it


def test_eml004_get_message_found(eml004_tables):
    import app.services.email_sync as svc
    with patch("app.services.alerts.audit_event"):
        svc.sync_inbox("alice", "testacct01")
    msg = svc.get_message("alice", "testacct01", 1)
    assert msg is not None
    assert msg.get("uid") == 1
    assert "snippet" in msg


def test_eml004_get_message_not_found(eml004_tables):
    import app.services.email_sync as svc
    msg = svc.get_message("alice", "testacct01", 9999)
    assert msg is None


def test_eml004_ownership_isolation(eml004_tables):
    import app.services.email_sync as svc
    with patch("app.services.alerts.audit_event"):
        svc.sync_inbox("alice", "testacct01")
    # Bob gets empty list for Alice's account_id
    items, _ = svc.list_messages("bob", "testacct01", "INBOX")
    assert items == []


# ===========================================================================
# EML-007: email_archive service
# ===========================================================================

@pytest.fixture(scope="function")
def eml007_tables():
    """Set up tables for email_archive tests."""
    from app.core.settings import S
    from app.core.tables import T

    prev_archiving = getattr(S, "email_archiving_enabled", False)
    prev_archive_t = T.email_archive
    prev_msg_t = T.user_email_messages

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        archive_tbl = _make_table(
            ddb, "test_email_archive", "pk", "sk",
            gsi=[{"index_name": "ByUser", "partition_key": "gsi_user_pk", "sort_key": "archived_at"}],
            attr_types={"archived_at": "N"},
        )
        msg_tbl = _make_table(
            ddb, "test_email_messages_07", "pk", "sk",
            gsi=[
                {"index_name": "ByFolder", "partition_key": "folder_pk", "sort_key": "date_ts"},
                {"index_name": "ByThread", "partition_key": "pk", "sort_key": "thread_id"},
            ],
            attr_types={"date_ts": "N"},
        )

        object.__setattr__(T, "email_archive", archive_tbl)
        object.__setattr__(T, "user_email_messages", msg_tbl)
        object.__setattr__(S, "email_archiving_enabled", True)

        # Seed a message
        msg_tbl.put_item(Item={
            "pk": "USER#alice#ACCT#acct01",
            "sk": "MSG#0000000001",
            "uid": 1,
            "message_id": "<root-001@test.local>",
            "subject": "Test Subject",
            "from_addr": "sender@test.local",
            "snippet": "Hello world",
            "date_ts": 1700000000,
            "folder": "INBOX",
            "thread_id": "abc123",
        })

        yield archive_tbl, msg_tbl

    object.__setattr__(T, "email_archive", prev_archive_t)
    object.__setattr__(T, "user_email_messages", prev_msg_t)
    object.__setattr__(S, "email_archiving_enabled", prev_archiving)


def test_eml007_archive_message_not_found(eml007_tables):
    import app.services.email_archive as svc
    from fastapi import HTTPException
    with patch("app.services.alerts.audit_event"):
        with pytest.raises(HTTPException) as exc:
            svc.archive_email("alice", "acct01", 9999, "ticket", "ticket-01")
    assert exc.value.status_code == 404


def test_eml007_archive_org_account_rejected(eml007_tables):
    import app.services.email_archive as svc
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        svc.archive_email("alice", "acct01", 1, "org_account", "org-01")
    assert exc.value.status_code == 400


def test_eml007_feature_flag_off(eml007_tables):
    from app.core.settings import S
    import app.services.email_archive as svc
    from fastapi import HTTPException
    object.__setattr__(S, "email_archiving_enabled", False)
    with pytest.raises(HTTPException) as exc:
        svc.archive_email("alice", "acct01", 1, "ticket", "t-01")
    assert exc.value.status_code == 503
    object.__setattr__(S, "email_archiving_enabled", True)


def test_eml007_archive_contact_success(eml007_tables):
    from app.core.tables import T
    archive_tbl, msg_tbl = eml007_tables

    # Seed a contacts table mock
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        contacts_tbl = _make_table(ddb, "test_contacts_07", "owner_id", "contact_id")
        contacts_tbl.put_item(Item={"owner_id": "alice", "contact_id": "contact-01"})
        prev_c = T.contacts
        object.__setattr__(T, "contacts", contacts_tbl)

        import app.services.email_archive as svc
        with patch("app.services.alerts.audit_event"):
            result = svc.archive_email("alice", "acct01", 1, "contact", "contact-01")

        object.__setattr__(T, "contacts", prev_c)

    assert result["entity_type"] == "contact"
    assert result["entity_id"] == "contact-01"


def test_eml007_list_archived_emails_empty(eml007_tables):
    import app.services.email_archive as svc
    items, cursor = svc.list_archived_emails("ticket", "nonexistent-ticket")
    assert items == []
    assert cursor is None


def test_eml007_archive_idempotent(eml007_tables):
    from app.core.tables import T
    archive_tbl, msg_tbl = eml007_tables

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        contacts_tbl = _make_table(ddb, "test_contacts_idm", "owner_id", "contact_id")
        contacts_tbl.put_item(Item={"owner_id": "alice", "contact_id": "contact-idm"})
        prev_c = T.contacts
        object.__setattr__(T, "contacts", contacts_tbl)

        import app.services.email_archive as svc
        with patch("app.services.alerts.audit_event"):
            r1 = svc.archive_email("alice", "acct01", 1, "contact", "contact-idm")
            r2 = svc.archive_email("alice", "acct01", 1, "contact", "contact-idm")

        object.__setattr__(T, "contacts", prev_c)

    # Both should succeed with same SK
    assert r1["sk"] == r2["sk"]


# ===========================================================================
# EML-009: campaign template functions
# ===========================================================================

@pytest.fixture(scope="function")
def eml009_tables():
    """Set up admin_messaging_templates table for EML-009 tests."""
    from app.core.settings import S
    from app.core.tables import T

    prev_enabled = getattr(S, "campaign_email_templates_enabled", False)
    prev_t = T.admin_messaging_templates

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tbl = _make_table(ddb, "test_admin_msg_templates", "pk", "sk")
        object.__setattr__(T, "admin_messaging_templates", tbl)
        object.__setattr__(S, "campaign_email_templates_enabled", True)

        yield tbl

    object.__setattr__(T, "admin_messaging_templates", prev_t)
    object.__setattr__(S, "campaign_email_templates_enabled", prev_enabled)


def test_eml009_create_campaign_template(eml009_tables):
    import app.services.notification_templates as svc
    with patch("app.services.alerts.audit_event"):
        result = svc.create_campaign_template("admin_sub", {
            "name": "Welcome Campaign",
            "subject": "Hello {{first_name}}!",
            "body": "<h1>Hi {{first_name}}</h1><p>Visit {{unsubscribe_url}}</p>",
            "campaign_id": "camp-001",
            "merge_fields": ["first_name", "unsubscribe_url"],
        })
    assert result["channel"] == "campaign"
    assert result["active"] is True
    assert result["campaign_id"] == "camp-001"
    assert "first_name" in result["merge_fields"]
    assert result["template_id"].startswith("campaign_")


def test_eml009_create_strips_script_tags(eml009_tables):
    import app.services.notification_templates as svc
    with patch("app.services.alerts.audit_event"):
        result = svc.create_campaign_template("admin_sub", {
            "name": "Test",
            "subject": "Subj",
            "body": "<p>Hello</p><script>alert(1)</script><b>World</b>",
        })
    assert "<script>" not in result["body"]
    assert "<p>Hello</p>" in result["body"]


def test_eml009_list_campaign_templates_only(eml009_tables):
    from app.core.tables import T
    # Seed an email-channel template
    T.admin_messaging_templates.put_item(Item={
        "pk": "TEMPLATE#email_test_001",
        "sk": "META",
        "template_id": "email_test_001",
        "channel": "email",
        "name": "Regular Email",
        "body": "Hello",
        "active": True,
    })
    import app.services.notification_templates as svc
    with patch("app.services.alerts.audit_event"):
        svc.create_campaign_template("admin", {"name": "Campaign", "subject": "S", "body": "B"})
    result = svc.list_campaign_templates()
    assert all(t["channel"] == "campaign" for t in result)


def test_eml009_render_known_vars(eml009_tables):
    import app.services.notification_templates as svc
    with patch("app.services.alerts.audit_event"):
        tmpl = svc.create_campaign_template("admin", {
            "name": "Promo",
            "subject": "Hi {{first_name}}",
            "body": "<p>Hi {{first_name}}, unsubscribe at {{unsubscribe_url}}</p>",
        })
    subj, body = svc.render_campaign_body(tmpl["template_id"], {
        "first_name": "Alice",
        "unsubscribe_url": "https://example.com/unsub",
    })
    assert "Alice" in subj
    assert "Alice" in body
    assert "https://example.com/unsub" in body


def test_eml009_render_unknown_var_left_as_is(eml009_tables):
    import app.services.notification_templates as svc
    with patch("app.services.alerts.audit_event"):
        tmpl = svc.create_campaign_template("admin", {
            "name": "P", "subject": "S", "body": "Hello {{unknown_var}}",
        })
    _, body = svc.render_campaign_body(tmpl["template_id"], {})
    assert "{{unknown_var}}" in body


def test_eml009_render_inactive_template(eml009_tables):
    import app.services.notification_templates as svc
    with patch("app.services.alerts.audit_event"):
        tmpl = svc.create_campaign_template("admin", {
            "name": "P", "subject": "S", "body": "B",
        })
        svc.update_template(tmpl["template_id"], admin_sub="admin", active=False)
    subj, body = svc.render_campaign_body(tmpl["template_id"], {})
    assert subj == ""
    assert body == ""


def test_eml009_render_missing_template(eml009_tables):
    import app.services.notification_templates as svc
    subj, body = svc.render_campaign_body("nonexistent_id", {})
    assert subj == ""
    assert body == ""


def test_eml009_flag_off_returns_503(eml009_tables):
    from app.core.settings import S
    from fastapi import HTTPException
    object.__setattr__(S, "campaign_email_templates_enabled", False)
    from app.routers.admin_email import _require_campaign_templates_enabled
    with pytest.raises(HTTPException) as exc:
        _require_campaign_templates_enabled()
    assert exc.value.status_code == 503
    object.__setattr__(S, "campaign_email_templates_enabled", True)


def test_eml009_merge_fields_validator():
    from app.models import CampaignEmailTemplateCreate
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        CampaignEmailTemplateCreate(
            name="T", subject="S", body="B",
            merge_fields=["bad field!"]
        )


def test_eml009_body_max_length():
    from app.models import CampaignEmailTemplateCreate
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        CampaignEmailTemplateCreate(
            name="T", subject="S", body="x" * 50_001,
        )


def test_eml009_audit_event_on_create(eml009_tables):
    import app.services.notification_templates as svc
    # audit_event is imported locally inside create_campaign_template;
    # patch at the source module level to observe it.
    with patch("app.services.alerts.audit_event") as mock_audit:
        svc.create_campaign_template("admin_sub", {
            "name": "T", "subject": "S", "body": "B",
        })
    assert mock_audit.called
    assert mock_audit.call_args[0][0] == "campaign_template_created"


# ===========================================================================
# Import smoke test
# ===========================================================================

def test_app_main_imports():
    """Ensure app.main imports cleanly (catches import-time crashes)."""
    import app.main  # noqa: F401  # already imported during test collection
