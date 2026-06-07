"""Regression tests for GAP-0340 + GAP-0341 (PRIVACY-001).

GAP-0340: process_deletion() must delete the user's file-manager DDB records AND
          their S3 objects (S.filemgr_bucket).
GAP-0341: process_deletion() must disable + delete the Cognito identity, guarded
          by _cognito_available().

Fully offline / hermetic:
- moto in-memory DynamoDB (file-manager table) bound onto app.core.aws.ddb, the
  same resource process_deletion uses.
- moto in-memory S3 bucket created and the filemgr objects PUT into it; we assert
  the objects are gone afterward.
- The other DDB tables (T.*) and delete_user_data are patched to no-ops so the
  function runs to completion.
- Cognito helpers are patched to spies; _cognito_available is patched True/False.

NO real AWS.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

FILEMGR_TABLE = "file_manager"
FILEMGR_BUCKET = "test-filemgr-bucket"
USER_SUB = "alice_sub"
USER_EMAIL = "alice@example.com"


def _make_filemgr_table(ddb):
    return ddb.create_table(
        TableName=FILEMGR_TABLE,
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestGdprFilemgrAndCognitoDeletion(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())

        # --- DynamoDB (file manager) ---
        self.ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.filemgr = _make_filemgr_table(self.ddb)

        # --- S3 (file manager bucket) ---
        self.s3 = boto3.client("s3", region_name="us-east-1")
        self.s3.create_bucket(Bucket=FILEMGR_BUCKET)

        from app.services import gdpr_service
        from app.core import aws as core_aws

        self.gdpr = gdpr_service

        # Bind the file-manager table onto the resource process_deletion uses.
        self.stack.enter_context(patch.object(core_aws, "ddb", self.ddb))

        # Stub the T.* table handles + delete_user_data so the function runs to
        # completion without needing every other table.
        fake_T = SimpleNamespace(
            data_requests=MagicMock(),
            billing=MagicMock(),
            profile=MagicMock(),
            addresses=MagicMock(),
            contacts=MagicMock(),
            calendar=MagicMock(),
            subscriptions=MagicMock(),
            account_state=MagicMock(),
            tickets=MagicMock(),
            video_metadata=MagicMock(),
        )
        # profile.get_item returns the email (captured before Step 3).
        fake_T.profile.get_item.return_value = {
            "Item": {"user_sub": USER_SUB, "email": USER_EMAIL}
        }
        # _query_all queries (billing, addresses, ...) return empty by default.
        for t in (
            fake_T.billing, fake_T.addresses, fake_T.contacts, fake_T.calendar,
            fake_T.subscriptions, fake_T.tickets, fake_T.video_metadata,
        ):
            t.query.return_value = {"Items": []}
        self.stack.enter_context(patch.object(gdpr_service, "T", fake_T))

        # delete_user_data is imported inside process_deletion from app.services.account
        self.stack.enter_context(
            patch("app.services.account.delete_user_data", MagicMock())
        )
        self.stack.enter_context(
            patch.object(gdpr_service, "write_alert", MagicMock())
        )
        self.stack.enter_context(
            patch.object(gdpr_service, "_write_audit", MagicMock())
        )

        # Messaging step (Step 11) uses os.environ table names against core_aws.ddb.
        # Those tables don't exist in moto here -> the step swallows the error
        # (messaging_error in summary), which is fine for these tests.

        # Frozen S: point at our moto table/bucket. S is frozen -> object.__setattr__.
        self._patch_setting("filemgr_table_name", FILEMGR_TABLE)
        self._patch_setting("filemgr_bucket", FILEMGR_BUCKET)
        self._patch_setting("s3_endpoint_url", None)
        self._patch_setting("aws_region", "us-east-1")

    def _patch_setting(self, name, value):
        from app.core.settings import S

        original = getattr(S, name)
        object.__setattr__(S, name, value)
        self.addCleanup(lambda: object.__setattr__(S, name, original))

    def _seed_file_node(self, path, s3_key, bucket=FILEMGR_BUCKET):
        self.filemgr.put_item(
            Item={
                "PK": f"USER#{USER_SUB}",
                "SK": f"NODE#{path}",
                "s3_key": s3_key,
                "s3_bucket": bucket,
                "name": path.rsplit("/", 1)[-1],
            }
        )
        self.s3.put_object(Bucket=bucket, Key=s3_key, Body=b"secret-bytes")

    # ----------------------------------------------------------------- GAP-0340
    def test_filemgr_records_and_s3_objects_deleted(self):
        keys = [
            ("/uploads/file0.txt", f"users/{USER_SUB}/file0.txt"),
            ("/uploads/file1.txt", f"users/{USER_SUB}/file1.txt"),
            ("/uploads/file2.txt", f"users/{USER_SUB}/file2.txt"),
        ]
        for path, s3_key in keys:
            self._seed_file_node(path, s3_key)

        # Sanity: objects + rows exist before deletion.
        before = self.filemgr.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("PK").eq(
                f"USER#{USER_SUB}"
            )
        )["Items"]
        self.assertEqual(len(before), 3)

        with patch("app.routers.register._cognito_available", return_value=False):
            summary = self.gdpr.process_deletion(USER_SUB, "req_0340")

        self.assertEqual(summary["files_deleted"], 3)
        self.assertEqual(summary["s3_objects_deleted"], 3)

        # DDB rows gone.
        after = self.filemgr.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("PK").eq(
                f"USER#{USER_SUB}"
            )
        )["Items"]
        self.assertEqual(after, [])

        # S3 objects gone.
        for _, s3_key in keys:
            with self.assertRaises(self.s3.exceptions.ClientError):
                self.s3.head_object(Bucket=FILEMGR_BUCKET, Key=s3_key)

    def test_filemgr_skipped_when_table_not_configured(self):
        self._patch_setting("filemgr_table_name", "")
        with patch("app.routers.register._cognito_available", return_value=False):
            summary = self.gdpr.process_deletion(USER_SUB, "req_skip")
        self.assertEqual(
            summary.get("filemgr_skipped"), "filemgr_table_name not configured"
        )

    # ----------------------------------------------------------------- GAP-0341
    def test_cognito_disabled_and_deleted_when_available(self):
        disable = MagicMock()
        delete = MagicMock()
        with patch("app.routers.register._cognito_available", return_value=True), \
             patch("app.services.cognito.cognito_admin_disable_user", disable), \
             patch("app.services.cognito.cognito_admin_delete_user", delete):
            summary = self.gdpr.process_deletion(USER_SUB, "req_cog")

        disable.assert_called_once_with(USER_EMAIL)
        delete.assert_called_once_with(USER_EMAIL)
        self.assertTrue(summary.get("cognito_deleted"))

    def test_cognito_not_called_in_dev_mode(self):
        disable = MagicMock()
        delete = MagicMock()
        with patch("app.routers.register._cognito_available", return_value=False), \
             patch("app.services.cognito.cognito_admin_disable_user", disable), \
             patch("app.services.cognito.cognito_admin_delete_user", delete):
            summary = self.gdpr.process_deletion(USER_SUB, "req_dev")

        disable.assert_not_called()
        delete.assert_not_called()
        self.assertEqual(summary.get("cognito_skipped"), "not_available")


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestCognitoHelpers(unittest.TestCase):
    """GAP-0341: the new cognito.py helpers call the right boto APIs."""

    def test_disable_and_delete_call_cognito(self):
        from app.services import cognito as cognito_svc

        fake_client = MagicMock()
        # exceptions.UserNotFoundException must be a real exception class.
        fake_client.exceptions.UserNotFoundException = type(
            "UserNotFoundException", (Exception,), {}
        )

        with patch.object(cognito_svc, "cognito_client", return_value=fake_client), \
             patch.object(cognito_svc, "_cognito_user_pool_id", return_value="pool-1"):
            cognito_svc.cognito_admin_disable_user("alice@example.com")
            cognito_svc.cognito_admin_delete_user("alice@example.com")

        fake_client.admin_disable_user.assert_called_once_with(
            UserPoolId="pool-1", Username="alice@example.com"
        )
        fake_client.admin_delete_user.assert_called_once_with(
            UserPoolId="pool-1", Username="alice@example.com"
        )

    def test_missing_user_is_not_an_error(self):
        from app.services import cognito as cognito_svc

        fake_client = MagicMock()
        unf = type("UserNotFoundException", (Exception,), {})
        fake_client.exceptions.UserNotFoundException = unf
        fake_client.admin_disable_user.side_effect = unf("missing")
        fake_client.admin_delete_user.side_effect = unf("missing")

        with patch.object(cognito_svc, "cognito_client", return_value=fake_client), \
             patch.object(cognito_svc, "_cognito_user_pool_id", return_value="pool-1"):
            # Should not raise.
            cognito_svc.cognito_admin_disable_user("ghost@example.com")
            cognito_svc.cognito_admin_delete_user("ghost@example.com")


if __name__ == "__main__":
    unittest.main()
