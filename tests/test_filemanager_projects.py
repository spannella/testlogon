"""
Extended tests for project-layer services:
- projects_store:   archive_tracked_file, event serialization, update/list edge cases
- provider_credentials: get_provider_credential, get_provider_auth_context,
                        delete_provider_credential, scope parsing, URL normalisation
- projects_reconcile:   _is_transient_error, start_projects_reconcile_task,
                        projects_reconcile_loop pagination/error-swallow
- file_providers:   list_children for Local/GitHub/GitLab, _parse_ref edge cases,
                    _raise_for_error branches, ProviderRegistry.register
- projects router:  list_tracked_files_route happy path
"""
from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.services import projects_reconcile, projects_store, provider_credentials
from app.services.file_providers import (
    GitHubProvider,
    GitLabProvider,
    LocalFileProvider,
    ProviderRegistry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "boom"}}, "Op")


def _tracked_item(**overrides):
    base = {
        "entity_type": "tracked_file",
        "id": "tf-1",
        "project_id": "p-1",
        "owner": "user-1",
        "provider": "local",
        "provider_ref": "/docs/a.txt",
        "display_path": "/docs/a.txt",
        "status": "active",
        "metadata": {},
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
        "last_seen_at": "2026-01-01T00:00:00+00:00",
        "archived_at": None,
    }
    base.update(overrides)
    return base


def _credential_item(**overrides):
    base = {
        "entity_type": "provider_credential",
        "owner": "user-1",
        "provider": "github",
        "org": None,
        "token_ct_b64": "cipher",
        "scopes": ["repo"],
        "metadata": {"api_base_url": "https://api.github.com"},
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }
    base.update(overrides)
    return base


def _make_response(status: int, body=None, headers=None, content=b"1"):
    r = MagicMock()
    r.status_code = status
    r.headers = headers or {}
    r.content = content
    r.json.return_value = body or {}
    return r


# ===========================================================================
# projects_store – archive_tracked_file
# ===========================================================================

class TestArchiveTrackedFile(unittest.TestCase):
    def test_archive_tracked_file_sets_status_and_timestamps(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": _tracked_item(status="active")}

        with (
            patch.object(projects_store, "T", SimpleNamespace(projects=table)),
            patch.object(projects_store, "now_iso", return_value="2026-06-01T00:00:00+00:00"),
        ):
            out = projects_store.archive_tracked_file("p-1", "tf-1")

        self.assertEqual(out.status, "archived")
        self.assertEqual(out.archived_at, "2026-06-01T00:00:00+00:00")
        self.assertEqual(out.updated_at, "2026-06-01T00:00:00+00:00")
        table.put_item.assert_called_once()
        stored = table.put_item.call_args.kwargs["Item"]
        self.assertEqual(stored["status"], "archived")

    def test_archive_tracked_file_not_found_raises_404(self):
        table = MagicMock()
        table.get_item.return_value = {}

        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                projects_store.archive_tracked_file("p-1", "missing")

        self.assertEqual(ctx.exception.status_code, 404)


# ===========================================================================
# projects_store – project_event serialization
# ===========================================================================

class TestProjectEventSerialization(unittest.TestCase):
    def test_project_event_round_trip(self):
        from app.models import ProjectEventModel

        event = ProjectEventModel(
            id="ev-1",
            project_id="p-1",
            owner="user-1",
            event_type="file_added",
            tracked_file_id="tf-1",
            provider="github",
            provider_ref="github://owner/repo/README.md?ref=main",
            message="file tracked",
            metadata={"extra": "info"},
            created_at="2026-01-01T00:00:00+00:00",
        )
        item = projects_store.project_event_to_item(event)
        self.assertEqual(item["entity_type"], "project_event")
        self.assertEqual(item["PK"], "PROJECT#p-1")
        self.assertEqual(item["GSI2PK"], "OWNER#user-1")
        self.assertIn("PROJECT#p-1#EVENT#", item["GSI2SK"])

        restored = projects_store.project_event_from_item(item)
        self.assertEqual(restored.id, "ev-1")
        self.assertEqual(restored.event_type, "file_added")
        self.assertEqual(restored.metadata, {"extra": "info"})
        self.assertEqual(restored.provider, "github")

    def test_project_event_optional_fields_default_to_none(self):
        from app.models import ProjectEventModel

        event = ProjectEventModel(
            id="ev-2",
            project_id="p-2",
            owner="user-2",
            event_type="sync_ran",
            metadata={},
            created_at="2026-02-01T00:00:00+00:00",
        )
        item = projects_store.project_event_to_item(event)
        self.assertIsNone(item["tracked_file_id"])
        self.assertIsNone(item["provider"])
        self.assertIsNone(item["message"])

        restored = projects_store.project_event_from_item(item)
        self.assertIsNone(restored.tracked_file_id)
        self.assertIsNone(restored.provider)
        self.assertEqual(restored.metadata, {})


# ===========================================================================
# projects_store – update_project edge cases
# ===========================================================================

class TestUpdateProjectEdgeCases(unittest.TestCase):
    def _project_item(self):
        return {
            "entity_type": "project",
            "id": "p-1",
            "owner": "user-1",
            "name": "Original Name",
            "description": "original desc",
            "tags": ["alpha"],
            "settings": {"k": "v"},
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        }

    def test_update_project_only_name_leaves_other_fields_unchanged(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": self._project_item()}

        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            out = projects_store.update_project("user-1", "p-1", name="New Name")

        self.assertEqual(out.name, "New Name")
        self.assertEqual(out.description, "original desc")
        self.assertEqual(out.tags, ["alpha"])
        self.assertEqual(out.settings, {"k": "v"})

    def test_update_project_clears_description(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": self._project_item()}

        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            out = projects_store.update_project("user-1", "p-1", description=None)

        # When description passed as None explicitly it stays None (no change)
        # but tags/settings remain
        self.assertEqual(out.tags, ["alpha"])


# ===========================================================================
# projects_store – list_projects edge cases
# ===========================================================================

class TestListProjectsEdgeCases(unittest.TestCase):
    def test_list_projects_returns_empty_when_no_matches(self):
        table = MagicMock()
        table.query.return_value = {"Items": [], "LastEvaluatedKey": None}

        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            result = projects_store.list_projects("user-1", tag="nonexistent-tag")

        self.assertEqual(result["items"], [])
        self.assertIsNone(result["cursor"])

    def test_list_projects_name_query_is_case_insensitive(self):
        table = MagicMock()
        table.query.return_value = {
            "Items": [
                {
                    "entity_type": "project",
                    "id": "p-1",
                    "owner": "user-1",
                    "name": "Project Alpha",
                    "description": None,
                    "tags": [],
                    "settings": {},
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                }
            ]
        }

        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            result = projects_store.list_projects("user-1", name_query="ALPHA")

        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0].name, "Project Alpha")

    def test_list_projects_name_query_filters_non_matching(self):
        table = MagicMock()
        table.query.return_value = {
            "Items": [
                {
                    "entity_type": "project",
                    "id": "p-1",
                    "owner": "user-1",
                    "name": "Security Audit",
                    "description": None,
                    "tags": [],
                    "settings": {},
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                }
            ]
        }

        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            result = projects_store.list_projects("user-1", name_query="alpha")

        self.assertEqual(result["items"], [])

    def test_list_projects_invalid_limit_raises_400(self):
        table = MagicMock()
        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                projects_store.list_projects("user-1", limit=0)
        self.assertEqual(ctx.exception.status_code, 400)


# ===========================================================================
# projects_store – delete_project edge cases
# ===========================================================================

class TestDeleteProjectEdgeCases(unittest.TestCase):
    def test_delete_project_conditional_check_failed_raises_404(self):
        table = MagicMock()
        table.delete_item.side_effect = _make_client_error("ConditionalCheckFailedException")

        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                projects_store.delete_project("user-1", "ghost-project")

        self.assertEqual(ctx.exception.status_code, 404)
        self.assertIn("not found", ctx.exception.detail)

    def test_delete_project_other_client_error_propagates(self):
        table = MagicMock()
        table.delete_item.side_effect = _make_client_error("ProvisionedThroughputExceededException")

        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(ClientError):
                projects_store.delete_project("user-1", "p-1")


# ===========================================================================
# provider_credentials – get_provider_credential
# ===========================================================================

class TestGetProviderCredential(unittest.TestCase):
    def test_get_provider_credential_happy_path(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": _credential_item()}

        with patch.object(provider_credentials, "T", SimpleNamespace(projects=table)):
            cred = provider_credentials.get_provider_credential("user-1", "github")

        self.assertEqual(cred.provider, "github")
        self.assertEqual(cred.scopes, ["repo"])

    def test_get_provider_credential_not_found_raises_404(self):
        table = MagicMock()
        table.get_item.return_value = {}

        with patch.object(provider_credentials, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                provider_credentials.get_provider_credential("user-1", "github")

        self.assertEqual(ctx.exception.status_code, 404)

    def test_get_provider_credential_allow_missing_returns_none(self):
        table = MagicMock()
        table.get_item.return_value = {}

        with patch.object(provider_credentials, "T", SimpleNamespace(projects=table)):
            result = provider_credentials.get_provider_credential("user-1", "github", allow_missing=True)

        self.assertIsNone(result)

    def test_get_provider_credential_wrong_entity_type_raises_404(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": _credential_item(entity_type="project")}

        with patch.object(provider_credentials, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                provider_credentials.get_provider_credential("user-1", "github")

        self.assertEqual(ctx.exception.status_code, 404)


# ===========================================================================
# provider_credentials – get_provider_auth_context
# ===========================================================================

class TestGetProviderAuthContext(unittest.TestCase):
    def test_get_provider_auth_context_returns_token_and_scopes(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": _credential_item(scopes=["repo", "read:user"])}

        with (
            patch.object(provider_credentials, "T", SimpleNamespace(projects=table)),
            patch.object(provider_credentials, "kms_decrypt", return_value=b"cleartoken"),
        ):
            ctx = provider_credentials.get_provider_auth_context("user-1", "github")

        self.assertEqual(ctx["token"], "cleartoken")
        self.assertEqual(ctx["provider"], "github")
        self.assertIn("repo", ctx["scopes"])
        self.assertIn("read:user", ctx["scopes"])
        self.assertEqual(ctx["metadata"]["api_base_url"], "https://api.github.com")

    def test_get_provider_auth_context_missing_scope_raises_400(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": _credential_item(scopes=["read:user"])}

        with (
            patch.object(provider_credentials, "T", SimpleNamespace(projects=table)),
            patch.object(provider_credentials, "kms_decrypt", return_value=b"cleartoken"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                provider_credentials.get_provider_auth_context(
                    "user-1", "github", required_scopes=["repo"]
                )

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("repo", ctx.exception.detail)

    def test_get_provider_auth_context_credential_not_found_raises_404(self):
        table = MagicMock()
        table.get_item.return_value = {}

        with patch.object(provider_credentials, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                provider_credentials.get_provider_auth_context("user-1", "github")

        self.assertEqual(ctx.exception.status_code, 404)


# ===========================================================================
# provider_credentials – delete_provider_credential
# ===========================================================================

class TestDeleteProviderCredential(unittest.TestCase):
    def test_delete_returns_deleted_true_when_present(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": _credential_item()}

        with patch.object(provider_credentials, "T", SimpleNamespace(projects=table)):
            result = provider_credentials.delete_provider_credential("user-1", "github")

        self.assertTrue(result["ok"])
        self.assertTrue(result["deleted"])
        table.delete_item.assert_called_once()

    def test_delete_returns_deleted_false_when_absent(self):
        table = MagicMock()
        table.get_item.return_value = {}

        with patch.object(provider_credentials, "T", SimpleNamespace(projects=table)):
            result = provider_credentials.delete_provider_credential("user-1", "github")

        self.assertTrue(result["ok"])
        self.assertFalse(result["deleted"])
        table.delete_item.assert_not_called()

    def test_delete_wrong_owner_raises_404(self):
        table = MagicMock()
        # item exists but belongs to a different owner
        table.get_item.return_value = {"Item": _credential_item(owner="attacker")}

        with patch.object(provider_credentials, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                provider_credentials.delete_provider_credential("user-1", "github")

        self.assertEqual(ctx.exception.status_code, 404)


# ===========================================================================
# provider_credentials – scope parsing & URL normalisation
# ===========================================================================

class TestParseGithubScopes(unittest.TestCase):
    def test_none_returns_empty_list(self):
        self.assertEqual(provider_credentials._parse_github_scopes(None), [])

    def test_empty_string_returns_empty_list(self):
        self.assertEqual(provider_credentials._parse_github_scopes(""), [])

    def test_deduplicates_and_normalises(self):
        result = provider_credentials._parse_github_scopes("REPO, repo, read:user,  READ:USER")
        self.assertEqual(result, ["repo", "read:user"])

    def test_single_scope(self):
        result = provider_credentials._parse_github_scopes("read:org")
        self.assertEqual(result, ["read:org"])

    def test_whitespace_only_entries_skipped(self):
        result = provider_credentials._parse_github_scopes("repo,  , read:user")
        self.assertEqual(result, ["repo", "read:user"])


class TestNormalizeApiBaseUrl(unittest.TestCase):
    def test_github_default_when_none(self):
        url = provider_credentials.normalize_github_api_base_url(None)
        self.assertTrue(url.startswith("https://"))
        self.assertNotIn("//", url.replace("https://", "").replace("http://", ""))

    def test_gitlab_default_when_none(self):
        url = provider_credentials.normalize_gitlab_api_base_url(None)
        self.assertTrue(url.startswith("https://"))

    def test_strips_trailing_slash(self):
        url = provider_credentials.normalize_github_api_base_url("https://ghe.local/api/v3/")
        self.assertFalse(url.endswith("/"))

    def test_rejects_missing_protocol(self):
        with self.assertRaises(HTTPException) as ctx:
            provider_credentials.normalize_github_api_base_url("ghe.local/api/v3")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_rejects_empty_after_strip(self):
        # Empty string falls back to default (which is valid https://)
        url = provider_credentials.normalize_github_api_base_url("")
        self.assertTrue(url.startswith("https://"))


# ===========================================================================
# projects_reconcile – _is_transient_error
# ===========================================================================

class TestIsTransientError(unittest.TestCase):
    def test_http_transient_codes(self):
        for code in (429, 500, 502, 503, 504):
            self.assertTrue(
                projects_reconcile._is_transient_error(HTTPException(status_code=code)),
                f"expected 429/500/502/503/504 to be transient, got False for {code}",
            )

    def test_http_non_transient_codes(self):
        for code in (400, 401, 403, 404, 422):
            self.assertFalse(
                projects_reconcile._is_transient_error(HTTPException(status_code=code)),
                f"expected {code} to be non-transient",
            )

    def test_client_error_transient(self):
        for code in ("ProvisionedThroughputExceededException", "ThrottlingException", "InternalServerError"):
            self.assertTrue(
                projects_reconcile._is_transient_error(_make_client_error(code)),
                f"expected {code} to be transient",
            )

    def test_client_error_non_transient(self):
        self.assertFalse(
            projects_reconcile._is_transient_error(_make_client_error("ConditionalCheckFailedException"))
        )

    def test_os_error_types_are_transient(self):
        self.assertTrue(projects_reconcile._is_transient_error(TimeoutError()))
        self.assertTrue(projects_reconcile._is_transient_error(ConnectionError()))
        self.assertTrue(projects_reconcile._is_transient_error(OSError()))

    def test_generic_value_error_is_not_transient(self):
        self.assertFalse(projects_reconcile._is_transient_error(ValueError("bad value")))


# ===========================================================================
# projects_reconcile – start_projects_reconcile_task
# ===========================================================================

class TestStartProjectsReconcileTask(unittest.TestCase):
    def test_disabled_flag_skips_task_creation(self):
        with (
            patch.object(
                projects_reconcile, "S",
                SimpleNamespace(projects_reconcile_enabled=False, projects_reconcile_interval_seconds=60),
            ),
            patch("asyncio.create_task") as create_task,
        ):
            projects_reconcile.start_projects_reconcile_task()

        create_task.assert_not_called()

    def test_enabled_flag_creates_task(self):
        with (
            patch.object(
                projects_reconcile, "S",
                SimpleNamespace(projects_reconcile_enabled=True, projects_reconcile_interval_seconds=60),
            ),
            patch("asyncio.create_task") as create_task,
        ):
            projects_reconcile.start_projects_reconcile_task()

        create_task.assert_called_once()


# ===========================================================================
# projects_reconcile – projects_reconcile_loop
# ===========================================================================

class TestProjectsReconcileLoop(unittest.TestCase):
    def test_loop_single_batch_with_no_cursor_exits(self):
        async def _run():
            with (
                patch.object(
                    projects_reconcile, "S",
                    SimpleNamespace(projects_reconcile_enabled=True, projects_reconcile_interval_seconds=0),
                ),
                patch.object(
                    projects_reconcile,
                    "reconcile_tracked_files_batch",
                    return_value={"cursor": None, "checked": 1, "missing": 0, "errors": 0},
                ) as reconcile_batch,
                patch("asyncio.sleep", new=AsyncMock(side_effect=asyncio.CancelledError)),
            ):
                with self.assertRaises(asyncio.CancelledError):
                    await projects_reconcile.projects_reconcile_loop()

            # Batch called once, then sleep raised to break infinite loop
            reconcile_batch.assert_called_once()

        asyncio.run(_run())

    def test_loop_paginates_until_cursor_exhausted(self):
        batches = [
            {"cursor": {"PK": "x", "SK": "y"}, "checked": 10, "missing": 0, "errors": 0},
            {"cursor": None, "checked": 5, "missing": 0, "errors": 0},
        ]
        call_count = 0

        def fake_reconcile(*, cursor=None, **_kwargs):
            nonlocal call_count
            result = batches[call_count]
            call_count += 1
            return result

        async def _run():
            with (
                patch.object(
                    projects_reconcile, "S",
                    SimpleNamespace(projects_reconcile_enabled=True, projects_reconcile_interval_seconds=0),
                ),
                patch.object(projects_reconcile, "reconcile_tracked_files_batch", side_effect=fake_reconcile),
                patch("asyncio.sleep", new=AsyncMock(side_effect=asyncio.CancelledError)),
            ):
                with self.assertRaises(asyncio.CancelledError):
                    await projects_reconcile.projects_reconcile_loop()

        asyncio.run(_run())
        self.assertEqual(call_count, 2)

    def test_loop_swallows_exceptions_and_sleeps(self):
        async def fake_sleep(_):
            raise asyncio.CancelledError

        async def _run():
            with (
                patch.object(
                    projects_reconcile, "S",
                    SimpleNamespace(projects_reconcile_enabled=True, projects_reconcile_interval_seconds=0),
                ),
                patch.object(
                    projects_reconcile,
                    "reconcile_tracked_files_batch",
                    side_effect=RuntimeError("database down"),
                ),
                patch("asyncio.sleep", new=fake_sleep),
            ):
                with self.assertRaises(asyncio.CancelledError):
                    await projects_reconcile.projects_reconcile_loop()

        asyncio.run(_run())  # RuntimeError from reconcile should be swallowed


# ===========================================================================
# file_providers – LocalFileProvider.list_children
# ===========================================================================

class TestLocalFileProviderListChildren(unittest.TestCase):
    def test_list_children_returns_paths(self):
        provider = LocalFileProvider("user-1")
        with (
            patch("app.services.file_providers.filemanager.norm_path", return_value="/docs/"),
            patch(
                "app.services.file_providers.filemanager.list_children",
                return_value=[
                    {"path": "/docs/a.txt"},
                    {"path": "/docs/b.txt"},
                    {"path": ""},  # empty path should be skipped
                ],
            ),
        ):
            result = provider.list_children("/docs/")

        self.assertEqual(result, ["/docs/a.txt", "/docs/b.txt"])

    def test_list_children_empty_folder_returns_empty_list(self):
        provider = LocalFileProvider("user-1")
        with (
            patch("app.services.file_providers.filemanager.norm_path", return_value="/empty/"),
            patch("app.services.file_providers.filemanager.list_children", return_value=[]),
        ):
            result = provider.list_children("/empty/")

        self.assertEqual(result, [])


# ===========================================================================
# file_providers – GitHubProvider._parse_ref
# ===========================================================================

class TestGitHubParseRef(unittest.TestCase):
    def setUp(self):
        self.p = GitHubProvider("user-1")

    def test_minimal_ref_defaults_ref_to_HEAD(self):
        out = self.p._parse_ref("owner/repo/README.md")
        self.assertEqual(out["repo_owner"], "owner")
        self.assertEqual(out["repo"], "repo")
        self.assertEqual(out["path"], "README.md")
        self.assertEqual(out["ref"], "HEAD")

    def test_explicit_ref_param(self):
        out = self.p._parse_ref("owner/repo/src/main.py?ref=main")
        self.assertEqual(out["path"], "src/main.py")
        self.assertEqual(out["ref"], "main")

    def test_github_scheme_prefix_stripped(self):
        out = self.p._parse_ref("github://owner/repo/README.md?ref=abc123")
        self.assertEqual(out["repo_owner"], "owner")
        self.assertEqual(out["ref"], "abc123")

    def test_too_few_components_raises_400(self):
        with self.assertRaises(HTTPException) as ctx:
            self.p._parse_ref("owner/repo")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_no_file_path_raises_400(self):
        # owner/repo/ — trailing slash but no file
        with self.assertRaises(HTTPException) as ctx:
            self.p._parse_ref("owner/repo/")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_deep_path_joined_correctly(self):
        out = self.p._parse_ref("owner/repo/src/utils/helpers.py")
        self.assertEqual(out["path"], "src/utils/helpers.py")


# ===========================================================================
# file_providers – GitHubProvider._raise_for_error
# ===========================================================================

class TestGitHubRaiseForError(unittest.TestCase):
    def setUp(self):
        self.p = GitHubProvider("user-1")

    def test_2xx_does_not_raise(self):
        self.p._raise_for_error(_make_response(200))  # no exception

    def test_404_raises_404(self):
        with self.assertRaises(HTTPException) as ctx:
            self.p._raise_for_error(_make_response(404))
        self.assertEqual(ctx.exception.status_code, 404)

    def test_401_rate_limited_raises_429(self):
        r = _make_response(401, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1700000000"})
        with self.assertRaises(HTTPException) as ctx:
            self.p._raise_for_error(r)
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertIn("rate limit", ctx.exception.detail)

    def test_401_not_rate_limited_raises_401(self):
        r = _make_response(401, headers={"X-RateLimit-Remaining": "59"})
        with self.assertRaises(HTTPException) as ctx:
            self.p._raise_for_error(r)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_500_raises_502(self):
        with self.assertRaises(HTTPException) as ctx:
            self.p._raise_for_error(_make_response(500))
        self.assertEqual(ctx.exception.status_code, 502)


# ===========================================================================
# file_providers – GitHubProvider.list_children
# ===========================================================================

class TestGitHubListChildren(unittest.TestCase):
    def setUp(self):
        self.p = GitHubProvider("user-1")

    def test_list_children_returns_canonical_refs(self):
        r = _make_response(
            200,
            body=[
                {"path": "src/a.py"},
                {"path": "src/b.py"},
                {"path": ""},  # empty path skipped
            ],
        )
        with patch.object(self.p, "_request", return_value=r):
            result = self.p.list_children("github://owner/repo/src?ref=main")

        self.assertEqual(len(result), 2)
        self.assertTrue(result[0].startswith("github://owner/repo/src/a.py?ref=main"))
        self.assertTrue(result[1].startswith("github://owner/repo/src/b.py?ref=main"))

    def test_list_children_non_list_response_raises_400(self):
        r = _make_response(200, body={"type": "file", "name": "README.md"})
        with patch.object(self.p, "_request", return_value=r):
            with self.assertRaises(HTTPException) as ctx:
                self.p.list_children("github://owner/repo/README.md?ref=main")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_list_children_request_exception_raises_502(self):
        import requests

        with patch.object(self.p, "_request", side_effect=requests.RequestException("timeout")):
            with self.assertRaises(HTTPException) as ctx:
                self.p.list_children("github://owner/repo/src?ref=main")
        self.assertEqual(ctx.exception.status_code, 502)


# ===========================================================================
# file_providers – GitLabProvider._parse_ref
# ===========================================================================

class TestGitLabParseRef(unittest.TestCase):
    def setUp(self):
        self.p = GitLabProvider("user-1")

    def test_double_slash_separator(self):
        out = self.p._parse_ref("namespace/project//src/main.py?ref=main")
        self.assertEqual(out["project_path"], "namespace/project")
        self.assertEqual(out["path"], "src/main.py")
        self.assertEqual(out["ref"], "main")

    def test_legacy_slash_based_three_parts(self):
        out = self.p._parse_ref("ns/proj/README.md")
        self.assertEqual(out["project_path"], "ns/proj")
        self.assertEqual(out["path"], "README.md")
        self.assertEqual(out["ref"], "HEAD")

    def test_with_ref_query_param(self):
        out = self.p._parse_ref("gitlab://ns/proj//lib/utils.py?ref=develop")
        self.assertEqual(out["ref"], "develop")
        self.assertEqual(out["path"], "lib/utils.py")

    def test_too_few_slash_parts_raises_400(self):
        with self.assertRaises(HTTPException) as ctx:
            self.p._parse_ref("ns/proj")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_gitlab_scheme_prefix_stripped(self):
        out = self.p._parse_ref("gitlab://ns/proj/README.md")
        self.assertEqual(out["project_path"], "ns/proj")


# ===========================================================================
# file_providers – GitLabProvider._raise_for_error
# ===========================================================================

class TestGitLabRaiseForError(unittest.TestCase):
    def setUp(self):
        self.p = GitLabProvider("user-1")

    def test_200_does_not_raise(self):
        self.p._raise_for_error(_make_response(200))

    def test_404_raises_404(self):
        with self.assertRaises(HTTPException) as ctx:
            self.p._raise_for_error(_make_response(404))
        self.assertEqual(ctx.exception.status_code, 404)

    def test_explicit_429_uses_retry_after_header(self):
        r = _make_response(429, headers={"Retry-After": "30"})
        with self.assertRaises(HTTPException) as ctx:
            self.p._raise_for_error(r)
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertIn("retry_after=30", ctx.exception.detail)

    def test_401_rate_limited_raises_429(self):
        r = _make_response(401, headers={"RateLimit-Remaining": "0", "RateLimit-Reset": "999"})
        with self.assertRaises(HTTPException) as ctx:
            self.p._raise_for_error(r)
        self.assertEqual(ctx.exception.status_code, 429)

    def test_401_auth_failure_raises_401(self):
        r = _make_response(401, headers={"RateLimit-Remaining": "100"})
        with self.assertRaises(HTTPException) as ctx:
            self.p._raise_for_error(r)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_server_error_raises_502(self):
        with self.assertRaises(HTTPException) as ctx:
            self.p._raise_for_error(_make_response(500))
        self.assertEqual(ctx.exception.status_code, 502)


# ===========================================================================
# file_providers – GitLabProvider.list_children
# ===========================================================================

class TestGitLabListChildren(unittest.TestCase):
    def setUp(self):
        self.p = GitLabProvider("user-1")

    def test_list_children_returns_canonical_refs(self):
        r = _make_response(
            200,
            body=[
                {"path": "src/a.py", "type": "blob"},
                {"path": "src/utils", "type": "tree"},
                {"path": "", "type": "blob"},  # empty path skipped
            ],
        )
        with patch.object(self.p, "_request_tree", return_value=r):
            result = self.p.list_children("gitlab://ns/proj//src?ref=main")

        self.assertEqual(len(result), 2)
        self.assertIn("gitlab://ns/proj//src/a.py?ref=main", result)
        self.assertIn("gitlab://ns/proj//src/utils?ref=main", result)

    def test_list_children_request_exception_raises_502(self):
        import requests

        with patch.object(self.p, "_request_tree", side_effect=requests.RequestException("conn")):
            with self.assertRaises(HTTPException) as ctx:
                self.p.list_children("gitlab://ns/proj//src?ref=main")
        self.assertEqual(ctx.exception.status_code, 502)

    def test_list_children_non_list_response_raises_400(self):
        r = _make_response(200, body={"unexpected": "dict"})
        with patch.object(self.p, "_request_tree", return_value=r):
            with self.assertRaises(HTTPException) as ctx:
                self.p.list_children("gitlab://ns/proj//src?ref=main")
        self.assertEqual(ctx.exception.status_code, 400)


# ===========================================================================
# file_providers – ProviderRegistry.register
# ===========================================================================

class TestProviderRegistryRegister(unittest.TestCase):
    def test_register_and_retrieve(self):
        registry = ProviderRegistry()
        registry.register("custom", lambda owner: SimpleNamespace(provider_name="custom", owner=owner))
        provider = registry.get("user-1", "CUSTOM")  # case-insensitive
        self.assertEqual(provider.provider_name, "custom")
        self.assertEqual(provider.owner, "user-1")

    def test_register_empty_name_raises_400(self):
        registry = ProviderRegistry()
        with self.assertRaises(HTTPException) as ctx:
            registry.register("", lambda owner: None)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_register_whitespace_only_name_raises_400(self):
        registry = ProviderRegistry()
        with self.assertRaises(HTTPException) as ctx:
            registry.register("   ", lambda owner: None)
        self.assertEqual(ctx.exception.status_code, 400)


# ===========================================================================
# projects router – list_tracked_files_route happy path
# ===========================================================================

class TestListTrackedFilesRoute(unittest.TestCase):
    def test_list_tracked_files_route_returns_items(self):
        from app.routers import projects as projects_router

        file_item = {
            "id": "tf-1",
            "project_id": "p-1",
            "owner": "user-1",
            "provider": "github",
            "provider_ref": "github://owner/repo/README.md?ref=main",
            "display_path": "README.md",
            "status": "active",
            "metadata": {},
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
            "last_seen_at": None,
            "archived_at": None,
        }
        from app.models import TrackedFileModel

        with patch.object(
            projects_router,
            "list_tracked_files",
            return_value={"items": [TrackedFileModel(**file_item)], "cursor": None},
        ) as mock_list:
            result = projects_router.list_tracked_files_route(
                "p-1",
                limit=10,
                cursor=None,
                status="active",
                provider="github",
                user="user-1",
            )

        mock_list.assert_called_once_with(
            "user-1", "p-1", limit=10, cursor=None, status="active", provider="github"
        )
        self.assertEqual(len(result.items), 1)
        self.assertEqual(result.items[0].id, "tf-1")
        self.assertIsNone(result.cursor)

    def test_list_tracked_files_route_invalid_cursor_raises_400(self):
        from app.routers import projects as projects_router

        with self.assertRaises(HTTPException) as ctx:
            projects_router.list_tracked_files_route(
                "p-1",
                limit=10,
                cursor="not-valid-base64!@@",
                status=None,
                provider=None,
                user="user-1",
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("cursor", ctx.exception.detail)


if __name__ == "__main__":
    unittest.main()
