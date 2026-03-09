from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.main import create_app
from app.routers import projects


def _ctx(user: str = "user-1"):
    return {"user_sub": user, "session_id": "sid"}


class TestProjectRoutes(unittest.TestCase):
    def test_create_project_route(self):
        body = projects.ProjectCreateIn(name="Project A", tags=["One"], settings={"x": 1})
        project = SimpleNamespace(
            model_dump=lambda: {
                "id": "p1",
                "owner": "user-1",
                "name": "Project A",
                "description": None,
                "tags": ["one"],
                "settings": {"x": 1},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        )
        with patch.object(projects, "create_project", return_value=project) as create_project:
            out = projects.create_project_route(body, user="user-1")
        create_project.assert_called_once_with("user-1", "Project A", description=None, tags=["One"], settings={"x": 1})
        self.assertEqual(out.id, "p1")

    def test_get_project_route_not_found(self):
        with patch.object(projects, "get_project", side_effect=HTTPException(status_code=404, detail="project not found")):
            with self.assertRaises(HTTPException) as ctx:
                projects.get_project_route("missing", user="user-1")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_list_projects_route_cursor_and_filters(self):
        item = SimpleNamespace(
            model_dump=lambda: {
                "id": "p1",
                "owner": "user-1",
                "name": "Alpha",
                "description": None,
                "tags": ["billing"],
                "settings": {},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        )
        with patch.object(projects, "list_projects", return_value={"items": [item], "cursor": {"PK": "OWNER#user-1"}}) as list_projects:
            out = projects.list_projects_route(limit=10, cursor=None, tag="billing", name_query="alp", user="user-1")
        list_projects.assert_called_once_with("user-1", limit=10, cursor=None, tag="billing", name_query="alp")
        self.assertEqual(len(out.items), 1)
        self.assertIsNotNone(out.cursor)

    def test_list_projects_route_invalid_cursor(self):
        with self.assertRaises(HTTPException) as ctx:
            projects.list_projects_route(limit=10, cursor="not-base64", user="user-1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid cursor")

    def test_update_project_route(self):
        body = projects.ProjectUpdateIn(name="New")
        project = SimpleNamespace(
            model_dump=lambda: {
                "id": "p1",
                "owner": "user-1",
                "name": "New",
                "description": None,
                "tags": [],
                "settings": {},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-02T00:00:00+00:00",
            }
        )
        with patch.object(projects, "update_project", return_value=project) as update_project:
            out = projects.update_project_route("p1", body, user="user-1")
        update_project.assert_called_once_with("user-1", "p1", name="New", description=None, tags=None, settings=None)
        self.assertEqual(out.name, "New")


    def test_add_tracked_file_route(self):
        body = projects.TrackedFileCreateIn(provider="local", provider_ref="/docs/a.txt")
        tracked = SimpleNamespace(
            model_dump=lambda: {
                "id": "tf-1",
                "project_id": "p1",
                "owner": "user-1",
                "provider": "local",
                "provider_ref": "/docs/a.txt",
                "display_path": "/docs/a.txt",
                "status": "active",
                "metadata": {"size": 1},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
                "last_seen_at": "2026-01-01T00:00:00+00:00",
                "archived_at": None,
            }
        )
        with patch.object(projects, "add_tracked_file", return_value=tracked) as add_tracked_file:
            out = projects.add_tracked_file_route("p1", body, user="user-1")
        add_tracked_file.assert_called_once_with("user-1", "p1", provider="local", provider_ref="/docs/a.txt", display_path=None, metadata={})
        self.assertEqual(out.id, "tf-1")

    def test_add_tracked_file_route_missing_file(self):
        body = projects.TrackedFileCreateIn(provider="local", provider_ref="/docs/missing.txt")
        with patch.object(projects, "add_tracked_file", side_effect=HTTPException(status_code=404, detail="tracked file target not found")):
            with self.assertRaises(HTTPException) as ctx:
                projects.add_tracked_file_route("p1", body, user="user-1")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_add_tracked_file_route_forbidden_project(self):
        body = projects.TrackedFileCreateIn(provider="local", provider_ref="/docs/a.txt")
        with patch.object(projects, "add_tracked_file", side_effect=HTTPException(status_code=404, detail="project not found")):
            with self.assertRaises(HTTPException) as ctx:
                projects.add_tracked_file_route("other-users-project", body, user="user-1")
        self.assertEqual(ctx.exception.status_code, 404)



    def test_add_tracked_file_route_duplicate_provider_ref(self):
        body = projects.TrackedFileCreateIn(provider="local", provider_ref="/docs/a.txt")
        with patch.object(projects, "add_tracked_file", side_effect=HTTPException(status_code=409, detail="tracked file already exists for provider_ref")):
            with self.assertRaises(HTTPException) as ctx:
                projects.add_tracked_file_route("p1", body, user="user-1")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_remove_tracked_file_route_idempotent(self):
        with patch.object(projects, "remove_tracked_file", return_value={"ok": True, "deleted": False}) as remove_tracked_file:
            out = projects.remove_tracked_file_route("p1", "tf-1", user="user-1")
        remove_tracked_file.assert_called_once_with("user-1", "p1", "tf-1")
        self.assertTrue(out.ok)
        self.assertFalse(out.deleted)


    def test_get_project_detail_route_returns_display_rows(self):
        result = {
            "project": SimpleNamespace(model_dump=lambda: {
                "id": "p1", "owner": "user-1", "name": "Alpha", "description": None,
                "tags": [], "settings": {}, "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00"
            }),
            "files": [
                {
                    "id": "tf-1",
                    "project_id": "p1",
                    "owner": "user-1",
                    "provider": "local",
                    "provider_ref": "/docs/a.txt",
                    "display_path": "/docs/a.txt",
                    "status": "active",
                    "metadata": {"size": 10},
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                    "last_seen_at": "2026-01-01T00:00:00+00:00",
                    "archived_at": None,
                }
            ],
            "cursor": None,
        }
        with patch.object(projects, "get_project_detail", return_value=result) as get_project_detail:
            out = projects.get_project_detail_route("p1", cursor=None, user="user-1")
        get_project_detail.assert_called_once()
        self.assertEqual(out.project.id, "p1")
        self.assertEqual(len(out.files), 1)
        self.assertEqual(out.files[0].display_path, "/docs/a.txt")

    def test_list_project_events_route(self):
        result = {
            "items": [
                SimpleNamespace(model_dump=lambda: {
                    "id": "e1",
                    "project_id": "p1",
                    "owner": "user-1",
                    "event_type": "file_added",
                    "tracked_file_id": "tf-1",
                    "provider": "local",
                    "provider_ref": "/docs/a.txt",
                    "message": None,
                    "metadata": {"display_path": "/docs/a.txt"},
                    "created_at": "2026-01-01T00:00:00+00:00",
                })
            ],
            "cursor": {"PK": "PROJECT#p1", "SK": "EVENT#x"},
        }
        with patch.object(projects, "list_project_events", return_value=result) as list_project_events:
            out = projects.list_project_events_route("p1", limit=10, cursor=None, user="user-1")
        list_project_events.assert_called_once_with("user-1", "p1", limit=10, cursor=None)
        self.assertEqual(len(out.items), 1)
        self.assertEqual(out.items[0].event_type, "file_added")
        self.assertIsNotNone(out.cursor)

    def test_upsert_provider_credential_route(self):
        body = projects.ProviderCredentialUpsertIn(
            token="token",
            required_scopes=["repo"],
            api_base_url="https://ghe.local/api/v3",
        )
        stored = SimpleNamespace(
            provider="github",
            org=None,
            scopes=["repo"],
            metadata={"login": "octocat"},
            created_at="2026-01-01T00:00:00+00:00",
            updated_at="2026-01-01T00:00:00+00:00",
        )
        with patch.object(projects, "upsert_provider_credential", return_value=stored) as upsert_provider_credential:
            out = projects.upsert_provider_credential_route("github", body, user="user-1")
        upsert_provider_credential.assert_called_once_with(
            "user-1",
            "github",
            "token",
            org=None,
            required_scopes=["repo"],
            api_base_url="https://ghe.local/api/v3",
        )
        self.assertEqual(out.provider, "github")
        self.assertEqual(out.scopes, ["repo"])

    def test_upsert_provider_credential_route_google_drive(self):
        body = projects.ProviderCredentialUpsertIn(
            token="drive-token",
        )
        stored = SimpleNamespace(
            provider="google_drive",
            org=None,
            scopes=[],
            metadata={},
            created_at="2026-01-01T00:00:00+00:00",
            updated_at="2026-01-01T00:00:00+00:00",
        )
        with patch.object(projects, "upsert_provider_credential", return_value=stored) as upsert_provider_credential:
            out = projects.upsert_provider_credential_route("google_drive", body, user="user-1")
        upsert_provider_credential.assert_called_once_with(
            "user-1",
            "google_drive",
            "drive-token",
            org=None,
            required_scopes=[],
            api_base_url=None,
        )
        self.assertEqual(out.provider, "google_drive")

    def test_complete_google_drive_oauth_callback_route(self):
        body = projects.ProviderOAuthCallbackIn(code="auth-code", state="opaque-state")
        stored = {
            "provider": "google_drive",
            "org": None,
            "scopes": ["https://www.googleapis.com/auth/drive.file"],
            "metadata": {"expires_at": "2026-01-01T00:10:00+00:00"},
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        }
        with patch.object(projects, "complete_google_oauth_callback", return_value=stored) as complete_google_oauth_callback:
            out = projects.complete_google_drive_oauth_callback_route(body, user="user-1")
        complete_google_oauth_callback.assert_called_once_with("user-1", code="auth-code", state="opaque-state")
        self.assertEqual(out.provider, "google_drive")
        self.assertIn("expires_at", out.metadata)

    def test_start_google_drive_oauth_route(self):
        payload = {
            "provider": "google_drive",
            "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?state=abc",
            "state": "abc",
            "expires_at": "2026-01-01T00:10:00+00:00",
        }
        with patch.object(projects, "build_google_oauth_start", return_value=payload) as build_google_oauth_start:
            out = projects.start_google_drive_oauth_route(user="user-1")
        build_google_oauth_start.assert_called_once_with("user-1")
        self.assertEqual(out.provider, "google_drive")
        self.assertIn("accounts.google.com", out.authorization_url)

    def test_get_provider_credential_route(self):
        stored = SimpleNamespace(
            provider="gitlab",
            org="org-1",
            scopes=["api"],
            metadata={"active": True},
            created_at="2026-01-01T00:00:00+00:00",
            updated_at="2026-01-01T00:00:00+00:00",
        )
        with patch.object(projects, "get_provider_credential", return_value=stored) as get_provider_credential:
            out = projects.get_provider_credential_route("gitlab", org="org-1", user="user-1")
        get_provider_credential.assert_called_once_with("user-1", "gitlab", org="org-1")
        self.assertEqual(out.provider, "gitlab")
        self.assertEqual(out.org, "org-1")

    def test_delete_provider_credential_route(self):
        with (
            patch.object(projects, "delete_provider_credential", return_value={"ok": True, "deleted": True}) as delete_provider_credential,
            patch.object(projects, "audit_event") as audit_event,
        ):
            out = projects.delete_provider_credential_route("github", org=None, user="user-1")
        delete_provider_credential.assert_called_once_with("user-1", "github", org=None)
        audit_event.assert_called_once_with(
            "provider_oauth_disconnect",
            "user-1",
            None,
            outcome="success",
            provider="github",
            deleted=True,
        )
        self.assertTrue(out.ok)
        self.assertTrue(out.deleted)


    def test_openapi_includes_project_crud_paths(self):
        app = create_app()
        schema = app.openapi()
        self.assertIn("/v1/projects", schema.get("paths", {}))
        self.assertIn("/v1/projects/{project_id}", schema.get("paths", {}))
        self.assertIn("/v1/projects/{project_id}/detail", schema.get("paths", {}))
        self.assertIn("/v1/projects/{project_id}/files", schema.get("paths", {}))
        self.assertIn("/v1/projects/{project_id}/files/{tracked_file_id}", schema.get("paths", {}))
        self.assertIn("/v1/projects/{project_id}/events", schema.get("paths", {}))
        self.assertIn("/v1/projects/providers/{provider}/credentials", schema.get("paths", {}))
        self.assertIn("/v1/projects/providers/google_drive/oauth/start", schema.get("paths", {}))
        self.assertIn("/v1/projects/providers/google_drive/oauth/callback", schema.get("paths", {}))

    def test_delete_project_route(self):
        with patch.object(projects, "delete_project", return_value={"ok": True}) as delete_project:
            out = projects.delete_project_route("p1", user="user-1")
        delete_project.assert_called_once_with("user-1", "p1")
        self.assertTrue(out.ok)


if __name__ == "__main__":
    unittest.main()
