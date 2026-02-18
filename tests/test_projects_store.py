from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch
from types import SimpleNamespace

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.services import projects_store


class TestProjectsStoreService(unittest.TestCase):
    def test_create_project_normalizes_tags_and_settings(self):
        table = MagicMock()
        with patch.object(projects_store, "T", SimpleNamespace(projects=table)), patch.object(projects_store, "record_project_count_delta") as record_project_count_delta:
            out = projects_store.create_project(
                "user-1",
                " Project Alpha ",
                description="  desc  ",
                tags=["A", "a", "  B "],
                settings={"theme": "dark"},
            )

        self.assertEqual(out.name, "Project Alpha")
        self.assertEqual(out.tags, ["a", "b"])
        self.assertEqual(out.settings, {"theme": "dark"})
        table.put_item.assert_called_once()
        record_project_count_delta.assert_called_once_with(1)

    def test_create_project_invalid_payload_returns_400(self):
        table = MagicMock()
        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                projects_store.create_project("user-1", "", tags=["x"])  # invalid required name
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid project payload")

    def test_get_project_not_found_returns_404(self):
        table = MagicMock()
        table.get_item.return_value = {}
        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                projects_store.get_project("user-1", "proj-1")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_list_projects_with_filters_and_pagination(self):
        table = MagicMock()
        table.query.side_effect = [
            {
                "Items": [
                    {
                        "entity_type": "project",
                        "id": "p3",
                        "owner": "user-1",
                        "name": "Alpha Security",
                        "description": None,
                        "tags": ["security"],
                        "settings": {},
                        "created_at": "2026-01-01T00:00:00+00:00",
                        "updated_at": "2026-01-01T00:00:00+00:00",
                    },
                    {
                        "entity_type": "project",
                        "id": "p2",
                        "owner": "user-1",
                        "name": "Beta Payments",
                        "description": None,
                        "tags": ["billing"],
                        "settings": {},
                        "created_at": "2026-01-01T00:00:00+00:00",
                        "updated_at": "2026-01-01T00:00:00+00:00",
                    },
                ],
                "LastEvaluatedKey": {"PK": "OWNER#user-1", "SK": "PROJECT#p2"},
            },
            {
                "Items": [
                    {
                        "entity_type": "project",
                        "id": "p1",
                        "owner": "user-1",
                        "name": "Alpha Billing",
                        "description": None,
                        "tags": ["billing"],
                        "settings": {},
                        "created_at": "2026-01-01T00:00:00+00:00",
                        "updated_at": "2026-01-01T00:00:00+00:00",
                    }
                ],
            },
        ]
        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            out = projects_store.list_projects("user-1", limit=1, tag="billing", name_query="alpha")

        self.assertEqual(len(out["items"]), 1)
        self.assertEqual(out["items"][0].id, "p1")
        self.assertIsNone(out["cursor"])
        self.assertEqual(table.query.call_count, 2)

    def test_list_projects_invalid_limit_returns_400(self):
        with self.assertRaises(HTTPException) as ctx:
            projects_store.list_projects("user-1", limit=0)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid limit")

    def test_update_project_happy_path(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "entity_type": "project",
                "id": "p1",
                "owner": "user-1",
                "name": "Alpha",
                "description": "Old",
                "tags": ["old"],
                "settings": {"x": 1},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        }
        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            out = projects_store.update_project(
                "user-1",
                "p1",
                name=" New Name ",
                tags=["Tag", "tag"],
                settings={"x": 2},
            )

        self.assertEqual(out.name, "New Name")
        self.assertEqual(out.tags, ["tag"])
        self.assertEqual(out.settings, {"x": 2})
        table.put_item.assert_called_once()

    def test_update_project_invalid_returns_400(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "entity_type": "project",
                "id": "p1",
                "owner": "user-1",
                "name": "Alpha",
                "description": None,
                "tags": [],
                "settings": {},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        }
        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                projects_store.update_project("user-1", "p1", name="")

        self.assertEqual(ctx.exception.status_code, 400)

    def test_delete_project_updates_project_count_metric(self):
        table = MagicMock()
        with patch.object(projects_store, "T", SimpleNamespace(projects=table)), patch.object(projects_store, "record_project_count_delta") as record_project_count_delta:
            out = projects_store.delete_project("user-1", "p1")
        self.assertTrue(out["ok"])
        record_project_count_delta.assert_called_once_with(-1)

    def test_delete_project_not_found_returns_404(self):
        table = MagicMock()
        table.delete_item.side_effect = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "missing"}},
            "DeleteItem",
        )
        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                projects_store.delete_project("user-1", "p1")

        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail, "project not found")


    def test_put_tracked_file_uses_provider_for_canonicalization(self):
        table = MagicMock()
        table.query.return_value = {"Items": []}
        provider = MagicMock()
        provider.resolve.return_value = "/docs/a.txt"
        provider.exists.return_value = True
        provider.get_metadata.return_value = {"size": 100, "type": "file"}
        registry = MagicMock()
        registry.get.return_value = provider

        tracked = projects_store.TrackedFileModel(
            id="tf-1",
            project_id="p1",
            owner="user-1",
            provider="local",
            provider_ref="docs//a.txt",
            display_path="/docs/raw.txt",
            status="active",
            metadata={"custom": True},
            created_at="2026-01-01T00:00:00+00:00",
            updated_at="2026-01-01T00:00:00+00:00",
        )

        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            out = projects_store.put_tracked_file(tracked, registry=registry)

        provider.resolve.assert_called_once_with("docs//a.txt")
        provider.exists.assert_called_once_with("/docs/a.txt")
        provider.get_metadata.assert_called_once_with("/docs/a.txt")
        self.assertEqual(out.provider_ref, "/docs/a.txt")
        self.assertEqual(out.display_path, "/docs/raw.txt")
        self.assertEqual(out.metadata["size"], 100)
        self.assertTrue(out.metadata["custom"])
        table.put_item.assert_called_once()

    def test_put_tracked_file_missing_target_returns_404(self):
        table = MagicMock()
        provider = MagicMock()
        provider.resolve.return_value = "/docs/missing.txt"
        provider.exists.return_value = False
        registry = MagicMock()
        registry.get.return_value = provider

        tracked = projects_store.TrackedFileModel(
            id="tf-2",
            project_id="p1",
            owner="user-1",
            provider="local",
            provider_ref="/docs/missing.txt",
            display_path="/docs/missing.txt",
            status="active",
            metadata={},
            created_at="2026-01-01T00:00:00+00:00",
            updated_at="2026-01-01T00:00:00+00:00",
        )

        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                projects_store.put_tracked_file(tracked, registry=registry)

        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail, "tracked file target not found")
        table.put_item.assert_not_called()


    def test_add_tracked_file_enforces_project_scope(self):
        table = MagicMock()
        table.get_item.return_value = {}
        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                projects_store.add_tracked_file(
                    "user-1",
                    "p1",
                    provider="local",
                    provider_ref="/docs/a.txt",
                )
        self.assertEqual(ctx.exception.status_code, 404)

    def test_list_tracked_files_filters_owner_and_provider(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "entity_type": "project",
                "id": "p1",
                "owner": "user-1",
                "name": "Alpha",
                "description": None,
                "tags": [],
                "settings": {},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        }
        table.query.return_value = {
            "Items": [
                {
                    "entity_type": "tracked_file",
                    "id": "tf-1",
                    "project_id": "p1",
                    "owner": "user-1",
                    "provider": "local",
                    "provider_ref": "/docs/a.txt",
                    "display_path": "/docs/a.txt",
                    "status": "active",
                    "metadata": {},
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                },
                {
                    "entity_type": "tracked_file",
                    "id": "tf-2",
                    "project_id": "p1",
                    "owner": "user-2",
                    "provider": "local",
                    "provider_ref": "/docs/b.txt",
                    "display_path": "/docs/b.txt",
                    "status": "active",
                    "metadata": {},
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                },
            ]
        }
        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            out = projects_store.list_tracked_files("user-1", "p1", provider="local")
        self.assertEqual(len(out["items"]), 1)
        self.assertEqual(out["items"][0].id, "tf-1")

    def test_add_and_list_github_tracked_file(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "entity_type": "project",
                "id": "p1",
                "owner": "user-1",
                "name": "Alpha",
                "description": None,
                "tags": [],
                "settings": {},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        }
        provider = MagicMock()
        provider.resolve.return_value = "github://octocat/hello-world/README.md?ref=main"
        provider.exists.return_value = True
        provider.get_metadata.return_value = {"type": "file", "size": 10}
        registry = MagicMock()
        registry.get.return_value = provider

        # uniqueness query for add, then list query
        table.query.side_effect = [
            {"Items": []},
            {
                "Items": [
                    {
                        "entity_type": "tracked_file",
                        "id": "tf-1",
                        "project_id": "p1",
                        "owner": "user-1",
                        "provider": "github",
                        "provider_ref": "github://octocat/hello-world/README.md?ref=main",
                        "display_path": "github://octocat/hello-world/README.md?ref=main",
                        "status": "active",
                        "metadata": {"type": "file", "size": 10},
                        "created_at": "2026-01-01T00:00:00+00:00",
                        "updated_at": "2026-01-01T00:00:00+00:00",
                    }
                ]
            },
        ]

        with (
            patch.object(projects_store, "T", SimpleNamespace(projects=table)),
            patch.object(projects_store, "record_tracked_file_count_delta"),
            patch.object(projects_store, "emit_project_event"),
        ):
            projects_store.add_tracked_file(
                "user-1",
                "p1",
                provider="github",
                provider_ref="octocat/hello-world/README.md?ref=main",
                registry=registry,
            )
            out = projects_store.list_tracked_files("user-1", "p1", provider="github")

        self.assertEqual(len(out["items"]), 1)
        self.assertEqual(out["items"][0].provider, "github")

    def test_add_and_list_gitlab_tracked_file(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "entity_type": "project",
                "id": "p1",
                "owner": "user-1",
                "name": "Alpha",
                "description": None,
                "tags": [],
                "settings": {},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        }
        provider = MagicMock()
        provider.resolve.return_value = "gitlab://group/project//README.md?ref=main"
        provider.exists.return_value = True
        provider.get_metadata.return_value = {"type": "file", "size": 12}
        registry = MagicMock()
        registry.get.return_value = provider

        table.query.side_effect = [
            {"Items": []},
            {
                "Items": [
                    {
                        "entity_type": "tracked_file",
                        "id": "tf-2",
                        "project_id": "p1",
                        "owner": "user-1",
                        "provider": "gitlab",
                        "provider_ref": "gitlab://group/project//README.md?ref=main",
                        "display_path": "gitlab://group/project//README.md?ref=main",
                        "status": "active",
                        "metadata": {"type": "file", "size": 12},
                        "created_at": "2026-01-01T00:00:00+00:00",
                        "updated_at": "2026-01-01T00:00:00+00:00",
                    }
                ]
            },
        ]

        with (
            patch.object(projects_store, "T", SimpleNamespace(projects=table)),
            patch.object(projects_store, "record_tracked_file_count_delta"),
            patch.object(projects_store, "emit_project_event"),
        ):
            projects_store.add_tracked_file(
                "user-1",
                "p1",
                provider="gitlab",
                provider_ref="group/project//README.md?ref=main",
                registry=registry,
            )
            out = projects_store.list_tracked_files("user-1", "p1", provider="gitlab")

        self.assertEqual(len(out["items"]), 1)
        self.assertEqual(out["items"][0].provider, "gitlab")

    def test_remove_tracked_file_is_idempotent(self):
        table = MagicMock()
        table.get_item.side_effect = [
            {
                "Item": {
                    "entity_type": "project",
                    "id": "p1",
                    "owner": "user-1",
                    "name": "Alpha",
                    "description": None,
                    "tags": [],
                    "settings": {},
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                }
            },
            {},
        ]
        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            out = projects_store.remove_tracked_file("user-1", "p1", "missing")
        self.assertTrue(out["ok"])
        self.assertFalse(out["deleted"])
        table.put_item.assert_not_called()

    def test_add_tracked_file_emits_file_added_event(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "entity_type": "project",
                "id": "p1",
                "owner": "user-1",
                "name": "Alpha",
                "description": None,
                "tags": [],
                "settings": {},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        }
        table.query.return_value = {"Items": []}
        provider = MagicMock()
        provider.resolve.return_value = "/docs/a.txt"
        provider.exists.return_value = True
        provider.get_metadata.return_value = {"size": 3}
        registry = MagicMock()
        registry.get.return_value = provider

        with patch.object(projects_store, "T", SimpleNamespace(projects=table)), patch.object(projects_store, "record_tracked_file_count_delta") as record_tracked_file_count_delta:
            projects_store.add_tracked_file(
                "user-1",
                "p1",
                provider="local",
                provider_ref="/docs/a.txt",
                registry=registry,
            )

        self.assertGreaterEqual(table.put_item.call_count, 2)
        event_item = table.put_item.call_args_list[1].kwargs["Item"]
        self.assertEqual(event_item["entity_type"], "project_event")
        self.assertEqual(event_item["event_type"], "file_added")
        record_tracked_file_count_delta.assert_called_once_with(1)

    def test_remove_tracked_file_emits_file_removed_event(self):
        table = MagicMock()
        table.get_item.side_effect = [
            {
                "Item": {
                    "entity_type": "project",
                    "id": "p1",
                    "owner": "user-1",
                    "name": "Alpha",
                    "description": None,
                    "tags": [],
                    "settings": {},
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                }
            },
            {
                "Item": {
                    "entity_type": "tracked_file",
                    "id": "tf-1",
                    "project_id": "p1",
                    "owner": "user-1",
                    "provider": "local",
                    "provider_ref": "/docs/a.txt",
                    "display_path": "/docs/a.txt",
                    "status": "active",
                    "metadata": {},
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                }
            },
        ]

        with patch.object(projects_store, "T", SimpleNamespace(projects=table)), patch.object(projects_store, "record_tracked_file_count_delta") as record_tracked_file_count_delta:
            out = projects_store.remove_tracked_file("user-1", "p1", "tf-1")

        self.assertTrue(out["deleted"])
        self.assertGreaterEqual(table.put_item.call_count, 2)
        event_item = table.put_item.call_args_list[1].kwargs["Item"]
        self.assertEqual(event_item["entity_type"], "project_event")
        self.assertEqual(event_item["event_type"], "file_removed")
        record_tracked_file_count_delta.assert_called_once_with(-1)

    def test_list_project_events_paginates(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "entity_type": "project",
                "id": "p1",
                "owner": "user-1",
                "name": "Alpha",
                "description": None,
                "tags": [],
                "settings": {},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        }
        table.query.return_value = {
            "Items": [
                {
                    "entity_type": "project_event",
                    "id": "e1",
                    "project_id": "p1",
                    "owner": "user-1",
                    "event_type": "sync_ran",
                    "metadata": {"status": "active"},
                    "created_at": "2026-01-02T00:00:00+00:00",
                }
            ],
            "LastEvaluatedKey": {"PK": "PROJECT#p1", "SK": "EVENT#x"},
        }

        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            out = projects_store.list_project_events("user-1", "p1", limit=10)

        self.assertEqual(len(out["items"]), 1)
        self.assertEqual(out["items"][0].event_type, "sync_ran")
        self.assertEqual(out["cursor"], {"PK": "PROJECT#p1", "SK": "EVENT#x"})


    def test_get_project_detail_hydrates_metadata_and_missing_fallback(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "entity_type": "project",
                "id": "p1",
                "owner": "user-1",
                "name": "Alpha",
                "description": None,
                "tags": [],
                "settings": {},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        }
        table.query.return_value = {
            "Items": [
                {
                    "entity_type": "tracked_file",
                    "id": "tf-1",
                    "project_id": "p1",
                    "owner": "user-1",
                    "provider": "local",
                    "provider_ref": "docs//a.txt",
                    "display_path": "/docs/a.txt",
                    "status": "active",
                    "metadata": {"custom": True},
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                    "last_seen_at": "2026-01-01T00:00:00+00:00",
                },
                {
                    "entity_type": "tracked_file",
                    "id": "tf-2",
                    "project_id": "p1",
                    "owner": "user-1",
                    "provider": "local",
                    "provider_ref": "/docs/missing.txt",
                    "display_path": "/docs/missing.txt",
                    "status": "active",
                    "metadata": {"saved": 1},
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                    "last_seen_at": "2026-01-01T00:00:00+00:00",
                },
            ]
        }
        provider = MagicMock()
        provider.resolve.side_effect = ["/docs/a.txt", "/docs/missing.txt"]
        provider.exists.side_effect = [True, False]
        provider.get_metadata.return_value = {"size": 9, "type": "file"}
        registry = MagicMock()
        registry.get.return_value = provider

        with patch.object(projects_store, "T", SimpleNamespace(projects=table)):
            out = projects_store.get_project_detail("user-1", "p1", registry=registry)

        self.assertEqual(out["project"].id, "p1")
        self.assertEqual(len(out["files"]), 2)
        self.assertEqual(out["files"][0]["provider_ref"], "/docs/a.txt")
        self.assertEqual(out["files"][0]["metadata"]["size"], 9)
        self.assertEqual(out["files"][1]["status"], "missing")
        self.assertEqual(out["files"][1]["metadata"]["saved"], 1)


if __name__ == "__main__":
    unittest.main()
