from __future__ import annotations

import unittest
from datetime import datetime, timezone

from pydantic import ValidationError

from app.models import ProjectModel, TrackedFileModel
from app.services.projects_store import (
    project_from_item,
    project_to_item,
    tracked_file_from_item,
    tracked_file_to_item,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class TestProjectModel(unittest.TestCase):
    def test_project_model_normalizes_tags_and_serializes(self):
        ts = _now_iso()
        model = ProjectModel(
            id="proj-1",
            owner="user-1",
            name=" Project One ",
            description="  A sample project  ",
            tags=["Tag", "tag", "  analytics ", ""],
            settings={"theme": "dark"},
            created_at=ts,
            updated_at=ts,
        )

        self.assertEqual(model.tags, ["tag", "analytics"])
        self.assertEqual(model.description, "A sample project")

        item = project_to_item(model)
        roundtrip = project_from_item(item)
        self.assertEqual(roundtrip.model_dump(), model.model_dump())

    def test_project_model_requires_tz_aware_iso_timestamps(self):
        with self.assertRaises(ValidationError):
            ProjectModel(
                id="proj-1",
                owner="user-1",
                name="Project",
                created_at="2026-01-01T00:00:00",
                updated_at="2026-01-01T00:00:00",
            )


class TestTrackedFileModel(unittest.TestCase):
    def test_tracked_file_model_serialization(self):
        ts = _now_iso()
        model = TrackedFileModel(
            id="tf-1",
            project_id="proj-1",
            owner="user-1",
            provider="LOCAL",
            provider_ref="  /docs/a.txt ",
            display_path="/docs/a.txt",
            status="active",
            metadata={"size": 42},
            created_at=ts,
            updated_at=ts,
            last_seen_at=ts,
        )

        self.assertEqual(model.provider, "local")
        self.assertEqual(model.provider_ref, "/docs/a.txt")

        item = tracked_file_to_item(model)
        self.assertEqual(item["GSI1SK"], "PROVIDER_REF#local#/docs/a.txt")
        roundtrip = tracked_file_from_item(item)
        self.assertEqual(roundtrip.model_dump(), model.model_dump())

    def test_tracked_file_archived_status_sets_archived_at(self):
        ts = _now_iso()
        model = TrackedFileModel(
            id="tf-2",
            project_id="proj-1",
            owner="user-1",
            provider="local",
            provider_ref="/docs/b.txt",
            display_path="/docs/b.txt",
            status="archived",
            metadata={},
            created_at=ts,
            updated_at=ts,
        )
        self.assertIsNotNone(model.archived_at)

    def test_tracked_file_rejects_invalid_provider(self):
        ts = _now_iso()
        with self.assertRaises(ValidationError):
            TrackedFileModel(
                id="tf-3",
                project_id="proj-1",
                owner="user-1",
                provider="Bad Provider!",
                provider_ref="/docs/c.txt",
                display_path="/docs/c.txt",
                status="active",
                metadata={},
                created_at=ts,
                updated_at=ts,
            )


if __name__ == "__main__":
    unittest.main()
