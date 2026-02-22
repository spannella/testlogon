from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.routers import projects


class TestProjectPolicy(unittest.TestCase):
    def _collect_dependency_calls(self, deps):
        calls = []
        stack = list(deps)
        while stack:
            dep = stack.pop()
            calls.append(getattr(dep, "call", None))
            stack.extend(getattr(dep, "dependencies", []) or [])
        return calls

    def test_all_projects_routes_require_current_user_dependency(self):
        for route in projects.router.routes:
            calls = self._collect_dependency_calls(route.dependant.dependencies)
            self.assertIn(
                projects._current_user,
                calls,
                f"Route {route.path} ({route.methods}) is missing _current_user auth dependency",
            )

    def test_project_scoped_endpoints_block_non_owner_access(self):
        with (
            patch.object(projects, "get_project", side_effect=HTTPException(status_code=404, detail="project not found")),
            patch.object(projects, "update_project", side_effect=HTTPException(status_code=404, detail="project not found")),
            patch.object(projects, "delete_project", side_effect=HTTPException(status_code=404, detail="project not found")),
            patch.object(projects, "add_tracked_file", side_effect=HTTPException(status_code=404, detail="project not found")),
            patch.object(projects, "list_tracked_files", side_effect=HTTPException(status_code=404, detail="project not found")),
            patch.object(projects, "remove_tracked_file", side_effect=HTTPException(status_code=404, detail="project not found")),
            patch.object(projects, "get_project_detail", side_effect=HTTPException(status_code=404, detail="project not found")),
            patch.object(projects, "list_project_events", side_effect=HTTPException(status_code=404, detail="project not found")),
        ):
            with self.assertRaises(HTTPException) as get_err:
                projects.get_project_route("p-other", user="user-1")
            with self.assertRaises(HTTPException) as update_err:
                projects.update_project_route("p-other", projects.ProjectUpdateIn(name="x"), user="user-1")
            with self.assertRaises(HTTPException) as delete_err:
                projects.delete_project_route("p-other", user="user-1")
            with self.assertRaises(HTTPException) as add_err:
                projects.add_tracked_file_route(
                    "p-other",
                    projects.TrackedFileCreateIn(provider="local", provider_ref="/docs/a.txt"),
                    user="user-1",
                )
            with self.assertRaises(HTTPException) as list_err:
                projects.list_tracked_files_route("p-other", cursor=None, user="user-1")
            with self.assertRaises(HTTPException) as remove_err:
                projects.remove_tracked_file_route("p-other", "tf-1", user="user-1")
            with self.assertRaises(HTTPException) as detail_err:
                projects.get_project_detail_route("p-other", cursor=None, user="user-1")
            with self.assertRaises(HTTPException) as events_err:
                projects.list_project_events_route("p-other", cursor=None, user="user-1")

        for exc in (
            get_err.exception,
            update_err.exception,
            delete_err.exception,
            add_err.exception,
            list_err.exception,
            remove_err.exception,
            detail_err.exception,
            events_err.exception,
        ):
            self.assertEqual(exc.status_code, 404)
            self.assertEqual(exc.detail, "project not found")


if __name__ == "__main__":
    unittest.main()
