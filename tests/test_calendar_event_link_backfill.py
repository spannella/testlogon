from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace


def _load_module():
    path = Path("scripts/migrations/20260407_calendar_event_link_backfill.py")
    spec = importlib.util.spec_from_file_location("calendar_backfill", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeTable:
    def __init__(self, items: list[dict]):
        self.items = [dict(it) for it in items]

    def scan(self):
        return {"Items": [dict(it) for it in self.items]}

    def get_item(self, *, Key):
        for row in self.items:
            if all(row.get(k) == v for k, v in Key.items()):
                return {"Item": dict(row)}
        return {}

    def put_item(self, *, Item):
        self.items.append(dict(Item))


class _FakeDdb:
    def __init__(self, calendar_items: list[dict], link_items: list[dict]):
        self.calendar_table = _FakeTable(calendar_items)
        self.links_table = _FakeTable(link_items)

    def Table(self, name: str):
        if name == "calendar":
            return self.calendar_table
        if name == "external_event_links":
            return self.links_table
        raise KeyError(name)


def test_backfill_dry_run_reports_changed_and_skipped():
    mod = _load_module()
    fake_ddb = _FakeDdb(
        calendar_items=[
            {"internal_event_id": "evt-1", "user_sub": "user-1", "external_calendar_id": "work", "remote_uid": "uid-1"},
            {"internal_event_id": "evt-2", "user_sub": "user-1", "external_calendar_id": "work"},
        ],
        link_items=[],
    )
    settings = SimpleNamespace(calendar_table_name="calendar", external_event_links_table_name="external_event_links")

    out = mod.run_backfill(apply=False, user_sub="user-1", ddb_resource=fake_ddb, settings=settings)

    assert out["mode"] == "dry_run"
    assert out["changed"] == 1
    assert out["skipped"] == 1
    assert out["errors"] == 0
    assert len(fake_ddb.links_table.items) == 0


def test_backfill_apply_writes_link_and_is_repeatable():
    mod = _load_module()
    fake_ddb = _FakeDdb(
        calendar_items=[
            {"internal_event_id": "evt-1", "user_sub": "user-1", "external_calendar_id": "work", "remote_uid": "uid-1"},
        ],
        link_items=[],
    )
    settings = SimpleNamespace(calendar_table_name="calendar", external_event_links_table_name="external_event_links")

    first = mod.run_backfill(apply=True, user_sub="user-1", ddb_resource=fake_ddb, settings=settings)
    second = mod.run_backfill(apply=True, user_sub="user-1", ddb_resource=fake_ddb, settings=settings)

    assert first["changed"] == 1
    assert second["changed"] == 0
    assert second["reasons"]["existing_link"] == 1
    assert len(fake_ddb.links_table.items) == 1
