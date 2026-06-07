"""GAP-0099 regression: agent-doc source hash must depend on file CONTENT.

Before the fix, ``_compute_source_hash`` derived a token purely from the path
string, so freshness/staleness detection could never fire — changing a doc's
source content left the hash (and therefore ``check_freshness``) unchanged.

These tests are fully offline (no real AWS): they exercise the dev-mode content
hashing branch directly and drive ``check_freshness`` against a fake DynamoDB
table object, so they pass without a stack or moto.
"""

from __future__ import annotations

import json
import types

import pytest

from app.services import agent_docs as svc


def _dev_mode(monkeypatch, enabled: bool = True) -> None:
    monkeypatch.setattr(svc, "S", types.SimpleNamespace(dev_mode=enabled), raising=False)


def test_dev_mode_hash_depends_on_content(tmp_path, monkeypatch):
    """FAILS before fix: hash was path-only, identical regardless of content."""
    _dev_mode(monkeypatch, True)
    src = tmp_path / "src.py"

    rel = src.relative_to(tmp_path)  # keep it a valid relative path for validate_path
    monkeypatch.chdir(tmp_path)

    src.write_text("x = 1\n")
    h1 = svc._compute_source_hash(str(rel))
    src.write_text("x = 2\n")
    h2 = svc._compute_source_hash(str(rel))

    assert h1 != h2, "Different file contents must produce different hashes in dev mode"
    assert h1.startswith("d_"), "Dev-mode content hash must use the d_ prefix"


def test_prod_mode_falls_back_to_path_stub(tmp_path, monkeypatch):
    """Outside dev mode the backend never touches the filesystem (path stub)."""
    _dev_mode(monkeypatch, False)
    src = tmp_path / "src.py"
    monkeypatch.chdir(tmp_path)
    rel = str(src.relative_to(tmp_path))

    src.write_text("a = 1\n")
    h1 = svc._compute_source_hash(rel)
    src.write_text("a = 2\n")
    h2 = svc._compute_source_hash(rel)

    assert h1 == h2, "Prod path-stub hash is content-independent and stable"
    assert h1.startswith("h_")


class _FakeTable:
    """Minimal DynamoDB table double capturing update_item calls."""

    def __init__(self, items):
        self._items = items
        self.updates = []

    def query(self, **kwargs):
        return {"Items": self._items}

    def update_item(self, **kwargs):
        self.updates.append(kwargs)
        return {}


def _make_doc_item(doc_path, refs, stored_hashes):
    return {
        "pk": svc._user_pk("u1"),
        "sk": svc._doc_sk(doc_path),
        "doc_path": doc_path,
        "doc_type": "api",
        "source_refs": json.dumps(refs),
        "source_hashes": json.dumps(stored_hashes),
        "is_stale": False,
    }


def test_check_freshness_detects_content_change(tmp_path, monkeypatch):
    """FAILS before fix: changed content was never detected as stale.

    Register-time hash is taken from the original content; after the content
    changes, ``check_freshness`` recomputes the content hash and must flag the
    doc stale.
    """
    _dev_mode(monkeypatch, True)
    monkeypatch.setattr(svc, "ensure_tables", lambda: None)

    src = tmp_path / "billing.py"
    monkeypatch.chdir(tmp_path)
    rel = str(src.relative_to(tmp_path))

    # Original content -> the hash that would have been stored at registration.
    src.write_text("def fee(): return 1\n")
    stored = svc.compute_source_hashes([rel])

    item = _make_doc_item(rel, [rel], stored)
    fake = _FakeTable([item])
    monkeypatch.setattr(svc, "T", types.SimpleNamespace(agent_doc_coverage=fake), raising=False)

    # Source content changes after registration.
    src.write_text("def fee(): return 999\n")

    result = svc.check_freshness(user_id="u1")

    assert result["stale"] == 1, "Doc whose source content changed must be stale"
    assert result["fresh"] == 0
    assert result["stale_docs"][0]["doc_path"] == rel
    assert rel in result["stale_docs"][0]["changed_sources"]


def test_check_freshness_unchanged_content_stays_fresh(tmp_path, monkeypatch):
    """Unchanged content must remain fresh (no false positives)."""
    _dev_mode(monkeypatch, True)
    monkeypatch.setattr(svc, "ensure_tables", lambda: None)

    src = tmp_path / "models.py"
    monkeypatch.chdir(tmp_path)
    rel = str(src.relative_to(tmp_path))

    src.write_text("schema = 1\n")
    stored = svc.compute_source_hashes([rel])

    item = _make_doc_item(rel, [rel], stored)
    fake = _FakeTable([item])
    monkeypatch.setattr(svc, "T", types.SimpleNamespace(agent_doc_coverage=fake), raising=False)

    result = svc.check_freshness(user_id="u1")

    assert result["fresh"] == 1
    assert result["stale"] == 0
