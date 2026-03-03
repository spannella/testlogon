from __future__ import annotations

from copy import deepcopy

from fastapi.testclient import TestClient

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role
from app.main import create_app
from app.routers import questionnaires
from app.services.sessions import require_ui_session


class _FakeTable:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict] = {}

    def reset(self) -> None:
        self.items.clear()

    def put_item(self, *, Item):
        self.items[(Item["pk"], Item["sk"])] = deepcopy(Item)

    def get_item(self, *, Key):
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": deepcopy(item)} if item else {}

    def update_item(self, *, Key, UpdateExpression, ExpressionAttributeValues, ExpressionAttributeNames=None, ConditionExpression=None):
        item = self.items[(Key["pk"], Key["sk"])]
        names = ExpressionAttributeNames or {}
        assignments = UpdateExpression.replace("SET", "", 1).strip().split(",")
        for assignment in assignments:
            left, right = assignment.strip().split("=", 1)
            left = left.strip()
            right = right.strip()
            attr = names.get(left, left)
            item[attr] = ExpressionAttributeValues[right]
        self.items[(Key["pk"], Key["sk"])] = item

    def query(self, **kwargs):
        vals = kwargs.get("ExpressionAttributeValues", {})
        index_name = kwargs.get("IndexName", "")
        pk = vals.get(":pk")
        limit = kwargs.get("Limit", 25)
        rows = []
        if "begins_with(sk" in (kwargs.get("KeyConditionExpression") or ""):
            prefix = vals.get(":sk_prefix", "")
            for item in self.items.values():
                if item.get("pk") == pk and item.get("sk", "").startswith(prefix):
                    rows.append(deepcopy(item))
            rows.sort(key=lambda r: r.get("sk", ""))
            return {"Items": rows}
        for item in self.items.values():
            if index_name.endswith("owner-updated-index") and item.get("gsi_owner_pk") == pk:
                rows.append(deepcopy(item))
            if ("published" in index_name) and item.get("gsi_published_pk") == pk:
                rows.append(deepcopy(item))
            if ("response" in index_name) and item.get("gsi_response_status_pk") == pk:
                rows.append(deepcopy(item))
        rows.sort(key=lambda r: r.get("sk", ""), reverse=not kwargs.get("ScanIndexForward", True))
        return {"Items": rows[:limit]}


_FAKE_TABLE = _FakeTable()
questionnaires.REPO._table = _FAKE_TABLE


def _build_client(user_sub: str) -> TestClient:
    app = create_app()

    async def _auth_override():
        return AuthenticatedUser(sub=user_sub, role=Role.USER)

    async def _session_override():
        return {"user_sub": user_sub, "session_id": "sess_1", "role": Role.USER.value}

    app.dependency_overrides[get_authenticated_user] = _auth_override
    app.dependency_overrides[require_ui_session] = _session_override
    return TestClient(app)


def _build_anon_client() -> TestClient:
    app = create_app()
    return TestClient(app)


def setup_function():
    _FAKE_TABLE.reset()


def test_e2e_core_workflow_draft_to_pdf_download() -> None:
    owner = _build_client("creator-1")

    created = owner.post(
        "/questionnaires/drafts",
        json={"questionnaire_id": "q_e2e", "title": "E2E Survey", "description": "flow", "visibility": "public"},
    )
    assert created.status_code == 200

    owner.post("/questionnaires/drafts/q_e2e/sections", json={"section_id": "s1", "title": "Intro"})
    owner.post("/questionnaires/drafts/q_e2e/questions", json={"section_id": "s1", "question_id": "q1", "type": "text", "label": "Name", "required": True, "config_json": {}})

    published = owner.post("/questionnaires/drafts/q_e2e/publish", json={"published_slug": "e2e-survey"})
    assert published.status_code == 200
    assert published.json()["version"]["version_number"] == 1

    anon = _build_anon_client()
    start = anon.post("/questionnaires/published/e2e-survey/sessions", json={})
    assert start.status_code == 200
    session_id = start.json()["session"]["response_session_id"]

    saved = anon.put(
        f"/questionnaires/published/e2e-survey/sessions/{session_id}",
        json={"answers_by_question_id": {"q1": "Ada"}, "current_section_index": 0, "current_question_id": "q1"},
    )
    assert saved.status_code == 200

    validated = anon.post(
        f"/questionnaires/published/e2e-survey/sessions/{session_id}/validate",
        json={"answers_by_question_id": {"q1": "Ada"}, "final_submit": False},
    )
    assert validated.status_code == 200
    assert validated.json()["can_submit"] is True

    submitted = anon.post(
        f"/questionnaires/published/e2e-survey/sessions/{session_id}/submit",
        json={"answers_by_question_id": {"q1": "Ada"}, "final_submit": True},
    )
    assert submitted.status_code == 200
    assert submitted.json()["session"]["status"] == "submitted"
    assert submitted.json()["session"]["submitted_at"] is not None

    generated_pdf = anon.post(f"/questionnaires/published/e2e-survey/sessions/{session_id}/pdf")
    assert generated_pdf.status_code == 200
    assert generated_pdf.json()["artifact"]["size_bytes"] > 0

    downloaded_pdf = anon.get(f"/questionnaires/published/e2e-survey/sessions/{session_id}/pdf")
    assert downloaded_pdf.status_code == 200
    assert downloaded_pdf.headers["content-type"].startswith("application/pdf")
    assert downloaded_pdf.content.startswith(b"%PDF")


def test_regression_session_uses_original_version_after_republish() -> None:
    owner = _build_client("creator-1")
    owner.post("/questionnaires/drafts", json={"questionnaire_id": "q_immutable", "title": "Immutable", "description": "d", "visibility": "public"})
    owner.post("/questionnaires/drafts/q_immutable/sections", json={"section_id": "s1", "title": "S1"})
    owner.post("/questionnaires/drafts/q_immutable/questions", json={"section_id": "s1", "question_id": "q1", "type": "text", "label": "L1", "required": True, "config_json": {}})
    first_pub = owner.post("/questionnaires/drafts/q_immutable/publish", json={"published_slug": "immutable-survey"})
    first_version_id = first_pub.json()["version"]["version_id"]

    anon = _build_anon_client()
    started = anon.post("/questionnaires/published/immutable-survey/sessions", json={})
    session_id = started.json()["session"]["response_session_id"]

    _FAKE_TABLE.items[("QNR#q_immutable", "META")]["status"] = "draft"
    owner.post("/questionnaires/drafts/q_immutable/questions", json={"section_id": "s1", "question_id": "q2", "type": "text", "label": "L2", "required": True, "config_json": {}})
    second_pub = owner.post("/questionnaires/drafts/q_immutable/publish", json={"published_slug": "immutable-survey"})
    assert second_pub.json()["version"]["version_id"] != first_version_id

    saved = anon.put(
        f"/questionnaires/published/immutable-survey/sessions/{session_id}",
        json={"answers_by_question_id": {"q1": "only-v1-answer"}, "current_section_index": 0, "current_question_id": "q1"},
    )
    assert saved.status_code == 200

    submit_v1 = anon.post(
        f"/questionnaires/published/immutable-survey/sessions/{session_id}/submit",
        json={"answers_by_question_id": {"q1": "only-v1-answer"}, "final_submit": True},
    )
    assert submit_v1.status_code == 200
    assert submit_v1.json()["session"]["version_id"] == first_version_id
