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
    questionnaires.REPO._table = _FAKE_TABLE


def test_owner_can_create_read_update_archive_draft() -> None:
    client = _build_client("user-1")

    created = client.post(
        "/questionnaires/drafts",
        json={"questionnaire_id": "q_1", "title": "My Q", "description": "desc"},
    )
    assert created.status_code == 200
    assert created.json()["draft"]["owner_id"] == "user-1"
    assert created.json()["draft"]["created_by"] == "user-1"

    fetched = client.get("/questionnaires/drafts/q_1")
    assert fetched.status_code == 200
    assert fetched.json()["draft"]["title"] == "My Q"

    updated = client.patch("/questionnaires/drafts/q_1", json={"title": "My Q2"})
    assert updated.status_code == 200
    assert updated.json()["draft"]["title"] == "My Q2"
    assert updated.json()["draft"]["updated_by"] == "user-1"

    archived = client.delete("/questionnaires/drafts/q_1")
    assert archived.status_code == 200
    assert archived.json()["draft"]["status"] == "archived"
    assert archived.json()["draft"]["archived_by"] == "user-1"


def test_non_owner_gets_403_for_read_update_archive() -> None:
    owner = _build_client("owner")
    other = _build_client("other")
    owner.post("/questionnaires/drafts", json={"questionnaire_id": "q_1", "title": "Q", "description": "d"})

    denied_get = other.get("/questionnaires/drafts/q_1")
    assert denied_get.status_code == 403

    denied_patch = other.patch("/questionnaires/drafts/q_1", json={"title": "x"})
    assert denied_patch.status_code == 403

    denied_delete = other.delete("/questionnaires/drafts/q_1")
    assert denied_delete.status_code == 403


def test_archived_excluded_from_default_list() -> None:
    client = _build_client("user-1")
    client.post("/questionnaires/drafts", json={"questionnaire_id": "q_1", "title": "Q1", "description": "d"})
    client.post("/questionnaires/drafts", json={"questionnaire_id": "q_2", "title": "Q2", "description": "d"})
    client.delete("/questionnaires/drafts/q_2")

    visible = client.get("/questionnaires/drafts")
    assert visible.status_code == 200
    ids = {it["questionnaire_id"] for it in visible.json()["items"]}
    assert ids == {"q_1"}

    with_archived = client.get("/questionnaires/drafts", params={"include_archived": True})
    ids_all = {it["questionnaire_id"] for it in with_archived.json()["items"]}
    assert ids_all == {"q_1", "q_2"}


def test_section_and_question_ordering_and_schema_serialization() -> None:
    client = _build_client("user-1")
    client.post("/questionnaires/drafts", json={"questionnaire_id": "q_1", "title": "Q1", "description": "d"})

    client.post("/questionnaires/drafts/q_1/sections", json={"section_id": "s1", "title": "S1"})
    client.post("/questionnaires/drafts/q_1/sections", json={"section_id": "s2", "title": "S2"})
    reorder_sections = client.post("/questionnaires/drafts/q_1/sections/reorder", json={"section_ids": ["s2", "s1"]})
    assert reorder_sections.status_code == 200
    assert [s["section_id"] for s in reorder_sections.json()["items"]] == ["s2", "s1"]

    client.post(
        "/questionnaires/drafts/q_1/questions",
        json={"section_id": "s2", "question_id": "q1", "type": "text", "label": "L1", "config_json": {}},
    )
    client.post(
        "/questionnaires/drafts/q_1/questions",
        json={"section_id": "s2", "question_id": "q2", "type": "text", "label": "L2", "config_json": {}},
    )
    reorder_questions = client.post(
        "/questionnaires/drafts/q_1/questions/reorder",
        json={"section_id": "s2", "question_ids": ["q2", "q1"]},
    )
    assert reorder_questions.status_code == 200
    assert [q["question_id"] for q in reorder_questions.json()["items"]] == ["q2", "q1"]

    delete_q = client.delete("/questionnaires/drafts/q_1/questions/q1", params={"section_id": "s2"})
    assert delete_q.status_code == 200

    schema = client.get("/questionnaires/drafts/q_1/schema")
    assert schema.status_code == 200
    sections = schema.json()["sections"]
    assert [s["section_id"] for s in sections] == ["s2", "s1"]
    assert [q["question_id"] for q in sections[0]["questions"]] == ["q2"]


def test_invalid_question_config_returns_4xx() -> None:
    client = _build_client("user-1")
    client.post("/questionnaires/drafts", json={"questionnaire_id": "q_1", "title": "Q1", "description": "d"})
    client.post("/questionnaires/drafts/q_1/sections", json={"section_id": "s1", "title": "S1"})

    invalid = client.post(
        "/questionnaires/drafts/q_1/questions",
        json={"section_id": "s1", "question_id": "q_bad", "type": "select", "label": "Pick", "config_json": {}},
    )
    assert invalid.status_code == 422
    assert invalid.json()["detail"]["error"]["code"] == "invalid_question_config"


def test_publish_creates_new_version_and_increments() -> None:
    client = _build_client("user-1")
    client.post("/questionnaires/drafts", json={"questionnaire_id": "q_1", "title": "Q1", "description": "d"})
    client.post("/questionnaires/drafts/q_1/sections", json={"section_id": "s1", "title": "S1"})
    client.post(
        "/questionnaires/drafts/q_1/questions",
        json={"section_id": "s1", "question_id": "q1", "type": "text", "label": "L1", "config_json": {}},
    )

    pub1 = client.post("/questionnaires/drafts/q_1/publish", json={"published_slug": "my-q"})
    assert pub1.status_code == 200
    assert pub1.json()["version"]["version_number"] == 1

    patch_after_publish = client.patch("/questionnaires/drafts/q_1", json={"title": "new"})
    assert patch_after_publish.status_code == 409
    assert patch_after_publish.json()["detail"]["error"]["code"] == "questionnaire_not_draft"

    # Simulate a resumed draft by directly setting status so we can validate version incrementing behavior.
    _FAKE_TABLE.items[("QNR#q_1", "META")]["status"] = "draft"
    pub2 = client.post("/questionnaires/drafts/q_1/publish", json={"published_slug": "my-q"})
    assert pub2.status_code == 200
    assert pub2.json()["version"]["version_number"] == 2


def test_existing_response_session_remains_bound_to_prior_version() -> None:
    repo = questionnaires.REPO
    repo.put_questionnaire(questionnaire_id="q_resp", owner_id="user-1", title="Q")
    repo.create_section(questionnaire_id="q_resp", section_id="s1", title="S1", description="", actor_sub="user-1")
    repo.create_question(
        questionnaire_id="q_resp",
        section_id="s1",
        question_id="q1",
        question_type="text",
        label="L1",
        required=False,
        hint="",
        config_json={},
        actor_sub="user-1",
    )
    v1 = repo.publish_draft(questionnaire_id="q_resp", owner_id="user-1", actor_sub="user-1")
    session = repo.put_response_session(response_session_id="r1", questionnaire_id="q_resp", version_id=v1["version_id"])

    _FAKE_TABLE.items[("QNR#q_resp", "META")]["status"] = "draft"
    repo.create_question(
        questionnaire_id="q_resp",
        section_id="s1",
        question_id="q2",
        question_type="text",
        label="L2",
        required=False,
        hint="",
        config_json={},
        actor_sub="user-1",
    )
    v2 = repo.publish_draft(questionnaire_id="q_resp", owner_id="user-1", actor_sub="user-1")

    fetched = repo._table.get_item(Key={"pk": "QNR#q_resp", "sk": "RESP#r1"})["Item"]
    assert session["version_id"] == v1["version_id"]
    assert fetched["version_id"] == v1["version_id"]
    assert fetched["version_id"] != v2["version_id"]


def test_validate_endpoint_returns_form_level_errors_and_blocks_final_submit() -> None:
    client = _build_client("user-1")
    client.post("/questionnaires/drafts", json={"questionnaire_id": "q_val", "title": "Q", "description": "d"})
    client.post("/questionnaires/drafts/q_val/sections", json={"section_id": "s1", "title": "S1"})
    client.post("/questionnaires/drafts/q_val/sections", json={"section_id": "s2", "title": "S2"})
    client.post(
        "/questionnaires/drafts/q_val/questions",
        json={"section_id": "s1", "question_id": "q_trigger", "type": "text", "label": "Trigger", "config_json": {}},
    )
    client.post(
        "/questionnaires/drafts/q_val/questions",
        json={"section_id": "s2", "question_id": "q_required", "type": "text", "label": "Required", "config_json": {}},
    )

    payload = {
        "answers_by_question_id": {"q_trigger": "x"},
        "form_rules": [
            {
                "rule_id": "fr1",
                "rule_type": "requires_if_answered",
                "config_json": {"if_question_id": "q_trigger", "required_question_ids": ["q_required"]},
                "blocking": True,
            }
        ],
        "final_submit": False,
    }
    pre = client.post("/questionnaires/drafts/q_val/validate", json=payload)
    assert pre.status_code == 200
    assert pre.json()["errors"]["form:fr1"][0]["code"] == "form_dependency_required"
    assert pre.json()["can_submit"] is False

    payload["final_submit"] = True
    final = client.post("/questionnaires/drafts/q_val/validate", json=payload)
    assert final.status_code == 422
    assert final.json()["detail"]["error"]["code"] == "form_validation_failed"


def test_validate_endpoint_rejects_invalid_form_rule_references() -> None:
    client = _build_client("user-1")
    client.post("/questionnaires/drafts", json={"questionnaire_id": "q_ref", "title": "Q", "description": "d"})
    client.post("/questionnaires/drafts/q_ref/sections", json={"section_id": "s1", "title": "S1"})
    client.post(
        "/questionnaires/drafts/q_ref/questions",
        json={"section_id": "s1", "question_id": "q1", "type": "text", "label": "Q1", "config_json": {}},
    )

    res = client.post(
        "/questionnaires/drafts/q_ref/validate",
        json={
            "answers_by_question_id": {},
            "form_rules": [
                {
                    "rule_id": "fr_bad",
                    "rule_type": "mutually_exclusive",
                    "config_json": {"question_ids": ["missing_a", "missing_b"]},
                    "blocking": True,
                }
            ],
            "final_submit": False,
        },
    )
    assert res.status_code == 422
    assert res.json()["detail"]["error"]["code"] == "invalid_rule_reference"


def test_question_hint_and_placeholder_are_sanitized() -> None:
    client = _build_client("user-1")
    client.post("/questionnaires/drafts", json={"questionnaire_id": "q_san", "title": "Q", "description": "d"})
    client.post("/questionnaires/drafts/q_san/sections", json={"section_id": "s1", "title": "S1"})

    created = client.post(
        "/questionnaires/drafts/q_san/questions",
        json={
            "section_id": "s1",
            "question_id": "q1",
            "type": "text",
            "label": "Q1",
            "hint": "<b>hint</b><script>x</script>",
            "config_json": {"placeholder": "<img src=x onerror=1>name", "help_text": "<i>help</i><script>x</script>", "minLength": 0, "maxLength": 10},
        },
    )
    assert created.status_code == 200
    q = created.json()["question"]
    assert q["hint"] == "hint"
    assert q["config_json"]["placeholder"] == "name"
    assert q["config_json"]["help_text"] == "help"


def test_published_fetch_and_session_start_public_and_private_access() -> None:
    owner = _build_client("owner")

    owner.post("/questionnaires/drafts", json={"questionnaire_id": "q_pub", "title": "Q", "description": "d", "visibility": "public"})
    owner.post("/questionnaires/drafts/q_pub/sections", json={"section_id": "s1", "title": "S1"})
    owner.post("/questionnaires/drafts/q_pub/questions", json={"section_id": "s1", "question_id": "q1", "type": "text", "label": "L1", "config_json": {}})
    owner.post("/questionnaires/drafts/q_pub/publish", json={"published_slug": "pub-slug"})

    anon = _build_anon_client()
    fetched_public = anon.get("/questionnaires/published/pub-slug")
    assert fetched_public.status_code == 200
    assert fetched_public.json()["version"]["published_slug"] == "pub-slug"

    started_anon = anon.post("/questionnaires/published/pub-slug/sessions", json={})
    assert started_anon.status_code == 200
    session = started_anon.json()["session"]
    assert session["status"] == "in_progress"
    assert session["version_id"] == fetched_public.json()["version"]["version_id"]
    assert session["started_at"]

    # Private questionnaire requires authenticated access and cannot be started anonymously.
    owner.post("/questionnaires/drafts", json={"questionnaire_id": "q_priv", "title": "Q2", "description": "d", "visibility": "private"})
    owner.post("/questionnaires/drafts/q_priv/sections", json={"section_id": "s1", "title": "S1"})
    owner.post("/questionnaires/drafts/q_priv/questions", json={"section_id": "s1", "question_id": "q1", "type": "text", "label": "L1", "config_json": {}})
    owner.post("/questionnaires/drafts/q_priv/publish", json={"published_slug": "priv-slug"})

    denied_fetch = anon.get("/questionnaires/published/priv-slug")
    assert denied_fetch.status_code == 401

    denied_start = anon.post("/questionnaires/published/priv-slug/sessions", json={})
    assert denied_start.status_code == 401

    authed = _build_anon_client()
    allowed_fetch = authed.get("/questionnaires/published/priv-slug", headers={"x-user-sub": "respondent-1"})
    assert allowed_fetch.status_code == 200

    allowed_start = authed.post("/questionnaires/published/priv-slug/sessions", json={}, headers={"x-user-sub": "respondent-1"})
    assert allowed_start.status_code == 200
    assert allowed_start.json()["session"]["respondent_id"] == "respondent-1"


def test_published_fetch_by_questionnaire_id() -> None:
    owner = _build_client("owner")
    owner.post("/questionnaires/drafts", json={"questionnaire_id": "q_id", "title": "Q", "description": "d", "visibility": "public"})
    owner.post("/questionnaires/drafts/q_id/sections", json={"section_id": "s1", "title": "S1"})
    owner.post("/questionnaires/drafts/q_id/questions", json={"section_id": "s1", "question_id": "q1", "type": "text", "label": "L1", "config_json": {}})
    pub = owner.post("/questionnaires/drafts/q_id/publish", json={"published_slug": "id-slug"})
    version_id = pub.json()["version"]["version_id"]

    anon = _build_anon_client()
    by_id = anon.get("/questionnaires/published/by-id/q_id")
    assert by_id.status_code == 200
    assert by_id.json()["version"]["version_id"] == version_id


def test_session_save_and_resume_progress() -> None:
    owner = _build_client("owner")
    owner.post("/questionnaires/drafts", json={"questionnaire_id": "q_resume", "title": "Q", "description": "d", "visibility": "public"})
    owner.post("/questionnaires/drafts/q_resume/sections", json={"section_id": "s1", "title": "S1"})
    owner.post("/questionnaires/drafts/q_resume/sections", json={"section_id": "s2", "title": "S2"})
    owner.post("/questionnaires/drafts/q_resume/questions", json={"section_id": "s1", "question_id": "q1", "type": "text", "label": "L1", "config_json": {}})
    owner.post("/questionnaires/drafts/q_resume/questions", json={"section_id": "s2", "question_id": "q2", "type": "text", "label": "L2", "config_json": {}})
    owner.post("/questionnaires/drafts/q_resume/publish", json={"published_slug": "resume-slug"})

    anon = _build_anon_client()
    started = anon.post("/questionnaires/published/resume-slug/sessions", json={})
    assert started.status_code == 200
    session_id = started.json()["session"]["response_session_id"]

    saved = anon.put(
        f"/questionnaires/published/resume-slug/sessions/{session_id}",
        json={"answers_by_question_id": {"q1": "hello"}, "current_section_index": 1, "current_question_id": "q2"},
    )
    assert saved.status_code == 200
    assert saved.json()["session"]["status"] == "in_progress"

    resumed = anon.get(f"/questionnaires/published/resume-slug/sessions/{session_id}")
    assert resumed.status_code == 200
    assert resumed.json()["answers_by_question_id"]["q1"] == "hello"
    assert resumed.json()["session"]["current_section_index"] == 1
    assert resumed.json()["session"]["current_question_id"] == "q2"
    assert resumed.json()["session"]["submitted_at"] is None


def test_session_save_does_not_allow_other_user_access() -> None:
    owner = _build_client("owner")
    owner.post("/questionnaires/drafts", json={"questionnaire_id": "q_priv_resume", "title": "Q", "description": "d", "visibility": "private"})
    owner.post("/questionnaires/drafts/q_priv_resume/sections", json={"section_id": "s1", "title": "S1"})
    owner.post("/questionnaires/drafts/q_priv_resume/questions", json={"section_id": "s1", "question_id": "q1", "type": "text", "label": "L1", "config_json": {}})
    owner.post("/questionnaires/drafts/q_priv_resume/publish", json={"published_slug": "priv-resume-slug"})

    authed = _build_anon_client()
    start = authed.post("/questionnaires/published/priv-resume-slug/sessions", json={}, headers={"x-user-sub": "u1"})
    session_id = start.json()["session"]["response_session_id"]

    forbidden_get = authed.get(f"/questionnaires/published/priv-resume-slug/sessions/{session_id}", headers={"x-user-sub": "u2"})
    assert forbidden_get.status_code == 403

    forbidden_put = authed.put(
        f"/questionnaires/published/priv-resume-slug/sessions/{session_id}",
        json={"answers_by_question_id": {"q1": "x"}, "current_section_index": 0},
        headers={"x-user-sub": "u2"},
    )
    assert forbidden_put.status_code == 403


def test_response_session_validate_and_submit_flow() -> None:
    owner = _build_client("owner")
    owner.post("/questionnaires/drafts", json={"questionnaire_id": "q_submit", "title": "Q", "description": "d", "visibility": "public"})
    owner.post("/questionnaires/drafts/q_submit/sections", json={"section_id": "s1", "title": "S1"})
    owner.post("/questionnaires/drafts/q_submit/questions", json={"section_id": "s1", "question_id": "q1", "type": "text", "label": "L1", "required": True, "config_json": {}})
    owner.post("/questionnaires/drafts/q_submit/publish", json={"published_slug": "submit-slug"})

    anon = _build_anon_client()
    started = anon.post("/questionnaires/published/submit-slug/sessions", json={})
    session_id = started.json()["session"]["response_session_id"]

    invalid = anon.post(
        f"/questionnaires/published/submit-slug/sessions/{session_id}/validate",
        json={"answers_by_question_id": {}, "group_rules": [{"rule_id": "g1", "group_id": "s1", "rule_type": "min_answered", "question_ids": ["q1"], "config_json": {"min_answered": 1}}], "final_submit": False},
    )
    assert invalid.status_code == 200
    assert "can_submit" in invalid.json()

    valid = anon.post(
        f"/questionnaires/published/submit-slug/sessions/{session_id}/submit",
        json={"answers_by_question_id": {"q1": "ok"}, "final_submit": True},
    )
    assert valid.status_code == 200
    assert valid.json()["session"]["status"] == "submitted"
    assert valid.json()["session"]["submitted_at"] is not None

    event_rows = [
        row
        for row in _FAKE_TABLE.items.values()
        if row.get("entity_type") == "response_session_audit_event" and row.get("response_session_id") == session_id
    ]
    assert len(event_rows) == 1
    assert event_rows[0]["event_type"] == "response_session_submitted"

    blocked_edit = anon.put(
        f"/questionnaires/published/submit-slug/sessions/{session_id}",
        json={"answers_by_question_id": {"q1": "late"}, "current_section_index": 0},
    )
    assert blocked_edit.status_code == 409


def test_submit_invalid_payload_does_not_transition_session() -> None:
    owner = _build_client("owner")
    owner.post("/questionnaires/drafts", json={"questionnaire_id": "q_submit_invalid", "title": "Q", "description": "d", "visibility": "public"})
    owner.post("/questionnaires/drafts/q_submit_invalid/sections", json={"section_id": "s1", "title": "S1"})
    owner.post("/questionnaires/drafts/q_submit_invalid/questions", json={"section_id": "s1", "question_id": "q_trigger", "type": "text", "label": "Trigger", "required": True, "config_json": {}})
    owner.post("/questionnaires/drafts/q_submit_invalid/questions", json={"section_id": "s1", "question_id": "q_required", "type": "text", "label": "Required", "required": True, "config_json": {}})
    owner.post("/questionnaires/drafts/q_submit_invalid/publish", json={"published_slug": "submit-invalid-slug"})

    anon = _build_anon_client()
    started = anon.post("/questionnaires/published/submit-invalid-slug/sessions", json={})
    session_id = started.json()["session"]["response_session_id"]

    invalid_submit = anon.post(
        f"/questionnaires/published/submit-invalid-slug/sessions/{session_id}/submit",
        json={"answers_by_question_id": {"q_trigger": "x"}, "form_rules": [{"rule_id": "fr1", "rule_type": "requires_if_answered", "config_json": {"if_question_id": "q_trigger", "required_question_ids": ["q_required"]}, "blocking": True}], "final_submit": True},
    )
    assert invalid_submit.status_code == 422

    resumed = anon.get(f"/questionnaires/published/submit-invalid-slug/sessions/{session_id}")
    assert resumed.status_code == 200
    assert resumed.json()["session"]["status"] == "in_progress"
    assert resumed.json()["session"]["submitted_at"] is None


def test_submitted_session_pdf_generation_and_access_control() -> None:
    owner = _build_client("owner")
    owner.post("/questionnaires/drafts", json={"questionnaire_id": "q_pdf", "title": "PDF Survey", "description": "desc", "visibility": "private"})
    owner.post("/questionnaires/drafts/q_pdf/sections", json={"section_id": "s1", "title": "Basics"})
    owner.post("/questionnaires/drafts/q_pdf/questions", json={"section_id": "s1", "question_id": "q1", "type": "text", "label": "Name", "required": True, "config_json": {}})
    owner.post("/questionnaires/drafts/q_pdf/publish", json={"published_slug": "pdf-slug"})

    authed = _build_anon_client()
    start = authed.post("/questionnaires/published/pdf-slug/sessions", json={}, headers={"x-user-sub": "resp-1"})
    assert start.status_code == 200
    session_id = start.json()["session"]["response_session_id"]

    submit = authed.post(
        f"/questionnaires/published/pdf-slug/sessions/{session_id}/submit",
        json={"answers_by_question_id": {"q1": "Alice"}, "final_submit": True},
        headers={"x-user-sub": "resp-1"},
    )
    assert submit.status_code == 200
    assert submit.json()["session"]["status"] == "submitted"

    generate = authed.post(
        f"/questionnaires/published/pdf-slug/sessions/{session_id}/pdf",
        headers={"x-user-sub": "resp-1"},
    )
    assert generate.status_code == 200
    assert generate.json()["artifact"]["content_type"] == "application/pdf"
    assert generate.json()["artifact"]["size_bytes"] > 0

    download = authed.get(
        f"/questionnaires/published/pdf-slug/sessions/{session_id}/pdf",
        headers={"x-user-sub": "resp-1"},
    )
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("application/pdf")
    assert b"PDF Survey" in download.content
    assert b"Alice" in download.content

    forbidden = authed.get(
        f"/questionnaires/published/pdf-slug/sessions/{session_id}/pdf",
        headers={"x-user-sub": "resp-2"},
    )
    assert forbidden.status_code == 403


def test_creator_analytics_reports_funnel_dropoff_and_validation_hotspots() -> None:
    owner = _build_client("owner")
    owner.post("/questionnaires/drafts", json={"questionnaire_id": "q_analytics", "title": "Q", "description": "d", "visibility": "public"})
    owner.post("/questionnaires/drafts/q_analytics/sections", json={"section_id": "s1", "title": "Section 1"})
    owner.post("/questionnaires/drafts/q_analytics/sections", json={"section_id": "s2", "title": "Section 2"})
    owner.post("/questionnaires/drafts/q_analytics/questions", json={"section_id": "s1", "question_id": "q_trigger", "type": "text", "label": "Trigger", "required": False, "config_json": {}})
    owner.post("/questionnaires/drafts/q_analytics/questions", json={"section_id": "s2", "question_id": "q_required", "type": "text", "label": "Required", "required": True, "config_json": {}})
    owner.post("/questionnaires/drafts/q_analytics/publish", json={"published_slug": "analytics-slug"})

    anon = _build_anon_client()
    s1 = anon.post("/questionnaires/published/analytics-slug/sessions", json={}).json()["session"]["response_session_id"]
    s2 = anon.post("/questionnaires/published/analytics-slug/sessions", json={}).json()["session"]["response_session_id"]

    anon.put(
        f"/questionnaires/published/analytics-slug/sessions/{s2}",
        json={"answers_by_question_id": {"q_trigger": "x"}, "current_section_index": 1, "current_question_id": "q_required"},
    )

    invalid_submit = anon.post(
        f"/questionnaires/published/analytics-slug/sessions/{s1}/submit",
        json={"answers_by_question_id": {"q_trigger": "x"}, "form_rules": [{"rule_id": "fr1", "rule_type": "requires_if_answered", "config_json": {"if_question_id": "q_trigger", "required_question_ids": ["q_required"]}, "blocking": True}], "final_submit": True},
    )
    assert invalid_submit.status_code == 422

    valid_submit = anon.post(
        f"/questionnaires/published/analytics-slug/sessions/{s1}/submit",
        json={"answers_by_question_id": {"q_trigger": "x", "q_required": "ok"}, "final_submit": True},
    )
    assert valid_submit.status_code == 200

    analytics = owner.get("/questionnaires/drafts/q_analytics/analytics")
    assert analytics.status_code == 200
    data = analytics.json()["analytics"]
    assert data["totals"]["starts"] == 2
    assert data["totals"]["completions"] == 1
    assert data["versions"][0]["funnel"]["starts"] == 2
    assert data["versions"][0]["funnel"]["completions"] == 1
    assert data["totals"]["top_dropoffs"][0]["label"].startswith("Section 2")
    assert any(item["key"].startswith("form:") for item in data["totals"]["top_validation_hotspots"])
    assert data["freshness_sla_seconds"] == 60


def test_session_requires_auth_when_bound_to_authenticated_respondent() -> None:
    owner = _build_client("owner")
    owner.post("/questionnaires/drafts", json={"questionnaire_id": "q_auth_lock", "title": "Q", "description": "d", "visibility": "private"})
    owner.post("/questionnaires/drafts/q_auth_lock/sections", json={"section_id": "s1", "title": "S1"})
    owner.post("/questionnaires/drafts/q_auth_lock/questions", json={"section_id": "s1", "question_id": "q1", "type": "text", "label": "L1", "config_json": {}})
    owner.post("/questionnaires/drafts/q_auth_lock/publish", json={"published_slug": "auth-lock"})

    authed = _build_anon_client()
    started = authed.post("/questionnaires/published/auth-lock/sessions", json={}, headers={"x-user-sub": "u1"})
    session_id = started.json()["session"]["response_session_id"]

    anon_get = authed.get(f"/questionnaires/published/auth-lock/sessions/{session_id}")
    assert anon_get.status_code == 401


def test_anonymous_public_submission_rate_limited() -> None:
    owner = _build_client("owner")
    owner.post("/questionnaires/drafts", json={"questionnaire_id": "q_rl", "title": "Q", "description": "d", "visibility": "public"})
    owner.post("/questionnaires/drafts/q_rl/sections", json={"section_id": "s1", "title": "S1"})
    owner.post("/questionnaires/drafts/q_rl/questions", json={"section_id": "s1", "question_id": "q1", "type": "text", "label": "L1", "config_json": {}})
    owner.post("/questionnaires/drafts/q_rl/publish", json={"published_slug": "rl-slug"})

    called = {"n": 0}

    def _fake_rl(*args, **kwargs):
        called["n"] += 1
        if called["n"] > 1:
            from fastapi import HTTPException
            raise HTTPException(status_code=429, detail="Too many recovery attempts; try again later")

    original = questionnaires.rate_limit_password_recovery
    questionnaires.rate_limit_password_recovery = _fake_rl
    try:
        anon = _build_anon_client()
        first = anon.post("/questionnaires/published/rl-slug/sessions", json={})
        assert first.status_code == 200

        second = anon.post("/questionnaires/published/rl-slug/sessions", json={})
        assert second.status_code == 429
    finally:
        questionnaires.rate_limit_password_recovery = original
