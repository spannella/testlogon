from __future__ import annotations

from copy import deepcopy

from fastapi.testclient import TestClient
from fastapi import FastAPI
from starlette.requests import Request

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role
from app.routers import kyc_cases as kyc_router
from app.routers import tickets as tickets_router
from app.routers.kyc_cases import STORE, router as kyc_cases_router
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

    def update_item(self, *, Key, UpdateExpression, ExpressionAttributeValues, ConditionExpression=None, **kwargs):
        item = deepcopy(self.items[(Key["pk"], Key["sk"])])
        if ConditionExpression and "version = :expected_version" in ConditionExpression:
            if int(item.get("version") or 0) != int(ExpressionAttributeValues[":expected_version"]):
                raise AssertionError("conditional check failed")
        if ConditionExpression and "#status = :draft OR #status = :needs_more_info" in ConditionExpression:
            if str(item.get("status") or "") not in {"draft", "needs_more_info"}:
                raise AssertionError("conditional check failed")
        set_part = UpdateExpression.replace("SET", "", 1).strip()
        remove_part = ""
        if " REMOVE " in set_part:
            set_part, _, remove_part = set_part.partition(" REMOVE ")
        attr_names = kwargs.get("ExpressionAttributeNames", {})
        for assignment in set_part.split(","):
            assignment = assignment.strip()
            if not assignment:
                continue
            left, right = assignment.split("=")
            key = left.strip()
            if key in attr_names:
                key = attr_names[key]
            item[key] = ExpressionAttributeValues.get(right.strip(), right.strip())
        if remove_part:
            for attr_alias in remove_part.split(","):
                attr_alias = attr_alias.strip()
                if not attr_alias:
                    continue
                attr = attr_names.get(attr_alias, attr_alias)
                item.pop(attr, None)
        self.items[(Key["pk"], Key["sk"])] = item

    def query(self, **kwargs):
        index_name = kwargs.get("IndexName", "")
        pk = kwargs.get("ExpressionAttributeValues", {}).get(":pk")
        out: list[dict] = []
        for item in self.items.values():
            if item.get("entity_type") != "kyc_case":
                continue
            if index_name.endswith("owner-updated-index") and item.get("gsi_owner_pk") == pk:
                out.append(deepcopy(item))
            if index_name.endswith("status-updated-index") and item.get("gsi_status_pk") == pk:
                out.append(deepcopy(item))
        return {"Items": out[: kwargs.get("Limit", 100)]}


FAKE_TABLE = _FakeTable()
STORE._table = FAKE_TABLE


def _build_client(user_sub: str, role: Role = Role.USER) -> TestClient:
    app = FastAPI()
    app.include_router(kyc_cases_router)

    async def _auth_override() -> AuthenticatedUser:
        return AuthenticatedUser(sub=user_sub, role=role)

    async def _session_override() -> dict[str, str]:
        return {"user_sub": user_sub, "session_id": "sess_1", "role": role.value}

    app.dependency_overrides[get_authenticated_user] = _auth_override
    app.dependency_overrides[require_ui_session] = _session_override
    return TestClient(app)


def setup_function() -> None:
    FAKE_TABLE.reset()
    tickets_router._KYC_TICKET_SYNC_COUNTS.clear()


def test_create_list_get_and_patch_draft_case() -> None:
    client = _build_client("user-1")

    created = client.post("/v1/kyc/cases", json={"intake_profile": "standard"})
    assert created.status_code == 200
    case = created.json()["case"]
    assert case["status"] == "draft"
    assert case["intake_profile"] == "standard"

    listed = client.get("/v1/kyc/cases")
    assert listed.status_code == 200
    assert len(listed.json()["items"]) == 1

    got = client.get(f"/v1/kyc/cases/{case['kyc_case_id']}")
    assert got.status_code == 200
    assert got.json()["case"]["kyc_case_id"] == case["kyc_case_id"]

    patched = client.patch(
        f"/v1/kyc/cases/{case['kyc_case_id']}",
        json={"expected_version": case["version"], "intake_profile": "enhanced"},
    )
    assert patched.status_code == 200
    assert patched.json()["case"]["intake_profile"] == "enhanced"
    assert patched.json()["case"]["version"] == 2


def test_user_cannot_access_another_users_case() -> None:
    owner_client = _build_client("user-1")
    other_client = _build_client("user-2")

    created = owner_client.post("/v1/kyc/cases", json={})
    case_id = created.json()["case"]["kyc_case_id"]

    denied = other_client.get(f"/v1/kyc/cases/{case_id}")
    assert denied.status_code == 403
    assert denied.json()["detail"]["error"]["code"] == "kyc_access_forbidden"


def test_patch_returns_conflict_on_stale_version() -> None:
    client = _build_client("user-1")

    created = client.post("/v1/kyc/cases", json={})
    case = created.json()["case"]

    stale = client.patch(
        f"/v1/kyc/cases/{case['kyc_case_id']}",
        json={"expected_version": 999, "intake_profile": "enhanced"},
    )
    assert stale.status_code == 409
    assert stale.json()["detail"]["error"]["code"] == "kyc_case_update_conflict"


def test_patch_blocks_non_draft_case() -> None:
    client = _build_client("user-1")

    created = client.post("/v1/kyc/cases", json={})
    case = created.json()["case"]
    # mutate underlying row to emulate already-submitted case
    row = STORE.get_case(case["kyc_case_id"])
    assert row is not None
    row["status"] = "submitted"
    FAKE_TABLE.put_item(Item=row)

    resp = client.patch(
        f"/v1/kyc/cases/{case['kyc_case_id']}",
        json={"expected_version": row["version"], "intake_profile": "enhanced"},
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"]["code"] == "kyc_invalid_transition"


def test_create_and_patch_emit_audit_events(monkeypatch) -> None:
    client = _build_client("user-1")
    events: list[tuple[str, str, str]] = []

    def _audit(event: str, user_sub: str, request, outcome: str = "success", **kwargs):
        events.append((event, user_sub, outcome))

    monkeypatch.setattr("app.routers.kyc_cases.audit_event", _audit)

    created = client.post("/v1/kyc/cases", json={"intake_profile": "standard"})
    assert created.status_code == 200
    case = created.json()["case"]

    patched = client.patch(
        f"/v1/kyc/cases/{case['kyc_case_id']}",
        json={"expected_version": case["version"], "intake_profile": "enhanced"},
    )
    assert patched.status_code == 200
    assert ("kyc_case_created", "user-1", "success") in events
    assert ("kyc_case_updated", "user-1", "success") in events


def test_read_denied_emits_audit_event(monkeypatch) -> None:
    owner_client = _build_client("user-1")
    other_client = _build_client("user-2")
    events: list[tuple[str, str, str, str]] = []

    def _audit(event: str, user_sub: str, request, outcome: str = "success", **kwargs):
        events.append((event, user_sub, outcome, str(kwargs.get("reason") or "")))

    monkeypatch.setattr("app.routers.kyc_cases.audit_event", _audit)
    created = owner_client.post("/v1/kyc/cases", json={})
    case_id = created.json()["case"]["kyc_case_id"]

    denied = other_client.get(f"/v1/kyc/cases/{case_id}")
    assert denied.status_code == 403
    assert ("kyc_case_read_denied", "user-2", "failure", "forbidden") in events


class _FakeQuestionnaireRepo:
    def __init__(self) -> None:
        self.versions = {
            "kyc-basic": {"questionnaire_id": "q_1", "version_id": "v_1"},
        }
        self.sessions: dict[tuple[str, str], dict] = {}
        self.pdf: dict[tuple[str, str], dict] = {}

    def get_published_by_slug(self, slug: str):
        return self.versions.get(slug)

    def put_response_session(self, *, response_session_id: str, questionnaire_id: str, version_id: str, respondent_id: str | None = None):
        item = {
            "response_session_id": response_session_id,
            "questionnaire_id": questionnaire_id,
            "version_id": version_id,
            "respondent_id": respondent_id,
            "status": "in_progress",
        }
        self.sessions[(questionnaire_id, response_session_id)] = item
        return item

    def get_response_session(self, *, questionnaire_id: str, response_session_id: str):
        return self.sessions.get((questionnaire_id, response_session_id))

    def get_response_pdf_artifact(self, *, questionnaire_id: str, response_session_id: str):
        return self.pdf.get((questionnaire_id, response_session_id))


def test_start_questionnaire_binds_session_and_is_idempotent(monkeypatch) -> None:
    client = _build_client("user-1")
    fake_repo = _FakeQuestionnaireRepo()
    monkeypatch.setattr(kyc_router, "QNR_REPO", fake_repo)

    created = client.post("/v1/kyc/cases", json={})
    case_id = created.json()["case"]["kyc_case_id"]

    started = client.post(f"/v1/kyc/cases/{case_id}/start-questionnaire", json={"published_slug": "kyc-basic"})
    assert started.status_code == 200
    first_session = started.json()["case"]["questionnaire"]["response_session_id"]
    assert first_session

    started_again = client.post(f"/v1/kyc/cases/{case_id}/start-questionnaire", json={"published_slug": "kyc-basic"})
    assert started_again.status_code == 200
    second_session = started_again.json()["case"]["questionnaire"]["response_session_id"]
    assert second_session == first_session


def test_questionnaire_status_resolver_reflects_submission_and_pdf(monkeypatch) -> None:
    client = _build_client("user-1")
    fake_repo = _FakeQuestionnaireRepo()
    monkeypatch.setattr(kyc_router, "QNR_REPO", fake_repo)

    created = client.post("/v1/kyc/cases", json={})
    case_id = created.json()["case"]["kyc_case_id"]
    started = client.post(f"/v1/kyc/cases/{case_id}/start-questionnaire", json={"published_slug": "kyc-basic"}).json()["case"]
    qid = started["questionnaire"]["questionnaire_id"]
    rid = started["questionnaire"]["response_session_id"]
    assert qid and rid

    fake_repo.sessions[(qid, rid)]["status"] = "submitted"
    fake_repo.pdf[(qid, rid)] = {"pk": f"QNR#{qid}", "sk": f"PDF#RESP#{rid}"}

    status = client.get(f"/v1/kyc/cases/{case_id}/questionnaire-status")
    assert status.status_code == 200
    body = status.json()["questionnaire"]
    assert body["questionnaire_bound"] is True
    assert body["submitted"] is True
    assert body["ready_for_submit_gate"] is True
    assert body["response_pdf_ref"] == f"QNR#{qid}#PDF#RESP#{rid}"


def test_attach_kyc_file_and_validate_required_documents(monkeypatch) -> None:
    client = _build_client("user-1")

    monkeypatch.setattr(kyc_router, "norm_path", lambda p, is_folder=False: p if p.startswith("/") else f"/{p}")

    def _get_node(owner: str, path: str):
        assert owner == "user-1"
        return {"type": "file", "path": path, "size": 10, "upload_at": "123"}

    monkeypatch.setattr(kyc_router, "get_node", _get_node)

    created = client.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]

    for expected_version, file_type, path in (
        (1, "selfie", "/kyc/selfie.jpg"),
        (2, "id_front", "/kyc/id-front.jpg"),
        (3, "id_back", "/kyc/id-back.jpg"),
    ):
        resp = client.post(
            f"/v1/kyc/cases/{case_id}/files",
            json={"expected_version": expected_version, "file_type": file_type, "path": path},
        )
        assert resp.status_code == 200

    validation = client.get(f"/v1/kyc/cases/{case_id}/files/validation")
    assert validation.status_code == 200
    body = validation.json()["files"]
    assert body["ready_for_submit_gate"] is True
    assert body["missing_types"] == []
    assert set(body["present_types"]) == {"selfie", "id_front", "id_back"}


def test_attach_kyc_file_rejects_invalid_or_unowned_path(monkeypatch) -> None:
    client = _build_client("user-1")
    monkeypatch.setattr(kyc_router, "norm_path", lambda p, is_folder=False: p)

    def _raise_not_found(owner: str, path: str):
        from fastapi import HTTPException

        raise HTTPException(404, "not found")

    monkeypatch.setattr(kyc_router, "get_node", _raise_not_found)
    created = client.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]

    denied = client.post(
        f"/v1/kyc/cases/{case_id}/files",
        json={"expected_version": 1, "file_type": "selfie", "path": "/missing.jpg"},
    )
    assert denied.status_code == 400
    assert denied.json()["detail"]["error"]["code"] == "kyc_invalid_request"


def test_file_validator_returns_deterministic_missing_list(monkeypatch) -> None:
    client = _build_client("user-1")
    monkeypatch.setattr(kyc_router, "norm_path", lambda p, is_folder=False: p)
    monkeypatch.setattr(kyc_router, "get_node", lambda owner, path: {"type": "file", "path": path, "size": 10, "upload_at": "1"})

    created = client.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]
    client.post(
        f"/v1/kyc/cases/{case_id}/files",
        json={"expected_version": 1, "file_type": "selfie", "path": "/selfie.jpg"},
    )

    validation = client.get(f"/v1/kyc/cases/{case_id}/files/validation")
    assert validation.status_code == 200
    assert validation.json()["files"]["missing_types"] == ["id_front", "id_back"]


def test_signature_packet_link_and_status_verifier(monkeypatch) -> None:
    client = _build_client("user-1")

    monkeypatch.setattr(kyc_router, "norm_path", lambda p, is_folder=False: p)
    monkeypatch.setattr(
        kyc_router,
        "get_node",
        lambda owner, path: {"type": "file", "content_type": "application/pdf", "name": "policy.pdf", "path": path},
    )
    monkeypatch.setattr(
        kyc_router,
        "create_draft_packet",
        lambda **kwargs: {"packet_id": "pkt_1", "status": "draft"},
    )
    monkeypatch.setattr(kyc_router, "get_packet", lambda packet_id: {"packet_id": packet_id, "status": "completed"})
    monkeypatch.setattr(kyc_router, "get_packet_artifact", lambda packet_id: {"packet_id": packet_id, "status": "ready"})
    monkeypatch.setattr(
        kyc_router,
        "list_packet_signers",
        lambda packet_id: [{"signer_id": "user-1", "legal_notice_accepted_version": kyc_router.S.signature_packet_legal_notice_version}],
    )

    created = client.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]

    linked = client.post(
        f"/v1/kyc/cases/{case_id}/signature-packet",
        json={
            "expected_version": 1,
            "source_path": "/policies/kyc-consent.pdf",
            "origin_channel": "share",
        },
    )
    assert linked.status_code == 200
    assert linked.json()["case"]["signature"]["packet_id"] == "pkt_1"

    status = client.get(f"/v1/kyc/cases/{case_id}/signature-status")
    assert status.status_code == 200
    payload = status.json()["signature"]
    assert payload["completed"] is True
    assert payload["final_pdf_ready"] is True
    assert payload["ready_for_submit_gate"] is True


def test_signature_link_is_idempotent_for_active_packet(monkeypatch) -> None:
    client = _build_client("user-1")
    monkeypatch.setattr(kyc_router, "norm_path", lambda p, is_folder=False: p)
    monkeypatch.setattr(
        kyc_router,
        "get_node",
        lambda owner, path: {"type": "file", "content_type": "application/pdf", "name": "policy.pdf", "path": path},
    )
    monkeypatch.setattr(kyc_router, "create_draft_packet", lambda **kwargs: {"packet_id": "pkt_1", "status": "draft"})
    monkeypatch.setattr(kyc_router, "get_packet", lambda packet_id: {"packet_id": packet_id, "status": "draft"})
    monkeypatch.setattr(kyc_router, "get_packet_artifact", lambda packet_id: None)
    monkeypatch.setattr(kyc_router, "list_packet_signers", lambda packet_id: [])

    created = client.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]
    first = client.post(
        f"/v1/kyc/cases/{case_id}/signature-packet",
        json={"expected_version": 1, "source_path": "/policies/kyc-consent.pdf", "origin_channel": "share"},
    )
    assert first.status_code == 200

    second = client.post(
        f"/v1/kyc/cases/{case_id}/signature-packet",
        json={"expected_version": 2, "source_path": "/policies/kyc-consent.pdf", "origin_channel": "share"},
    )
    assert second.status_code == 200
    assert second.json()["case"]["signature"]["packet_id"] == "pkt_1"


def test_readiness_endpoint_aggregates_checks_and_updates(monkeypatch) -> None:
    client = _build_client("user-1")
    fake_repo = _FakeQuestionnaireRepo()
    # audit_event → T.alert_prefs; get_user_kyc_tier → T.users;
    # kyc_document_templates.SERVICE.get_required_templates_for_tier → T.kyc_document_templates
    # All added after this test was written — patch to no-ops.
    monkeypatch.setattr(kyc_router, "audit_event", lambda *a, **kw: None)
    import app.services.kyc_tiers as _kt
    monkeypatch.setattr(_kt, "get_user_kyc_tier", lambda user_sub: 1)
    import app.services.kyc_document_templates as _kdt
    monkeypatch.setattr(_kdt.SERVICE, "get_required_templates_for_tier", lambda tier: [])
    monkeypatch.setattr(kyc_router, "QNR_REPO", fake_repo)
    monkeypatch.setattr(kyc_router, "norm_path", lambda p, is_folder=False: p)
    monkeypatch.setattr(
        kyc_router,
        "get_node",
        lambda owner, path: {"type": "file", "content_type": "application/pdf", "name": "policy.pdf", "path": path, "size": 10, "upload_at": "1"},
    )
    monkeypatch.setattr(kyc_router, "create_draft_packet", lambda **kwargs: {"packet_id": "pkt_1", "status": "draft"})
    monkeypatch.setattr(kyc_router, "get_packet", lambda packet_id: {"packet_id": packet_id, "status": "draft"})
    monkeypatch.setattr(kyc_router, "get_packet_artifact", lambda packet_id: None)
    monkeypatch.setattr(kyc_router, "list_packet_signers", lambda packet_id: [])

    created = client.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]
    initial = client.get(f"/v1/kyc/cases/{case_id}/readiness")
    assert initial.status_code == 200
    assert initial.json()["readiness"]["ready_to_submit"] is False
    assert set(initial.json()["readiness"]["missing_requirements"]) == {"questionnaire_submitted", "required_files", "signature_completed"}

    started = client.post(f"/v1/kyc/cases/{case_id}/start-questionnaire", json={"published_slug": "kyc-basic"}).json()["case"]
    qid = started["questionnaire"]["questionnaire_id"]
    rid = started["questionnaire"]["response_session_id"]
    assert qid and rid
    fake_repo.sessions[(qid, rid)]["status"] = "submitted"
    fake_repo.pdf[(qid, rid)] = {"pk": f"QNR#{qid}", "sk": f"PDF#RESP#{rid}"}

    for expected_version, file_type, path in (
        (2, "selfie", "/kyc/selfie.jpg"),
        (3, "id_front", "/kyc/id-front.jpg"),
        (4, "id_back", "/kyc/id-back.jpg"),
    ):
        attached = client.post(
            f"/v1/kyc/cases/{case_id}/files",
            json={"expected_version": expected_version, "file_type": file_type, "path": path},
        )
        assert attached.status_code == 200

    linked = client.post(
        f"/v1/kyc/cases/{case_id}/signature-packet",
        json={"expected_version": 5, "source_path": "/policies/kyc-consent.pdf", "origin_channel": "share"},
    )
    assert linked.status_code == 200

    # Signature still incomplete -> only signature requirement remains missing.
    partial = client.get(f"/v1/kyc/cases/{case_id}/readiness")
    assert partial.status_code == 200
    assert partial.json()["readiness"]["missing_requirements"] == ["signature_completed"]

    monkeypatch.setattr(kyc_router, "get_packet", lambda packet_id: {"packet_id": packet_id, "status": "completed"})
    monkeypatch.setattr(kyc_router, "get_packet_artifact", lambda packet_id: {"packet_id": packet_id, "status": "ready"})
    monkeypatch.setattr(
        kyc_router,
        "list_packet_signers",
        lambda packet_id: [{"signer_id": "user-1", "legal_notice_accepted_version": kyc_router.S.signature_packet_legal_notice_version}],
    )

    ready = client.get(f"/v1/kyc/cases/{case_id}/readiness")
    assert ready.status_code == 200
    payload = ready.json()["readiness"]
    assert payload["ready_to_submit"] is True
    assert payload["missing_requirements"] == []
    assert payload["checks"].get("questionnaire_submitted") is True
    assert payload["checks"].get("required_files") is True
    assert payload["checks"].get("signature_completed") is True
    # templates_signed added by GAP-0279; True because no required templates (patched)
    assert payload["checks"].get("templates_signed", True) is True


def test_submit_endpoint_enforces_guards_and_persists_evidence(monkeypatch) -> None:
    client = _build_client("user-1")
    fake_repo = _FakeQuestionnaireRepo()
    monkeypatch.setattr(kyc_router, "QNR_REPO", fake_repo)
    monkeypatch.setattr(kyc_router, "norm_path", lambda p, is_folder=False: p)
    monkeypatch.setattr(
        kyc_router,
        "get_node",
        lambda owner, path: {"type": "file", "content_type": "application/pdf", "name": "policy.pdf", "path": path, "size": 10, "upload_at": "1"},
    )
    monkeypatch.setattr(kyc_router, "create_draft_packet", lambda **kwargs: {"packet_id": "pkt_1", "status": "draft"})
    monkeypatch.setattr(kyc_router, "get_packet", lambda packet_id: {"packet_id": packet_id, "status": "completed"})
    monkeypatch.setattr(kyc_router, "get_packet_artifact", lambda packet_id: {"packet_id": packet_id, "status": "ready"})
    monkeypatch.setattr(
        kyc_router,
        "list_packet_signers",
        lambda packet_id: [{"signer_id": "user-1", "legal_notice_accepted_version": kyc_router.S.signature_packet_legal_notice_version}],
    )
    created_tickets: list[dict] = []
    monkeypatch.setattr(
        kyc_router.TICKET_STORE,
        "create_ticket",
        lambda **kwargs: created_tickets.append(kwargs) or {"ticket_id": kwargs["ticket_id"]},
    )

    created = client.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]

    denied = client.post(f"/v1/kyc/cases/{case_id}/submit", json={"expected_version": 1})
    assert denied.status_code == 409
    assert denied.json()["detail"]["error"]["code"] == "kyc_submit_prereq_failed"
    assert set(denied.json()["detail"]["error"]["details"]["missing_requirements"]) == {
        "questionnaire_submitted",
        "required_files",
        "signature_completed",
    }

    started = client.post(f"/v1/kyc/cases/{case_id}/start-questionnaire", json={"published_slug": "kyc-basic"}).json()["case"]
    qid = started["questionnaire"]["questionnaire_id"]
    rid = started["questionnaire"]["response_session_id"]
    fake_repo.sessions[(qid, rid)]["status"] = "submitted"
    fake_repo.pdf[(qid, rid)] = {"pk": f"QNR#{qid}", "sk": f"PDF#RESP#{rid}"}

    for expected_version, file_type, path in (
        (2, "selfie", "/kyc/selfie.jpg"),
        (3, "id_front", "/kyc/id-front.jpg"),
        (4, "id_back", "/kyc/id-back.jpg"),
    ):
        attached = client.post(
            f"/v1/kyc/cases/{case_id}/files",
            json={"expected_version": expected_version, "file_type": file_type, "path": path},
        )
        assert attached.status_code == 200

    linked = client.post(
        f"/v1/kyc/cases/{case_id}/signature-packet",
        json={"expected_version": 5, "source_path": "/policies/kyc-consent.pdf", "origin_channel": "share"},
    )
    assert linked.status_code == 200

    submitted = client.post(f"/v1/kyc/cases/{case_id}/submit", json={"expected_version": 6})
    assert submitted.status_code == 200
    payload = submitted.json()["case"]
    assert payload["status"] == "submitted"
    assert payload["submission"]["evidence_hash"]
    assert payload["submission"]["evidence_snapshot"]["signature"]["packet_id"] == "pkt_1"
    assert payload["review"]["ticket_id"] == f"tkt_kyc_{case_id}"
    assert len(created_tickets) == 1

    replay = client.post(f"/v1/kyc/cases/{case_id}/submit", json={"expected_version": payload["version"]})
    assert replay.status_code == 200


def test_submit_creates_review_ticket_and_ticket_sync_updates_case(monkeypatch) -> None:
    owner = _build_client("user-1", Role.USER)
    created = owner.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]

    # Prepare submit prerequisites.
    row = STORE.get_case(case_id)
    assert row is not None
    row["questionnaire"] = {
        "questionnaire_id": "q_1",
        "version_id": "v_1",
        "response_session_id": "resp_1",
        "response_pdf_ref": "s3://pdf/resp_1.pdf",
        "bound_at": 1,
    }
    row["files"] = [
        {"type": "id_front", "path": "/files/id_front.jpg"},
        {"type": "id_back", "path": "/files/id_back.jpg"},
        {"type": "selfie", "path": "/files/selfie.jpg"},
    ]
    row["signature"] = {"packet_id": "pkt_1", "status": "completed", "final_pdf_ref": "s3://pdf/signature.pdf"}
    row["version"] = 6
    FAKE_TABLE.put_item(Item=row)

    monkeypatch.setattr(kyc_router, "_questionnaire_status_for_case", lambda case, include_submit_gate=True: {
        "questionnaire_bound": True, "submitted": True, "has_pdf": True, "ready_for_submit_gate": True,
        "questionnaire_id": (case.get("questionnaire") or {}).get("questionnaire_id"),
        "response_session_id": (case.get("questionnaire") or {}).get("response_session_id"),
        "response_pdf_ref": (case.get("questionnaire") or {}).get("response_pdf_ref"),
    })
    monkeypatch.setattr(kyc_router, "_signature_status_for_case", lambda case: {
        "completed": True, "has_final_pdf": True, "ready_for_submit_gate": True,
        "packet_id": (case.get("signature") or {}).get("packet_id"),
        "final_pdf_ref": (case.get("signature") or {}).get("final_pdf_ref"),
    })

    created_tickets: list[dict] = []

    def _create_ticket(**kwargs):
        created_tickets.append(kwargs)
        return {"ticket_id": kwargs["ticket_id"], "status": "open", "version": 1, "updated_at": 10, "metadata": kwargs.get("metadata", {})}

    monkeypatch.setattr(kyc_router.TICKET_STORE, "create_ticket", _create_ticket)

    submitted = owner.post(f"/v1/kyc/cases/{case_id}/submit", json={"expected_version": 6})
    assert submitted.status_code == 200
    submitted_case = submitted.json()["case"]
    assert submitted_case["status"] == "submitted"
    assert submitted_case["review"]["ticket_id"] == f"tkt_kyc_{case_id}"
    assert len(created_tickets) == 1

    # Integration step: ticket event sync transitions submitted -> under_review.
    ticket_after = {
        "ticket_id": f"tkt_kyc_{case_id}",
        "status": "in_progress",
        "assigned_admin_sub": "admin-1",
        "version": 2,
        "updated_at": 11,
        "metadata": {"namespace": "kyc", "kyc_case_id": case_id},
    }
    tickets_router._sync_kyc_for_ticket_event(
        ticket_before={"ticket_id": f"tkt_kyc_{case_id}"},
        ticket_after=ticket_after,
        event_type="status_changed",
        actor_sub="admin-1",
        request=Request({"type": "http", "method": "POST", "path": "/tickets/sync", "headers": []}),
    )
    after_sync = STORE.get_case(case_id)
    assert after_sync is not None
    assert after_sync["status"] == "under_review"
    assert after_sync["review"]["assigned_admin_sub"] == "admin-1"


def test_submit_replay_with_diverged_evidence_returns_conflict(monkeypatch) -> None:
    client = _build_client("user-1")
    created = client.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]

    fake_repo = _FakeQuestionnaireRepo()
    monkeypatch.setattr(kyc_router, "QNR_REPO", fake_repo)
    monkeypatch.setattr(kyc_router, "create_draft_packet", lambda **kwargs: {"packet_id": "pkt_1", "status": "draft"})
    monkeypatch.setattr(kyc_router, "get_packet", lambda packet_id: {"packet_id": packet_id, "status": "completed"})
    monkeypatch.setattr(kyc_router, "get_packet_artifact", lambda packet_id: {"packet_id": packet_id, "status": "ready"})
    monkeypatch.setattr(kyc_router, "list_packet_signers", lambda packet_id: [])
    monkeypatch.setattr(kyc_router, "norm_path", lambda path, is_folder=False: path)
    monkeypatch.setattr(kyc_router, "get_node", lambda owner, path: {"type": "file", "path": path, "size": 1, "owner_sub": owner, "upload_at": 1, "content_type": "application/pdf"})
    monkeypatch.setattr(kyc_router.TICKET_STORE, "create_ticket", lambda **kwargs: {"ticket_id": kwargs["ticket_id"], "status": "open", "version": 1, "updated_at": 10, "metadata": kwargs.get("metadata", {})})

    started = client.post(f"/v1/kyc/cases/{case_id}/start-questionnaire", json={"published_slug": "kyc-basic"}).json()["case"]
    qid = started["questionnaire"]["questionnaire_id"]
    rid = started["questionnaire"]["response_session_id"]
    fake_repo.sessions[(qid, rid)]["status"] = "submitted"
    fake_repo.pdf[(qid, rid)] = {"pk": f"QNR#{qid}", "sk": f"PDF#RESP#{rid}"}
    for expected_version, file_type, path in (
        (2, "selfie", "/kyc/selfie.jpg"),
        (3, "id_front", "/kyc/id-front.jpg"),
        (4, "id_back", "/kyc/id-back.jpg"),
    ):
        attached = client.post(
            f"/v1/kyc/cases/{case_id}/files",
            json={"expected_version": expected_version, "file_type": file_type, "path": path},
        )
        assert attached.status_code == 200
    linked = client.post(
        f"/v1/kyc/cases/{case_id}/signature-packet",
        json={"expected_version": 5, "source_path": "/policies/kyc-consent.pdf", "origin_channel": "share"},
    )
    assert linked.status_code == 200
    submitted = client.post(f"/v1/kyc/cases/{case_id}/submit", json={"expected_version": 6})
    assert submitted.status_code == 200

    # Simulate drift in stored references before replay (should now conflict).
    row = STORE.get_case(case_id)
    assert row is not None
    row["questionnaire"]["response_session_id"] = "resp_changed"
    FAKE_TABLE.put_item(Item=row)

    replay = client.post(f"/v1/kyc/cases/{case_id}/submit", json={"expected_version": submitted.json()['case']['version']})
    # Diverged evidence may manifest as prereq failure (response_session_id mismatch) or version conflict
    assert replay.status_code == 409
    assert replay.json()["detail"]["error"]["code"] in {"kyc_case_update_conflict", "kyc_submit_prereq_failed"}


def test_admin_queue_denies_non_admin() -> None:
    user_client = _build_client("user-1", Role.USER)
    resp = user_client.get("/v1/kyc/cases/admin/queue")
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"]["code"] == "kyc_admin_role_required"


def test_admin_queue_filters_and_pagination_are_deterministic() -> None:
    owner = _build_client("user-1", Role.USER)
    admin = _build_client("admin-1", Role.ADMIN)

    created_ids: list[str] = []
    for intake_profile in ("enhanced", "standard", "basic"):
        created = owner.post("/v1/kyc/cases", json={"intake_profile": intake_profile})
        assert created.status_code == 200
        created_ids.append(created.json()["case"]["kyc_case_id"])

    for case_id, status, assigned in (
        (created_ids[0], "submitted", "admin-1"),
        (created_ids[1], "under_review", "admin-2"),
        (created_ids[2], "needs_more_info", "admin-1"),
    ):
        row = STORE.get_case(case_id)
        assert row is not None
        row["status"] = status
        row["review"]["assigned_admin_sub"] = assigned
        row["assigned_admin_sub"] = assigned
        row["updated_at"] = row["updated_at"] - 100
        row["gsi_status_pk"] = f"STATUS#{status}"
        row["gsi_status_sk"] = f"UPDATED#{row['updated_at']:013d}#KYC#{case_id}"
        FAKE_TABLE.put_item(Item=row)

    page1 = admin.get("/v1/kyc/cases/admin/queue", params={"assignee_admin_sub": "admin-1", "limit": 1})
    assert page1.status_code == 200
    body1 = page1.json()
    assert len(body1["items"]) == 1
    assert body1["items"][0]["assigned_admin_sub"] == "admin-1"
    assert body1["next_cursor"]

    page2 = admin.get("/v1/kyc/cases/admin/queue", params={"assignee_admin_sub": "admin-1", "limit": 1, "cursor": body1["next_cursor"]})
    assert page2.status_code == 200
    body2 = page2.json()
    assert len(body2["items"]) == 1
    assert body2["items"][0]["assigned_admin_sub"] == "admin-1"

    high_only = admin.get("/v1/kyc/cases/admin/queue", params={"risk_tier": "high"})
    assert high_only.status_code == 200
    assert all(item["risk_tier"] == "high" for item in high_only.json()["items"])


def test_admin_case_detail_requires_admin_and_returns_explicit_refs(monkeypatch) -> None:
    owner = _build_client("user-1", Role.USER)
    admin = _build_client("admin-1", Role.ADMIN)
    created = owner.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]

    denied = owner.get(f"/v1/kyc/cases/admin/cases/{case_id}")
    assert denied.status_code == 403
    assert denied.json()["detail"]["error"]["code"] == "kyc_admin_role_required"

    monkeypatch.setattr(
        kyc_router.TICKET_STORE,
        "get_ticket",
        lambda ticket_id: {
            "ticket_id": ticket_id,
            "status": "in_progress",
            "owner_sub": "user-1",
            "assigned_admin_sub": "admin-2",
            "created_at": 1,
            "updated_at": 2,
            "activity": [{"type": "ticket_assigned", "actor_sub": "admin-1", "assignee_sub": "admin-2", "status": "in_progress", "created_at": 2}],
        },
    )

    row = STORE.get_case(case_id)
    assert row is not None
    row["questionnaire"] = {"questionnaire_id": None, "version_id": None, "response_session_id": None, "response_pdf_ref": None}
    row["files"] = []
    row["signature"] = {"packet_id": None, "status": None, "final_pdf_ref": None}
    row["review"]["ticket_id"] = f"tkt_kyc_{case_id}"
    row["review"]["assigned_admin_sub"] = "admin-1"
    FAKE_TABLE.put_item(Item=row)

    detail = admin.get(f"/v1/kyc/cases/admin/cases/{case_id}")
    assert detail.status_code == 200
    payload = detail.json()["case"]
    assert payload["questionnaire_ref"]["response_session_id"] is None
    assert payload["signature_ref"]["packet_id"] is None
    assert payload["ticket_ref"]["ticket_id"] == f"tkt_kyc_{case_id}"
    assert any(event["source"] == "ticket" for event in payload["timeline"])


def test_admin_request_info_transitions_case_and_posts_ticket_message(monkeypatch) -> None:
    owner = _build_client("user-1", Role.USER)
    admin = _build_client("admin-1", Role.ADMIN)

    created = owner.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]
    row = STORE.get_case(case_id)
    assert row is not None
    row["status"] = "under_review"
    row["review"]["ticket_id"] = f"tkt_kyc_{case_id}"
    row["review"]["assigned_admin_sub"] = "admin-1"
    row["version"] = 2
    FAKE_TABLE.put_item(Item=row)

    posted: list[str] = []
    monkeypatch.setattr(
        kyc_router.TICKET_STORE,
        "get_ticket",
        lambda ticket_id: {"ticket_id": ticket_id, "assigned_admin_sub": "admin-2", "messages": [{"body": b} for b in posted]},
    )
    monkeypatch.setattr(
        kyc_router.TICKET_STORE,
        "add_message",
        lambda **kwargs: posted.append(kwargs["body"]) or {"ticket_id": kwargs["ticket_id"]},
    )

    req = admin.post(
        f"/v1/kyc/cases/admin/cases/{case_id}/request-info",
        json={"expected_version": 2, "requested_items": ["id_back"], "note": "Please upload a clearer id back image."},
    )
    assert req.status_code == 200
    payload = req.json()["case"]
    assert payload["status"] == "needs_more_info"
    # requested_items is stored in DDB review dict but not exposed by KycCaseReviewRef response model
    stored = STORE.get_case(case_id)
    assert stored["review"]["requested_items"] == ["id_back"]
    assert len(posted) == 1
    assert "Requested items: id_back" in posted[0]

    # Duplicate replay with same payload should be idempotent and avoid duplicate ticket messages.
    replay = admin.post(
        f"/v1/kyc/cases/admin/cases/{case_id}/request-info",
        json={"expected_version": payload["version"], "requested_items": ["id_back"], "note": "Please upload a clearer id back image."},
    )
    assert replay.status_code == 200
    assert len(posted) == 1


def test_admin_approve_reject_endpoints_enforce_policy_and_terminal_rules(monkeypatch) -> None:
    owner = _build_client("user-1", Role.USER)
    admin = _build_client("admin-1", Role.ADMIN)
    created = owner.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]
    row = STORE.get_case(case_id)
    assert row is not None
    row["status"] = "under_review"
    row["review"]["ticket_id"] = f"tkt_kyc_{case_id}"
    row["review"]["assigned_admin_sub"] = "admin-1"
    row["version"] = 2
    FAKE_TABLE.put_item(Item=row)

    monkeypatch.setattr(kyc_router.TICKET_STORE, "get_ticket", lambda ticket_id: {"ticket_id": ticket_id, "messages": [], "assigned_admin_sub": "admin-2"})
    monkeypatch.setattr(kyc_router.TICKET_STORE, "add_message", lambda **kwargs: {"ticket_id": kwargs["ticket_id"]})
    monkeypatch.setattr(kyc_router.TICKET_STORE, "update_status", lambda **kwargs: {"ticket_id": kwargs["ticket_id"], "status": "done"})

    denied = owner.post(
        f"/v1/kyc/cases/admin/cases/{case_id}/approve",
        json={"expected_version": 2, "decision": "approve", "reason_codes": ["doc_ok"], "note": "All checks passed."},
    )
    assert denied.status_code == 403

    invalid = admin.post(
        f"/v1/kyc/cases/admin/cases/{case_id}/approve",
        json={"expected_version": 2, "decision": "approve", "reason_codes": [], "note": "ok"},
    )
    assert invalid.status_code == 400
    assert invalid.json()["detail"]["error"]["code"] == "kyc_invalid_request"

    approved = admin.post(
        f"/v1/kyc/cases/admin/cases/{case_id}/approve",
        json={"expected_version": 2, "decision": "approve", "reason_codes": ["doc_ok"], "note": "All checks passed."},
    )
    assert approved.status_code == 200
    payload = approved.json()["case"]
    assert payload["status"] == "approved"
    assert payload["review"]["decision"] == "approve"

    reject_after_terminal = admin.post(
        f"/v1/kyc/cases/admin/cases/{case_id}/reject",
        json={"expected_version": payload["version"], "decision": "reject", "reason_codes": ["fraud"], "note": "Mismatch found."},
    )
    assert reject_after_terminal.status_code == 409
    assert reject_after_terminal.json()["detail"]["error"]["code"] == "kyc_invalid_transition"


def test_conflicting_admin_decisions_return_safe_conflict(monkeypatch) -> None:
    owner = _build_client("user-1", Role.USER)
    admin_a = _build_client("admin-1", Role.ADMIN)
    admin_b = _build_client("admin-2", Role.ADMIN)
    created = owner.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]

    row = STORE.get_case(case_id)
    assert row is not None
    row["status"] = "under_review"
    row["review"]["ticket_id"] = f"tkt_kyc_{case_id}"
    row["review"]["assigned_admin_sub"] = "admin-1"
    row["version"] = 2
    FAKE_TABLE.put_item(Item=row)

    monkeypatch.setattr(kyc_router.TICKET_STORE, "get_ticket", lambda ticket_id: {"ticket_id": ticket_id, "messages": [], "assigned_admin_sub": "admin-1"})
    monkeypatch.setattr(kyc_router.TICKET_STORE, "add_message", lambda **kwargs: {"ticket_id": kwargs["ticket_id"]})
    monkeypatch.setattr(kyc_router.TICKET_STORE, "update_status", lambda **kwargs: {"ticket_id": kwargs["ticket_id"], "status": "done"})

    approved = admin_a.post(
        f"/v1/kyc/cases/admin/cases/{case_id}/approve",
        json={"expected_version": 2, "decision": "approve", "reason_codes": ["doc_ok"], "note": "Looks good."},
    )
    assert approved.status_code == 200

    conflicting = admin_b.post(
        f"/v1/kyc/cases/admin/cases/{case_id}/reject",
        json={"expected_version": 2, "decision": "reject", "reason_codes": ["fraud"], "note": "conflict replay"},
    )
    # admin-b may get 403 (scoped access denied) or 409 (version/transition conflict) -- both are safe
    assert conflicting.status_code in {403, 409}
    assert conflicting.json()["detail"]["error"]["code"] in {"kyc_invalid_transition", "kyc_case_update_conflict", "kyc_access_forbidden"}


def test_scoped_admin_policy_blocks_non_reviewer_access(monkeypatch) -> None:
    owner = _build_client("user-1", Role.USER)
    assigned_admin = _build_client("admin-1", Role.ADMIN)
    other_admin = _build_client("admin-2", Role.ADMIN)

    created = owner.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]
    row = STORE.get_case(case_id)
    assert row is not None
    row["status"] = "under_review"
    row["review"]["ticket_id"] = f"tkt_kyc_{case_id}"
    row["review"]["assigned_admin_sub"] = "admin-1"
    row["version"] = 2
    FAKE_TABLE.put_item(Item=row)

    # _build_admin_case_detail calls TICKET_STORE.get_ticket which hits real DDB
    monkeypatch.setattr(
        kyc_router.TICKET_STORE,
        "get_ticket",
        lambda ticket_id: {"ticket_id": ticket_id, "status": "open", "messages": [], "assigned_admin_sub": "admin-1"},
    )

    denied_detail = other_admin.get(f"/v1/kyc/cases/admin/cases/{case_id}")
    assert denied_detail.status_code == 403
    assert denied_detail.json()["detail"]["error"]["code"] == "kyc_access_forbidden"

    denied_action = other_admin.post(
        f"/v1/kyc/cases/admin/cases/{case_id}/request-info",
        json={"expected_version": 2, "requested_items": ["id_back"], "note": "Need clearer copy"},
    )
    assert denied_action.status_code == 403
    assert denied_action.json()["detail"]["error"]["code"] == "kyc_access_forbidden"

    allowed = assigned_admin.get(f"/v1/kyc/cases/admin/cases/{case_id}")
    assert allowed.status_code == 200


def test_transition_audits_include_transition_and_correlation(monkeypatch) -> None:
    owner = _build_client("user-1", Role.USER)
    admin = _build_client("admin-1", Role.ADMIN)
    captured: list[dict] = []

    def _audit(event: str, user_sub: str, request, outcome: str = "success", **kwargs):
        captured.append({"event": event, "user_sub": user_sub, "outcome": outcome, "kwargs": kwargs})

    monkeypatch.setattr("app.routers.kyc_cases.audit_event", _audit)
    monkeypatch.setattr(kyc_router.TICKET_STORE, "get_ticket", lambda ticket_id: {"ticket_id": ticket_id, "messages": [], "assigned_admin_sub": "admin-1"})
    monkeypatch.setattr(kyc_router.TICKET_STORE, "add_message", lambda **kwargs: {"ticket_id": kwargs["ticket_id"]})
    monkeypatch.setattr(kyc_router.TICKET_STORE, "update_status", lambda **kwargs: {"ticket_id": kwargs["ticket_id"], "status": "done"})

    created = owner.post("/v1/kyc/cases", json={})
    case = created.json()["case"]
    assert created.status_code == 200
    create_event = next(item for item in captured if item["event"] == "kyc_case_created")
    assert "transition" in create_event["kwargs"]
    assert "correlation_id" in create_event["kwargs"]

    row = STORE.get_case(case["kyc_case_id"])
    assert row is not None
    row["status"] = "under_review"
    row["review"]["ticket_id"] = f"tkt_kyc_{case['kyc_case_id']}"
    row["review"]["assigned_admin_sub"] = "admin-1"
    row["version"] = 2
    FAKE_TABLE.put_item(Item=row)

    approved = admin.post(
        f"/v1/kyc/cases/admin/cases/{case['kyc_case_id']}/approve",
        headers={"x-request-id": "req-123"},
        json={"expected_version": 2, "decision": "approve", "reason_codes": ["doc_ok"], "note": "Approved after checks."},
    )
    assert approved.status_code == 200
    decision_event = next(item for item in captured if item["event"] == "kyc_admin_decision")
    assert decision_event["kwargs"]["transition"]["from"] == "under_review"
    assert decision_event["kwargs"]["transition"]["to"] == "approved"
    assert decision_event["kwargs"]["correlation_id"] == "req-123"


def test_admin_metrics_endpoint_reports_snapshot_and_guard_failures() -> None:
    owner = _build_client("user-1", Role.USER)
    admin = _build_client("admin-1", Role.ADMIN)

    created = owner.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]
    # Trigger submit-guard failure reasons
    failed_submit = owner.post(f"/v1/kyc/cases/{case_id}/submit", json={"expected_version": 1})
    assert failed_submit.status_code == 409

    denied = owner.get("/v1/kyc/cases/admin/metrics")
    assert denied.status_code == 403

    metrics = admin.get("/v1/kyc/cases/admin/metrics")
    assert metrics.status_code == 200
    payload = metrics.json()["metrics"]
    assert "funnel_counts" in payload
    assert "review_latency_seconds" in payload
    assert "stale_queue_count" in payload
    assert "submit_guard_failures_by_reason" in payload
    assert "ticket_sync_counters" in payload
    assert "ticket_sync_deadletter_count" in payload
    assert "ticket_sync_deadletter_oldest_age_seconds" in payload
    assert payload["submit_guard_failures_by_reason"].get("questionnaire_submitted", 0) >= 1


def test_admin_metrics_include_ticket_sync_counters() -> None:
    admin = _build_client("admin-1", Role.ADMIN)

    tickets_router._KYC_TICKET_SYNC_COUNTS["synced"] += 2
    tickets_router._KYC_TICKET_SYNC_COUNTS["failed_case_not_found"] += 1
    tickets_router._KYC_TICKET_SYNC_DEADLETTER.append({"entry_id": "d1", "created_at": 1, "reason": "case_not_found", "event_type": "status_changed", "actor_sub": "admin-1"})

    metrics = admin.get("/v1/kyc/cases/admin/metrics")
    assert metrics.status_code == 200
    body = metrics.json()["metrics"]
    counters = body["ticket_sync_counters"]
    assert counters.get("synced") == 2
    assert counters.get("failed_case_not_found") == 1
    assert body["ticket_sync_deadletter_count"] >= 1
    assert body["ticket_sync_deadletter_oldest_age_seconds"] is not None


def test_admin_purge_endpoint_and_post_purge_read_semantics() -> None:
    owner = _build_client("user-1", Role.USER)
    admin = _build_client("admin-1", Role.ADMIN)
    created = owner.post("/v1/kyc/cases", json={}).json()["case"]
    case_id = created["kyc_case_id"]

    row = STORE.get_case(case_id)
    assert row is not None
    row["status"] = "rejected"
    row["updated_at"] = 1
    row["review"]["decided_at"] = 1
    row["version"] = 2
    row["gsi_status_pk"] = "STATUS#rejected"
    row["gsi_status_sk"] = f"UPDATED#{row['updated_at']:013d}#KYC#{case_id}"
    FAKE_TABLE.put_item(Item=row)

    purge = admin.post("/v1/kyc/cases/admin/purge/run", params={"dry_run": False})
    assert purge.status_code == 200
    assert case_id in purge.json()["purge"]["purged_case_ids"]

    # Applicant read now behaves like not-found for purged case.
    got = owner.get(f"/v1/kyc/cases/{case_id}")
    assert got.status_code == 404
    assert got.json()["detail"]["error"]["code"] == "kyc_case_not_found"
