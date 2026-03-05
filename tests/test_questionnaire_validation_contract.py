from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from fastapi.testclient import TestClient

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role
from app.contracts.questionnaire_validation_contract import VALIDATION_CONTRACT_VERSION, QuestionnaireValidationResponse
from app.main import create_app
from app.routers import questionnaires
from app.services.sessions import require_ui_session

CONTRACT_SCHEMA_PATH = Path("docs/questionnaire-validation-contract-v1.json")
FRONTEND_TYPES_PATH = Path("frontend/src/api/types.ts")


class _FakeTable:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict] = {}

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
        return {"Items": rows[:limit]}


def _build_client(user_sub: str, fake_table: _FakeTable) -> tuple[TestClient, object]:
    app = create_app()
    previous_table = questionnaires.REPO._table
    questionnaires.REPO._table = fake_table

    async def _auth_override():
        return AuthenticatedUser(sub=user_sub, role=Role.USER)

    async def _session_override():
        return {"user_sub": user_sub, "session_id": "sess_1", "role": Role.USER.value}

    app.dependency_overrides[get_authenticated_user] = _auth_override
    app.dependency_overrides[require_ui_session] = _session_override
    return TestClient(app), previous_table


def test_contract_schema_version_is_stable() -> None:
    assert CONTRACT_SCHEMA_PATH.exists()
    schema = json.loads(CONTRACT_SCHEMA_PATH.read_text())
    assert schema["properties"]["contract_version"]["const"] == VALIDATION_CONTRACT_VERSION


def test_frontend_types_include_validation_contract_interfaces() -> None:
    text = FRONTEND_TYPES_PATH.read_text()
    assert "QUESTIONNAIRE_VALIDATION_CONTRACT_VERSION" in text
    assert "QuestionnaireValidationReq" in text
    assert "QuestionnaireValidationResp" in text


def test_validate_endpoint_response_matches_shared_contract() -> None:
    client, previous_table = _build_client("user-1", _FakeTable())
    client.post("/questionnaires/drafts", json={"questionnaire_id": "q_contract", "title": "Q", "description": "d"})
    client.post("/questionnaires/drafts/q_contract/sections", json={"section_id": "s1", "title": "S1"})
    client.post(
        "/questionnaires/drafts/q_contract/questions",
        json={"section_id": "s1", "question_id": "q1", "type": "date", "label": "D", "required": True, "config_json": {}},
    )

    res = client.post(
        "/questionnaires/drafts/q_contract/validate",
        json={
            "contract_version": VALIDATION_CONTRACT_VERSION,
            "answers_by_question_id": {"q1": "bad-date"},
            "group_rules": [],
            "form_rules": [],
            "final_submit": False,
        },
    )
    assert res.status_code == 200

    parsed = QuestionnaireValidationResponse.model_validate(res.json())
    assert parsed.contract_version == VALIDATION_CONTRACT_VERSION
    assert "q1" in parsed.errors
    assert parsed.errors["q1"][0].code == "invalid_date_format"
    questionnaires.REPO._table = previous_table


def test_incompatible_contract_version_is_rejected() -> None:
    client, previous_table = _build_client("user-1", _FakeTable())
    client.post("/questionnaires/drafts", json={"questionnaire_id": "q_contract_2", "title": "Q", "description": "d"})

    res = client.post(
        "/questionnaires/drafts/q_contract_2/validate",
        json={
            "contract_version": "2027-01-validation-v2",
            "answers_by_question_id": {},
            "group_rules": [],
            "form_rules": [],
            "final_submit": False,
        },
    )
    assert res.status_code == 422
    questionnaires.REPO._table = previous_table
