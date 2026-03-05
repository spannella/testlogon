from __future__ import annotations

from dataclasses import dataclass, field
import base64
import json
from uuid import uuid4
from typing import Any, Protocol

from app.core.crypto import kms_decrypt, kms_encrypt
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


class QuestionnaireRepository(Protocol):
    def get_questionnaire(self, questionnaire_id: str) -> dict[str, Any] | None: ...
    def create_draft(self, *, questionnaire_id: str, owner_id: str, title: str, description: str = "", visibility: str = "private", actor_sub: str) -> dict[str, Any]: ...
    def update_draft_metadata(self, *, questionnaire_id: str, owner_id: str, title: str | None = None, description: str | None = None, visibility: str | None = None, actor_sub: str) -> dict[str, Any] | None: ...
    def archive_draft(self, *, questionnaire_id: str, owner_id: str, actor_sub: str) -> dict[str, Any] | None: ...
    def rebind_response_version(self, *, questionnaire_id: str, response_session_id: str, new_version_id: str) -> dict[str, Any] | None: ...
    def list_questionnaires_by_owner(self, owner_id: str, *, limit: int = 25) -> list[dict[str, Any]]: ...
    def list_questionnaires_by_status(self, status: str, *, limit: int = 25) -> list[dict[str, Any]]: ...
    def get_published_by_slug(self, published_slug: str) -> dict[str, Any] | None: ...
    def list_response_sessions_by_status(self, status: str, *, limit: int = 25) -> list[dict[str, Any]]: ...
    def publish_draft(self, *, questionnaire_id: str, owner_id: str, actor_sub: str, published_slug: str | None = None) -> dict[str, Any]: ...
    def get_response_session(self, *, questionnaire_id: str, response_session_id: str) -> dict[str, Any] | None: ...
    def list_session_answers(self, *, questionnaire_id: str, response_session_id: str) -> dict[str, Any]: ...
    def save_session_answers(self, *, questionnaire_id: str, response_session_id: str, answers_by_question_id: dict[str, Any], current_section_index: int | None = None, current_question_id: str | None = None) -> dict[str, Any] | None: ...
    def mark_response_submitted(self, *, questionnaire_id: str, response_session_id: str, actor_sub: str | None = None) -> dict[str, Any] | None: ...
    def put_response_pdf_artifact(self, *, questionnaire_id: str, response_session_id: str, pdf_bytes: bytes, generated_by: str | None = None) -> dict[str, Any]: ...
    def get_response_pdf_artifact(self, *, questionnaire_id: str, response_session_id: str) -> dict[str, Any] | None: ...
    def list_response_sessions(self, *, questionnaire_id: str) -> list[dict[str, Any]]: ...
    def put_response_event(self, *, questionnaire_id: str, response_session_id: str, event_type: str, payload: dict[str, Any] | None = None, actor_sub: str | None = None) -> dict[str, Any]: ...
    def list_response_events(self, *, questionnaire_id: str, response_session_id: str | None = None, event_type: str | None = None) -> list[dict[str, Any]]: ...


@dataclass
class DynamoQuestionnaireRepository:
    _table: Any = field(default=T.questionnaires)

    def get_questionnaire(self, questionnaire_id: str) -> dict[str, Any] | None:
        return self._table.get_item(Key={"pk": _q_pk(questionnaire_id), "sk": "META"}).get("Item")

    def create_draft(self, *, questionnaire_id: str, owner_id: str, title: str, description: str = "", visibility: str = "private", actor_sub: str) -> dict[str, Any]:
        return self.put_questionnaire(
            questionnaire_id=questionnaire_id,
            owner_id=owner_id,
            title=title,
            description=description,
            visibility=visibility,
            actor_sub=actor_sub,
        )

    def update_draft_metadata(self, *, questionnaire_id: str, owner_id: str, title: str | None = None, description: str | None = None, visibility: str | None = None, actor_sub: str) -> dict[str, Any] | None:
        existing = self.get_questionnaire(questionnaire_id)
        if not existing or existing.get("owner_id") != owner_id:
            return None
        ts = str(now_ts())
        assignments = ["updated_at=:updated_at", "updated_by=:updated_by", "gsi_owner_sk=:gsi_owner_sk", "gsi_status_sk=:gsi_status_sk"]
        values: dict[str, Any] = {
            ":updated_at": ts,
            ":updated_by": actor_sub,
            ":gsi_owner_sk": _updated_sk(ts, questionnaire_id),
            ":gsi_status_sk": _updated_sk(ts, questionnaire_id),
        }
        if title is not None:
            assignments.append("title=:title")
            values[":title"] = title
        if description is not None:
            assignments.append("description=:description")
            values[":description"] = description
        if visibility is not None:
            assignments.append("visibility=:visibility")
            values[":visibility"] = visibility
        self._table.update_item(
            Key={"pk": _q_pk(questionnaire_id), "sk": "META"},
            UpdateExpression="SET " + ", ".join(assignments),
            ExpressionAttributeValues=values,
        )
        return self.get_questionnaire(questionnaire_id)

    def archive_draft(self, *, questionnaire_id: str, owner_id: str, actor_sub: str) -> dict[str, Any] | None:
        existing = self.get_questionnaire(questionnaire_id)
        if not existing or existing.get("owner_id") != owner_id:
            return None
        ts = str(now_ts())
        self._table.update_item(
            Key={"pk": _q_pk(questionnaire_id), "sk": "META"},
            UpdateExpression="SET #status=:archived, archived_at=:archived_at, archived_by=:archived_by, updated_at=:updated_at, updated_by=:updated_by, gsi_status_pk=:gsi_status_pk, gsi_status_sk=:gsi_status_sk",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":archived": "archived",
                ":archived_at": ts,
                ":archived_by": actor_sub,
                ":updated_at": ts,
                ":updated_by": actor_sub,
                ":gsi_status_pk": _status_pk("archived"),
                ":gsi_status_sk": _updated_sk(ts, questionnaire_id),
            },
        )
        return self.get_questionnaire(questionnaire_id)

    def put_questionnaire(self, *, questionnaire_id: str, owner_id: str, title: str, description: str = "", visibility: str = "private", actor_sub: str | None = None) -> dict[str, Any]:
        ts = str(now_ts())
        actor_sub = actor_sub or owner_id
        item = {
            "pk": _q_pk(questionnaire_id),
            "sk": "META",
            "entity_type": "questionnaire",
            "questionnaire_id": questionnaire_id,
            "owner_id": owner_id,
            "title": title,
            "description": description,
            "status": "draft",
            "visibility": visibility,
            "published_version_id": None,
            "created_at": ts,
            "updated_at": ts,
            "created_by": actor_sub,
            "updated_by": actor_sub,
            "gsi_owner_pk": _owner_pk(owner_id),
            "gsi_owner_sk": _updated_sk(ts, questionnaire_id),
            "gsi_status_pk": _status_pk("draft"),
            "gsi_status_sk": _updated_sk(ts, questionnaire_id),
        }
        self._table.put_item(Item=item)
        return item

    def create_section(self, *, questionnaire_id: str, section_id: str, title: str, description: str, actor_sub: str) -> dict[str, Any]:
        ts = str(now_ts())
        sections = self.list_sections(questionnaire_id)
        item = {
            "pk": _q_pk(questionnaire_id),
            "sk": _section_sk(section_id),
            "entity_type": "section",
            "questionnaire_id": questionnaire_id,
            "section_id": section_id,
            "title": title,
            "description": description,
            "position": len(sections),
            "created_at": ts,
            "updated_at": ts,
            "created_by": actor_sub,
            "updated_by": actor_sub,
            "deleted_at": None,
        }
        self._table.put_item(Item=item)
        return item

    def list_sections(self, questionnaire_id: str, *, include_deleted: bool = False) -> list[dict[str, Any]]:
        items = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
            ExpressionAttributeValues={":pk": _q_pk(questionnaire_id), ":sk_prefix": "SECTION#"},
            ScanIndexForward=True,
        ).get("Items", [])
        rows = [r for r in items if r.get("entity_type") == "section"]
        if not include_deleted:
            rows = [r for r in rows if not r.get("deleted_at")]
        return sorted(rows, key=lambda r: int(r.get("position", 0)))

    def update_section(self, *, questionnaire_id: str, section_id: str, title: str | None, description: str | None, actor_sub: str) -> dict[str, Any] | None:
        existing = self._table.get_item(Key={"pk": _q_pk(questionnaire_id), "sk": _section_sk(section_id)}).get("Item")
        if not existing or existing.get("deleted_at"):
            return None
        ts = str(now_ts())
        assignments = ["updated_at=:updated_at", "updated_by=:updated_by"]
        values: dict[str, Any] = {":updated_at": ts, ":updated_by": actor_sub}
        if title is not None:
            assignments.append("title=:title")
            values[":title"] = title
        if description is not None:
            assignments.append("description=:description")
            values[":description"] = description
        self._table.update_item(
            Key={"pk": _q_pk(questionnaire_id), "sk": _section_sk(section_id)},
            UpdateExpression="SET " + ", ".join(assignments),
            ExpressionAttributeValues=values,
        )
        return self._table.get_item(Key={"pk": _q_pk(questionnaire_id), "sk": _section_sk(section_id)}).get("Item")

    def delete_section(self, *, questionnaire_id: str, section_id: str, actor_sub: str) -> dict[str, Any] | None:
        existing = self._table.get_item(Key={"pk": _q_pk(questionnaire_id), "sk": _section_sk(section_id)}).get("Item")
        if not existing or existing.get("deleted_at"):
            return None
        ts = str(now_ts())
        self._table.update_item(
            Key={"pk": _q_pk(questionnaire_id), "sk": _section_sk(section_id)},
            UpdateExpression="SET deleted_at=:deleted_at, deleted_by=:deleted_by, updated_at=:updated_at, updated_by=:updated_by",
            ExpressionAttributeValues={":deleted_at": ts, ":deleted_by": actor_sub, ":updated_at": ts, ":updated_by": actor_sub},
        )
        return self._table.get_item(Key={"pk": _q_pk(questionnaire_id), "sk": _section_sk(section_id)}).get("Item")

    def reorder_sections(self, *, questionnaire_id: str, ordered_section_ids: list[str], actor_sub: str) -> list[dict[str, Any]]:
        ts = str(now_ts())
        for pos, section_id in enumerate(ordered_section_ids):
            self._table.update_item(
                Key={"pk": _q_pk(questionnaire_id), "sk": _section_sk(section_id)},
                UpdateExpression="SET position=:position, updated_at=:updated_at, updated_by=:updated_by",
                ExpressionAttributeValues={":position": pos, ":updated_at": ts, ":updated_by": actor_sub},
            )
        return self.list_sections(questionnaire_id)

    def create_question(
        self,
        *,
        questionnaire_id: str,
        section_id: str,
        question_id: str,
        question_type: str,
        label: str,
        required: bool,
        hint: str,
        config_json: dict[str, Any],
        actor_sub: str,
    ) -> dict[str, Any]:
        ts = str(now_ts())
        section_questions = self.list_questions(questionnaire_id, section_id)
        item = {
            "pk": _q_pk(questionnaire_id),
            "sk": _question_sk(section_id, question_id),
            "entity_type": "question",
            "questionnaire_id": questionnaire_id,
            "section_id": section_id,
            "question_id": question_id,
            "type": question_type,
            "label": label,
            "required": required,
            "hint": hint,
            "config_json": config_json,
            "position": len(section_questions),
            "created_at": ts,
            "updated_at": ts,
            "created_by": actor_sub,
            "updated_by": actor_sub,
            "deleted_at": None,
        }
        self._table.put_item(Item=item)
        return item

    def list_questions(self, questionnaire_id: str, section_id: str, *, include_deleted: bool = False) -> list[dict[str, Any]]:
        items = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
            ExpressionAttributeValues={":pk": _q_pk(questionnaire_id), ":sk_prefix": f"QUESTION#{section_id}#"},
            ScanIndexForward=True,
        ).get("Items", [])
        rows = [r for r in items if r.get("entity_type") == "question" and r.get("section_id") == section_id]
        if not include_deleted:
            rows = [r for r in rows if not r.get("deleted_at")]
        return sorted(rows, key=lambda r: int(r.get("position", 0)))

    def update_question(
        self,
        *,
        questionnaire_id: str,
        section_id: str,
        question_id: str,
        label: str | None,
        required: bool | None,
        hint: str | None,
        config_json: dict[str, Any] | None,
        actor_sub: str,
    ) -> dict[str, Any] | None:
        existing = self._table.get_item(Key={"pk": _q_pk(questionnaire_id), "sk": _question_sk(section_id, question_id)}).get("Item")
        if not existing or existing.get("deleted_at"):
            return None
        ts = str(now_ts())
        assignments = ["updated_at=:updated_at", "updated_by=:updated_by"]
        values: dict[str, Any] = {":updated_at": ts, ":updated_by": actor_sub}
        if label is not None:
            assignments.append("label=:label")
            values[":label"] = label
        if required is not None:
            assignments.append("required=:required")
            values[":required"] = required
        if hint is not None:
            assignments.append("hint=:hint")
            values[":hint"] = hint
        if config_json is not None:
            assignments.append("config_json=:config_json")
            values[":config_json"] = config_json
        self._table.update_item(
            Key={"pk": _q_pk(questionnaire_id), "sk": _question_sk(section_id, question_id)},
            UpdateExpression="SET " + ", ".join(assignments),
            ExpressionAttributeValues=values,
        )
        return self._table.get_item(Key={"pk": _q_pk(questionnaire_id), "sk": _question_sk(section_id, question_id)}).get("Item")

    def delete_question(self, *, questionnaire_id: str, section_id: str, question_id: str, actor_sub: str) -> dict[str, Any] | None:
        existing = self._table.get_item(Key={"pk": _q_pk(questionnaire_id), "sk": _question_sk(section_id, question_id)}).get("Item")
        if not existing or existing.get("deleted_at"):
            return None
        ts = str(now_ts())
        self._table.update_item(
            Key={"pk": _q_pk(questionnaire_id), "sk": _question_sk(section_id, question_id)},
            UpdateExpression="SET deleted_at=:deleted_at, deleted_by=:deleted_by, updated_at=:updated_at, updated_by=:updated_by",
            ExpressionAttributeValues={":deleted_at": ts, ":deleted_by": actor_sub, ":updated_at": ts, ":updated_by": actor_sub},
        )
        return self._table.get_item(Key={"pk": _q_pk(questionnaire_id), "sk": _question_sk(section_id, question_id)}).get("Item")

    def reorder_questions(self, *, questionnaire_id: str, section_id: str, ordered_question_ids: list[str], actor_sub: str) -> list[dict[str, Any]]:
        ts = str(now_ts())
        for pos, question_id in enumerate(ordered_question_ids):
            self._table.update_item(
                Key={"pk": _q_pk(questionnaire_id), "sk": _question_sk(section_id, question_id)},
                UpdateExpression="SET position=:position, updated_at=:updated_at, updated_by=:updated_by",
                ExpressionAttributeValues={":position": pos, ":updated_at": ts, ":updated_by": actor_sub},
            )
        return self.list_questions(questionnaire_id, section_id)

    def build_schema_snapshot(self, questionnaire_id: str) -> dict[str, Any]:
        sections = self.list_sections(questionnaire_id)
        snapshot_sections: list[dict[str, Any]] = []
        for section in sections:
            questions = self.list_questions(questionnaire_id, section["section_id"])  # excludes deleted
            snapshot_sections.append(
                {
                    "section_id": section["section_id"],
                    "title": section.get("title", ""),
                    "description": section.get("description", ""),
                    "position": section.get("position", 0),
                    "questions": [
                        {
                            "question_id": q["question_id"],
                            "section_id": q["section_id"],
                            "type": q.get("type", "text"),
                            "label": q.get("label", ""),
                            "required": bool(q.get("required", False)),
                            "hint": q.get("hint", ""),
                            "config_json": q.get("config_json", {}),
                            "position": q.get("position", 0),
                        }
                        for q in questions
                    ],
                }
            )
        return {"questionnaire_id": questionnaire_id, "sections": snapshot_sections}

    def list_versions(self, questionnaire_id: str) -> list[dict[str, Any]]:
        items = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
            ExpressionAttributeValues={":pk": _q_pk(questionnaire_id), ":sk_prefix": "VERSION#"},
            ScanIndexForward=True,
        ).get("Items", [])
        rows = [r for r in items if r.get("entity_type") == "questionnaire_version"]
        return sorted(rows, key=lambda r: int(r.get("version_number", 0)))

    def get_version_by_id(self, questionnaire_id: str, version_id: str) -> dict[str, Any] | None:
        for row in self.list_versions(questionnaire_id):
            if row.get("version_id") == version_id:
                return row
        return None

    def publish_draft(self, *, questionnaire_id: str, owner_id: str, actor_sub: str, published_slug: str | None = None) -> dict[str, Any]:
        draft = self.get_questionnaire(questionnaire_id)
        if not draft:
            raise ValueError("questionnaire_not_found")
        if draft.get("owner_id") != owner_id:
            raise PermissionError("questionnaire_forbidden")
        if draft.get("status") == "archived":
            raise ValueError("questionnaire_archived")

        versions = self.list_versions(questionnaire_id)
        next_version_number = (int(versions[-1]["version_number"]) + 1) if versions else 1
        version_id = f"ver_{uuid4().hex}"
        slug = (published_slug or draft.get("questionnaire_id") or questionnaire_id).strip()
        schema_json = self.build_schema_snapshot(questionnaire_id)
        return self.put_version(
            questionnaire_id=questionnaire_id,
            version_id=version_id,
            version_number=next_version_number,
            schema_json=schema_json,
            published_slug=slug,
            actor_sub=actor_sub,
        )

    def put_version(
        self,
        *,
        questionnaire_id: str,
        version_id: str,
        version_number: int,
        schema_json: dict[str, Any],
        published_slug: str,
        actor_sub: str | None = None,
    ) -> dict[str, Any]:
        ts = str(now_ts())
        item = {
            "pk": _q_pk(questionnaire_id),
            "sk": f"VERSION#{version_number:06d}",
            "entity_type": "questionnaire_version",
            "questionnaire_id": questionnaire_id,
            "version_id": version_id,
            "version_number": version_number,
            "schema_json": schema_json,
            "published_slug": published_slug,
            "published_at": ts,
            "published_by": actor_sub,
            "visibility": (self.get_questionnaire(questionnaire_id) or {}).get("visibility", "private"),
            "allow_anonymous": (self.get_questionnaire(questionnaire_id) or {}).get("visibility", "private") != "private",
            "gsi_published_pk": _published_pk(published_slug),
            "gsi_published_sk": f"VERSION#{version_number:06d}",
        }
        self._table.put_item(Item=item)
        self._table.update_item(
            Key={"pk": _q_pk(questionnaire_id), "sk": "META"},
            UpdateExpression="SET #status=:status, published_version_id=:version_id, updated_at=:updated, gsi_status_pk=:gsi_status_pk, gsi_status_sk=:gsi_status_sk",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":status": "published",
                ":version_id": version_id,
                ":updated": ts,
                ":gsi_status_pk": _status_pk("published"),
                ":gsi_status_sk": _updated_sk(ts, questionnaire_id),
            },
        )
        return item

    def put_response_session(self, *, response_session_id: str, questionnaire_id: str, version_id: str, respondent_id: str | None = None) -> dict[str, Any]:
        ts = str(now_ts())
        item = {
            "pk": _q_pk(questionnaire_id),
            "sk": f"RESP#{response_session_id}",
            "entity_type": "response_session",
            "response_session_id": response_session_id,
            "questionnaire_id": questionnaire_id,
            "version_id": version_id,
            "respondent_id": respondent_id,
            "status": "in_progress",
            "started_at": ts,
            "submitted_at": None,
            "current_section_index": 0,
            "gsi_response_status_pk": _response_status_pk("in_progress"),
            "gsi_response_status_sk": _updated_sk(ts, response_session_id),
        }
        self._table.put_item(Item=item)
        return item

    def mark_response_submitted(self, *, questionnaire_id: str, response_session_id: str, actor_sub: str | None = None) -> dict[str, Any] | None:
        key = {"pk": _q_pk(questionnaire_id), "sk": f"RESP#{response_session_id}"}
        item = self._table.get_item(Key=key).get("Item")
        if not item:
            return None

        ts = str(now_ts())
        if item.get("status") != "submitted":
            self._table.update_item(
                Key=key,
                ConditionExpression="#status=:in_progress",
                UpdateExpression="SET #status=:submitted, submitted_at=:submitted_at, gsi_response_status_pk=:gsi_response_status_pk, gsi_response_status_sk=:gsi_response_status_sk",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":in_progress": "in_progress",
                    ":submitted": "submitted",
                    ":submitted_at": ts,
                    ":gsi_response_status_pk": _response_status_pk("submitted"),
                    ":gsi_response_status_sk": _updated_sk(ts, response_session_id),
                },
            )
            item = self._table.get_item(Key=key).get("Item")

        self.put_response_event(
            questionnaire_id=questionnaire_id,
            response_session_id=response_session_id,
            event_type="response_session_submitted",
            payload={"status": item.get("status"), "version_id": item.get("version_id")},
            actor_sub=actor_sub,
        )
        return item

    def put_response_pdf_artifact(self, *, questionnaire_id: str, response_session_id: str, pdf_bytes: bytes, generated_by: str | None = None) -> dict[str, Any]:
        ts = str(now_ts())
        item = {
            "pk": _q_pk(questionnaire_id),
            "sk": f"PDF#RESP#{response_session_id}",
            "entity_type": "response_session_pdf",
            "questionnaire_id": questionnaire_id,
            "response_session_id": response_session_id,
            "content_type": "application/pdf",
            "pdf_base64": base64.b64encode(pdf_bytes).decode("ascii"),
            "size_bytes": len(pdf_bytes),
            "generated_at": ts,
            "generated_by": generated_by,
        }
        self._table.put_item(Item=item)
        return item

    def get_response_pdf_artifact(self, *, questionnaire_id: str, response_session_id: str) -> dict[str, Any] | None:
        return self._table.get_item(Key={"pk": _q_pk(questionnaire_id), "sk": f"PDF#RESP#{response_session_id}"}).get("Item")

    def list_response_sessions(self, *, questionnaire_id: str) -> list[dict[str, Any]]:
        items = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
            ExpressionAttributeValues={":pk": _q_pk(questionnaire_id), ":sk_prefix": "RESP#"},
            ScanIndexForward=True,
        ).get("Items", [])
        rows = [row for row in items if row.get("entity_type") == "response_session"]
        return sorted(rows, key=lambda row: int(row.get("started_at", 0)))

    def put_response_event(self, *, questionnaire_id: str, response_session_id: str, event_type: str, payload: dict[str, Any] | None = None, actor_sub: str | None = None) -> dict[str, Any]:
        ts = str(now_ts())
        item = {
            "pk": _q_pk(questionnaire_id),
            "sk": f"EVENT#RESP#{response_session_id}#{event_type}#{ts}",
            "entity_type": "response_session_audit_event",
            "questionnaire_id": questionnaire_id,
            "response_session_id": response_session_id,
            "event_type": event_type,
            "event_at": ts,
            "actor_sub": actor_sub,
            "payload": payload or {},
        }
        self._table.put_item(Item=item)
        return item

    def list_response_events(self, *, questionnaire_id: str, response_session_id: str | None = None, event_type: str | None = None) -> list[dict[str, Any]]:
        items = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
            ExpressionAttributeValues={":pk": _q_pk(questionnaire_id), ":sk_prefix": "EVENT#RESP#"},
            ScanIndexForward=True,
        ).get("Items", [])
        rows = [row for row in items if row.get("entity_type") == "response_session_audit_event"]
        if response_session_id is not None:
            rows = [row for row in rows if row.get("response_session_id") == response_session_id]
        if event_type is not None:
            rows = [row for row in rows if row.get("event_type") == event_type]
        return rows

    def rebind_response_version(self, *, questionnaire_id: str, response_session_id: str, new_version_id: str) -> dict[str, Any] | None:
        """Allows rebinding only before submit; submitted responses remain immutable."""
        key = {"pk": _q_pk(questionnaire_id), "sk": f"RESP#{response_session_id}"}
        item = self._table.get_item(Key=key).get("Item")
        if not item:
            return None
        if item.get("status") == "submitted":
            raise ValueError("submitted response sessions cannot be reassigned to another version")
        self._table.update_item(
            Key=key,
            UpdateExpression="SET version_id=:version_id",
            ExpressionAttributeValues={":version_id": new_version_id},
        )
        return self._table.get_item(Key=key).get("Item")

    def get_response_session(self, *, questionnaire_id: str, response_session_id: str) -> dict[str, Any] | None:
        return self._table.get_item(Key={"pk": _q_pk(questionnaire_id), "sk": f"RESP#{response_session_id}"}).get("Item")

    def _sensitive_question_ids_for_version(self, *, questionnaire_id: str, version_id: str) -> set[str]:
        version = self.get_version_by_id(questionnaire_id, version_id)
        if not version:
            return set()
        schema = version.get("schema_json") or {}
        sensitive_types = {"address", "date", "time", "timezone"}
        out: set[str] = set()
        for section in schema.get("sections") or []:
            for question in section.get("questions") or []:
                qid = str(question.get("question_id") or "")
                qtype = str(question.get("type") or "")
                if qid and qtype in sensitive_types:
                    out.add(qid)
        return out

    def _encrypt_sensitive_answer(self, value: Any) -> str:
        return kms_encrypt(json.dumps(value, separators=(",", ":")))

    def _decrypt_sensitive_answer(self, ciphertext_b64: str) -> Any:
        try:
            plaintext = kms_decrypt(ciphertext_b64).decode("utf-8")
            return json.loads(plaintext)
        except Exception:
            return None

    def list_session_answers(self, *, questionnaire_id: str, response_session_id: str) -> dict[str, Any]:
        items = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
            ExpressionAttributeValues={":pk": _q_pk(questionnaire_id), ":sk_prefix": f"ANSWER#{response_session_id}#"},
            ScanIndexForward=True,
        ).get("Items", [])
        answers: dict[str, Any] = {}
        for row in items:
            if row.get("entity_type") != "answer":
                continue
            qid = str(row.get("question_id", ""))
            if not qid:
                continue
            if row.get("value_encrypted"):
                answers[qid] = self._decrypt_sensitive_answer(str(row.get("value_enc") or ""))
            else:
                answers[qid] = row.get("value")
        return answers

    def save_session_answers(
        self,
        *,
        questionnaire_id: str,
        response_session_id: str,
        answers_by_question_id: dict[str, Any],
        current_section_index: int | None = None,
        current_question_id: str | None = None,
    ) -> dict[str, Any] | None:
        session = self.get_response_session(questionnaire_id=questionnaire_id, response_session_id=response_session_id)
        if not session:
            return None
        if session.get("status") != "in_progress":
            return session

        ts = str(now_ts())
        sensitive_question_ids = self._sensitive_question_ids_for_version(
            questionnaire_id=questionnaire_id,
            version_id=str(session.get("version_id") or ""),
        )
        encrypt_sensitive = bool(getattr(S, "questionnaire_encrypt_sensitive_answers", False))

        for question_id, value in (answers_by_question_id or {}).items():
            item = {
                "pk": _q_pk(questionnaire_id),
                "sk": f"ANSWER#{response_session_id}#{question_id}",
                "entity_type": "answer",
                "questionnaire_id": questionnaire_id,
                "response_session_id": response_session_id,
                "question_id": question_id,
                "updated_at": ts,
            }
            if encrypt_sensitive and question_id in sensitive_question_ids:
                item["value_encrypted"] = True
                item["value_enc"] = self._encrypt_sensitive_answer(value)
            else:
                item["value_encrypted"] = False
                item["value"] = value
            self._table.put_item(Item=item)

        assignments = ["last_saved_at=:last_saved_at"]
        values: dict[str, Any] = {":last_saved_at": ts}
        if current_section_index is not None:
            assignments.append("current_section_index=:current_section_index")
            values[":current_section_index"] = max(0, int(current_section_index))
        if current_question_id is not None:
            assignments.append("current_question_id=:current_question_id")
            values[":current_question_id"] = current_question_id

        self._table.update_item(
            Key={"pk": _q_pk(questionnaire_id), "sk": f"RESP#{response_session_id}"},
            UpdateExpression="SET " + ", ".join(assignments),
            ExpressionAttributeValues=values,
        )
        return self.get_response_session(questionnaire_id=questionnaire_id, response_session_id=response_session_id)

    def list_questionnaires_by_owner(self, owner_id: str, *, limit: int = 25) -> list[dict[str, Any]]:
        return self._table.query(
            IndexName=S.questionnaire_owner_index_name,
            KeyConditionExpression="gsi_owner_pk = :pk",
            ExpressionAttributeValues={":pk": _owner_pk(owner_id)},
            Limit=max(1, min(int(limit or 25), 100)),
            ScanIndexForward=False,
        ).get("Items", [])

    def list_questionnaires_by_status(self, status: str, *, limit: int = 25) -> list[dict[str, Any]]:
        return self._table.query(
            IndexName=S.questionnaire_status_index_name,
            KeyConditionExpression="gsi_status_pk = :pk",
            ExpressionAttributeValues={":pk": _status_pk(status)},
            Limit=max(1, min(int(limit or 25), 100)),
            ScanIndexForward=False,
        ).get("Items", [])

    def get_published_by_slug(self, published_slug: str) -> dict[str, Any] | None:
        rows = self._table.query(
            IndexName=S.questionnaire_published_index_name,
            KeyConditionExpression="gsi_published_pk = :pk",
            ExpressionAttributeValues={":pk": _published_pk(published_slug)},
            Limit=1,
            ScanIndexForward=False,
        ).get("Items", [])
        return rows[0] if rows else None

    def list_response_sessions_by_status(self, status: str, *, limit: int = 25) -> list[dict[str, Any]]:
        return self._table.query(
            IndexName=S.questionnaire_response_status_index_name,
            KeyConditionExpression="gsi_response_status_pk = :pk",
            ExpressionAttributeValues={":pk": _response_status_pk(status)},
            Limit=max(1, min(int(limit or 25), 100)),
            ScanIndexForward=False,
        ).get("Items", [])


def _q_pk(questionnaire_id: str) -> str:
    return f"QNR#{questionnaire_id}"


def _owner_pk(owner_id: str) -> str:
    return f"OWNER#{owner_id}"


def _status_pk(status: str) -> str:
    return f"STATUS#{status}"


def _published_pk(slug: str) -> str:
    return f"PUBLISHED#{slug}"


def _response_status_pk(status: str) -> str:
    return f"RESPONSE_STATUS#{status}"


def _section_sk(section_id: str) -> str:
    return f"SECTION#{section_id}"


def _question_sk(section_id: str, question_id: str) -> str:
    return f"QUESTION#{section_id}#{question_id}"


def _updated_sk(updated_at: str, object_id: str) -> str:
    return f"UPDATED#{updated_at}#{object_id}"
