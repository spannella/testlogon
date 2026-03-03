from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

QuestionType = Literal[
    "text",
    "select",
    "multiselect",
    "radio",
    "slider",
    "date",
    "time",
    "timezone",
    "address",
]

QuestionnaireStatus = Literal["draft", "published", "archived"]
ResponseSessionStatus = Literal["in_progress", "submitted"]
ValidationScope = Literal["question", "group", "form"]
GroupRuleType = Literal["min_answered", "requires_if_answered", "mutually_exclusive"]
FormRuleType = Literal["requires_if_answered", "mutually_exclusive"]


class Questionnaire(BaseModel):
    questionnaire_id: str
    owner_id: str
    title: str
    description: str = ""
    status: QuestionnaireStatus = "draft"
    published_version_id: str | None = None
    created_at: datetime
    updated_at: datetime


class QuestionnaireVersion(BaseModel):
    version_id: str
    questionnaire_id: str
    version_number: int
    schema_json: dict[str, Any] = Field(default_factory=dict)
    published_at: datetime


class Section(BaseModel):
    section_id: str
    version_id: str
    title: str
    description: str = ""
    position: int = 0


class Question(BaseModel):
    question_id: str
    section_id: str
    type: QuestionType
    label: str
    hint: str = ""
    required: bool = False
    config_json: dict[str, Any] = Field(default_factory=dict)
    position: int = 0


class GroupValidationRuleDefinition(BaseModel):
    rule_id: str
    group_id: str
    rule_type: GroupRuleType
    question_ids: list[str] = Field(default_factory=list)
    config_json: dict[str, Any] = Field(default_factory=dict)


class FormValidationRuleDefinition(BaseModel):
    rule_id: str
    rule_type: FormRuleType
    config_json: dict[str, Any] = Field(default_factory=dict)
    blocking: bool = True


class ValidationRule(BaseModel):
    rule_id: str
    version_id: str
    scope: ValidationScope
    scope_ref: str
    rule_type: str
    rule_config_json: dict[str, Any] = Field(default_factory=dict)
    error_message: str


class ResponseSession(BaseModel):
    response_session_id: str
    version_id: str
    respondent_id: str | None = None
    status: ResponseSessionStatus = "in_progress"
    started_at: datetime
    submitted_at: datetime | None = None
    current_section_index: int = 0


class Answer(BaseModel):
    answer_id: str
    response_session_id: str
    question_id: str
    value_json: Any
    is_valid: bool = True
    validation_errors_json: list[dict[str, Any]] = Field(default_factory=list)
