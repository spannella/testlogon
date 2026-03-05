from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

VALIDATION_CONTRACT_VERSION = "2026-03-validation-v1"
SUPPORTED_VALIDATION_CONTRACT_VERSIONS = {VALIDATION_CONTRACT_VERSION}


class ValidationIssue(BaseModel):
    code: str
    message: str
    blocking: bool | None = None
    rule_id: str | None = None


class QuestionnaireValidationRequest(BaseModel):
    contract_version: Literal["2026-03-validation-v1"] = VALIDATION_CONTRACT_VERSION
    answers_by_question_id: dict[str, Any] = Field(default_factory=dict)
    group_rules: list[dict[str, Any]] = Field(default_factory=list)
    form_rules: list[dict[str, Any]] = Field(default_factory=list)
    final_submit: bool = False


class QuestionnaireValidationResponse(BaseModel):
    contract_version: Literal["2026-03-validation-v1"] = VALIDATION_CONTRACT_VERSION
    is_valid: bool
    can_submit: bool
    has_blocking_form_error: bool
    errors: dict[str, list[ValidationIssue]]
