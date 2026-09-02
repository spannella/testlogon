package com.testlogon.android.core.network.workflow

import com.squareup.moshi.Json

/**
 * Transport DTOs for the SuiteCRM Workflow (WFL) admin surface — READ + WRITE.
 *
 * Backend router: app/routers/workflow_rules.py (prefix /ui/admin/crm/workflow).
 * Gated by CRM_WORKFLOW_ENABLED (default OFF -> 404); the repository degrades on 404.
 *
 * Mirrors frontend/src/api/endpoints/crmWorkflow.ts (WorkflowRule* / WorkflowRun* / DripSequence*). The
 * full admin CRUD is ported: list/read, create (POST /rules), update (PATCH /rules/{id}), delete, enable,
 * disable, run history (GET /rules/{id}/runs), and drip-sequence CRUD (GET/POST/GET/PATCH/DELETE
 * /drip-sequences).
 *
 * CODEGEN NOTE: reflective Moshi factory -> explicit @Json(name=...) on every key. The loosely-typed
 * config / conditions / actions / stages payloads are Map / List<Map> of String -> Any? with
 * @JvmSuppressWildcards to keep Moshi's generic resolution happy. Timestamps are Unix-second Longs.
 */

/** One workflow rule (mirrors WorkflowRuleOut). `rule_id` + `name` are required. */
data class WorkflowRuleDto(
    @Json(name = "rule_id") val ruleId: String,
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String = "",
    @Json(name = "target_module") val targetModule: String = "",
    @Json(name = "trigger_type") val triggerType: String = "",
    @Json(name = "trigger_config")
    val triggerConfig: Map<String, @JvmSuppressWildcards Any?> = emptyMap(),
    @Json(name = "conditions")
    val conditions: List<Map<String, @JvmSuppressWildcards Any?>> = emptyList(),
    @Json(name = "actions")
    val actions: List<Map<String, @JvmSuppressWildcards Any?>> = emptyList(),
    @Json(name = "enabled") val enabled: Boolean = false,
    @Json(name = "created_by") val createdBy: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

/** The rule-list envelope (mirrors WorkflowRuleListOut). */
data class WorkflowRuleListDto(
    @Json(name = "rules") val rules: List<WorkflowRuleDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

// ---------------------------------------------------------------------------
// Write requests (mirror WorkflowRuleCreateIn / WorkflowRuleUpdateIn)
// ---------------------------------------------------------------------------

/** A single rule condition (mirrors WorkflowConditionIn). `value` is optional/nullable. */
data class WorkflowConditionDto(
    @Json(name = "field") val field: String,
    @Json(name = "operator") val operator: String,
    @Json(name = "value") val value: String? = null,
)

/** A single rule action (mirrors WorkflowActionIn). `config` is a loosely-typed map. */
data class WorkflowActionDto(
    @Json(name = "action_type") val actionType: String,
    @Json(name = "config") val config: Map<String, @JvmSuppressWildcards Any?> = emptyMap(),
)

/** Create body for POST /rules (mirrors WorkflowRuleCreateIn). */
data class WorkflowRuleCreateRequest(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String = "",
    @Json(name = "target_module") val targetModule: String,
    @Json(name = "trigger_type") val triggerType: String,
    @Json(name = "trigger_config")
    val triggerConfig: Map<String, @JvmSuppressWildcards Any?> = emptyMap(),
    @Json(name = "conditions") val conditions: List<WorkflowConditionDto> = emptyList(),
    @Json(name = "actions") val actions: List<WorkflowActionDto> = emptyList(),
    @Json(name = "enabled") val enabled: Boolean = false,
)

/**
 * Update body for PATCH /rules/{id} (mirrors WorkflowRuleUpdateIn). Backend uses exclude_unset so only
 * non-null fields are sent; Moshi's `serializeNulls` is OFF by default, so null fields are omitted.
 */
data class WorkflowRuleUpdateRequest(
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "trigger_config")
    val triggerConfig: Map<String, @JvmSuppressWildcards Any?>? = null,
    @Json(name = "conditions") val conditions: List<WorkflowConditionDto>? = null,
    @Json(name = "actions") val actions: List<WorkflowActionDto>? = null,
)

// ---------------------------------------------------------------------------
// Run history (mirror WorkflowRunOut / WorkflowRunListOut)
// ---------------------------------------------------------------------------

/** One rule-run history entry (mirrors WorkflowRunOut). */
data class WorkflowRunDto(
    @Json(name = "run_id") val runId: String = "",
    @Json(name = "rule_id") val ruleId: String = "",
    @Json(name = "target_module") val targetModule: String = "",
    @Json(name = "record_id") val recordId: String = "",
    @Json(name = "trigger_type") val triggerType: String = "",
    @Json(name = "outcome") val outcome: String = "",
    @Json(name = "actions_fired")
    val actionsFired: List<Map<String, @JvmSuppressWildcards Any?>> = emptyList(),
    @Json(name = "started_at") val startedAt: Long = 0,
    @Json(name = "finished_at") val finishedAt: Long? = null,
    @Json(name = "error_message") val errorMessage: String? = null,
)

/** The run-history envelope (mirrors WorkflowRunListOut). */
data class WorkflowRunListDto(
    @Json(name = "runs") val runs: List<WorkflowRunDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

// ---------------------------------------------------------------------------
// Drip sequences (mirror DripSequence* + DripStageIn)
// ---------------------------------------------------------------------------

/** One drip-sequence stage (mirrors DripStageIn). */
data class DripStageDto(
    @Json(name = "stage_number") val stageNumber: Int,
    @Json(name = "delay_hours") val delayHours: Int,
    @Json(name = "template_id") val templateId: String,
    @Json(name = "to_field") val toField: String,
)

/** One drip sequence (mirrors DripSequenceOut). Stages come back as loosely-typed maps. */
data class DripSequenceDto(
    @Json(name = "sequence_id") val sequenceId: String,
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String = "",
    @Json(name = "stages")
    val stages: List<Map<String, @JvmSuppressWildcards Any?>> = emptyList(),
    @Json(name = "created_by") val createdBy: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

/** The drip-sequence list envelope (mirrors DripSequenceListOut). */
data class DripSequenceListDto(
    @Json(name = "sequences") val sequences: List<DripSequenceDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

/** Create body for POST /drip-sequences (mirrors DripSequenceCreateIn). */
data class DripSequenceCreateRequest(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String = "",
    @Json(name = "stages") val stages: List<DripStageDto> = emptyList(),
)

/** Update body for PATCH /drip-sequences/{id} (mirrors DripSequenceUpdateIn). */
data class DripSequenceUpdateRequest(
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "stages") val stages: List<DripStageDto>? = null,
)
