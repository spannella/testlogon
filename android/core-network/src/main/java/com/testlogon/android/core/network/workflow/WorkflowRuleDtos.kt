package com.testlogon.android.core.network.workflow

import com.squareup.moshi.Json

/**
 * Transport DTOs for the SuiteCRM Workflow (WFL) admin surface — READ subset.
 *
 * Backend router: app/routers/workflow_rules.py (prefix /ui/admin/crm/workflow).
 * Gated by CRM_WORKFLOW_ENABLED (default OFF -> 404); the repository degrades on 404.
 *
 * Mirrors frontend/src/api/endpoints/crmWorkflow.ts (WorkflowRuleOut / WorkflowRuleListOut). The Android
 * MVP is list/read only, so only the read shapes are ported (create/update/delete/enable/disable + drip
 * sequences + run history are intentionally NOT ported — see repository KDoc).
 *
 * CODEGEN NOTE: reflective Moshi factory -> explicit @Json(name=...) on every key. The loosely-typed
 * config / conditions / actions payloads are Map / List<Map> of String -> Any? with @JvmSuppressWildcards
 * to keep Moshi's generic resolution happy. Timestamps are Unix-second Longs.
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
