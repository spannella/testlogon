package com.testlogon.android.core.network.agents

import com.squareup.moshi.Json

/**
 * AGENTS-BASICS (web-parity) - transport DTOs for the agents-BASICS surfaces: WORKERS, LLM keys, FLEET.
 *
 * CODEGEN NOTE (identical to the AND-398 WebhookDtos / B-APIKEY pattern): core-network does NOT apply the Moshi
 * KSP codegen plugin, so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the shared
 * Moshi in NetworkModule.provideMoshi. That factory maps Kotlin property names to JSON keys VERBATIM (Moshi does
 * NOT auto snake_case), so every wire key is pinned with an explicit @Json(name = ...).
 * @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * TIME fields are EPOCH SECONDS typed as Long (0 == "never"/"unset"). Mirrors backend app/routers/agent_workers.py,
 * app/routers/agent_fleet.py, app/routers/llm_provider_keys.py + app/models.py. All paths are require_ui_session.
 */

// ------------------------------------------------------------------ WORKERS

/** One provision-log step for a worker (GET .../{id}/provision-log and embedded in a worker). */
data class ProvisionStepDto(
    @Json(name = "step") val step: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "ts") val ts: Long = 0,
    @Json(name = "detail") val detail: String = "",
)

/** One worker (runtime agent instance). GET/POST ui/agent/workers[/{id}] + lifecycle endpoints. */
data class WorkerDto(
    @Json(name = "worker_id") val workerId: String,
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "agent_type") val agentType: String = "",
    @Json(name = "tool") val tool: String = "",
    @Json(name = "tool_version") val toolVersion: String = "",
    @Json(name = "compute_type") val computeType: String = "",
    @Json(name = "compute_instance_id") val computeInstanceId: String = "",
    @Json(name = "instance_type") val instanceType: String = "",
    @Json(name = "llm_key_id") val llmKeyId: String = "",
    @Json(name = "llm_provider") val llmProvider: String = "",
    @Json(name = "host_id") val hostId: String = "",
    @Json(name = "public_ip") val publicIp: String = "",
    @Json(name = "worker_status") val workerStatus: String = "",
    @Json(name = "provision_log") val provisionLog: List<ProvisionStepDto> = emptyList(),
    @Json(name = "repo_url") val repoUrl: String = "",
    @Json(name = "branch_convention") val branchConvention: String = "",
    @Json(name = "idle_timeout_seconds") val idleTimeoutSeconds: Long = 0,
    @Json(name = "last_activity_at") val lastActivityAt: Long = 0,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "started_at") val startedAt: Long = 0,
    @Json(name = "stopped_at") val stoppedAt: Long = 0,
    @Json(name = "terminated_at") val terminatedAt: Long = 0,
    @Json(name = "template_id") val templateId: String = "",
    @Json(name = "error_message") val errorMessage: String = "",
)

/** Envelope for GET ui/agent/workers ({workers:[...],count}). */
data class WorkerListDto(
    @Json(name = "workers") val workers: List<WorkerDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

/** Request body for POST ui/agent/workers (create a worker). */
data class CreateWorkerRequest(
    @Json(name = "label") val label: String,
    @Json(name = "agent_type") val agentType: String,
    @Json(name = "tool") val tool: String,
    @Json(name = "compute_type") val computeType: String,
    @Json(name = "instance_type") val instanceType: String,
    @Json(name = "llm_key_id") val llmKeyId: String,
    @Json(name = "repo_url") val repoUrl: String? = null,
)

/** One selectable tool (GET ui/agent/workers/tools). */
data class ToolInfoDto(
    @Json(name = "tool") val tool: String = "",
    @Json(name = "display_name") val displayName: String = "",
    @Json(name = "description") val description: String = "",
    @Json(name = "install_time_seconds") val installTimeSeconds: Long = 0,
    @Json(name = "required_provider") val requiredProvider: String = "",
)

data class ToolListDto(
    @Json(name = "tools") val tools: List<ToolInfoDto> = emptyList(),
)

/** One compute option (GET ui/agent/workers/compute-options). */
data class ComputeOptionDto(
    @Json(name = "compute_type") val computeType: String = "",
    @Json(name = "instance_type") val instanceType: String = "",
    @Json(name = "vcpu") val vcpu: Int = 0,
    @Json(name = "memory_gb") val memoryGb: Double = 0.0,
    @Json(name = "cost_cents_per_min") val costCentsPerMin: Double = 0.0,
    @Json(name = "startup_seconds") val startupSeconds: Long = 0,
)

data class ComputeOptionListDto(
    @Json(name = "options") val options: List<ComputeOptionDto> = emptyList(),
)

// ------------------------------------------------------------------ LLM KEYS

/** One LLM provider key (GET/POST ui/agent/llm-keys[/{id}]). The api_key is NEVER returned (only key_suffix). */
data class LlmKeyDto(
    @Json(name = "key_id") val keyId: String,
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "provider") val provider: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "key_suffix") val keySuffix: String = "",
    @Json(name = "base_url") val baseUrl: String = "",
    @Json(name = "model_preference") val modelPreference: String = "",
    @Json(name = "available_models") val availableModels: List<String> = emptyList(),
    @Json(name = "rate_limit_rpm") val rateLimitRpm: Int = 60,
    @Json(name = "monthly_budget_cents") val monthlyBudgetCents: Int = 0,
    @Json(name = "current_month_usage_cents") val currentMonthUsageCents: Int = 0,
    @Json(name = "total_requests") val totalRequests: Long = 0,
    @Json(name = "total_tokens_used") val totalTokensUsed: Long = 0,
    @Json(name = "status") val status: String = "active",
    @Json(name = "last_tested_at") val lastTestedAt: Long = 0,
    @Json(name = "last_used_at") val lastUsedAt: Long = 0,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "assigned_worker_ids") val assignedWorkerIds: List<String> = emptyList(),
)

data class LlmKeyListDto(
    @Json(name = "keys") val keys: List<LlmKeyDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

/** Request body for POST ui/agent/llm-keys (create/add a key). The plaintext api_key is sent once. */
data class CreateLlmKeyRequest(
    @Json(name = "provider") val provider: String,
    @Json(name = "label") val label: String,
    @Json(name = "api_key") val apiKey: String,
    @Json(name = "base_url") val baseUrl: String = "",
    @Json(name = "model_preference") val modelPreference: String = "",
    @Json(name = "rate_limit_rpm") val rateLimitRpm: Int = 60,
    @Json(name = "monthly_budget_cents") val monthlyBudgetCents: Int = 0,
)

/** Result of POST ui/agent/llm-keys/{id}/test. */
data class LlmKeyTestDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "models") val models: List<String> = emptyList(),
    @Json(name = "error") val error: String = "",
    @Json(name = "latency_ms") val latencyMs: Long = 0,
)

/** One provider descriptor (GET ui/agent/llm-providers). */
data class LlmProviderInfoDto(
    @Json(name = "provider") val provider: String = "",
    @Json(name = "display_name") val displayName: String = "",
    @Json(name = "base_url") val baseUrl: String = "",
    @Json(name = "models") val models: List<String> = emptyList(),
    @Json(name = "supports_usage_api") val supportsUsageApi: Boolean = false,
)

data class LlmProviderListDto(
    @Json(name = "providers") val providers: List<LlmProviderInfoDto> = emptyList(),
)

// ------------------------------------------------------------------ FLEET

/** A compact worker summary as embedded in the fleet status. */
data class WorkerSummaryDto(
    @Json(name = "worker_id") val workerId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "agent_type") val agentType: String = "",
    @Json(name = "tool") val tool: String = "",
    @Json(name = "worker_status") val workerStatus: String = "",
    @Json(name = "agent_state") val agentState: String = "",
    @Json(name = "current_ticket_id") val currentTicketId: String = "",
    @Json(name = "current_ticket_title") val currentTicketTitle: String = "",
    @Json(name = "uptime_seconds") val uptimeSeconds: Long = 0,
    @Json(name = "estimated_cost_cents") val estimatedCostCents: Long = 0,
    @Json(name = "tickets_completed") val ticketsCompleted: Int = 0,
)

/** GET ui/agent/fleet/status. */
data class FleetStatusDto(
    @Json(name = "total_workers") val totalWorkers: Int = 0,
    @Json(name = "status_counts") val statusCounts: Map<String, Int> = emptyMap(),
    @Json(name = "queue_depth") val queueDepth: Int = 0,
    @Json(name = "workers") val workers: List<WorkerSummaryDto> = emptyList(),
)

/** GET ui/agent/fleet/capacity (untyped server dict; keys pinned). */
data class FleetCapacityDto(
    @Json(name = "queue_by_type") val queueByType: Map<String, Int> = emptyMap(),
    @Json(name = "workers_by_type") val workersByType: Map<String, Int> = emptyMap(),
    @Json(name = "workers_by_state") val workersByState: Map<String, Int> = emptyMap(),
    @Json(name = "recommended_action") val recommendedAction: String = "",
)

/** POST ui/agent/fleet/start-all | stop-all - per-worker error entry. */
data class BulkActionErrorDto(
    @Json(name = "worker_id") val workerId: String = "",
    @Json(name = "error") val error: String = "",
)

data class BulkActionResultDto(
    @Json(name = "count") val count: Int = 0,
    @Json(name = "errors") val errors: List<BulkActionErrorDto> = emptyList(),
)

/** One fleet worker-template (GET/POST ui/agent/fleet/templates). */
data class WorkerTemplateDto(
    @Json(name = "template_id") val templateId: String,
    @Json(name = "label") val label: String = "",
    @Json(name = "agent_type") val agentType: String = "",
    @Json(name = "tool") val tool: String = "",
    @Json(name = "compute_type") val computeType: String = "",
    @Json(name = "instance_type") val instanceType: String = "",
    @Json(name = "llm_key_id") val llmKeyId: String = "",
    @Json(name = "repo_url") val repoUrl: String = "",
    @Json(name = "branch_convention") val branchConvention: String = "",
    @Json(name = "idle_timeout_seconds") val idleTimeoutSeconds: Long = 0,
    @Json(name = "created_at") val createdAt: Long = 0,
)

data class WorkerTemplateListDto(
    @Json(name = "templates") val templates: List<WorkerTemplateDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)
