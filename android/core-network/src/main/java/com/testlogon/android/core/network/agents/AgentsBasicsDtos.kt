package com.testlogon.android.core.network.agents

import com.squareup.moshi.Json

/**
 * AGENTS-BASICS (web-parity) - transport DTOs for the second wave of agents-BASICS surfaces:
 * FEEDBACK, agent PRs, agent MEMORY, and DOC-COVERAGE (+ doc templates).
 *
 * CODEGEN NOTE (identical to AgentsDtos / the AND-398 WebhookDtos pattern): core-network does NOT apply Moshi
 * KSP codegen, so these DTOs decode via the reflective KotlinJsonAdapterFactory on the shared Moshi. That
 * factory maps property names to JSON keys VERBATIM (no auto snake_case), so every wire key is pinned with an
 * explicit @Json(name = ...). @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * TIME fields are EPOCH SECONDS typed as Long (0 == "never"/"unset"). Mirrors backend
 * app/routers/agent_feedback.py, agent_pr_integration.py, agent_memory.py, agent_docs.py + app/models.py.
 * FEEDBACK/PR/MEMORY paths are ui/agent/... ; DOCS paths are ui/agents/docs/... (plural). All require_ui_session.
 */

// ------------------------------------------------------------------ FEEDBACK

/** One feedback request raised by a worker awaiting an operator response. */
data class FeedbackRequestDto(
    @Json(name = "request_id") val requestId: String,
    @Json(name = "worker_id") val workerId: String = "",
    @Json(name = "ticket_id") val ticketId: String = "",
    @Json(name = "feedback_status") val feedbackStatus: String = "",
    @Json(name = "question") val question: String = "",
    @Json(name = "terminal_context") val terminalContext: String = "",
    @Json(name = "detected_pattern") val detectedPattern: String = "",
    @Json(name = "response_text") val responseText: String = "",
    @Json(name = "responded_at") val respondedAt: Long = 0,
    @Json(name = "timeout_at") val timeoutAt: Long = 0,
    @Json(name = "timeout_action") val timeoutAction: String = "skip",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "user_id") val userId: String = "",
)

data class FeedbackListDto(
    @Json(name = "requests") val requests: List<FeedbackRequestDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
    @Json(name = "pending_count") val pendingCount: Int = 0,
)

/** Body for POST ui/agent/feedback/{workerId}/{requestId}/respond. */
data class FeedbackRespondRequest(
    @Json(name = "response_text") val responseText: String,
)

// ------------------------------------------------------------------ AGENT PRs

/** One agent-authored pull request. */
data class AgentPrDto(
    @Json(name = "pr_id") val prId: String,
    @Json(name = "worker_id") val workerId: String = "",
    @Json(name = "ticket_id") val ticketId: String = "",
    @Json(name = "repo_url") val repoUrl: String = "",
    @Json(name = "pr_url") val prUrl: String = "",
    @Json(name = "pr_number") val prNumber: Int = 0,
    @Json(name = "branch") val branch: String = "",
    @Json(name = "title") val title: String = "",
    @Json(name = "description") val description: String = "",
    @Json(name = "files_changed") val filesChanged: List<String> = emptyList(),
    @Json(name = "commit_count") val commitCount: Int = 0,
    @Json(name = "status") val status: String = "open",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "merged_at") val mergedAt: Long = 0,
    @Json(name = "user_id") val userId: String = "",
)

data class AgentPrListDto(
    @Json(name = "prs") val prs: List<AgentPrDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

// ------------------------------------------------------------------ MEMORY

/** GET/PUT ui/agent/memory/{workerId}/identity. */
data class AgentIdentityDto(
    @Json(name = "agent_type") val agentType: String = "",
    @Json(name = "identity_text") val identityText: String = "",
    @Json(name = "custom_instructions") val customInstructions: String = "",
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

data class AgentIdentityUpdateRequest(
    @Json(name = "identity_text") val identityText: String? = null,
    @Json(name = "custom_instructions") val customInstructions: String? = null,
)

/** GET/PUT ui/agent/memory/{workerId}/project. */
data class ProjectContextDto(
    @Json(name = "repo_url") val repoUrl: String = "",
    @Json(name = "branch_convention") val branchConvention: String = "",
    @Json(name = "coding_standards") val codingStandards: String = "",
    @Json(name = "pr_template") val prTemplate: String = "",
    @Json(name = "test_framework") val testFramework: String = "",
    @Json(name = "ci_commands") val ciCommands: String = "",
    @Json(name = "file_structure_notes") val fileStructureNotes: String = "",
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

data class ProjectContextUpdateRequest(
    @Json(name = "repo_url") val repoUrl: String? = null,
    @Json(name = "branch_convention") val branchConvention: String? = null,
    @Json(name = "coding_standards") val codingStandards: String? = null,
    @Json(name = "pr_template") val prTemplate: String? = null,
    @Json(name = "test_framework") val testFramework: String? = null,
    @Json(name = "ci_commands") val ciCommands: String? = null,
    @Json(name = "file_structure_notes") val fileStructureNotes: String? = null,
)

/** One memory entry. GET/POST ui/agent/memory/{workerId}/entries. */
data class MemoryEntryDto(
    @Json(name = "memory_id") val memoryId: String,
    @Json(name = "category") val category: String = "",
    @Json(name = "title") val title: String = "",
    @Json(name = "content") val content: String = "",
    @Json(name = "ticket_id") val ticketId: String = "",
    @Json(name = "importance") val importance: Int = 3,
    @Json(name = "token_count") val tokenCount: Int = 0,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "summarized") val summarized: Boolean = false,
    @Json(name = "summary") val summary: String = "",
)

data class MemoryListDto(
    @Json(name = "entries") val entries: List<MemoryEntryDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
    @Json(name = "total_tokens") val totalTokens: Int = 0,
)

/** Body for POST ui/agent/memory/{workerId}/entries. */
data class MemoryEntryCreateRequest(
    @Json(name = "category") val category: String,
    @Json(name = "title") val title: String,
    @Json(name = "content") val content: String,
    @Json(name = "ticket_id") val ticketId: String = "",
    @Json(name = "importance") val importance: Int = 3,
)

/** GET ui/agent/memory/{workerId}/full-context. */
data class FullContextDto(
    @Json(name = "context_text") val contextText: String = "",
    @Json(name = "total_tokens") val totalTokens: Int = 0,
    @Json(name = "sections") val sections: List<String> = emptyList(),
)

/** One memory template (GET ui/agent/memory/templates - a bare array). */
data class MemoryTemplateDto(
    @Json(name = "agent_type") val agentType: String = "",
    @Json(name = "identity_text") val identityText: String = "",
    @Json(name = "description") val description: String = "",
)

// ------------------------------------------------------------------ DOC-COVERAGE

/** GET ui/agents/docs/coverage. by_type maps a doc-type -> {avg_coverage, count, stale, ...} (opaque values). */
data class DocCoverageSummaryDto(
    @Json(name = "overall_coverage") val overallCoverage: Double = 0.0,
    @Json(name = "total_docs") val totalDocs: Int = 0,
    @Json(name = "stale_docs") val staleDocs: Int = 0,
    @Json(name = "by_type") val byType: Map<String, Map<String, Double>> = emptyMap(),
)

/** One doc-coverage record. */
data class DocCoverageDto(
    @Json(name = "doc_path") val docPath: String = "",
    @Json(name = "doc_type") val docType: String = "",
    @Json(name = "source_refs") val sourceRefs: List<String> = emptyList(),
    @Json(name = "coverage_score") val coverageScore: Double = 0.0,
    @Json(name = "is_stale") val isStale: Boolean = false,
    @Json(name = "stale_since") val staleSince: Long = 0,
    @Json(name = "last_verified") val lastVerified: Long = 0,
    @Json(name = "last_updated") val lastUpdated: Long = 0,
    @Json(name = "created_at") val createdAt: Long = 0,
)

data class DocCoverageDetailsDto(
    @Json(name = "docs") val docs: List<DocCoverageDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

data class StaleDocsListDto(
    @Json(name = "docs") val docs: List<DocCoverageDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

/** POST ui/agents/docs/freshness-check. */
data class FreshnessCheckDto(
    @Json(name = "total") val total: Int = 0,
    @Json(name = "stale") val stale: Int = 0,
    @Json(name = "fresh") val fresh: Int = 0,
    @Json(name = "checked_at") val checkedAt: Long = 0,
)

/** One doc template. GET/POST ui/agents/docs/templates. */
data class DocTemplateDto(
    @Json(name = "template_id") val templateId: String,
    @Json(name = "name") val name: String = "",
    @Json(name = "doc_type") val docType: String = "",
    @Json(name = "template_body") val templateBody: String = "",
    @Json(name = "required_sections") val requiredSections: List<String> = emptyList(),
    @Json(name = "created_at") val createdAt: Long = 0,
)

data class DocTemplatesListDto(
    @Json(name = "templates") val templates: List<DocTemplateDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

/** Body for POST ui/agents/docs/templates (create). */
data class CreateDocTemplateRequest(
    @Json(name = "name") val name: String,
    @Json(name = "doc_type") val docType: String,
    @Json(name = "template_body") val templateBody: String,
    @Json(name = "required_sections") val requiredSections: List<String> = emptyList(),
)
