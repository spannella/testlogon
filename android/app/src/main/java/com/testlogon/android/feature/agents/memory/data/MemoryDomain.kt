package com.testlogon.android.feature.agents.memory.data

/**
 * AGENTS-BASICS (web-parity) - framework-free domain models for the per-worker MEMORY surface. Kept in
 * feature/data. Times are EPOCH SECONDS (0 -> null via the mapper).
 */

/** The worker's agent identity (system prompt + custom instructions). */
data class AgentIdentity(
    val agentType: String,
    val identityText: String,
    val customInstructions: String,
    val updatedAt: Long?,
)

/** The worker's project context (repo, conventions, standards, CI). */
data class ProjectContext(
    val repoUrl: String,
    val branchConvention: String,
    val codingStandards: String,
    val prTemplate: String,
    val testFramework: String,
    val ciCommands: String,
    val fileStructureNotes: String,
    val updatedAt: Long?,
)

/** One memory entry. */
data class MemoryEntry(
    val memoryId: String,
    val category: String,
    val title: String,
    val content: String,
    val ticketId: String,
    val importance: Int,
    val tokenCount: Int,
    val createdAt: Long?,
    val summarized: Boolean,
    val summary: String,
)

/** The entries list + aggregate token count. */
data class MemoryList(
    val entries: List<MemoryEntry>,
    val totalTokens: Int,
)
