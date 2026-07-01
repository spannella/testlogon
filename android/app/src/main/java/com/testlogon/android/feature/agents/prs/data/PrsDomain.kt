package com.testlogon.android.feature.agents.prs.data

/**
 * AGENTS-BASICS (web-parity) - framework-free domain models for the agent-PR surface. Kept in feature/data.
 * Times are EPOCH SECONDS (0 -> null via the mapper).
 */

/** A PR lifecycle status. UNKNOWN preserves an unrecognised server string for forward-compat display. */
enum class AgentPrStatus(val wire: String) {
    OPEN("open"),
    MERGED("merged"),
    CLOSED("closed"),
    UNKNOWN("");

    companion object {
        fun from(wire: String): AgentPrStatus = entries.firstOrNull { it.wire == wire } ?: UNKNOWN
    }
}

/** One agent-authored pull request. */
data class AgentPr(
    val prId: String,
    val workerId: String,
    val ticketId: String,
    val repoUrl: String,
    val prUrl: String,
    val prNumber: Int,
    val branch: String,
    val title: String,
    val description: String,
    val filesChanged: List<String>,
    val commitCount: Int,
    val status: AgentPrStatus,
    val statusWire: String,
    val createdAt: Long?,
    val mergedAt: Long?,
)
