package com.testlogon.android.data.jira

import com.testlogon.android.core.network.jira.JiraConstants

/**
 * JIRA-AND-1 - PURE, framework-free logic + model for the Jira integration surface. No Android / java.time /
 * Moshi types, so every function here is JVM-unit-testable (mirrors the KbMath / PurchaseHistoryMath idiom).
 *
 * Responsibilities:
 *  - normalize the RAW wire sync_state token into a closed [JiraLinkState] (unknown-safe -> UNKNOWN, never throws).
 *  - normalize the RAW connection status into "connected?" (any active connection counts).
 *  - derive the user-facing [JiraSyncSummary] (a link-state + label + whether the ticket is actionable, i.e.
 *    conflict needs resolution / failed needs retry).
 *  - the CONFLICT-RESOLUTION model: pair up the per-field local vs remote values so the UI can show a diff, and
 *    map the chosen [JiraConflictChoice] to the wire action token.
 *  - degrade-on-404: a not-connected / not-linked status is a first-class honest-empty value, NOT an error.
 */
object JiraMath {

    /** The closed set of link states derived from the RAW server sync_state token. */
    enum class JiraLinkState { NOT_LINKED, QUEUED, IN_SYNC, CONFLICT, FAILED, UNKNOWN }

    /** The user's conflict-resolution choice (maps to the wire action token). */
    enum class JiraConflictChoice { KEEP_INTERNAL, KEEP_JIRA }

    /** One field's local-vs-remote diff row for the conflict UI. */
    data class JiraConflictRow(
        val field: String,
        val localValue: String,
        val remoteValue: String,
    )

    /** The derived, render-ready summary of a ticket's Jira sync status. */
    data class JiraSyncSummary(
        val linked: Boolean,
        val state: JiraLinkState,
        val rawState: String,
        val issueKey: String?,
        val jiraStatus: String?,
        /** True when the state requires user action (conflict -> resolve, failed -> retry). */
        val needsAttention: Boolean,
        val conflictRows: List<JiraConflictRow>,
    )

    /**
     * Map a RAW wire sync_state token to the closed [JiraLinkState]. Blank / null / unknown -> UNKNOWN
     * (never throws). Case- and surrounding-whitespace-insensitive.
     */
    fun linkState(rawState: String?): JiraLinkState = when (rawState?.trim()?.lowercase()) {
        JiraConstants.SyncState.NOT_LINKED -> JiraLinkState.NOT_LINKED
        JiraConstants.SyncState.QUEUED -> JiraLinkState.QUEUED
        JiraConstants.SyncState.IN_SYNC -> JiraLinkState.IN_SYNC
        JiraConstants.SyncState.CONFLICT -> JiraLinkState.CONFLICT
        JiraConstants.SyncState.FAILED -> JiraLinkState.FAILED
        null, "" -> JiraLinkState.NOT_LINKED
        else -> JiraLinkState.UNKNOWN
    }

    /** True when the state warrants an explicit user action (resolve a conflict / retry a failure). */
    fun needsAttention(state: JiraLinkState): Boolean =
        state == JiraLinkState.CONFLICT || state == JiraLinkState.FAILED

    /**
     * True when ANY connection in the status list is active. Degrade-on-404 supplies an empty list, which is
     * honestly not-connected (false), never an error.
     */
    fun isConnected(connectionStatuses: List<String?>): Boolean =
        connectionStatuses.any { (it ?: "").trim().equals(JiraConstants.ConnectionStatus.ACTIVE, ignoreCase = true) }

    /** Map the user's conflict choice to the wire action token. */
    fun conflictAction(choice: JiraConflictChoice): String = when (choice) {
        JiraConflictChoice.KEEP_INTERNAL -> JiraConstants.ResolveAction.KEEP_INTERNAL
        JiraConflictChoice.KEEP_JIRA -> JiraConstants.ResolveAction.KEEP_JIRA
    }

    /**
     * Build the ordered per-field conflict diff. Fields come from [conflictFields] (server-authoritative order);
     * missing values render as an empty string. Values are stringified defensively (null -> "").
     */
    fun conflictRows(
        conflictFields: List<String>,
        localValues: Map<String, Any?>,
        remoteValues: Map<String, Any?>,
    ): List<JiraConflictRow> = conflictFields
        .filter { it.isNotBlank() }
        .map { field ->
            JiraConflictRow(
                field = field,
                localValue = stringify(localValues[field]),
                remoteValue = stringify(remoteValues[field]),
            )
        }

    /**
     * Fold a sync-status into a render-ready [JiraSyncSummary]. This is the single choke point the ViewModel
     * uses: it normalizes the state, decides attention, and precomputes the conflict rows (empty unless the
     * state is CONFLICT).
     */
    fun summarize(
        linked: Boolean,
        rawState: String?,
        issueKey: String?,
        jiraStatus: String?,
        conflictFields: List<String>,
        localValues: Map<String, Any?>,
        remoteValues: Map<String, Any?>,
    ): JiraSyncSummary {
        val state = linkState(rawState)
        val rows = if (state == JiraLinkState.CONFLICT) {
            conflictRows(conflictFields, localValues, remoteValues)
        } else {
            emptyList()
        }
        return JiraSyncSummary(
            linked = linked && state != JiraLinkState.NOT_LINKED,
            state = state,
            rawState = (rawState ?: "").trim(),
            issueKey = issueKey?.takeIf { it.isNotBlank() },
            jiraStatus = jiraStatus?.takeIf { it.isNotBlank() },
            needsAttention = needsAttention(state),
            conflictRows = rows,
        )
    }

    /**
     * Validate a user-entered Jira issue key for the link-existing flow (client-side pre-gate ONLY; the server
     * is the authority). A Jira key is PROJECT-123: 1+ uppercase letters, a hyphen, 1+ digits. Returns the
     * normalized (trimmed, upper-cased) key, or null when invalid.
     */
    fun normalizeIssueKey(raw: String?): String? {
        val trimmed = raw?.trim()?.uppercase() ?: return null
        if (trimmed.isEmpty()) return null
        return if (ISSUE_KEY_REGEX.matches(trimmed)) trimmed else null
    }

    /** True when [raw] is a syntactically-valid Jira issue key. */
    fun isValidIssueKey(raw: String?): Boolean = normalizeIssueKey(raw) != null

    private val ISSUE_KEY_REGEX = Regex("^[A-Z][A-Z0-9]*-[0-9]+$")

    private fun stringify(value: Any?): String = when (value) {
        null -> ""
        is String -> value
        else -> value.toString()
    }
}
