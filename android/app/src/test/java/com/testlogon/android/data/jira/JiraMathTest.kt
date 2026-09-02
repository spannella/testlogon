package com.testlogon.android.data.jira

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JIRA-AND-1 - JVM unit tests for the PURE [JiraMath] logic (no Android / Moshi types). Covers state
 * normalization (incl. unknown-safe + blank -> not_linked), connection detection, conflict-choice -> action
 * mapping, conflict-row building, issue-key validation/normalization, and the [JiraMath.summarize] choke point
 * (including that conflict rows are only produced in the CONFLICT state).
 */
class JiraMathTest {

    @Test
    fun linkState_mapsKnownTokens() {
        assertEquals(JiraMath.JiraLinkState.QUEUED, JiraMath.linkState("queued"))
        assertEquals(JiraMath.JiraLinkState.IN_SYNC, JiraMath.linkState("in_sync"))
        assertEquals(JiraMath.JiraLinkState.CONFLICT, JiraMath.linkState("conflict"))
        assertEquals(JiraMath.JiraLinkState.FAILED, JiraMath.linkState("failed"))
        assertEquals(JiraMath.JiraLinkState.NOT_LINKED, JiraMath.linkState("not_linked"))
    }

    @Test
    fun linkState_isCaseAndWhitespaceInsensitive() {
        assertEquals(JiraMath.JiraLinkState.IN_SYNC, JiraMath.linkState("  IN_SYNC "))
    }

    @Test
    fun linkState_blankOrNull_isNotLinked() {
        assertEquals(JiraMath.JiraLinkState.NOT_LINKED, JiraMath.linkState(null))
        assertEquals(JiraMath.JiraLinkState.NOT_LINKED, JiraMath.linkState(""))
        assertEquals(JiraMath.JiraLinkState.NOT_LINKED, JiraMath.linkState("   "))
    }

    @Test
    fun linkState_unknownToken_isUnknown() {
        assertEquals(JiraMath.JiraLinkState.UNKNOWN, JiraMath.linkState("banana"))
    }

    @Test
    fun needsAttention_onlyConflictAndFailed() {
        assertTrue(JiraMath.needsAttention(JiraMath.JiraLinkState.CONFLICT))
        assertTrue(JiraMath.needsAttention(JiraMath.JiraLinkState.FAILED))
        assertFalse(JiraMath.needsAttention(JiraMath.JiraLinkState.IN_SYNC))
        assertFalse(JiraMath.needsAttention(JiraMath.JiraLinkState.QUEUED))
        assertFalse(JiraMath.needsAttention(JiraMath.JiraLinkState.NOT_LINKED))
    }

    @Test
    fun isConnected_trueWhenAnyActive() {
        assertTrue(JiraMath.isConnected(listOf("revoked", "active")))
        assertTrue(JiraMath.isConnected(listOf("ACTIVE")))
    }

    @Test
    fun isConnected_falseWhenNoneActiveOrEmpty() {
        assertFalse(JiraMath.isConnected(emptyList()))
        assertFalse(JiraMath.isConnected(listOf("revoked", null, "")))
    }

    @Test
    fun conflictAction_mapsChoiceToWireToken() {
        assertEquals("keep_internal", JiraMath.conflictAction(JiraMath.JiraConflictChoice.KEEP_INTERNAL))
        assertEquals("keep_jira", JiraMath.conflictAction(JiraMath.JiraConflictChoice.KEEP_JIRA))
    }

    @Test
    fun conflictRows_pairsLocalAndRemote_defaultsBlank() {
        val rows = JiraMath.conflictRows(
            conflictFields = listOf("summary", "status", ""),
            localValues = mapOf("summary" to "Local title", "status" to "open"),
            remoteValues = mapOf("summary" to "Remote title"),
        )
        assertEquals(2, rows.size) // blank field filtered
        assertEquals("summary", rows[0].field)
        assertEquals("Local title", rows[0].localValue)
        assertEquals("Remote title", rows[0].remoteValue)
        assertEquals("open", rows[1].localValue)
        assertEquals("", rows[1].remoteValue) // missing remote -> blank
    }

    @Test
    fun conflictRows_stringifiesNonStringValues() {
        val rows = JiraMath.conflictRows(
            conflictFields = listOf("priority"),
            localValues = mapOf("priority" to 3),
            remoteValues = mapOf("priority" to null),
        )
        assertEquals("3", rows[0].localValue)
        assertEquals("", rows[0].remoteValue)
    }

    @Test
    fun normalizeIssueKey_validKeysUpperCased() {
        assertEquals("ABC-123", JiraMath.normalizeIssueKey("abc-123"))
        assertEquals("ABC-123", JiraMath.normalizeIssueKey("  ABC-123 "))
        assertEquals("PROJ2-7", JiraMath.normalizeIssueKey("proj2-7"))
    }

    @Test
    fun normalizeIssueKey_invalidReturnsNull() {
        assertNull(JiraMath.normalizeIssueKey(null))
        assertNull(JiraMath.normalizeIssueKey(""))
        assertNull(JiraMath.normalizeIssueKey("nodash"))
        assertNull(JiraMath.normalizeIssueKey("ABC-"))
        assertNull(JiraMath.normalizeIssueKey("-123"))
        assertNull(JiraMath.normalizeIssueKey("1ABC-2")) // must start with a letter
    }

    @Test
    fun isValidIssueKey_matchesNormalization() {
        assertTrue(JiraMath.isValidIssueKey("ABC-1"))
        assertFalse(JiraMath.isValidIssueKey("bad key"))
    }

    @Test
    fun summarize_conflict_populatesRowsAndAttention() {
        val s = JiraMath.summarize(
            linked = true,
            rawState = "conflict",
            issueKey = "ABC-123",
            jiraStatus = "In Progress",
            conflictFields = listOf("summary"),
            localValues = mapOf("summary" to "L"),
            remoteValues = mapOf("summary" to "R"),
        )
        assertTrue(s.linked)
        assertEquals(JiraMath.JiraLinkState.CONFLICT, s.state)
        assertTrue(s.needsAttention)
        assertEquals(1, s.conflictRows.size)
        assertEquals("ABC-123", s.issueKey)
        assertEquals("In Progress", s.jiraStatus)
    }

    @Test
    fun summarize_inSync_hasNoConflictRows() {
        val s = JiraMath.summarize(
            linked = true,
            rawState = "in_sync",
            issueKey = "ABC-1",
            jiraStatus = null,
            conflictFields = listOf("summary"),
            localValues = mapOf("summary" to "L"),
            remoteValues = mapOf("summary" to "R"),
        )
        assertTrue(s.conflictRows.isEmpty())
        assertFalse(s.needsAttention)
        assertNull(s.jiraStatus)
    }

    @Test
    fun summarize_notLinked_isUnlinkedEvenIfLinkedFlagTrue() {
        val s = JiraMath.summarize(
            linked = true,
            rawState = "not_linked",
            issueKey = null,
            jiraStatus = null,
            conflictFields = emptyList(),
            localValues = emptyMap(),
            remoteValues = emptyMap(),
        )
        assertFalse(s.linked)
        assertEquals(JiraMath.JiraLinkState.NOT_LINKED, s.state)
    }
}
