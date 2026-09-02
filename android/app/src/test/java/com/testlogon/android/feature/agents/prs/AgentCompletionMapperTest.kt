package com.testlogon.android.feature.agents.prs

import com.testlogon.android.core.network.agents.AgentCompletionDto
import com.testlogon.android.core.network.agents.AgentPrDto
import com.testlogon.android.core.network.agents.WorkSummaryDto
import com.testlogon.android.feature.agents.prs.data.toDomain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AGENTS-BASICS - JVM tests for the DTO -> domain mappers of the work-completion result (web AgentCompletion).
 * Verifies the null-PR path, test_results map -> ordered pairs, and nested summary mapping.
 */
class AgentCompletionMapperTest {

    @Test
    fun completion_withNullPr_mapsPrToNull() {
        val dto = AgentCompletionDto(
            ticketId = "T-9",
            summary = WorkSummaryDto(ticketId = "T-9", text = "done", filesChanged = listOf("x.kt")),
            pr = null,
            newStatus = "in_review",
            nextAgentType = "reviewer",
        )
        val d = dto.toDomain()
        assertNull(d.pr)
        assertEquals("T-9", d.ticketId)
        assertEquals("in_review", d.newStatus)
        assertEquals("reviewer", d.nextAgentType)
        assertEquals(listOf("x.kt"), d.summary.filesChanged)
    }

    @Test
    fun completion_withPr_mapsPr() {
        val dto = AgentCompletionDto(
            ticketId = "T-9",
            summary = WorkSummaryDto(),
            pr = AgentPrDto(prId = "PR-1", prNumber = 42, status = "open"),
            newStatus = "done",
        )
        val d = dto.toDomain()
        assertNotNull(d.pr)
        assertEquals("PR-1", d.pr!!.prId)
        assertEquals(42, d.pr!!.prNumber)
    }

    @Test
    fun workSummary_testResultsMapToPairs() {
        val dto = WorkSummaryDto(
            ticketId = "T-1",
            testResults = linkedMapOf("passed" to 5, "failed" to 1),
        )
        val d = dto.toDomain()
        assertEquals(2, d.testResults.size)
        assertEquals(5, d.testResults.toMap()["passed"])
        assertEquals(1, d.testResults.toMap()["failed"])
    }

    @Test
    fun workSummary_defaultsAreEmpty() {
        val d = WorkSummaryDto().toDomain()
        assertEquals(emptyList<String>(), d.filesChanged)
        assertEquals(emptyList<String>(), d.decisions)
        assertEquals(0, d.testResults.size)
    }
}
