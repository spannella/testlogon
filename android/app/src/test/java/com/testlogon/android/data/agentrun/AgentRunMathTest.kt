package com.testlogon.android.data.agentrun

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AGENT-RUN (web-parity) - JVM unit tests for the PURE run-state machine + free-form-map output projection in
 * [AgentRunMath]. No Android / coroutine / network deps.
 */
class AgentRunMathTest {

    // ---- state machine ----

    @Test
    fun claimFromIdleGoesToClaimed() {
        assertEquals(RunState.CLAIMED, AgentRunMath.nextState(RunState.IDLE, RunEvent.ClaimTicket))
    }

    @Test
    fun executeFromClaimedGoesToExecuting() {
        assertEquals(RunState.EXECUTING, AgentRunMath.nextState(RunState.CLAIMED, RunEvent.StartExecute))
    }

    @Test
    fun executeDoneWithoutApprovalGoesToCompleted() {
        assertEquals(
            RunState.COMPLETED,
            AgentRunMath.nextState(RunState.EXECUTING, RunEvent.ExecuteDone, awaitingApproval = false),
        )
    }

    @Test
    fun executeDoneWithApprovalGoesToAwaiting() {
        assertEquals(
            RunState.AWAITING_APPROVAL,
            AgentRunMath.nextState(RunState.EXECUTING, RunEvent.ExecuteDone, awaitingApproval = true),
        )
    }

    @Test
    fun approveOnlyFromAwaiting() {
        assertEquals(RunState.APPROVED, AgentRunMath.nextState(RunState.AWAITING_APPROVAL, RunEvent.Approve))
        // illegal from COMPLETED -> unchanged
        assertEquals(RunState.COMPLETED, AgentRunMath.nextState(RunState.COMPLETED, RunEvent.Approve))
    }

    @Test
    fun rejectOnlyFromAwaiting() {
        assertEquals(RunState.REJECTED, AgentRunMath.nextState(RunState.AWAITING_APPROVAL, RunEvent.Reject))
    }

    @Test
    fun resetAlwaysReturnsToIdle() {
        assertEquals(RunState.IDLE, AgentRunMath.nextState(RunState.AWAITING_APPROVAL, RunEvent.Reset))
        assertEquals(RunState.IDLE, AgentRunMath.nextState(RunState.EXECUTING, RunEvent.Reset))
    }

    @Test
    fun errorAndNotFoundAlwaysAccepted() {
        assertEquals(RunState.ERROR, AgentRunMath.nextState(RunState.EXECUTING, RunEvent.Error))
        assertEquals(RunState.NOT_FOUND, AgentRunMath.nextState(RunState.CLAIMED, RunEvent.NotFound))
    }

    @Test
    fun canExecuteRules() {
        assertTrue(AgentRunMath.canExecute(RunState.CLAIMED, AgentRunType.CODER))
        assertFalse(AgentRunMath.canExecute(RunState.EXECUTING, AgentRunType.CODER))
        assertFalse(AgentRunMath.canExecute(RunState.IDLE, AgentRunType.CODER))
        // PM is operation-driven -> executable from IDLE
        assertTrue(AgentRunMath.canExecute(RunState.IDLE, AgentRunType.PM))
    }

    @Test
    fun canDecideOnlyDevopsAwaiting() {
        assertTrue(AgentRunMath.canDecide(RunState.AWAITING_APPROVAL, AgentRunType.DEVOPS))
        assertFalse(AgentRunMath.canDecide(RunState.AWAITING_APPROVAL, AgentRunType.CODER))
        assertFalse(AgentRunMath.canDecide(RunState.COMPLETED, AgentRunType.DEVOPS))
    }

    @Test
    fun pmExecutesFromIdle() {
        assertEquals(RunState.EXECUTING, AgentRunMath.nextState(RunState.IDLE, RunEvent.StartExecute))
    }

    @Test
    fun buildRunIdIsDeterministic() {
        assertEquals("run_coder_42", AgentRunMath.buildRunId(AgentRunType.CODER, 42L))
        assertEquals("run_devops_7", AgentRunMath.buildRunId(AgentRunType.DEVOPS, 7L))
    }

    // ---- output projection ----

    @Test
    fun parseCoderOutputLiftsBranchFilesAndTests() {
        val raw = mapOf(
            "branch_name" to "feat/ABC-1",
            "pr_url" to "https://x/pr/9",
            "pr_number" to 9.0,
            "files_changed" to listOf("a.kt", "b.kt"),
            "insertions" to 10.0,
            "deletions" to 3.0,
            "test_results" to listOf(
                mapOf("command" to "just test", "exit_code" to 0.0, "duration_seconds" to 12.0),
            ),
            "total_duration_seconds" to 120.0,
            "escalated" to false,
        )
        val out = AgentRunMath.parseOutput(AgentRunType.CODER, raw)
        assertEquals("feat/ABC-1", out.headline)
        assertEquals("https://x/pr/9", out.prUrl)
        assertEquals(listOf("a.kt", "b.kt"), out.filesChanged)
        assertEquals(10, out.insertions)
        assertEquals(1, out.testResults.size)
        assertTrue(out.testResults[0].passed)
        assertEquals("pass", out.status)
        assertTrue(out.extras.contains("PR #" to "9"))
    }

    @Test
    fun parseCoderFailingTestGivesDoneStatus() {
        val raw = mapOf(
            "branch_name" to "b",
            "test_results" to listOf(mapOf("command" to "t", "exit_code" to 1.0)),
        )
        val out = AgentRunMath.parseOutput(AgentRunType.CODER, raw)
        assertFalse(out.testResults[0].passed)
        assertEquals("done", out.status)
    }

    @Test
    fun parseQaVerdictAndCounts() {
        val raw = mapOf(
            "verdict" to "fail",
            "new_tests_pass_count" to 3.0,
            "new_tests_fail_count" to 1.0,
            "regression_tests_pass" to 40.0,
            "regression_tests_fail" to 0.0,
            "bug_ticket_ids" to listOf("BUG-1"),
        )
        val out = AgentRunMath.parseOutput(AgentRunType.QA, raw)
        assertEquals("fail", out.status)
        assertEquals("Verdict: fail", out.headline)
        assertEquals(2, out.testResults.size)
        assertTrue(out.extras.any { it.first == "Bugs filed" && it.second == "BUG-1" })
    }

    @Test
    fun parseDevopsAwaitingApproval() {
        val raw = mapOf(
            "deployment_id" to "dep_1",
            "status" to "pending_approval",
            "environment" to "prod",
            "steps_completed" to 2.0,
            "steps_total" to 5.0,
        )
        val out = AgentRunMath.parseOutput(AgentRunType.DEVOPS, raw)
        assertEquals("dep_1", out.headline)
        assertTrue(out.awaitingApproval)
        assertTrue(out.extras.contains("Environment" to "prod"))
    }

    @Test
    fun parseDevopsSuccessNotAwaiting() {
        val raw = mapOf("deployment_id" to "d", "status" to "success")
        val out = AgentRunMath.parseOutput(AgentRunType.DEVOPS, raw)
        assertFalse(out.awaitingApproval)
        assertEquals("success", out.status)
    }

    @Test
    fun parsePmCounts() {
        val raw = mapOf(
            "operation_type" to "idea_triage",
            "ideas_processed" to 5.0,
            "ideas_accepted" to 2.0,
            "blockers_found" to 1.0,
        )
        val out = AgentRunMath.parseOutput(AgentRunType.PM, raw)
        assertEquals("idea triage", out.headline)
        assertTrue(out.extras.contains("Ideas processed" to "5"))
        assertTrue(out.extras.contains("Blockers" to "1"))
    }

    @Test
    fun parseArchitectSummary() {
        val raw = mapOf(
            "feature_ticket_id" to "FEAT-9",
            "total_tickets" to 4.0,
            "total_estimated_hours" to 12.5,
            "decomposition_summary" to "split into 4",
        )
        val out = AgentRunMath.parseOutput(AgentRunType.ARCHITECT, raw)
        assertEquals("Feature FEAT-9", out.headline)
        assertEquals("decomposed", out.status)
        assertTrue(out.extras.contains("Tickets created" to "4"))
        assertTrue(out.extras.contains("Est. hours" to "12.5"))
    }

    @Test
    fun parseOutputDegradesOnEmptyMap() {
        val out = AgentRunMath.parseOutput(AgentRunType.CODER, emptyMap())
        assertEquals("Coder run", out.headline)
        assertEquals(0, out.insertions)
        assertTrue(out.filesChanged.isEmpty())
        assertNull(out.prUrl)
    }

    @Test
    fun parseEligibleTicketsSkipsMalformed() {
        val raw = mapOf(
            "tickets" to listOf(
                mapOf("ticket_id" to "T-1", "subject" to "s", "labels" to listOf("a"), "estimated_effort_hours" to 3.0),
                mapOf("subject" to "no id"), // dropped
                "not a map", // dropped
            ),
        )
        val list = AgentRunMath.parseEligibleTickets(raw)
        assertEquals(1, list.size)
        assertEquals("T-1", list[0].ticketId)
        assertEquals(3, list[0].estimatedEffortHours)
        assertEquals(listOf("a"), list[0].labels)
    }

    @Test
    fun parseMetricsRendersRatesAsPercent() {
        val raw = mapOf(
            "completed_count" to 12.0,
            "failure_rate" to 0.25,
            "avg_duration_seconds" to 90.5,
        )
        val rows = AgentRunMath.parseMetrics(raw).rows.toMap()
        assertEquals("12", rows["Completed Count"])
        assertEquals("25%", rows["Failure Rate"])
        assertEquals("90.5", rows["Avg Duration Seconds"])
    }

    @Test
    fun parseDecisionReadsFields() {
        val raw = mapOf(
            "run_id" to "run_x",
            "deployment_id" to "dep_x",
            "approval_status" to "approved",
            "approved_by" to "op",
            "notes" to "lgtm",
        )
        val d = AgentRunMath.parseDecision("fallback", raw)
        assertEquals("run_x", d.runId)
        assertEquals("approved", d.approvalStatus)
        assertEquals("lgtm", d.notes)
    }

    @Test
    fun asIntToleratesStringsAndDoubles() {
        assertEquals(5, AgentRunMath.asInt("5"))
        assertEquals(7, AgentRunMath.asInt(7.9))
        assertEquals(0, AgentRunMath.asInt("nope"))
        assertEquals(0, AgentRunMath.asInt(null))
    }
}
