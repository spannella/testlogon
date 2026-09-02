package com.testlogon.android.data.agentrun

import java.util.Locale

/**
 * AGENT-RUN (web-parity) - PURE, framework-free logic for the generic agent-run console: the run-state
 * machine and the free-form-map -> [AgentRunOutput] projection. No Android / coroutine / network deps, so it
 * is fully JVM-unit-testable (mirrors PrsCompletionMath).
 *
 * All map access is defensive: JSON decoded via the shared reflective Moshi yields Double for every number
 * and String/Boolean/List/Map for the rest, so numeric reads go through [asInt] (which tolerates Double, Long,
 * Int and numeric strings) and every field degrades to a neutral default when absent or the wrong type.
 */
object AgentRunMath {

    // ---------------------------------------------------------------------
    // Run-state machine
    // ---------------------------------------------------------------------

    /**
     * The single allowed successor of [current] for [event]. Returns the SAME state when the event is not
     * legal from [current] (the console simply ignores an illegal control), except that [RunEvent.Reset]
     * always returns to IDLE and error/not-found events are always accepted.
     */
    fun nextState(current: RunState, event: RunEvent, awaitingApproval: Boolean = false): RunState =
        when (event) {
            RunEvent.Reset -> RunState.IDLE
            RunEvent.NotFound -> RunState.NOT_FOUND
            RunEvent.Error -> RunState.ERROR
            RunEvent.ClaimTicket -> when (current) {
                RunState.IDLE, RunState.NOT_FOUND, RunState.ERROR -> RunState.CLAIMED
                else -> current
            }
            RunEvent.StartExecute -> when (current) {
                // PM is operation-driven: it may execute straight from IDLE (no claim step).
                RunState.CLAIMED, RunState.IDLE, RunState.COMPLETED,
                RunState.NOT_FOUND, RunState.ERROR -> RunState.EXECUTING
                else -> current
            }
            RunEvent.ExecuteDone -> when (current) {
                RunState.EXECUTING ->
                    if (awaitingApproval) RunState.AWAITING_APPROVAL else RunState.COMPLETED
                else -> current
            }
            RunEvent.Approve -> if (current == RunState.AWAITING_APPROVAL) RunState.APPROVED else current
            RunEvent.Reject -> if (current == RunState.AWAITING_APPROVAL) RunState.REJECTED else current
        }

    /** True when executing is a meaningful action from [state] for [type]. */
    fun canExecute(state: RunState, type: AgentRunType): Boolean = when {
        state == RunState.EXECUTING -> false
        type.operationDriven -> state != RunState.AWAITING_APPROVAL
        else -> state == RunState.CLAIMED || state == RunState.COMPLETED ||
            state == RunState.NOT_FOUND || state == RunState.ERROR
    }

    /** True when the console should offer approve/reject controls. */
    fun canDecide(state: RunState, type: AgentRunType): Boolean =
        type.supportsApproval && state == RunState.AWAITING_APPROVAL

    // ---------------------------------------------------------------------
    // Run-id generation (client-side, mirrors the web crypto.randomUUID run ids)
    // ---------------------------------------------------------------------

    /**
     * A stable, URL-safe run id from a monotonically-unique [seed] (e.g. System.currentTimeMillis()) and the
     * [type]. Deterministic for a given seed so it is testable; the ViewModel supplies a real clock.
     */
    fun buildRunId(type: AgentRunType, seed: Long): String = "run_${type.typeName}_$seed"

    // ---------------------------------------------------------------------
    // Output projection
    // ---------------------------------------------------------------------

    /**
     * Projects a raw agent-output map into the uniform [AgentRunOutput]. Never throws; unknown/absent fields
     * degrade to neutral defaults. The [type] selects which headline/status keys are authoritative.
     */
    fun parseOutput(type: AgentRunType, raw: Map<String, Any?>): AgentRunOutput {
        val prUrl = (raw["pr_url"] as? String)?.takeIf { it.isNotBlank() }
        val filesChanged = stringList(raw["files_changed"])
        val insertions = asInt(raw["insertions"])
        val deletions = asInt(raw["deletions"])
        val duration = asInt(raw["total_duration_seconds"])
        val escalated = (raw["escalated"] as? Boolean) ?: false
        val escalationReason = (raw["escalation_reason"] as? String)?.takeIf { it.isNotBlank() }

        val headline: String
        val status: String
        val testResults: List<RunTestResult>
        val awaiting: Boolean
        val extras = mutableListOf<Pair<String, String>>()

        when (type) {
            AgentRunType.CODER -> {
                headline = (raw["branch_name"] as? String)?.takeIf { it.isNotBlank() } ?: "Coder run"
                testResults = coderTestResults(raw["test_results"])
                status = if (escalated) "escalated" else if (allTestsPassed(testResults)) "pass" else "done"
                awaiting = false
                addInt(extras, "PR #", raw["pr_number"])
                addInt(extras, "Retries", raw["test_retry_count"])
            }
            AgentRunType.QA -> {
                val verdict = (raw["verdict"] as? String)?.takeIf { it.isNotBlank() } ?: "unknown"
                headline = "Verdict: $verdict"
                status = verdict
                testResults = qaTestResults(raw)
                awaiting = false
                addInt(extras, "New tests", raw["new_tests_written"])
                addInt(extras, "Regression run", raw["regression_tests_run"])
                addInt(extras, "Regression failed", raw["regression_tests_fail"])
                stringList(raw["bug_ticket_ids"]).takeIf { it.isNotEmpty() }
                    ?.let { extras.add("Bugs filed" to it.joinToString(", ")) }
            }
            AgentRunType.DEVOPS -> {
                val depId = (raw["deployment_id"] as? String)?.takeIf { it.isNotBlank() } ?: "deployment"
                val st = (raw["status"] as? String)?.takeIf { it.isNotBlank() } ?: "unknown"
                headline = depId
                status = st
                awaiting = isAwaitingApproval(st)
                testResults = emptyList()
                (raw["environment"] as? String)?.let { extras.add("Environment" to it) }
                addInt(extras, "Steps done", raw["steps_completed"])
                addInt(extras, "Steps total", raw["steps_total"])
                (raw["version_deployed"] as? String)?.let { extras.add("Version" to it) }
                if ((raw["rollback_executed"] as? Boolean) == true) extras.add("Rollback" to "executed")
            }
            AgentRunType.ARCHITECT -> {
                val fid = (raw["feature_ticket_id"] as? String)?.takeIf { it.isNotBlank() }
                headline = fid?.let { "Feature $it" } ?: "Decomposition"
                val total = asInt(raw["total_tickets"])
                status = if (total > 0) "decomposed" else "done"
                testResults = emptyList()
                awaiting = false
                addInt(extras, "Tickets created", raw["total_tickets"])
                addDouble(extras, "Est. hours", raw["total_estimated_hours"])
                (raw["decomposition_summary"] as? String)?.takeIf { it.isNotBlank() }
                    ?.let { extras.add("Summary" to it) }
            }
            AgentRunType.PM -> {
                val op = (raw["operation_type"] as? String)?.takeIf { it.isNotBlank() } ?: "operation"
                headline = op.replace('_', ' ')
                status = "done"
                testResults = emptyList()
                awaiting = false
                addInt(extras, "Ideas processed", raw["ideas_processed"])
                addInt(extras, "Ideas accepted", raw["ideas_accepted"])
                addInt(extras, "Reprioritized", raw["tickets_reprioritized"])
                addInt(extras, "Blockers", raw["blockers_found"])
                addInt(extras, "Escalations", raw["escalations_created"])
                (raw["report_id"] as? String)?.let { extras.add("Report id" to it) }
            }
            AgentRunType.DOCS -> {
                headline = "Docs run"
                status = "done"
                testResults = emptyList()
                awaiting = false
            }
        }

        return AgentRunOutput(
            type = type,
            headline = headline,
            status = status,
            prUrl = prUrl,
            filesChanged = filesChanged,
            insertions = insertions,
            deletions = deletions,
            testResults = testResults,
            totalDurationSeconds = duration,
            escalated = escalated,
            escalationReason = escalationReason,
            awaitingApproval = awaiting,
            extras = extras,
        )
    }

    /** Projects an eligible-tickets response map into the uniform ticket list. */
    fun parseEligibleTickets(raw: Map<String, Any?>): List<EligibleTicket> {
        val list = raw["tickets"] as? List<*> ?: return emptyList()
        return list.mapNotNull { item ->
            val m = item as? Map<*, *> ?: return@mapNotNull null
            val id = (m["ticket_id"] as? String)?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
            EligibleTicket(
                ticketId = id,
                subject = (m["subject"] as? String).orEmpty(),
                labels = stringList(m["labels"]),
                complexity = (m["complexity"] as? String)?.takeIf { it.isNotBlank() },
                estimatedEffortHours = m["estimated_effort_hours"]?.let { asIntOrNull(it) },
                status = (m["status"] as? String)?.takeIf { it.isNotBlank() },
            )
        }
    }

    /** Projects a metrics map into labelled rows (integers rendered cleanly, rates as percentages). */
    fun parseMetrics(raw: Map<String, Any?>): RunMetrics {
        val rows = mutableListOf<Pair<String, String>>()
        for ((key, value) in raw) {
            if (value == null) continue
            val label = key.split('_').joinToString(" ") { it.replaceFirstChar { c -> c.uppercase(Locale.US) } }
            val rendered = when {
                key.endsWith("_rate") -> asDoubleOrNull(value)?.let { pct(it) } ?: value.toString()
                value is Boolean -> if (value) "yes" else "no"
                value is Double -> if (value % 1.0 == 0.0) value.toLong().toString() else trimDouble(value)
                value is Map<*, *> -> value.entries.joinToString(", ") { "${it.key}=${it.value}" }
                value is List<*> -> value.joinToString(", ")
                else -> value.toString()
            }
            rows.add(label to rendered)
        }
        return RunMetrics(rows = rows)
    }

    /** Parses a deployment approve/reject response map. */
    fun parseDecision(runId: String, raw: Map<String, Any?>): DeploymentDecision = DeploymentDecision(
        runId = (raw["run_id"] as? String)?.takeIf { it.isNotBlank() } ?: runId,
        deploymentId = (raw["deployment_id"] as? String).orEmpty(),
        approvalStatus = (raw["approval_status"] as? String).orEmpty(),
        approvedBy = (raw["approved_by"] as? String).orEmpty(),
        notes = (raw["notes"] as? String)?.takeIf { it.isNotBlank() },
    )

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    private fun isAwaitingApproval(status: String): Boolean {
        val s = status.trim().lowercase(Locale.US)
        return s == "pending_approval" || s == "awaiting_approval" || s == "pending"
    }

    private fun allTestsPassed(results: List<RunTestResult>): Boolean =
        results.isNotEmpty() && results.all { it.passed }

    private fun coderTestResults(raw: Any?): List<RunTestResult> {
        val list = raw as? List<*> ?: return emptyList()
        return list.mapNotNull { item ->
            val m = item as? Map<*, *> ?: return@mapNotNull null
            val exit = asInt(m["exit_code"])
            RunTestResult(
                label = (m["command"] as? String)?.takeIf { it.isNotBlank() } ?: "test",
                passed = exit == 0,
                durationSeconds = m["duration_seconds"]?.let { asIntOrNull(it) },
            )
        }
    }

    private fun qaTestResults(raw: Map<String, Any?>): List<RunTestResult> {
        val out = mutableListOf<RunTestResult>()
        val newPass = asInt(raw["new_tests_pass_count"])
        val newFail = asInt(raw["new_tests_fail_count"])
        if (newPass + newFail > 0) {
            out.add(RunTestResult("New tests: $newPass passed", newFail == 0, null))
        }
        val regPass = asInt(raw["regression_tests_pass"])
        val regFail = asInt(raw["regression_tests_fail"])
        if (regPass + regFail > 0) {
            out.add(RunTestResult("Regression: $regPass/${regPass + regFail}", regFail == 0, null))
        }
        return out
    }

    private fun stringList(raw: Any?): List<String> =
        (raw as? List<*>)?.mapNotNull { it?.toString()?.takeIf { s -> s.isNotBlank() } } ?: emptyList()

    private fun addInt(into: MutableList<Pair<String, String>>, label: String, raw: Any?) {
        asIntOrNull(raw)?.let { into.add(label to it.toString()) }
    }

    private fun addDouble(into: MutableList<Pair<String, String>>, label: String, raw: Any?) {
        asDoubleOrNull(raw)?.let { into.add(label to trimDouble(it)) }
    }

    /** Tolerant int read (Double/Long/Int/numeric-String); non-numeric -> 0. */
    fun asInt(raw: Any?): Int = asIntOrNull(raw) ?: 0

    private fun asIntOrNull(raw: Any?): Int? = when (raw) {
        is Int -> raw
        is Long -> raw.toInt()
        is Double -> raw.toInt()
        is String -> raw.trim().toDoubleOrNull()?.toInt()
        else -> null
    }

    private fun asDoubleOrNull(raw: Any?): Double? = when (raw) {
        is Double -> raw
        is Int -> raw.toDouble()
        is Long -> raw.toDouble()
        is String -> raw.trim().toDoubleOrNull()
        else -> null
    }

    private fun pct(rate: Double): String {
        val p = rate * 100.0
        return if (p % 1.0 == 0.0) "${p.toLong()}%" else String.format(Locale.US, "%.1f%%", p)
    }

    private fun trimDouble(v: Double): String =
        if (v % 1.0 == 0.0) v.toLong().toString() else v.toString()
}

/** Events that drive the [RunState] machine. */
enum class RunEvent {
    ClaimTicket,
    StartExecute,
    ExecuteDone,
    Approve,
    Reject,
    NotFound,
    Error,
    Reset,
}
