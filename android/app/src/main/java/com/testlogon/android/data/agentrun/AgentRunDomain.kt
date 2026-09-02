package com.testlogon.android.data.agentrun

import java.util.Locale

/**
 * AGENT-RUN (web-parity) - framework-free domain for the generic agent-run CONSOLE, the mobile mirror of the
 * web *RunOutputPanel / DeploymentApprovalPanel family (frontend/src/pages/agents/{Coder,Qa,DevOps,Architect,
 * Pm}RunOutputPanel + DeploymentApprovalPanel). One console drives the "eligible tickets -> claim -> execute
 * -> view output/report/metrics" lifecycle across the six agent types; DevOps additionally exposes deployment
 * approve/reject.
 *
 * There is deliberately NO shared "AgentRunOut" server model - each agent type has a bespoke output SHAPE
 * (see app/models.py CoderOutputOut / QaOutputOut / DevOpsOutputOut / ArchitectOutputOut / PmOutputOut). To
 * keep ONE transport + ONE screen the outputs are transported as free-form Map<String, Any?> (exactly like
 * AgentConfigApi does for the config bodies) and projected here into a small, uniform, display-only
 * [AgentRunOutput] via [AgentRunMath.parseOutput]. Only the fields the console renders are lifted; every
 * type's map degrades safely when a field is absent.
 *
 * Times are epoch seconds where present. All parsing is PURE (no Android / coroutine deps) so it is
 * JVM-unit-testable.
 */

/** The six executable agent types. [typeName] is the fixed URL segment (coder/qa/devops/architect/pm). */
enum class AgentRunType(
    val typeName: String,
    val title: String,
    /** True when this type surfaces a production-deployment approve/reject gate (DevOps only). */
    val supportsApproval: Boolean = false,
    /** True when this type has a markdown report endpoint (QA only). */
    val hasReport: Boolean = false,
    /** True when this type is driven by an operation selector rather than a ticket (PM only). */
    val operationDriven: Boolean = false,
) {
    CODER("coder", "Coder Agent"),
    QA("qa", "QA Agent", hasReport = true),
    DEVOPS("devops", "DevOps / SRE Agent", supportsApproval = true),
    ARCHITECT("architect", "Solution Architect Agent"),
    PM("pm", "Project Manager Agent", operationDriven = true),
    DOCS("docs", "Docs Agent");

    companion object {
        fun from(raw: String?): AgentRunType? =
            entries.firstOrNull { it.typeName == raw?.lowercase(Locale.US) }
    }
}

/** A PM operation the console can trigger (mirrors runPmOperation's operation_type union). */
enum class PmOperation(val wire: String, val label: String) {
    IDEA_TRIAGE("idea_triage", "Idea triage"),
    BACKLOG_PRIORITIZE("backlog_prioritize", "Backlog reprioritize"),
    BLOCKER_DETECT("blocker_detect", "Blocker detection"),
    REPORT_GENERATE("report_generate", "Generate report");
}

/**
 * The finite states of a single console run. Drives which controls the screen offers. The transitions are
 * enforced by [AgentRunMath.nextState]; the console never lets the user execute before a ticket is claimed
 * (except PM which is operation-driven), nor approve/reject a deployment that is not awaiting approval.
 */
enum class RunState {
    /** No ticket selected yet (pick from eligible tickets). PM starts here too (pick an operation). */
    IDLE,

    /** A ticket has been claimed to this run; ready to execute. */
    CLAIMED,

    /** Execute in flight. */
    EXECUTING,

    /** Execution produced output that does NOT need approval - terminal-ish (can re-load output). */
    COMPLETED,

    /** DevOps deployment produced output that is awaiting a human approve/reject decision. */
    AWAITING_APPROVAL,

    /** Deployment approved (terminal). */
    APPROVED,

    /** Deployment rejected (terminal). */
    REJECTED,

    /** The run/output call 404'd (degrade-on-404: nothing to show, offer retry). */
    NOT_FOUND,

    /** A non-404 error (network / 403 forbidden / server). */
    ERROR,
}

/** An eligible ticket the console can claim (union of the per-type eligible-ticket shapes). */
data class EligibleTicket(
    val ticketId: String,
    val subject: String,
    val labels: List<String>,
    val complexity: String?,
    val estimatedEffortHours: Int?,
    val status: String?,
)

/** One test-result row lifted from a run output (coder test_results / qa regression counts). */
data class RunTestResult(
    val label: String,
    val passed: Boolean,
    val durationSeconds: Int?,
)

/**
 * The uniform, display-only projection of ANY agent run output. Fields absent for a given type stay at their
 * neutral default so the console renders a coherent card set regardless of which agent produced the output.
 */
data class AgentRunOutput(
    val type: AgentRunType,
    /** Headline line (branch name / deployment id / verdict / operation), never blank when there IS output. */
    val headline: String,
    /** A short status/verdict token (e.g. "pass", "fail", "success", "pending_approval"). */
    val status: String,
    val prUrl: String?,
    val filesChanged: List<String>,
    val insertions: Int,
    val deletions: Int,
    val testResults: List<RunTestResult>,
    val totalDurationSeconds: Int,
    val escalated: Boolean,
    val escalationReason: String?,
    /** True only when the parsed output represents a deployment awaiting a human approval decision. */
    val awaitingApproval: Boolean,
    /** Free-form extra key/value lines the console shows verbatim (per-type extras, e.g. PM counts). */
    val extras: List<Pair<String, String>>,
)

/** Outcome of a deployment approve/reject decision. */
data class DeploymentDecision(
    val runId: String,
    val deploymentId: String,
    val approvalStatus: String,
    val approvedBy: String,
    val notes: String?,
)

/** A run's markdown report (QA). */
data class RunReport(
    val runId: String,
    val verdict: String,
    val markdown: String,
)

/** A compact metrics projection (union of the per-type metrics maps) rendered as labelled rows. */
data class RunMetrics(
    val rows: List<Pair<String, String>>,
)
