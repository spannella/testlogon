package com.testlogon.android.feature.agents.orchestrator.data

/**
 * AGENT-ORCHESTRATOR (web-parity) - PURE loop-lifecycle logic for the orchestrator console. No Android /
 * coroutine / Retrofit deps -> fully JVM-unit-testable. Mirrors the guard rules the backend
 * app/routers/agent_orchestrator.py enforces, so the console never offers an action the server would reject:
 *
 *  - START     : only when the loop is NOT already running (idle/stopped/unknown). 409 loop_already_running.
 *  - PAUSE     : only when the loop IS running. (finish current work, don't pick new)
 *  - RESUME    : only when paused.
 *  - STOP      : whenever the loop is running or paused (graceful).
 *  - CLAIM     : only when NO active ticket (409 worker_busy otherwise).
 *  - COMPLETE  : only when there IS an active ticket (400 no_active_ticket otherwise).
 *  - RELEASE   : only when there IS an active ticket.
 *  - HEARTBEAT : always available (debug ping).
 *
 * These are UI-affordance guards, not a re-implementation of server truth: the server remains the source of
 * truth (a rejected action still surfaces its error).
 */
object OrchestratorMath {

    /** The set of loop-control + ticket actions that are currently valid for [status]. */
    fun availableActions(status: AgentStatus): Set<LoopAction> {
        val actions = linkedSetOf<LoopAction>()
        val running = status.loopRunning
        when (status.state) {
            AgentLoopState.PAUSED -> {
                actions += LoopAction.RESUME
                actions += LoopAction.STOP
            }
            AgentLoopState.WORKING -> {
                actions += LoopAction.PAUSE
                actions += LoopAction.STOP
            }
            AgentLoopState.IDLE, AgentLoopState.STOPPED, AgentLoopState.UNKNOWN -> {
                if (running) {
                    actions += LoopAction.PAUSE
                    actions += LoopAction.STOP
                } else {
                    actions += LoopAction.START
                }
            }
        }
        // Ticket operations gate purely on whether a ticket is claimed.
        if (status.hasActiveTicket) {
            actions += LoopAction.COMPLETE
            actions += LoopAction.RELEASE
        } else {
            actions += LoopAction.CLAIM
        }
        actions += LoopAction.HEARTBEAT
        return actions
    }

    fun canStart(status: AgentStatus): Boolean = LoopAction.START in availableActions(status)
    fun canPause(status: AgentStatus): Boolean = LoopAction.PAUSE in availableActions(status)
    fun canResume(status: AgentStatus): Boolean = LoopAction.RESUME in availableActions(status)
    fun canStop(status: AgentStatus): Boolean = LoopAction.STOP in availableActions(status)
    fun canClaim(status: AgentStatus): Boolean = LoopAction.CLAIM in availableActions(status)
    fun canComplete(status: AgentStatus): Boolean = LoopAction.COMPLETE in availableActions(status)
    fun canRelease(status: AgentStatus): Boolean = LoopAction.RELEASE in availableActions(status)

    /**
     * Optimistic local projection of what [status] becomes after [action] succeeds. Used to keep the console
     * responsive before the follow-up status refetch lands (and, for CLAIM, to seed the claimed ticket id). The
     * server refetch always overwrites this, so it only needs to be plausible, not authoritative.
     */
    fun project(status: AgentStatus, action: LoopAction, claimedTicketId: String = ""): AgentStatus =
        when (action) {
            LoopAction.START -> status.copy(state = AgentLoopState.WORKING, loopRunning = true)
            LoopAction.RESUME -> status.copy(state = AgentLoopState.IDLE, loopRunning = true)
            LoopAction.PAUSE -> status.copy(state = AgentLoopState.PAUSED)
            LoopAction.STOP -> status.copy(state = AgentLoopState.STOPPED, loopRunning = false)
            LoopAction.CLAIM -> status.copy(currentTicketId = claimedTicketId)
            LoopAction.RELEASE -> status.copy(
                currentTicketId = "",
                currentTicketTitle = "",
                state = AgentLoopState.IDLE,
            )
            LoopAction.COMPLETE -> status.copy(
                currentTicketId = "",
                currentTicketTitle = "",
                state = AgentLoopState.IDLE,
                ticketsCompleted = status.ticketsCompleted + 1,
            )
            LoopAction.HEARTBEAT -> status
        }

    /**
     * Seconds since the last heartbeat given [nowSeconds]; null when never beaten or when the clock is behind
     * the recorded beat (do not surface a negative age).
     */
    fun heartbeatAgeSeconds(status: AgentStatus, nowSeconds: Long): Long? {
        if (status.heartbeatAt <= 0) return null
        val age = nowSeconds - status.heartbeatAt
        return if (age < 0) null else age
    }

    /**
     * True when the loop is running but the last heartbeat is older than [staleThresholdSeconds] - the console
     * badges the worker as "may be stalled". A stopped/never-beaten worker is never "stale".
     */
    fun isHeartbeatStale(status: AgentStatus, nowSeconds: Long, staleThresholdSeconds: Long): Boolean {
        if (!status.loopRunning) return false
        val age = heartbeatAgeSeconds(status, nowSeconds) ?: return false
        return age > staleThresholdSeconds
    }

    /** A short, human summary line for the status header. */
    fun summaryLine(status: AgentStatus): String {
        val running = if (status.loopRunning) "loop running" else "loop stopped"
        val ticket = if (status.hasActiveTicket) {
            "on ${status.currentTicketTitle.ifBlank { status.currentTicketId }}"
        } else {
            "no active ticket"
        }
        return "${status.state.label} · $running · $ticket"
    }
}
