package com.testlogon.android.feature.infraec2

import com.testlogon.android.data.infraec2.Ec2Action

/**
 * PURE (no Android / Compose types) EC2 instance state logic, extracted from Ec2Screen so it is unit-
 * testable on the JVM and is the single source of truth for which lifecycle actions an instance in a
 * given status may take. Mirrors the backend ec2_launcher state machine (start<->stop, reboot only when
 * running, terminate from running/stopped; a terminated instance takes no action).
 *
 * The backend normalizes statuses to lowercase strings (running/stopped/pending/stopping/... /terminated);
 * we compare case-insensitively and treat any unknown status conservatively (no destructive default).
 */
object Ec2InstanceMath {

    private fun norm(status: String): String = status.trim().lowercase()

    fun isRunning(status: String): Boolean = norm(status) == "running"
    fun isStopped(status: String): Boolean = norm(status) == "stopped"
    fun isTerminated(status: String): Boolean = norm(status) == "terminated"

    /** True once the instance is terminated (no further lifecycle actions are possible). */
    fun isActionable(status: String): Boolean = !isTerminated(status)

    /**
     * The set of lifecycle actions valid for [status]. Empty for terminated / transient / unknown
     * states (mirrors the Screen: Start when not-running, Stop+Reboot when running, Terminate when
     * running or stopped). Order is stable for deterministic rendering + assertions.
     */
    fun allowedActions(status: String): List<Ec2Action> {
        if (isTerminated(status)) return emptyList()
        val running = isRunning(status)
        val stopped = isStopped(status)
        val out = ArrayList<Ec2Action>(4)
        if (!running) out.add(Ec2Action.START)
        if (running) {
            out.add(Ec2Action.STOP)
            out.add(Ec2Action.REBOOT)
        }
        if (running || stopped) out.add(Ec2Action.TERMINATE)
        return out
    }

    fun canPerform(status: String, action: Ec2Action): Boolean = action in allowedActions(status)
}
