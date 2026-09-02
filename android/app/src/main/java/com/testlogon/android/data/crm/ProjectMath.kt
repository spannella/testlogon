package com.testlogon.android.data.crm

/**
 * CRM-AND-PRJ — PURE, framework-free logic for the SuiteCRM Projects task-board / milestones /
 * workload / members surfaces. No Android / java.time types leak in, so every function is
 * JVM-unit-testable (mirrors the CrmPecMath / CrmSalesMath idiom).
 *
 * Mirrors the LIVE web contract (frontend/src/api/endpoints/crmProjects.ts) + the backend
 * (app/routers/crm_projects.py + app/models.py CrmProjectTask* / CrmMilestone* / CrmTaskWorkload*
 * / CrmProjectMember*).
 *
 * Responsibilities:
 *  - task ordering + a client-side reorder (move up / move down / drag) that yields the ordered
 *    id list the PUT /tasks/order route expects.
 *  - milestone summary roll-up (total / overdue / on-track / no-date counts) derived client-side so
 *    the board still shows sane numbers when GET /milestones degrades (404).
 *  - workload aggregation (per-assignee task + overdue counts) derived from a task list when GET
 *    /workload degrades.
 *  - member-role ordering + labels (mirror CrmProjectMemberRole).
 *
 * Degrade, never throw: null / malformed inputs render neutrally rather than raising.
 */
object ProjectMath {

    const val EM_DASH: String = "—"

    // ── Task order / reorder ──────────────────────────────────────────────────

    /**
     * Stable sort of tasks by their [CrmProjectTask.taskOrder], breaking ties by name so the board
     * is deterministic even when the server hands back duplicate orders (dev-host drift).
     */
    fun sortedByOrder(tasks: List<CrmProjectTask>): List<CrmProjectTask> =
        tasks.sortedWith(compareBy({ it.taskOrder }, { it.name }))

    /**
     * Move the task at [index] one slot toward the front (up). Returns the new ordered id list to
     * send to PUT /tasks/order. Out-of-range / first-position is a no-op (returns the current ids).
     */
    fun moveUp(tasks: List<CrmProjectTask>, index: Int): List<String> {
        val ids = sortedByOrder(tasks).map { it.id }.toMutableList()
        if (index <= 0 || index >= ids.size) return ids
        val tmp = ids[index - 1]
        ids[index - 1] = ids[index]
        ids[index] = tmp
        return ids
    }

    /**
     * Move the task at [index] one slot toward the back (down). Out-of-range / last-position is a
     * no-op (returns the current ids).
     */
    fun moveDown(tasks: List<CrmProjectTask>, index: Int): List<String> {
        val ids = sortedByOrder(tasks).map { it.id }.toMutableList()
        if (index < 0 || index >= ids.size - 1) return ids
        val tmp = ids[index + 1]
        ids[index + 1] = ids[index]
        ids[index] = tmp
        return ids
    }

    /**
     * The next task_order to hand a freshly-created task so it lands at the end of the board. Mirrors
     * the backend's "0 = auto-assign" convention by returning (max existing order + 1), or 0 for an
     * empty project.
     */
    fun nextTaskOrder(tasks: List<CrmProjectTask>): Int =
        if (tasks.isEmpty()) 0 else (tasks.maxOf { it.taskOrder } + 1)

    // ── Milestones ────────────────────────────────────────────────────────────

    /** A task is a milestone when the server flag is set. */
    fun milestones(tasks: List<CrmProjectTask>): List<CrmProjectTask> =
        sortedByOrder(tasks.filter { it.isMilestone })

    /**
     * Overdue = a not-yet-complete task whose end_date is in the past (relative to [nowSeconds]).
     * Tolerant of epoch-millis end dates (magnitude ≥ 1e12 is divided down). A null / non-positive
     * end date is never overdue (no date to miss).
     */
    fun isOverdue(task: CrmProjectTask, nowSeconds: Long): Boolean {
        if (task.percentComplete >= 100) return false
        val end = task.endDate ?: return false
        if (end <= 0) return false
        val endSec = if (end >= 1_000_000_000_000L) end / 1000 else end
        return endSec < nowSeconds
    }

    /** On track = a milestone that is neither complete nor overdue and has a target end date. */
    fun isOnTrack(task: CrmProjectTask, nowSeconds: Long): Boolean {
        if (task.percentComplete >= 100) return true
        val end = task.endDate ?: return false
        if (end <= 0) return false
        return !isOverdue(task, nowSeconds)
    }

    /**
     * Client-side milestone roll-up used when GET /milestones degrades (404) — mirrors
     * CrmMilestoneSummaryResp's counts. `noDate` milestones have no end date (can't be judged).
     */
    data class MilestoneSummary(
        val total: Int,
        val overdue: Int,
        val onTrack: Int,
        val noDate: Int,
    )

    fun milestoneSummary(tasks: List<CrmProjectTask>, nowSeconds: Long): MilestoneSummary {
        val ms = milestones(tasks)
        var overdue = 0
        var onTrack = 0
        var noDate = 0
        for (m in ms) {
            val end = m.endDate
            when {
                end == null || end <= 0 -> noDate++
                isOverdue(m, nowSeconds) -> overdue++
                else -> onTrack++
            }
        }
        return MilestoneSummary(total = ms.size, overdue = overdue, onTrack = onTrack, noDate = noDate)
    }

    // ── Workload ──────────────────────────────────────────────────────────────

    /** Per-assignee workload row derived from a task list (mirrors CrmTaskWorkloadEntry). */
    data class WorkloadRow(
        val assigneeKey: String,
        val taskCount: Int,
        val overdueCount: Int,
    )

    private const val UNASSIGNED_KEY = "unassigned"

    /**
     * Aggregate a task list into per-assignee workload rows, sorted by task count (desc) then key.
     * Tasks with no assignee roll up under an "unassigned" bucket. Used when GET /workload degrades.
     */
    fun workload(tasks: List<CrmProjectTask>, nowSeconds: Long): List<WorkloadRow> {
        val counts = LinkedHashMap<String, IntArray>() // key -> [total, overdue]
        for (t in tasks) {
            val key = t.assignedUserSub?.takeIf { it.isNotBlank() } ?: UNASSIGNED_KEY
            val row = counts.getOrPut(key) { intArrayOf(0, 0) }
            row[0] += 1
            if (isOverdue(t, nowSeconds)) row[1] += 1
        }
        return counts.entries
            .map { WorkloadRow(it.key, it.value[0], it.value[1]) }
            .sortedWith(compareByDescending<WorkloadRow> { it.taskCount }.thenBy { it.assigneeKey })
    }

    /** Display label for a workload assignee key (the "unassigned" bucket gets a friendly name). */
    fun assigneeLabel(key: String?): String = when {
        key.isNullOrBlank() -> "Unassigned"
        key == UNASSIGNED_KEY -> "Unassigned"
        else -> key
    }

    // ── Member roles ──────────────────────────────────────────────────────────

    const val ROLE_OWNER = "owner"
    const val ROLE_MEMBER = "member"
    const val ROLE_VIEWER = "viewer"

    /** Ordered, curated role list for the add/edit chip row (mirror CrmProjectMemberRole). */
    val MEMBER_ROLES: List<String> = listOf(ROLE_OWNER, ROLE_MEMBER, ROLE_VIEWER)

    fun memberRoleLabel(role: String?): String = when (role) {
        ROLE_OWNER -> "Owner"
        ROLE_MEMBER -> "Member"
        ROLE_VIEWER -> "Viewer"
        null -> EM_DASH
        else -> titleCaseSnake(role)
    }

    /** Sort members owner → member → viewer, then by user sub, so the roster is stable. */
    fun sortedMembers(members: List<CrmProjectMember>): List<CrmProjectMember> {
        val rank = mapOf(ROLE_OWNER to 0, ROLE_MEMBER to 1, ROLE_VIEWER to 2)
        return members.sortedWith(
            compareBy({ rank[it.role] ?: 99 }, { it.userSub }),
        )
    }

    // ── Templates ─────────────────────────────────────────────────────────────

    /** Count of milestone task-defs in a template (surfaced on the template picker row). */
    fun templateMilestoneCount(def: CrmProjectTemplate): Int =
        def.taskDefs.count { it.isMilestone }

    /** Short "N tasks · M milestones" label for a template row. */
    fun templateSummaryLabel(def: CrmProjectTemplate): String {
        val tasks = def.taskDefs.size
        val ms = templateMilestoneCount(def)
        val tPart = if (tasks == 1) "1 task" else "$tasks tasks"
        return if (ms > 0) "$tPart · $ms milestone${if (ms == 1) "" else "s"}" else tPart
    }

    // ── internal ──────────────────────────────────────────────────────────────

    private fun titleCaseSnake(raw: String): String =
        raw.split('_', ' ')
            .filter { it.isNotBlank() }
            .joinToString(" ") { part -> part.replaceFirstChar { c -> c.uppercaseChar() } }
            .ifBlank { EM_DASH }
}
