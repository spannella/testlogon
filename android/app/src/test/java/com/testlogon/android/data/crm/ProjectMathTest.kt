package com.testlogon.android.data.crm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * CRM-AND-PRJ — JVM unit tests for the pure Projects task-board / milestone / workload / member
 * logic. No Android types; degrade-on-bad-input is asserted so the UI never crashes on a 404
 * (module disabled) or dev-host drift.
 */
class ProjectMathTest {

    private fun task(
        id: String,
        order: Int = 0,
        name: String = id,
        pct: Int = 0,
        end: Long? = null,
        milestone: Boolean = false,
        assignee: String? = null,
    ) = CrmProjectTask(
        id = id,
        name = name,
        description = null,
        taskOrder = order,
        durationDays = 1,
        startDate = null,
        endDate = end,
        percentComplete = pct,
        isMilestone = milestone,
        assignedUserSub = assignee,
        predecessorTaskIds = emptyList(),
    )

    // ── Ordering / reorder ────────────────────────────────────────────────────

    @Test
    fun sortedByOrder_ordersByTaskOrderThenName() {
        // order 1 ties broken by name: "a" (name="a") < "c" (name="zzz"); then order 2 "b".
        val out = ProjectMath.sortedByOrder(
            listOf(task("b", order = 2), task("a", order = 1), task("c", order = 1, name = "zzz")),
        )
        assertEquals(listOf("a", "c", "b"), out.map { it.id })
    }

    @Test
    fun moveUp_swapsWithPrevious() {
        val tasks = listOf(task("a", 0), task("b", 1), task("c", 2))
        assertEquals(listOf("a", "c", "b"), ProjectMath.moveUp(tasks, 2))
    }

    @Test
    fun moveUp_firstPositionIsNoOp() {
        val tasks = listOf(task("a", 0), task("b", 1))
        assertEquals(listOf("a", "b"), ProjectMath.moveUp(tasks, 0))
    }

    @Test
    fun moveDown_swapsWithNext() {
        val tasks = listOf(task("a", 0), task("b", 1), task("c", 2))
        assertEquals(listOf("b", "a", "c"), ProjectMath.moveDown(tasks, 0))
    }

    @Test
    fun moveDown_lastPositionIsNoOp() {
        val tasks = listOf(task("a", 0), task("b", 1))
        assertEquals(listOf("a", "b"), ProjectMath.moveDown(tasks, 1))
    }

    @Test
    fun nextTaskOrder_emptyAndPopulated() {
        assertEquals(0, ProjectMath.nextTaskOrder(emptyList()))
        assertEquals(6, ProjectMath.nextTaskOrder(listOf(task("a", 5), task("b", 2))))
    }

    // ── Overdue / on-track ────────────────────────────────────────────────────

    @Test
    fun isOverdue_pastEndAndIncomplete() {
        val now = 1_000_000L
        assertTrue(ProjectMath.isOverdue(task("a", end = 900_000L, pct = 40), now))
        // complete -> never overdue
        assertFalse(ProjectMath.isOverdue(task("a", end = 900_000L, pct = 100), now))
        // future end -> not overdue
        assertFalse(ProjectMath.isOverdue(task("a", end = 1_100_000L, pct = 0), now))
        // no date -> not overdue
        assertFalse(ProjectMath.isOverdue(task("a", end = null, pct = 0), now))
    }

    @Test
    fun isOverdue_toleratesEpochMillis() {
        // now = 1_000_000 s; end supplied in millis for the same instant -> not overdue
        assertFalse(ProjectMath.isOverdue(task("a", end = 1_000_000_000L * 1000, pct = 0), 1_000_000L))
    }

    // ── Milestone summary ─────────────────────────────────────────────────────

    @Test
    fun milestoneSummary_countsBuckets() {
        val now = 1_000_000L
        val tasks = listOf(
            task("m1", milestone = true, end = 900_000L, pct = 10),   // overdue
            task("m2", milestone = true, end = 1_100_000L, pct = 10), // on track
            task("m3", milestone = true, end = null, pct = 0),        // no date
            task("m4", milestone = true, end = 900_000L, pct = 100),  // complete -> on track
            task("t1", milestone = false, end = 900_000L),            // not a milestone
        )
        val s = ProjectMath.milestoneSummary(tasks, now)
        assertEquals(4, s.total)
        assertEquals(1, s.overdue)
        assertEquals(2, s.onTrack)
        assertEquals(1, s.noDate)
    }

    // ── Workload ──────────────────────────────────────────────────────────────

    @Test
    fun workload_aggregatesPerAssigneeWithOverdue() {
        val now = 1_000_000L
        val rows = ProjectMath.workload(
            listOf(
                task("a", assignee = "u1", end = 900_000L, pct = 0),   // u1 overdue
                task("b", assignee = "u1", end = 1_100_000L, pct = 0), // u1 ok
                task("c", assignee = "u2", end = 900_000L, pct = 0),   // u2 overdue
                task("d", assignee = null, end = null),                // unassigned
            ),
            now,
        )
        // u1 has the most tasks -> first
        assertEquals("u1", rows[0].assigneeKey)
        assertEquals(2, rows[0].taskCount)
        assertEquals(1, rows[0].overdueCount)
        val unassigned = rows.first { it.assigneeKey == "unassigned" }
        assertEquals(1, unassigned.taskCount)
        assertEquals(0, unassigned.overdueCount)
    }

    @Test
    fun assigneeLabel_unassignedFriendly() {
        assertEquals("Unassigned", ProjectMath.assigneeLabel(null))
        assertEquals("Unassigned", ProjectMath.assigneeLabel("unassigned"))
        assertEquals("u1", ProjectMath.assigneeLabel("u1"))
    }

    // ── Member roles ──────────────────────────────────────────────────────────

    @Test
    fun memberRoleLabel_knownAndUnknown() {
        assertEquals("Owner", ProjectMath.memberRoleLabel("owner"))
        assertEquals("Member", ProjectMath.memberRoleLabel("member"))
        assertEquals("Viewer", ProjectMath.memberRoleLabel("viewer"))
        assertEquals(ProjectMath.EM_DASH, ProjectMath.memberRoleLabel(null))
        assertEquals("Co Owner", ProjectMath.memberRoleLabel("co_owner"))
    }

    @Test
    fun sortedMembers_ownerFirst() {
        val members = listOf(
            CrmProjectMember(projectId = "p", userSub = "v", role = "viewer", addedBy = "x", addedAt = 0),
            CrmProjectMember(projectId = "p", userSub = "o", role = "owner", addedBy = "x", addedAt = 0),
            CrmProjectMember(projectId = "p", userSub = "m", role = "member", addedBy = "x", addedAt = 0),
        )
        assertEquals(listOf("o", "m", "v"), ProjectMath.sortedMembers(members).map { it.userSub })
    }

    // ── Templates ─────────────────────────────────────────────────────────────

    @Test
    fun templateSummary_labelsTasksAndMilestones() {
        val def = CrmProjectTemplate(
            id = "t",
            name = "Launch",
            description = null,
            taskDefs = listOf(
                CrmTemplateTaskDef("1", "kick", null, 0, 1, false),
                CrmTemplateTaskDef("2", "ms", null, 1, 1, true),
            ),
            createdAt = 0,
            updatedAt = 0,
        )
        assertEquals(1, ProjectMath.templateMilestoneCount(def))
        assertEquals("2 tasks · 1 milestone", ProjectMath.templateSummaryLabel(def))
    }
}
