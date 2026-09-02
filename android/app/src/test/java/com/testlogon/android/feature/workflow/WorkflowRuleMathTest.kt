package com.testlogon.android.feature.workflow

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.network.workflow.DripSequenceDto
import com.testlogon.android.core.network.workflow.WorkflowRunDto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * WFL — pure tests for the workflow admin CRUD extension: enable-gating + create-form validation
 * (WorkflowRuleMath), run + drip mappers, request builders, and the runs/drip folds (degrade on 404/403).
 */
class WorkflowRuleMathTest {

    // ----- toggle / enable gating -----

    @Test
    fun toggleLabel_reflectsCurrentState() {
        assertEquals("Disable", WorkflowRuleMath.toggleLabel(enabled = true))
        assertEquals("Enable", WorkflowRuleMath.toggleLabel(enabled = false))
    }

    @Test
    fun nextEnabledState_flips() {
        assertTrue(WorkflowRuleMath.nextEnabledState(false))
        assertFalse(WorkflowRuleMath.nextEnabledState(true))
    }

    // ----- create validation -----

    @Test
    fun validateCreate_blankName_reportsProblem() {
        val problems = WorkflowRuleMath.validateCreate(
            name = "  ",
            targetModule = WorkflowTargetModule.TICKET,
            triggerType = WorkflowTriggerType.ON_SAVE,
        )
        assertEquals(listOf("Name is required."), problems)
    }

    @Test
    fun validateCreate_unknownModuleAndTrigger_reportBoth() {
        val problems = WorkflowRuleMath.validateCreate(
            name = "Escalate",
            targetModule = WorkflowTargetModule.UNKNOWN,
            triggerType = null,
        )
        assertEquals(2, problems.size)
    }

    @Test
    fun canSubmitCreate_validForm_true() {
        assertTrue(
            WorkflowRuleMath.canSubmitCreate(
                name = "Escalate",
                targetModule = WorkflowTargetModule.CONTACT,
                triggerType = WorkflowTriggerType.ON_SCHEDULE,
            ),
        )
    }

    // ----- drip validation -----

    @Test
    fun validateDripCreate_emptyStages_reportsProblem() {
        val problems = WorkflowRuleMath.validateDripCreate("Welcome", emptyList())
        assertTrue(problems.contains("Add at least one stage."))
    }

    @Test
    fun validateDripCreate_badStage_reportsTemplateAndDelay() {
        val problems = WorkflowRuleMath.validateDripCreate(
            "Welcome",
            listOf(DripStage(stageNumber = 1, delayHours = -5, templateId = "", toField = "email")),
        )
        assertTrue(problems.any { it.contains("template id") })
        assertTrue(problems.any { it.contains("delay") })
    }

    @Test
    fun canSubmitDrip_validForm_true() {
        assertTrue(
            WorkflowRuleMath.canSubmitDrip(
                "Welcome",
                listOf(DripStage(1, 24, "tmpl_1", "email")),
            ),
        )
    }

    // ----- outcome bucketing -----

    @Test
    fun outcomeOf_mapsKnownValues_andFallsBack() {
        assertEquals(RunOutcome.MATCHED, WorkflowRuleMath.outcomeOf("matched"))
        assertEquals(RunOutcome.ERROR, WorkflowRuleMath.outcomeOf("ERROR"))
        assertEquals(RunOutcome.SKIPPED, WorkflowRuleMath.outcomeOf("skipped"))
        assertEquals(RunOutcome.UNKNOWN, WorkflowRuleMath.outcomeOf("weird"))
        assertEquals(RunOutcome.UNKNOWN, WorkflowRuleMath.outcomeOf(null))
    }

    // ----- run mapper -----

    @Test
    fun runDtoMapper_countsActions_bucketsOutcome_dropsZeroTimestamps() {
        val dto = WorkflowRunDto(
            runId = "run1",
            ruleId = "r1",
            targetModule = "ticket",
            triggerType = "on_save",
            outcome = "matched",
            actionsFired = listOf(mapOf("a" to 1), mapOf("b" to 2)),
            startedAt = 1_700_000_000,
            finishedAt = 0,
            errorMessage = "  ",
        )
        val d = dto.toDomain()
        assertEquals(RunOutcome.MATCHED, d.outcome)
        assertEquals(2, d.actionsFiredCount)
        assertEquals(WorkflowTargetModule.TICKET, d.targetModule)
        assertTrue(d.startedAt != null)
        assertEquals(null, d.finishedAt)
        assertEquals(null, d.errorMessage)
    }

    // ----- drip mapper -----

    @Test
    fun dripDtoMapper_countsStages() {
        val dto = DripSequenceDto(
            sequenceId = "seq1",
            name = "Welcome",
            stages = listOf(mapOf("s" to 1), mapOf("s" to 2), mapOf("s" to 3)),
            createdAt = 1_700_000_000,
            updatedAt = 1_700_000_500,
        )
        val d = dto.toDomain()
        assertEquals(3, d.stageCount)
        assertTrue(d.createdAt != null)
    }

    // ----- request builders -----

    @Test
    fun buildRuleCreateRequest_trimsAndMapsTokens() {
        val req = buildRuleCreateRequest(
            name = "  Escalate  ",
            description = " urgent ",
            targetModule = WorkflowTargetModule.ORDER,
            triggerType = WorkflowTriggerType.ON_TIME_ELAPSED,
            enabled = true,
        )
        assertEquals("Escalate", req.name)
        assertEquals("urgent", req.description)
        assertEquals("order", req.targetModule)
        assertEquals("on_time_elapsed", req.triggerType)
        assertTrue(req.enabled)
    }

    @Test
    fun buildDripCreateRequest_trimsStageFields() {
        val req = buildDripCreateRequest(
            name = " Welcome ",
            description = "",
            stages = listOf(DripStage(1, 24, "  tmpl_1  ", " email ")),
        )
        assertEquals("Welcome", req.name)
        assertEquals(1, req.stages.size)
        assertEquals("tmpl_1", req.stages.first().templateId)
        assertEquals("email", req.stages.first().toField)
    }

    // ----- folds -----

    @Test
    fun foldRunsResult_degradesOn404and403() {
        assertEquals(WorkflowRunsUiState.Unavailable, foldRunsResult(null, ApiError(404, "x")))
        assertEquals(WorkflowRunsUiState.Unavailable, foldRunsResult(null, ApiError(403, "x")))
        assertTrue(foldRunsResult(null, ApiError(500, "x")) is WorkflowRunsUiState.Error)
        assertEquals(WorkflowRunsUiState.Empty, foldRunsResult(emptyList(), null))
    }

    @Test
    fun foldRunsResult_sortsByStartedAtDescending() {
        val a = WorkflowRun(runId = "a", ruleId = "r", startedAt = java.time.Instant.ofEpochSecond(100))
        val b = WorkflowRun(runId = "b", ruleId = "r", startedAt = java.time.Instant.ofEpochSecond(200))
        val state = foldRunsResult(listOf(a, b), null)
        assertTrue(state is WorkflowRunsUiState.Content)
        assertEquals("b", (state as WorkflowRunsUiState.Content).runs.first().runId)
    }

    @Test
    fun foldDripResult_degradesAndSortsByName() {
        assertEquals(DripSequencesUiState.Unavailable, foldDripResult(null, ApiError(404, "x")))
        assertEquals(DripSequencesUiState.Empty, foldDripResult(emptyList(), null))
        val state = foldDripResult(
            listOf(
                DripSequence(sequenceId = "1", name = "Zeta"),
                DripSequence(sequenceId = "2", name = "alpha"),
            ),
            null,
        )
        assertTrue(state is DripSequencesUiState.Content)
        assertEquals("2", (state as DripSequencesUiState.Content).sequences.first().sequenceId)
    }
}
