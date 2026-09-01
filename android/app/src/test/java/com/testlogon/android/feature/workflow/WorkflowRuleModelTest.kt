package com.testlogon.android.feature.workflow

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.network.workflow.WorkflowRuleDto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** WFL — pure tests for workflow-rule mapping, sort, enabled-count + list fold (degrade on 404/403). */
class WorkflowRuleModelTest {

    private fun rule(id: String, name: String, enabled: Boolean) = WorkflowRule(
        ruleId = id,
        name = name,
        enabled = enabled,
    )

    @Test
    fun dtoMapper_countsConditionsActions_andLenientEnums() {
        val dto = WorkflowRuleDto(
            ruleId = "r1",
            name = "Escalate",
            targetModule = "ticket",
            triggerType = "on_save",
            conditions = listOf(mapOf("field" to "x"), mapOf("field" to "y")),
            actions = listOf(mapOf("action_type" to "send_email")),
            enabled = true,
        )
        val d = dto.toDomain()
        assertEquals(WorkflowTargetModule.TICKET, d.targetModule)
        assertEquals(WorkflowTriggerType.ON_SAVE, d.triggerType)
        assertEquals(2, d.conditionCount)
        assertEquals(1, d.actionCount)
    }

    @Test
    fun dtoMapper_unknownModuleAndTrigger_fallBack() {
        val dto = WorkflowRuleDto(ruleId = "r2", name = "n", targetModule = "zzz", triggerType = "qqq")
        val d = dto.toDomain()
        assertEquals(WorkflowTargetModule.UNKNOWN, d.targetModule)
        assertEquals(WorkflowTriggerType.UNKNOWN, d.triggerType)
    }

    @Test
    fun sortRules_enabledFirst_thenNameCaseInsensitive() {
        val sorted = sortRules(
            listOf(
                rule("1", "beta", enabled = false),
                rule("2", "Alpha", enabled = true),
                rule("3", "alpha", enabled = false),
            ),
        )
        assertEquals(listOf("2", "3", "1"), sorted.map { it.ruleId })
    }

    @Test
    fun enabledCount_counts() {
        assertEquals(
            2,
            enabledCount(listOf(rule("1", "a", true), rule("2", "b", false), rule("3", "c", true))),
        )
    }

    @Test
    fun foldRulesResult_404and403_areUnavailable() {
        assertEquals(WorkflowRulesUiState.Unavailable, foldRulesResult(null, ApiError(404, "x")))
        assertEquals(WorkflowRulesUiState.Unavailable, foldRulesResult(null, ApiError(403, "x")))
    }

    @Test
    fun foldRulesResult_otherError_isError_emptyIsEmpty_contentSorted() {
        assertTrue(foldRulesResult(null, ApiError(500, "x")) is WorkflowRulesUiState.Error)
        assertEquals(WorkflowRulesUiState.Empty, foldRulesResult(emptyList(), null))
        val state = foldRulesResult(
            listOf(rule("1", "b", false), rule("2", "a", true)),
            null,
        )
        assertTrue(state is WorkflowRulesUiState.Content)
        val content = state as WorkflowRulesUiState.Content
        assertEquals("2", content.rules.first().ruleId)
        assertEquals(1, content.enabledCount)
    }
}
