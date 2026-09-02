package com.testlogon.android.feature.workflow

import com.testlogon.android.core.network.workflow.DripSequenceCreateRequest
import com.testlogon.android.core.network.workflow.DripSequenceDto
import com.testlogon.android.core.network.workflow.DripStageDto
import com.testlogon.android.core.network.workflow.WorkflowRuleCreateRequest
import com.testlogon.android.core.network.workflow.WorkflowRunDto
import java.time.Instant

/**
 * WFL — extra feature domain (run history + drip sequences) + DTO mappers + request builders for the
 * SuiteCRM Workflow admin CRUD. Android-free + JVM-testable. Complements [WorkflowRule] in
 * WorkflowRuleModel.kt (the shared epoch->Instant helper is duplicated privately to keep files decoupled).
 */

private fun epochOrNull(sec: Long?): Instant? =
    sec?.takeIf { it > 0 }?.let { Instant.ofEpochSecond(it) }

// ---------------------------------------------------------------------------
// Run history
// ---------------------------------------------------------------------------

/** One rule-run history entry (mapped from [WorkflowRunDto]). */
data class WorkflowRun(
    val runId: String,
    val ruleId: String,
    val targetModule: WorkflowTargetModule = WorkflowTargetModule.UNKNOWN,
    val recordId: String = "",
    val triggerType: WorkflowTriggerType = WorkflowTriggerType.UNKNOWN,
    val outcome: RunOutcome = RunOutcome.UNKNOWN,
    val actionsFiredCount: Int = 0,
    val startedAt: Instant? = null,
    val finishedAt: Instant? = null,
    val errorMessage: String? = null,
)

/** Maps a transport run to the feature domain. */
fun WorkflowRunDto.toDomain(): WorkflowRun = WorkflowRun(
    runId = runId,
    ruleId = ruleId,
    targetModule = WorkflowTargetModule.fromToken(targetModule),
    recordId = recordId,
    triggerType = WorkflowTriggerType.fromToken(triggerType),
    outcome = WorkflowRuleMath.outcomeOf(outcome),
    actionsFiredCount = actionsFired.size,
    startedAt = epochOrNull(startedAt),
    finishedAt = epochOrNull(finishedAt),
    errorMessage = errorMessage?.takeIf { it.isNotBlank() },
)

// ---------------------------------------------------------------------------
// Drip sequences
// ---------------------------------------------------------------------------

/** One drip-sequence stage (domain form; used by the create form + list display). */
data class DripStage(
    val stageNumber: Int,
    val delayHours: Int,
    val templateId: String,
    val toField: String,
)

/** One drip sequence (mapped from [DripSequenceDto]). */
data class DripSequence(
    val sequenceId: String,
    val name: String,
    val description: String = "",
    val stageCount: Int = 0,
    val createdBy: String = "",
    val createdAt: Instant? = null,
    val updatedAt: Instant? = null,
)

/** Maps a transport drip sequence to the feature domain (counting stages, not carrying raw payloads). */
fun DripSequenceDto.toDomain(): DripSequence = DripSequence(
    sequenceId = sequenceId,
    name = name,
    description = description,
    stageCount = stages.size,
    createdBy = createdBy,
    createdAt = epochOrNull(createdAt),
    updatedAt = epochOrNull(updatedAt),
)

// ---------------------------------------------------------------------------
// Request builders (domain -> transport). Kept PURE so they are unit-tested.
// ---------------------------------------------------------------------------

/** Builds the minimal create request for a rule (no conditions/actions from the lightweight form). */
fun buildRuleCreateRequest(
    name: String,
    description: String,
    targetModule: WorkflowTargetModule,
    triggerType: WorkflowTriggerType,
    enabled: Boolean,
): WorkflowRuleCreateRequest = WorkflowRuleCreateRequest(
    name = name.trim(),
    description = description.trim(),
    targetModule = targetModule.token,
    triggerType = triggerType.token,
    enabled = enabled,
)

/** Builds the create request for a drip sequence from domain stages. */
fun buildDripCreateRequest(
    name: String,
    description: String,
    stages: List<DripStage>,
): DripSequenceCreateRequest = DripSequenceCreateRequest(
    name = name.trim(),
    description = description.trim(),
    stages = stages.map {
        DripStageDto(
            stageNumber = it.stageNumber,
            delayHours = it.delayHours,
            templateId = it.templateId.trim(),
            toField = it.toField.trim(),
        )
    },
)
