package com.testlogon.android.feature.workflow

import com.testlogon.android.core.network.workflow.WorkflowRuleDto
import java.time.Instant

/**
 * WFL — feature domain + DTO mappers + PURE summary logic for the SuiteCRM Workflow admin list/read MVP.
 * Android-free + JVM-testable.
 *
 * Target-module + trigger-type are lenient enums (UNKNOWN fallback) mirroring the web constant lists.
 * Timestamps are Unix-second Longs on the wire; 0 degrades to null [Instant].
 */

/** Module a rule targets (mirrors WORKFLOW_TARGET_MODULES). */
enum class WorkflowTargetModule(val token: String) {
    TICKET("ticket"),
    CONTACT("contact"),
    ORDER("order"),
    SUBSCRIPTION("subscription"),
    LEAD("lead"),
    UNKNOWN("unknown"),
    ;

    companion object {
        fun fromToken(t: String?): WorkflowTargetModule = entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** Trigger kind for a rule (mirrors WORKFLOW_TRIGGER_TYPES). */
enum class WorkflowTriggerType(val token: String) {
    ON_SAVE("on_save"),
    ON_SCHEDULE("on_schedule"),
    ON_TIME_ELAPSED("on_time_elapsed"),
    UNKNOWN("unknown"),
    ;

    companion object {
        fun fromToken(t: String?): WorkflowTriggerType = entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** One workflow rule (mapped from [WorkflowRuleDto]). */
data class WorkflowRule(
    val ruleId: String,
    val name: String,
    val description: String = "",
    val targetModule: WorkflowTargetModule = WorkflowTargetModule.UNKNOWN,
    val triggerType: WorkflowTriggerType = WorkflowTriggerType.UNKNOWN,
    val conditionCount: Int = 0,
    val actionCount: Int = 0,
    val enabled: Boolean = false,
    val createdBy: String = "",
    val createdAt: Instant? = null,
    val updatedAt: Instant? = null,
)

private fun epochToInstant(sec: Long?): Instant? =
    sec?.takeIf { it > 0 }?.let { Instant.ofEpochSecond(it) }

/** Maps a transport rule to the feature domain (counting conditions/actions, not carrying raw payloads). */
fun WorkflowRuleDto.toDomain(): WorkflowRule = WorkflowRule(
    ruleId = ruleId,
    name = name,
    description = description,
    targetModule = WorkflowTargetModule.fromToken(targetModule),
    triggerType = WorkflowTriggerType.fromToken(triggerType),
    conditionCount = conditions.size,
    actionCount = actions.size,
    enabled = enabled,
    createdBy = createdBy,
    createdAt = epochToInstant(createdAt),
    updatedAt = epochToInstant(updatedAt),
)

/**
 * PURE list ordering for the admin rule list: enabled rules first, then by name (case-insensitive),
 * stable + total. This is the read-only board's deterministic order.
 */
fun sortRules(rules: List<WorkflowRule>): List<WorkflowRule> =
    rules.sortedWith(
        compareByDescending<WorkflowRule> { it.enabled }
            .thenBy { it.name.lowercase() }
            .thenBy { it.ruleId },
    )

/** PURE count of enabled rules — powers the list header badge. */
fun enabledCount(rules: List<WorkflowRule>): Int = rules.count { it.enabled }
