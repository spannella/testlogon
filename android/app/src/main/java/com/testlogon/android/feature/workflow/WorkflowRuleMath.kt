package com.testlogon.android.feature.workflow

/**
 * WFL — PURE rule-state + enable-gating + create-form validation logic for the SuiteCRM Workflow admin.
 * Android-free + JVM-testable. No I/O, no framework types.
 *
 * Mirrors the web constant lists in frontend/src/api/endpoints/crmWorkflow.ts
 * (WORKFLOW_TARGET_MODULES / WORKFLOW_TRIGGER_TYPES / WORKFLOW_OPERATORS / WORKFLOW_ACTION_TYPES) and the
 * backend validation in app/services/workflow_rules.py.
 */
object WorkflowRuleMath {

    /** Selectable target modules for the create form (mirrors WORKFLOW_TARGET_MODULES, real ones only). */
    val TARGET_MODULES: List<WorkflowTargetModule> = listOf(
        WorkflowTargetModule.TICKET,
        WorkflowTargetModule.CONTACT,
        WorkflowTargetModule.ORDER,
        WorkflowTargetModule.SUBSCRIPTION,
        WorkflowTargetModule.LEAD,
    )

    /** Selectable trigger types for the create form (mirrors WORKFLOW_TRIGGER_TYPES, real ones only). */
    val TRIGGER_TYPES: List<WorkflowTriggerType> = listOf(
        WorkflowTriggerType.ON_SAVE,
        WorkflowTriggerType.ON_SCHEDULE,
        WorkflowTriggerType.ON_TIME_ELAPSED,
    )

    /** Condition operators (mirrors WORKFLOW_OPERATORS). */
    val OPERATORS: List<String> = listOf(
        "eq", "neq", "contains", "gt", "lt", "is_empty", "is_not_empty",
    )

    /** Action types (mirrors WORKFLOW_ACTION_TYPES). */
    val ACTION_TYPES: List<String> = listOf(
        "modify_field", "create_record", "send_email", "drip_sequence",
    )

    /**
     * The label + intent for the enable/disable toggle of a rule. Enabled rules offer "Disable";
     * disabled rules offer "Enable". PURE — drives the row action button.
     */
    fun toggleLabel(enabled: Boolean): String = if (enabled) "Disable" else "Enable"

    /**
     * Whether the enable/disable toggle should be shown for a rule. A rule with NO actions can be created
     * but firing it is a no-op; we still allow the toggle (backend permits it) but callers may warn. This
     * returns the *target* enabled state after a toggle.
     */
    fun nextEnabledState(current: Boolean): Boolean = !current

    /**
     * PURE create-form validation. Mirrors the backend's required-field checks (name non-blank; a real
     * target module + trigger type must be chosen). Returns the list of human-readable problems; empty ==
     * ready to submit.
     */
    fun validateCreate(
        name: String,
        targetModule: WorkflowTargetModule?,
        triggerType: WorkflowTriggerType?,
    ): List<String> {
        val problems = mutableListOf<String>()
        if (name.isBlank()) problems += "Name is required."
        if (targetModule == null || targetModule == WorkflowTargetModule.UNKNOWN) {
            problems += "Pick a target module."
        }
        if (triggerType == null || triggerType == WorkflowTriggerType.UNKNOWN) {
            problems += "Pick a trigger type."
        }
        return problems
    }

    /** Convenience: is the create form submittable? */
    fun canSubmitCreate(
        name: String,
        targetModule: WorkflowTargetModule?,
        triggerType: WorkflowTriggerType?,
    ): Boolean = validateCreate(name, targetModule, triggerType).isEmpty()

    /**
     * PURE drip-sequence create validation. Mirrors app/services/workflow_drip_sequences.py: name
     * non-blank and at least one stage, each stage needs a template id and a non-negative delay. Returns
     * the problems; empty == ready.
     */
    fun validateDripCreate(name: String, stages: List<DripStage>): List<String> {
        val problems = mutableListOf<String>()
        if (name.isBlank()) problems += "Name is required."
        if (stages.isEmpty()) problems += "Add at least one stage."
        stages.forEachIndexed { i, s ->
            if (s.templateId.isBlank()) problems += "Stage ${i + 1}: template id is required."
            if (s.delayHours < 0) problems += "Stage ${i + 1}: delay can't be negative."
        }
        return problems
    }

    /** Convenience: is the drip create form submittable? */
    fun canSubmitDrip(name: String, stages: List<DripStage>): Boolean =
        validateDripCreate(name, stages).isEmpty()

    /**
     * PURE outcome bucketing for run history rows: normalizes the free-form `outcome` string into a small
     * closed set for display / colouring. Unknown values fall back to [RunOutcome.UNKNOWN].
     */
    fun outcomeOf(raw: String?): RunOutcome = when (raw?.lowercase()) {
        "matched" -> RunOutcome.MATCHED
        "error" -> RunOutcome.ERROR
        "skipped" -> RunOutcome.SKIPPED
        else -> RunOutcome.UNKNOWN
    }
}

/** Closed set of run outcomes for display. */
enum class RunOutcome { MATCHED, ERROR, SKIPPED, UNKNOWN }
