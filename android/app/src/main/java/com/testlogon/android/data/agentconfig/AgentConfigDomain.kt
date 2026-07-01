package com.testlogon.android.data.agentconfig

import java.util.Locale

/**
 * Framework-free domain for the five agent-TYPE config forms (web /agents/types/:typeId/{coder,qa,devops,
 * architect,pm}). One parametrized model drives ONE screen: [AgentConfigType] identifies the surface and
 * carries its endpoint routing hints + its ordered [AgentField] spec (mirroring the editable fields of the
 * matching web *AgentConfigPage). The loaded config JSON is projected into [ConfigForm] (a per-field value
 * map) and re-serialized back into a PUT body via [ConfigForm.toRequestBody].
 *
 * Field types kept deliberately small (mirror what the web renders): TEXT (single-line String), MULTILINE
 * (String textarea), NUMBER (Long/Double), BOOL (Switch), ENUM (Select), STRING_LIST (one-per-line textarea
 * -> List<String>). Advanced nested structures (devops `environments[]`, coder `complexity_labels`) are
 * intentionally out of the mobile edit surface for parity of the CORE fields; they are preserved untouched
 * on save (passthrough of the loaded raw value).
 */
enum class AgentField {
    TEXT,
    MULTILINE,
    NUMBER_INT,
    NUMBER_DOUBLE,
    BOOL,
    ENUM,
    STRING_LIST,
}

/** One editable field in a config form. [key] is the wire (snake_case) key. */
data class FieldSpec(
    val key: String,
    val label: String,
    val type: AgentField,
    val options: List<String> = emptyList(),
    val helper: String? = null,
)

/**
 * The five agent config surfaces. [typeName] is the fixed segment used by config-schema (e.g.
 * "coder/config-schema"); the config GET/PUT are keyed by the RUNTIME typeId (the agent-type instance id),
 * which the user supplies. [wrappedUnder] is non-null for DevOps whose GET/PUT nest the config under that
 * envelope key.
 */
enum class AgentConfigType(
    val typeName: String,
    val title: String,
    val wrappedUnder: String? = null,
    val fields: List<FieldSpec>,
) {
    CODER(
        typeName = "coder",
        title = "Coder Agent",
        fields = listOf(
            FieldSpec("repo_url", "Repository URL", AgentField.TEXT, helper = "https://github.com/org/repo.git"),
            FieldSpec("repo_branch_base", "Base branch", AgentField.TEXT),
            FieldSpec("branch_pattern", "Branch pattern", AgentField.TEXT, helper = "feat/{ticket_id}-{slug}"),
            FieldSpec("test_commands", "Test commands (one per line)", AgentField.STRING_LIST),
            FieldSpec("test_timeout_seconds", "Test timeout (s)", AgentField.NUMBER_INT),
            FieldSpec("test_retry_limit", "Test retry limit", AgentField.NUMBER_INT),
            FieldSpec("pr_template", "PR template", AgentField.MULTILINE),
            FieldSpec("pr_base_branch", "PR base branch", AgentField.TEXT),
            FieldSpec("skill_level", "Skill level", AgentField.ENUM, options = listOf("junior", "mid", "senior")),
            FieldSpec("max_ticket_time_seconds", "Time budget (s)", AgentField.NUMBER_INT),
            FieldSpec("coding_tool", "Coding tool", AgentField.ENUM, options = listOf("claude_code", "codex")),
            FieldSpec("coding_tool_model", "Model override", AgentField.TEXT),
        ),
    ),
    QA(
        typeName = "qa",
        title = "QA Agent",
        fields = listOf(
            FieldSpec("test_framework", "Test framework", AgentField.ENUM, options = listOf("playwright", "cypress", "pytest")),
            FieldSpec("browser", "Browser", AgentField.ENUM, options = listOf("chromium", "firefox", "webkit")),
            FieldSpec("test_dir", "Test directory", AgentField.TEXT),
            FieldSpec("test_file_pattern", "Test file pattern", AgentField.TEXT),
            FieldSpec("test_run_command", "Run command", AgentField.TEXT),
            FieldSpec("test_run_specific_command", "Run-specific command", AgentField.TEXT),
            FieldSpec("regression_scope", "Regression scope", AgentField.ENUM, options = listOf("full", "affected", "none")),
            FieldSpec("regression_command", "Regression command", AgentField.TEXT),
            FieldSpec("screenshot_enabled", "Screenshots enabled", AgentField.BOOL),
            FieldSpec("screenshot_on_failure", "Screenshot on failure", AgentField.BOOL),
            FieldSpec("screenshot_s3_prefix", "Screenshot S3 prefix", AgentField.TEXT),
            FieldSpec("visual_diff_threshold", "Visual diff threshold", AgentField.NUMBER_DOUBLE),
            FieldSpec("max_test_time_seconds", "Max test time (s)", AgentField.NUMBER_INT),
            FieldSpec("flaky_retry_count", "Flaky retry count", AgentField.NUMBER_INT),
            FieldSpec("pr_review_enabled", "PR review enabled", AgentField.BOOL),
            FieldSpec("coding_tool", "Coding tool", AgentField.ENUM, options = listOf("claude_code", "codex")),
            FieldSpec("coding_tool_model", "Model override", AgentField.TEXT),
        ),
    ),
    DEVOPS(
        typeName = "devops",
        title = "DevOps / SRE Agent",
        wrappedUnder = "devops_config",
        fields = listOf(
            FieldSpec("deploy_ticket_labels", "Deploy ticket labels (one per line)", AgentField.STRING_LIST),
            FieldSpec("infra_ticket_labels", "Infra ticket labels (one per line)", AgentField.STRING_LIST),
            FieldSpec("incident_ticket_labels", "Incident ticket labels (one per line)", AgentField.STRING_LIST),
            FieldSpec("auto_deploy_on_qa_approved", "Auto-deploy on QA approved", AgentField.BOOL),
            FieldSpec("coding_tool", "Coding tool", AgentField.ENUM, options = listOf("claude_code", "codex")),
            FieldSpec("max_operation_time_seconds", "Max operation time (s)", AgentField.NUMBER_INT),
            FieldSpec("incident_space_id", "Incident space id", AgentField.TEXT),
        ),
    ),
    ARCHITECT(
        typeName = "architect",
        title = "Solution Architect Agent",
        fields = listOf(
            FieldSpec("repo_url", "Repository URL", AgentField.TEXT, helper = "https://github.com/org/repo.git"),
            FieldSpec("repo_branch", "Branch", AgentField.TEXT),
            FieldSpec("reference_docs", "Reference docs (one per line)", AgentField.STRING_LIST),
            FieldSpec("scan_paths", "Scan paths (one per line)", AgentField.STRING_LIST),
            FieldSpec("ticket_template", "Ticket template", AgentField.MULTILINE),
            FieldSpec("architecture_guidelines", "Architecture guidelines", AgentField.MULTILINE),
            FieldSpec("max_tickets_per_feature", "Max tickets / feature", AgentField.NUMBER_INT),
            FieldSpec("target_ticket_space_id", "Target ticket space id", AgentField.TEXT),
            FieldSpec("coding_tool", "Coding tool", AgentField.ENUM, options = listOf("claude_code", "codex")),
            FieldSpec("coding_tool_model", "Model override", AgentField.TEXT),
            FieldSpec("max_analysis_time_seconds", "Max analysis time (s)", AgentField.NUMBER_INT),
            FieldSpec("require_design_review", "Require design review", AgentField.BOOL),
            FieldSpec("ticket_spec_style", "Ticket spec style", AgentField.ENUM, options = listOf("full", "compact")),
        ),
    ),
    PM(
        typeName = "pm",
        title = "Project Manager Agent",
        fields = listOf(
            FieldSpec("sprint_duration_days", "Sprint duration (days)", AgentField.NUMBER_INT),
            FieldSpec("reporting_cadence", "Reporting cadence", AgentField.ENUM, options = listOf("daily", "weekly", "both")),
            FieldSpec("report_time_utc", "Report time (UTC)", AgentField.TEXT, helper = "HH:MM"),
            FieldSpec("idea_intake_enabled", "Idea intake enabled", AgentField.BOOL),
            FieldSpec("auto_prioritize", "Auto-prioritize", AgentField.BOOL),
            FieldSpec("auto_create_feature_requests", "Auto-create feature requests", AgentField.BOOL),
            FieldSpec("blocker_stale_hours", "Blocker stale hours", AgentField.NUMBER_INT),
            FieldSpec("escalation_on_conflict", "Escalation on conflict", AgentField.BOOL),
            FieldSpec("coding_tool", "Coding tool", AgentField.ENUM, options = listOf("claude_code", "codex")),
            FieldSpec("coding_tool_model", "Model override", AgentField.TEXT),
            FieldSpec("project_space_id", "Project space id", AgentField.TEXT),
        ),
    );

    companion object {
        fun from(raw: String?): AgentConfigType? =
            entries.firstOrNull { it.typeName == raw?.lowercase(Locale.US) }
    }
}

/** Validation outcome of the last save/validate call. */
data class ConfigValidation(
    val valid: Boolean,
    val errors: List<String>,
)

/**
 * Render-ready form: the string-rendered value per field key (Compose edits strings; typed coercion happens
 * at [toRequestBody] time), plus the untouched [raw] loaded config (so unmapped keys - devops environments,
 * complexity_labels, etc. - survive the round-trip).
 */
data class ConfigForm(
    val type: AgentConfigType,
    val values: Map<String, String>,
    val bools: Map<String, Boolean>,
    private val raw: Map<String, Any?>,
) {
    /**
     * Rebuilds the PUT/validate body: starts from the untouched loaded [raw] (preserving unmapped keys), then
     * overwrites each editable field with its typed value. Empty TEXT/MULTILINE/model keys become null
     * (matches the web `model || null` idiom) unless the key never existed. For DevOps the envelope
     * ([type]'s wrappedUnder) is NOT re-added here - the repository unwraps on load and re-wraps on save.
     */
    fun toRequestBody(): Map<String, Any?> {
        val out = raw.toMutableMap()
        for (spec in type.fields) {
            when (spec.type) {
                AgentField.BOOL -> out[spec.key] = bools[spec.key] ?: false
                AgentField.STRING_LIST -> out[spec.key] = (values[spec.key] ?: "")
                    .split("\n").map { it.trim() }.filter { it.isNotEmpty() }
                AgentField.NUMBER_INT -> (values[spec.key] ?: "").trim().toLongOrNull()?.let { out[spec.key] = it }
                AgentField.NUMBER_DOUBLE -> (values[spec.key] ?: "").trim().toDoubleOrNull()?.let { out[spec.key] = it }
                AgentField.TEXT, AgentField.MULTILINE, AgentField.ENUM -> {
                    val v = (values[spec.key] ?: "").trim()
                    out[spec.key] = v.ifEmpty { null }
                }
            }
        }
        return out
    }
}
