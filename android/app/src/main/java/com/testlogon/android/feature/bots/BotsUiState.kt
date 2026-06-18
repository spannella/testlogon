package com.testlogon.android.feature.bots

import androidx.annotation.StringRes
import com.testlogon.android.data.bots.AutoReplyMatchType
import com.testlogon.android.data.bots.AutoReplyRule
import com.testlogon.android.data.bots.Bot
import com.testlogon.android.data.bots.BotTemplate
import com.testlogon.android.data.bots.TemplateCategory

/** Shared top-level phase enum reused across the bots screens. */
enum class BotsPhase { Loading, Content, Empty, SessionExpired, Error, Offline }

// =====================================================================
// Bots list
// =====================================================================

/**
 * Render-ready state for the bots list. One immutable data class (not a sealed hierarchy) so content
 * persists across refresh (show prior [bots] while [isRefreshing]). [create] carries the create-bot
 * form/dialog state.
 */
data class BotsListUiState(
    val phase: BotsPhase = BotsPhase.Loading,
    val bots: List<Bot> = emptyList(),
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val isMutating: Boolean = false,
    val errorMessage: String? = null,
    val create: CreateBotFormState = CreateBotFormState(),
)

/** State for the create-bot dialog. [canSubmit] gates the confirm button. */
data class CreateBotFormState(
    val isOpen: Boolean = false,
    val name: String = "",
    val description: String = "",
    val personality: String = "",
    val isSubmitting: Boolean = false,
) {
    val canSubmit: Boolean
        get() = !isSubmitting && name.isNotBlank()
}

/** One-shot side effects (Channel-backed so they are not replayed on rotation). */
sealed interface BotsListEffect {
    data class ShowMessage(@StringRes val resId: Int) : BotsListEffect
}

// =====================================================================
// Auto-reply rules
// =====================================================================

/**
 * Render-ready state for a bot's auto-reply rules. [form] carries the create/edit-rule dialog state;
 * [editingRuleId] is non-null while editing an existing rule (vs creating).
 */
data class AutoReplyUiState(
    val phase: BotsPhase = BotsPhase.Loading,
    val rules: List<AutoReplyRule> = emptyList(),
    val isRefreshing: Boolean = false,
    val isMutating: Boolean = false,
    val errorMessage: String? = null,
    val form: AutoReplyFormState = AutoReplyFormState(),
)

/** State for the create/edit auto-reply rule dialog. */
data class AutoReplyFormState(
    val isOpen: Boolean = false,
    val editingRuleId: String? = null,
    val triggerPattern: String = "",
    val responseTemplate: String = "",
    val matchType: AutoReplyMatchType = AutoReplyMatchType.KEYWORD,
    val priority: String = "100",
    val enabled: Boolean = true,
    val isSubmitting: Boolean = false,
) {
    val isEditing: Boolean get() = editingRuleId != null

    val canSubmit: Boolean
        get() = !isSubmitting && triggerPattern.isNotBlank() && responseTemplate.isNotBlank()

    /** Parsed priority, defaulting to 100 when blank/invalid (matches the web). */
    val priorityValue: Int
        get() = priority.trim().toIntOrNull() ?: 100
}

/** One-shot side effects for the auto-reply screen. */
sealed interface AutoReplyEffect {
    data class ShowMessage(@StringRes val resId: Int) : AutoReplyEffect
}

// =====================================================================
// Templates
// =====================================================================

/** Render-ready state for a bot's message templates. [form] carries the create-template dialog state. */
data class TemplatesUiState(
    val phase: BotsPhase = BotsPhase.Loading,
    val templates: List<BotTemplate> = emptyList(),
    val isRefreshing: Boolean = false,
    val isMutating: Boolean = false,
    val errorMessage: String? = null,
    val form: TemplateFormState = TemplateFormState(),
)

/** State for the create-template dialog. */
data class TemplateFormState(
    val isOpen: Boolean = false,
    val name: String = "",
    val text: String = "",
    val category: TemplateCategory = TemplateCategory.GREETING,
    val isSubmitting: Boolean = false,
) {
    val canSubmit: Boolean
        get() = !isSubmitting && name.isNotBlank() && text.isNotBlank()
}

/** One-shot side effects for the templates screen. */
sealed interface TemplatesEffect {
    data class ShowMessage(@StringRes val resId: Int) : TemplatesEffect
}
