package com.testlogon.android.feature.subscriptions

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.subscriptions.BillingInterval
import com.testlogon.android.data.subscriptions.PlanBenefitDto
import com.testlogon.android.data.subscriptions.PlanWriteReqDto
import com.testlogon.android.data.subscriptions.SubscriptionTier
import com.testlogon.android.data.subscriptions.SubscriptionsRepository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import com.testlogon.android.feature.billing.error.Recoverability
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * SUBX-40 — mobile tier authoring. Presentation logic for the creator "Your subscription tiers"
 * screen: list the creator's own tiers (owner-scoped — X-User-Id = creator id) and create / edit /
 * price / re-interval / set benefits+level / archive / reorder them through the real plan-write
 * endpoints (create/patch/archive/reorder) added to [SubscriptionsRepository]. Before X4 the Android
 * console was GET-only, so the top creator action was web-only.
 */
@HiltViewModel
class CreatorTierManagerViewModel @Inject constructor(
    private val repository: SubscriptionsRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    private val _uiState = MutableStateFlow<TierManagerUiState>(TierManagerUiState.Loading)
    val uiState: StateFlow<TierManagerUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun load() {
        _uiState.value = TierManagerUiState.Loading
        viewModelScope.launch {
            when (val result = repository.getMyTiers()) {
                is ApiResult.Success -> _uiState.value = TierManagerUiState.Content(
                    tiers = sortTiers(result.data),
                )
                else -> {
                    val error = errorMapper.map(result)
                    _uiState.value = TierManagerUiState.Error(
                        message = error.message,
                        retryable = error.recoverability == Recoverability.RETRYABLE,
                    )
                }
            }
        }
    }

    fun onRetry() = load()

    // ---- editor open/close ----

    fun onNewTier() = updateContent { it.copy(editor = TierDraft()) }

    fun onEditTier(tier: SubscriptionTier) = updateContent {
        it.copy(
            editor = TierDraft(
                planId = tier.planId,
                name = tier.name,
                description = tier.description.orEmpty(),
                priceInput = centsToInput(tier.priceCents),
                interval = tier.interval,
                level = tier.level?.toString().orEmpty(),
                benefits = tier.benefits.map { b -> b.label } + tier.perks,
            ),
        )
    }

    fun onEditorDismissed() = updateContent { it.copy(editor = null) }

    fun onDraftChanged(transform: (TierDraft) -> TierDraft) = updateContent { c ->
        c.editor?.let { c.copy(editor = transform(it)) } ?: c
    }

    fun onAddBenefit(label: String) {
        val trimmed = label.trim()
        if (trimmed.isEmpty()) return
        onDraftChanged { it.copy(benefits = it.benefits + trimmed) }
    }

    fun onRemoveBenefit(index: Int) = onDraftChanged {
        it.copy(benefits = it.benefits.filterIndexed { i, _ -> i != index })
    }

    // ---- save ----

    fun onSaveDraft() {
        val content = currentContent() ?: return
        val draft = content.editor ?: return
        val cents = parseInputToCents(draft.priceInput)
        if (draft.name.trim().length < 2 || cents == null || cents <= 0) {
            _uiState.value = content.copy(editor = draft.copy(validationError = true))
            return
        }
        val body = PlanWriteReqDto(
            name = draft.name.trim(),
            description = draft.description.trim().ifEmpty { null },
            priceCents = cents,
            interval = when (draft.interval) {
                BillingInterval.YEAR -> "year"
                else -> "month"
            },
            level = draft.level.trim().toIntOrNull()?.takeIf { it >= 1 },
            benefits = draft.benefits.map { PlanBenefitDto(label = it) },
        )
        _uiState.value = content.copy(saving = true, editor = draft.copy(validationError = false))
        viewModelScope.launch {
            val result = if (draft.planId == null) {
                repository.createTier(body)
            } else {
                repository.updateTier(draft.planId, body)
            }
            when (result) {
                is ApiResult.Success -> reload(closeEditor = true)
                else -> updateContent {
                    it.copy(saving = false, actionError = errorMapper.map(result).message)
                }
            }
        }
    }

    // ---- archive ----

    fun onArchiveTier(tier: SubscriptionTier) {
        val content = currentContent() ?: return
        if (content.saving) return
        _uiState.value = content.copy(saving = true)
        viewModelScope.launch {
            when (val result = repository.archiveTier(tier.planId)) {
                is ApiResult.Success -> reload(closeEditor = false)
                else -> updateContent {
                    it.copy(saving = false, actionError = errorMapper.map(result).message)
                }
            }
        }
    }

    // ---- reorder ----

    fun onMove(tier: SubscriptionTier, up: Boolean) {
        val content = currentContent() ?: return
        if (content.saving) return
        val ordered = content.tiers.toMutableList()
        val idx = ordered.indexOfFirst { it.planId == tier.planId }
        if (idx < 0) return
        val target = if (up) idx - 1 else idx + 1
        if (target < 0 || target >= ordered.size) return
        val moved = ordered.removeAt(idx)
        ordered.add(target, moved)
        // optimistic local reorder + persist
        _uiState.value = content.copy(tiers = ordered, saving = true)
        viewModelScope.launch {
            when (val result = repository.reorderTiers(ordered.map { it.planId })) {
                is ApiResult.Success -> updateContent {
                    it.copy(saving = false, tiers = sortTiers(result.data))
                }
                else -> updateContent {
                    it.copy(saving = false, actionError = errorMapper.map(result).message)
                }
            }
        }
    }

    fun onActionErrorConsumed() = updateContent { it.copy(actionError = null) }

    private suspend fun reload(closeEditor: Boolean) {
        when (val result = repository.getMyTiers()) {
            is ApiResult.Success -> updateContent {
                it.copy(
                    saving = false,
                    tiers = sortTiers(result.data),
                    editor = if (closeEditor) null else it.editor,
                )
            }
            else -> updateContent {
                it.copy(saving = false, actionError = errorMapper.map(result).message)
            }
        }
    }

    private fun sortTiers(tiers: List<SubscriptionTier>): List<SubscriptionTier> =
        tiers.sortedWith(
            compareBy(
                { it.displayOrder ?: Int.MAX_VALUE },
                { -(it.createdAtEpochSeconds ?: 0L) },
            ),
        )

    private fun currentContent(): TierManagerUiState.Content? =
        _uiState.value as? TierManagerUiState.Content

    private inline fun updateContent(block: (TierManagerUiState.Content) -> TierManagerUiState.Content) {
        val content = currentContent() ?: return
        _uiState.value = block(content)
    }

    companion object {
        const val ROUTE = "subscriptions/tiers/manage"

        /** Parse a "12.50" / "12" dollars string to integer cents, or null when unparseable. */
        internal fun parseInputToCents(input: String): Long? {
            val cleaned = input.trim().removePrefix("$").replace(",", "")
            if (cleaned.isEmpty()) return null
            val d = cleaned.toDoubleOrNull() ?: return null
            if (d < 0) return null
            return Math.round(d * 100.0)
        }

        internal fun centsToInput(cents: Long): String =
            if (cents % 100L == 0L) (cents / 100L).toString() else "%.2f".format(cents / 100.0)
    }
}

/** SUBX-40 — an in-progress tier create/edit form. planId == null => creating a new tier. */
data class TierDraft(
    val planId: String? = null,
    val name: String = "",
    val description: String = "",
    val priceInput: String = "",
    val interval: BillingInterval = BillingInterval.MONTH,
    val level: String = "",
    val benefits: List<String> = emptyList(),
    val validationError: Boolean = false,
) {
    val isNew: Boolean get() = planId == null
}

/** SUBX-40 — creator tier-manager screen state. */
sealed interface TierManagerUiState {
    data object Loading : TierManagerUiState

    data class Content(
        val tiers: List<SubscriptionTier> = emptyList(),
        /** Non-null => the create/edit editor is open. */
        val editor: TierDraft? = null,
        val saving: Boolean = false,
        val actionError: UiText? = null,
    ) : TierManagerUiState

    data class Error(val message: UiText, val retryable: Boolean) : TierManagerUiState
}
