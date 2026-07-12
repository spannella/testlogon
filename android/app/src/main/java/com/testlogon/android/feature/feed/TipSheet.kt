@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.feed

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.feature.common.tip.TipComposerContent
import com.testlogon.android.feature.common.tip.TipVisibility

/** Stable test tags for the tip sheet (AND-178). */
object TipSheetTestTags {
    const val SHEET = "tip_sheet"
    const val CUSTOM = "tip_custom"
    const val SEND = "tip_send"
    const val CONFIRMED = "tip_confirmed"
    fun preset(cents: Int): String = "tip_preset_$cents"
}

/**
 * AND-178 - modal tip bottom sheet. Stateless: state arrives via [state]; events are hoisted up. Dismiss
 * is blocked while Submitting (FR-10). The Send button shows a spinner + disables inputs during
 * Submitting (FR-5/FR-8); Confirmed shows "Tip sent". Hidden => the sheet is not shown.
 *
 * TIP-504 - the Entry body is now the shared [TipComposerContent] used by every tip surface. TIP-505 -
 * the public/private visibility toggle is rendered when [onVisibility] is wired.
 */
@Composable
fun TipSheet(
    state: TipSheetState,
    onSelectPreset: (cents: Int) -> Unit,
    onCustomAmount: (text: String) -> Unit,
    onSend: () -> Unit,
    onDismiss: () -> Unit,
    onVisibility: (TipVisibility) -> Unit = {},
) {
    if (state is TipSheetState.Hidden) return
    val submitting = state is TipSheetState.Submitting
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    ModalBottomSheet(
        onDismissRequest = { if (!submitting) onDismiss() },
        sheetState = sheetState,
        modifier = Modifier.testTag(TipSheetTestTags.SHEET),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp).padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = stringResource(R.string.tip_sheet_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
            )
            when (state) {
                is TipSheetState.Entry -> TipEntryBody(state, onSelectPreset, onCustomAmount, onSend, onVisibility)
                is TipSheetState.Submitting -> TipSubmittingBody()
                is TipSheetState.Confirmed -> TipConfirmedBody(state)
                is TipSheetState.Hidden -> Unit
            }
        }
    }
}

@Composable
private fun TipEntryBody(
    state: TipSheetState.Entry,
    onSelectPreset: (Int) -> Unit,
    onCustomAmount: (String) -> Unit,
    onSend: () -> Unit,
    onVisibility: (TipVisibility) -> Unit,
) {
    // TIP-504 - shared composer body. Feed preset cents are Int; the shared component is Long-cents, so
    // adapt at the boundary. Test tags are preserved (tip_preset_<cents>/tip_custom/tip_send).
    TipComposerContent(
        presetsCents = state.config.presetsCents.map(Int::toLong),
        selectedCents = state.selectedCents?.toLong(),
        customText = state.customAmountText,
        canSend = state.canSend,
        inFlight = false,
        onSelectPreset = { onSelectPreset(it.toInt()) },
        onCustomAmount = onCustomAmount,
        onSend = onSend,
        currency = state.config.currency,
        error = state.error,
        visibility = state.visibility,
        onVisibility = onVisibility,
        presetTag = { TipSheetTestTags.preset(it.toInt()) },
        customTag = TipSheetTestTags.CUSTOM,
        sendTag = TipSheetTestTags.SEND,
    )
}

@Composable
private fun TipSubmittingBody() {
    TlButton(
        text = stringResource(R.string.tip_send),
        onClick = {},
        enabled = false,
        loading = true,
        modifier = Modifier.fillMaxWidth().testTag(TipSheetTestTags.SEND),
    )
}

@Composable
private fun TipConfirmedBody(state: TipSheetState.Confirmed) {
    // TIP-505 - the tipper always sees their own amount; a private tip is labelled "sent privately".
    val amount = PriceFormatter.format(state.receipt.amountCents) ?: "${state.receipt.amountCents}"
    val label = if (state.visibility.isPrivate) {
        stringResource(R.string.tip_sent_private) + " · " + amount
    } else {
        stringResource(R.string.tip_sent) + " · " + amount
    }
    Column(
        modifier = Modifier.fillMaxWidth().testTag(TipSheetTestTags.CONFIRMED),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Icon(
            imageVector = Icons.Filled.CheckCircle,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(40.dp),
        )
        Text(
            text = label,
            style = MaterialTheme.typography.titleMedium,
        )
    }
}
