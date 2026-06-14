@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.feed

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.core.ui.input.TlButton

/** Stable test tags for the tip sheet (AND-178). */
object TipSheetTestTags {
    const val SHEET = "tip_sheet"
    const val CUSTOM = "tip_custom"
    const val SEND = "tip_send"
    const val CONFIRMED = "tip_confirmed"
    fun preset(cents: Int): String = "tip_preset_$cents"
}

/**
 * AND-178 — modal tip bottom sheet. Stateless: state arrives via [state]; events are hoisted up. Dismiss
 * is blocked while Submitting (FR-10). The Send button shows a spinner + disables inputs during
 * Submitting (FR-5/FR-8); Confirmed shows "Tip sent". Hidden => the sheet is not shown.
 */
@Composable
fun TipSheet(
    state: TipSheetState,
    onSelectPreset: (cents: Int) -> Unit,
    onCustomAmount: (text: String) -> Unit,
    onSend: () -> Unit,
    onDismiss: () -> Unit,
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
                is TipSheetState.Entry -> TipEntryBody(state, onSelectPreset, onCustomAmount, onSend)
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
) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        state.config.presetsCents.forEach { cents ->
            FilterChip(
                selected = state.selectedCents == cents && state.customAmountText.isBlank(),
                onClick = { onSelectPreset(cents) },
                label = { Text(PriceFormatter.format(cents) ?: "$cents") },
                modifier = Modifier.testTag(TipSheetTestTags.preset(cents)),
            )
        }
    }
    OutlinedTextField(
        value = state.customAmountText,
        onValueChange = onCustomAmount,
        label = { Text(stringResource(R.string.tip_custom_amount)) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        singleLine = true,
        modifier = Modifier.fillMaxWidth().testTag(TipSheetTestTags.CUSTOM),
    )
    if (state.error != null) {
        Text(
            text = state.error,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }
    TlButton(
        text = stringResource(R.string.tip_send),
        onClick = onSend,
        enabled = state.canSend,
        modifier = Modifier.fillMaxWidth().testTag(TipSheetTestTags.SEND),
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
    val amount = PriceFormatter.format(state.receipt.amountCents) ?: "${state.receipt.amountCents}"
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
            text = "${stringResource(R.string.tip_sent)} · $amount",
            style = MaterialTheme.typography.titleMedium,
        )
    }
}
