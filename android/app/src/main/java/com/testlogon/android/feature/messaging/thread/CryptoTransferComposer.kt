@file:OptIn(
    androidx.compose.material3.ExperimentalMaterial3Api::class,
    androidx.compose.ui.ExperimentalComposeUiApi::class,
    androidx.compose.foundation.layout.ExperimentalLayoutApi::class,
)

package com.testlogon.android.feature.messaging.thread

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.testlogon.android.feature.markets.ui.MarketColors
import com.testlogon.android.feature.messaging.CryptoTransferModel
import java.util.Locale

object CryptoSendComposerTestTags {
    const val ATTACH = "thread_attach_crypto_send"
    const val SHEET = "thread_crypto_send_sheet"
    const val ASSET_CHIP = "thread_crypto_send_asset_"
    const val AMOUNT = "thread_crypto_send_amount"
    const val MAX = "thread_crypto_send_max"
    const val REVIEW = "thread_crypto_send_review"
    const val CONFIRM = "thread_crypto_send_confirm"
    const val BACK = "thread_crypto_send_back"
}

/**
 * FE-110 — "Send crypto" DM composer: pick an asset (from custody balances), enter an amount, see the
 * live fiat estimate + an inline insufficient-funds / KYC note, then a two-step confirm. The actual
 * send is the crypto_transfer card over the text path (degrade-safe; no dedicated endpoint). Validation
 * + fiat math are the pure [CryptoTransferModel]; this only renders + collects input.
 */
@Composable
fun CryptoSendSheet(
    state: CryptoSendState,
    onSelectAsset: (String) -> Unit,
    onAmountChange: (String) -> Unit,
    onMax: () -> Unit,
    onReview: () -> Unit,
    onBack: () -> Unit,
    onConfirmSend: () -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(CryptoSendComposerTestTags.SHEET).semantics { testTagsAsResourceId = true },
    ) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp).verticalScroll(rememberScrollState())) {
            Text("Send crypto", style = MaterialTheme.typography.titleMedium)
            when {
                state.loading -> CircularProgressIndicator(Modifier.padding(16.dp))
                state.assets.isEmpty() -> Text(
                    state.error ?: "You have no spendable custody balance to send.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
                state.confirming -> ConfirmStep(state, onBack, onConfirmSend)
                else -> ComposeStep(state, onSelectAsset, onAmountChange, onMax, onReview)
            }
            Box(Modifier.fillMaxWidth().heightIn(min = 16.dp))
        }
    }
}

@Composable
private fun ComposeStep(
    state: CryptoSendState,
    onSelectAsset: (String) -> Unit,
    onAmountChange: (String) -> Unit,
    onMax: () -> Unit,
    onReview: () -> Unit,
) {
    val selected = state.selected
    val validation = CryptoTransferModel.validateSend(state.selectedSymbol, state.amount, selected?.balance)
    val fiatCents = CryptoTransferModel.fiatEquivalentCents(state.selectedSymbol, state.amount)

    Text("Asset", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 8.dp))
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        state.assets.forEach { a ->
            FilterChip(
                selected = state.selectedSymbol == a.symbol,
                onClick = { onSelectAsset(a.symbol) },
                label = { Text("${a.symbol}  ${a.balanceText}") },
                modifier = Modifier.testTag(CryptoSendComposerTestTags.ASSET_CHIP + a.symbol),
            )
        }
    }
    selected?.let {
        Text(
            "Available: ${it.balanceText} ${it.symbol}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 6.dp),
        )
    }

    Row(Modifier.fillMaxWidth().padding(top = 12.dp), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
        OutlinedTextField(
            value = state.amount,
            onValueChange = onAmountChange,
            modifier = Modifier.weight(1f).testTag(CryptoSendComposerTestTags.AMOUNT),
            placeholder = { Text("Amount") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
            isError = validation == CryptoTransferModel.SendValidation.INSUFFICIENT,
        )
        if (selected != null) {
            TextButton(onClick = onMax, modifier = Modifier.padding(start = 4.dp).testTag(CryptoSendComposerTestTags.MAX)) {
                Text("Max")
            }
        }
    }
    fiatCents?.let {
        Text(
            "~ " + fmtUsd(it),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 4.dp),
        )
    }

    // Inline validation + KYC/limits messaging.
    val msg = when (validation) {
        CryptoTransferModel.SendValidation.INSUFFICIENT -> "Amount exceeds your available balance."
        else -> state.kycNote
    }
    msg?.let {
        Text(
            it,
            style = MaterialTheme.typography.bodySmall,
            color = if (validation == CryptoTransferModel.SendValidation.INSUFFICIENT) MarketColors.Down else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 6.dp),
        )
    }

    Button(
        onClick = onReview,
        enabled = validation.ok,
        modifier = Modifier.fillMaxWidth().padding(top = 16.dp).testTag(CryptoSendComposerTestTags.REVIEW),
    ) { Text("Review") }
}

@Composable
private fun ConfirmStep(
    state: CryptoSendState,
    onBack: () -> Unit,
    onConfirmSend: () -> Unit,
) {
    val fiatCents = CryptoTransferModel.fiatEquivalentCents(state.selectedSymbol, state.amount)
    Text("Confirm send", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 12.dp))
    Text(
        "${state.amount} ${state.selectedSymbol ?: ""}",
        style = MaterialTheme.typography.headlineSmall,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(top = 8.dp),
    )
    fiatCents?.let {
        Text("~ " + fmtUsd(it), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    state.error?.let {
        Text(it, style = MaterialTheme.typography.bodySmall, color = MarketColors.Down, modifier = Modifier.padding(top = 8.dp))
    }
    Row(Modifier.fillMaxWidth().padding(top = 16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(
            onClick = onBack,
            enabled = !state.sending,
            modifier = Modifier.weight(1f).testTag(CryptoSendComposerTestTags.BACK),
        ) { Text("Back") }
        Button(
            onClick = onConfirmSend,
            enabled = !state.sending,
            modifier = Modifier.weight(1f).testTag(CryptoSendComposerTestTags.CONFIRM),
        ) { Text(if (state.sending) "Sending…" else "Send") }
    }
}

private fun fmtUsd(cents: Long): String =
    "$" + String.format(Locale.US, "%,.2f", cents / 100.0)
