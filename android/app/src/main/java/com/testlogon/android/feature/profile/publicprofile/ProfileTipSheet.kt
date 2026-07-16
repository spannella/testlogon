@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.profile.publicprofile

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.feature.common.tip.TipComposerContent

/** TIPX-C2 - stable test tags for the profile (creator) tip sheet. */
object ProfileTipTestTags {
    const val SHEET = "profile_tip_sheet"
    const val CUSTOM = "profile_tip_custom"
    const val SEND = "profile_tip_send"
    const val CONFIRMED = "profile_tip_confirmed"
    const val DONE = "profile_tip_done"
    fun preset(cents: Int): String = "profile_tip_preset_$cents"
}

/**
 * TIPX-C2 - the "Tip this creator" modal bottom sheet. Stateless: state arrives via [state]; events are
 * hoisted. Reuses the shared [TipComposerContent] body used by every tip surface. Dismiss is blocked
 * while Submitting; Confirmed shows "Tip sent · $X" with an explicit Done.
 */
@Composable
fun ProfileTipSheet(
    state: ProfileTipState,
    onSelectPreset: (cents: Int) -> Unit,
    onCustomAmount: (text: String) -> Unit,
    onSend: () -> Unit,
    onDismiss: () -> Unit,
) {
    if (state is ProfileTipState.Hidden) return
    val submitting = state is ProfileTipState.Submitting
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    ModalBottomSheet(
        onDismissRequest = { if (!submitting) onDismiss() },
        sheetState = sheetState,
        modifier = Modifier.testTag(ProfileTipTestTags.SHEET),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp).padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            val title = when (state) {
                is ProfileTipState.Entry -> {
                    val name = state.displayName?.takeIf { it.isNotBlank() } ?: state.identifier
                    "Tip $name"
                }
                else -> "Tip this creator"
            }
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
            )
            when (state) {
                is ProfileTipState.Entry -> ProfileTipEntryBody(state, onSelectPreset, onCustomAmount, onSend)
                is ProfileTipState.Submitting -> ProfileTipSubmittingBody()
                is ProfileTipState.Confirmed -> ProfileTipConfirmedBody(state, onDismiss)
                is ProfileTipState.Hidden -> Unit
            }
        }
    }
}

@Composable
private fun ProfileTipEntryBody(
    state: ProfileTipState.Entry,
    onSelectPreset: (Int) -> Unit,
    onCustomAmount: (String) -> Unit,
    onSend: () -> Unit,
) {
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
        presetTag = { ProfileTipTestTags.preset(it.toInt()) },
        customTag = ProfileTipTestTags.CUSTOM,
        sendTag = ProfileTipTestTags.SEND,
    )
}

@Composable
private fun ProfileTipSubmittingBody() {
    TlButton(
        text = "Send tip",
        onClick = {},
        enabled = false,
        loading = true,
        modifier = Modifier.fillMaxWidth().testTag(ProfileTipTestTags.SEND),
    )
}

@Composable
private fun ProfileTipConfirmedBody(state: ProfileTipState.Confirmed, onDone: () -> Unit) {
    val amount = String.format(java.util.Locale.US, "$%.2f", state.amountCents / 100.0)
    Column(
        modifier = Modifier.fillMaxWidth().testTag(ProfileTipTestTags.CONFIRMED),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Icon(
            imageVector = Icons.Filled.CheckCircle,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(40.dp),
        )
        Text(text = "Tip sent · $amount", style = MaterialTheme.typography.titleMedium)
        TlButton(
            text = "Done",
            onClick = onDone,
            modifier = Modifier.fillMaxWidth().testTag(ProfileTipTestTags.DONE),
        )
    }
}
