@file:OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.common.tip

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Public
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.feature.catalog.formatPrice
import java.util.Locale

/**
 * TIP-504 / TIP-505 - the single shared tip composer used by EVERY tip surface (feed, groups, video,
 * messaging, broadcast). Previously each surface hand-rolled its own preset-chips + custom-amount +
 * note sheet body; they now all render this one component, so the tip UX + a11y + test hooks are
 * identical everywhere and there is one place to change tipping UI.
 *
 * Stateless by design: all state arrives via params and every event is hoisted, so each surface keeps
 * its own money-path ViewModel/state machine unchanged (no charge logic moved here). Optional slots
 * (onNote, onVisibility) render ONLY when a callback is supplied, so a preset-only quick-tip and a
 * full broadcast composer are the same component with different slots enabled.
 */
object TipComposer {
    /** Default max note length (chars); surfaces may pass a tighter cap. */
    const val MAX_NOTE_LEN = 500
}

/** Stable, surface-agnostic test tags for the shared composer (surfaces may override per-node). */
object TipComposerTags {
    const val NOTE = "tip_note"
    const val VISIBILITY = "tip_visibility"
    const val VISIBILITY_PUBLIC = "tip_visibility_public"
    const val VISIBILITY_PRIVATE = "tip_visibility_private"
    fun preset(cents: Long): String = "tip_preset_$cents"
}

/**
 * TIP-505 - whether a tip's tipper identity + amount are shown to other viewers on the surface. A
 * PRIVATE tip still charges, credits + notifies the recipient (money-path unchanged); only the public
 * rendering of the amount/identity is suppressed for third parties.
 */
enum class TipVisibility {
    PUBLIC,
    PRIVATE;

    val isPrivate: Boolean get() = this == PRIVATE

    companion object {
        val Default: TipVisibility = PUBLIC
    }
}

/**
 * TIP-505 - the amount label to render for a tip with [visibility], or null when a PRIVATE tip's amount
 * must be hidden from a third-party viewer. The tipper + recipient always see the amount ([isOwn]).
 * Pure / JVM-testable.
 */
fun tipVisibleAmount(
    cents: Long,
    currency: String,
    visibility: TipVisibility,
    isOwn: Boolean = false,
): String? = if (visibility.isPrivate && !isOwn) null else formatPrice(cents, currency.uppercase(Locale.US))

/**
 * The shared composer body (no surrounding sheet/title - each surface wraps this in its own
 * ModalBottomSheet so the surface keeps its own dismiss/scrim/test-tag). Presets are integer cents.
 */
@Composable
fun TipComposerContent(
    presetsCents: List<Long>,
    selectedCents: Long?,
    customText: String,
    canSend: Boolean,
    inFlight: Boolean,
    onSelectPreset: (Long) -> Unit,
    onCustomAmount: (String) -> Unit,
    onSend: () -> Unit,
    modifier: Modifier = Modifier,
    currency: String = "USD",
    sendLabel: String? = null,
    error: String? = null,
    note: String? = null,
    onNote: ((String) -> Unit)? = null,
    maxNoteLen: Int = TipComposer.MAX_NOTE_LEN,
    visibility: TipVisibility? = null,
    onVisibility: ((TipVisibility) -> Unit)? = null,
    presetTag: (Long) -> String = TipComposerTags::preset,
    customTag: String = "tip_custom",
    sendTag: String = "tip_send",
) {
    val cur = currency.uppercase(Locale.US)
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            presetsCents.forEach { cents ->
                FilterChip(
                    selected = selectedCents == cents && customText.isBlank(),
                    onClick = { onSelectPreset(cents) },
                    enabled = !inFlight,
                    label = { Text(formatPrice(cents, cur)) },
                    modifier = Modifier.testTag(presetTag(cents)),
                )
            }
        }
        OutlinedTextField(
            value = customText,
            onValueChange = onCustomAmount,
            enabled = !inFlight,
            label = { Text(stringResource(R.string.tip_custom_amount)) },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            singleLine = true,
            isError = error != null,
            modifier = Modifier.fillMaxWidth().testTag(customTag),
        )
        if (onNote != null) {
            val noteText = note.orEmpty()
            OutlinedTextField(
                value = noteText,
                onValueChange = { if (it.length <= maxNoteLen) onNote(it) },
                enabled = !inFlight,
                label = { Text(stringResource(R.string.tip_note)) },
                supportingText = { Text("${noteText.length} / $maxNoteLen") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag(TipComposerTags.NOTE),
            )
        }
        if (visibility != null && onVisibility != null) {
            TipVisibilitySelector(
                visibility = visibility,
                onVisibility = onVisibility,
                enabled = !inFlight,
            )
        }
        if (error != null) {
            Text(
                text = error,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        TlButton(
            text = sendLabel ?: stringResource(R.string.tip_send),
            onClick = onSend,
            enabled = canSend,
            loading = inFlight,
            modifier = Modifier.fillMaxWidth().testTag(sendTag),
        )
    }
}

/**
 * TIP-505 - the public/private visibility selector (two chips + an explanatory hint). Hoisted so a
 * surface can render it standalone if it composes its own body.
 */
@Composable
fun TipVisibilitySelector(
    visibility: TipVisibility,
    onVisibility: (TipVisibility) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    Column(
        modifier = modifier.fillMaxWidth().testTag(TipComposerTags.VISIBILITY),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            text = stringResource(R.string.tip_visibility_label),
            style = MaterialTheme.typography.labelLarge,
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = visibility == TipVisibility.PUBLIC,
                onClick = { onVisibility(TipVisibility.PUBLIC) },
                enabled = enabled,
                leadingIcon = { Icon(Icons.Filled.Public, contentDescription = null) },
                label = { Text(stringResource(R.string.tip_visibility_public)) },
                modifier = Modifier.testTag(TipComposerTags.VISIBILITY_PUBLIC),
            )
            FilterChip(
                selected = visibility == TipVisibility.PRIVATE,
                onClick = { onVisibility(TipVisibility.PRIVATE) },
                enabled = enabled,
                leadingIcon = { Icon(Icons.Filled.Lock, contentDescription = null) },
                label = { Text(stringResource(R.string.tip_visibility_private)) },
                modifier = Modifier.testTag(TipComposerTags.VISIBILITY_PRIVATE),
            )
        }
        Text(
            text = stringResource(
                if (visibility.isPrivate) R.string.tip_visibility_private_hint
                else R.string.tip_visibility_public_hint,
            ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
