package com.testlogon.android.core.ui.blocking

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant

/**
 * AND-382 - shared, stateless block / unblock affordances reused by the profile and message-thread
 * screens so the interaction is identical across surfaces (spec sec.4.5).
 *
 * All copy is passed in already-resolved by the host (the host owns the app `strings.xml` entries and
 * interpolates the handle), keeping these composables free of any module-specific R reference. Every
 * affordance carries a contentDescription / semantics for TalkBack and uses text labels (never
 * icon-only) so state is not conveyed by color alone (spec sec.9). Touch targets meet 48dp via the
 * Material defaults (DropdownMenuItem / TlButton minimums).
 */

/** Overflow-menu entry. Use inside a DropdownMenu / ExposedDropdownMenuBox content lambda. */
@Composable
fun BlockUserMenuItem(
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    DropdownMenuItem(
        text = { Text(label) },
        onClick = onClick,
        leadingIcon = {
            Icon(Icons.Filled.Block, contentDescription = null, modifier = Modifier.size(20.dp))
        },
        modifier = modifier.semantics { contentDescription = label },
    )
}

/**
 * Confirmation dialog summarizing the effects of a block. Focus-trapped by [AlertDialog]; the title
 * is announced by TalkBack. [confirmLabel] / [dismissLabel] are explicit text (not icon-only).
 */
@Composable
fun BlockConfirmDialog(
    title: String,
    body: String,
    confirmLabel: String,
    dismissLabel: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Filled.Block, contentDescription = null) },
        title = { Text(title, modifier = Modifier.semantics { contentDescription = title }) },
        text = { Text(body) },
        confirmButton = {
            TextButton(onClick = onConfirm) { Text(confirmLabel) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(dismissLabel) }
        },
    )
}

/**
 * Placeholder shown in place of a blocked user's profile body, offering an Unblock action.
 * [loading] disables the button + shows a spinner while the unblock mutation is in flight.
 */
@Composable
fun BlockedProfilePlaceholder(
    title: String,
    body: String,
    unblockLabel: String,
    onUnblock: () -> Unit,
    modifier: Modifier = Modifier,
    loading: Boolean = false,
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            Icons.Filled.Block,
            contentDescription = null,
            modifier = Modifier.size(40.dp),
        )
        Spacer(Modifier.height(12.dp))
        Text(
            title,
            style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center,
            modifier = Modifier.semantics { contentDescription = title },
        )
        Spacer(Modifier.height(4.dp))
        Text(
            body,
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(16.dp))
        TlButton(
            text = unblockLabel,
            onClick = onUnblock,
            variant = TlButtonVariant.Secondary,
            loading = loading,
        )
    }
}

/**
 * Banner shown over a locked message composer when contact is blocked (either direction). Text + icon
 * (not color-only) so the state is conveyed accessibly.
 */
@Composable
fun CannotContactBanner(
    message: String,
    modifier: Modifier = Modifier,
) {
    androidx.compose.foundation.layout.Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .semantics { contentDescription = message },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Icon(Icons.Filled.Block, contentDescription = null, modifier = Modifier.size(18.dp))
        Text(message, style = MaterialTheme.typography.bodyMedium)
    }
}
