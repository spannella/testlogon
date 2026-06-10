@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.messaging.legalhold

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.messaging.legalhold.LegalHold

/** AND-164 — test tags for the legal-hold indicators (used by Compose UI tests). */
object LegalHoldTestTags {
    const val BADGE = "legal_hold_badge"
    const val BANNER = "legal_hold_banner"
    const val DETAIL_SHEET = "legal_hold_detail_sheet"
    const val DETAIL_CLOSE = "legal_hold_detail_close"
}

/**
 * AND-164 — "On legal hold" chip. Not color-only: a lock icon PLUS a contentDescription. A full
 * (non-compact) badge is tappable to open the read-only detail sheet; a compact marker (per-message)
 * is decorative + accessible only.
 */
@Composable
fun LegalHoldBadge(
    hold: LegalHold,
    compact: Boolean = false,
    onClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val cd = stringResource(R.string.legal_hold_badge)
    val base = modifier.testTag(LegalHoldTestTags.BADGE).semantics { contentDescription = cd }
    if (compact || onClick == null) {
        AssistChip(
            onClick = onClick ?: {},
            enabled = onClick != null,
            label = { Text(if (compact) stringResource(R.string.legal_hold_badge_short) else cd) },
            leadingIcon = { Icon(Icons.Filled.Lock, contentDescription = null) },
            colors = AssistChipDefaults.assistChipColors(
                containerColor = MaterialTheme.colorScheme.tertiaryContainer,
            ),
            modifier = base,
        )
    } else {
        AssistChip(
            onClick = onClick,
            label = { Text(cd) },
            leadingIcon = { Icon(Icons.Filled.Lock, contentDescription = null) },
            colors = AssistChipDefaults.assistChipColors(
                containerColor = MaterialTheme.colorScheme.tertiaryContainer,
            ),
            modifier = base,
        )
    }
}

/** AND-164 — conversation-level banner; announced as a polite live region when it appears. */
@Composable
fun LegalHoldBanner(hold: LegalHold, modifier: Modifier = Modifier) {
    val text = stringResource(R.string.legal_hold_banner)
    Surface(
        color = MaterialTheme.colorScheme.tertiaryContainer,
        modifier = modifier.fillMaxWidth()
            .testTag(LegalHoldTestTags.BANNER)
            .semantics {
                liveRegion = LiveRegionMode.Polite
                contentDescription = text
            },
    ) {
        androidx.compose.foundation.layout.Row(
            Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        ) {
            Icon(Icons.Filled.Lock, contentDescription = null)
            Text(text = text, modifier = Modifier.padding(start = 8.dp))
        }
    }
}

/**
 * AND-164 — read-only detail sheet. Shows available LegalHoldOut metadata (reason, case_id, status,
 * created_at). The ONLY affordance is "Close" — there are no create/release/modify-hold buttons.
 */
@Composable
fun LegalHoldDetailSheet(hold: LegalHold, onDismiss: () -> Unit) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(LegalHoldTestTags.DETAIL_SHEET),
    ) {
        Column(Modifier.fillMaxWidth().padding(16.dp)) {
            Text(stringResource(R.string.legal_hold_detail_title))
            Text(stringResource(R.string.legal_hold_generic_explanation))
            Text(stringResource(R.string.legal_hold_reason, hold.reason))
            Text(stringResource(R.string.legal_hold_case_id, hold.caseId))
            Text(stringResource(R.string.legal_hold_status, hold.status.name.lowercase()))
            hold.createdAtEpochSeconds?.let {
                Text(stringResource(R.string.legal_hold_created_at, it.toString()))
            }
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)
                    .testTag(LegalHoldTestTags.DETAIL_CLOSE),
            ) { Text(stringResource(R.string.action_close)) }
        }
    }
}
