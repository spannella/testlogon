package com.testlogon.android.feature.messaging.typing

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/**
 * AND-146 — "X is typing…" affordance shown above the composer. Driven by the resolved typers list;
 * empty list = hidden. The label is announced politely (liveRegion = Polite) so TalkBack reads
 * appearance/clearing without interrupting message reads, and never conveys state by motion alone.
 */
@Composable
fun TypingIndicator(
    users: List<TypingUiUser>,
    modifier: Modifier = Modifier,
) {
    AnimatedVisibility(
        visible = users.isNotEmpty(),
        enter = fadeIn(),
        exit = fadeOut(),
        modifier = modifier,
    ) {
        Row(
            horizontalArrangement = Arrangement.Start,
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .padding(horizontal = 16.dp, vertical = 4.dp)
                .semantics { liveRegion = LiveRegionMode.Polite },
        ) {
            Text(
                text = typingLabelText(users),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.width(8.dp))
        }
    }
}

/** Resolves the localized typing label for the current typers (FR-4 pluralization). */
@Composable
fun typingLabelText(users: List<TypingUiUser>): String {
    val someone = stringResource(R.string.typing_someone)
    return when (val label = TypingLabel.of(users)) {
        TypingLabel.Hidden -> ""
        is TypingLabel.One -> stringResource(R.string.typing_one, label.name.ifBlank { someone })
        is TypingLabel.Two ->
            stringResource(
                R.string.typing_two,
                label.first.ifBlank { someone },
                label.second.ifBlank { someone },
            )
        TypingLabel.Several -> stringResource(R.string.typing_several)
    }
}
