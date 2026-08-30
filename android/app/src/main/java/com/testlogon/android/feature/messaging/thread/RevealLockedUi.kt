@file:OptIn(androidx.compose.animation.ExperimentalAnimationApi::class)

package com.testlogon.android.feature.messaging.thread

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.scaleIn
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.feature.messaging.RevealAtMath
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.flow

/** FE-120 (EPIC C) — test tags for the scheduled-reveal locked bubble + composer indicator. */
object RevealLockedTestTags {
    const val LOCKED_BUBBLE = "thread_reveal_locked_bubble"
    const val COUNTDOWN = "thread_reveal_countdown"
    const val COMPOSER_INDICATOR = "thread_reveal_armed_indicator"
    const val COMPOSER_CLEAR = "thread_reveal_armed_clear"
    const val OPTION_FIELD = "thread_option_reveal_at"
}

/**
 * FE-120 (EPIC C, <- BE-120/BE-121) — the RECIPIENT's pre-reveal bubble for a scheduled "reveal at"
 * drop. Renders a blurred/locked placeholder (lock icon + "Scheduled reveal") with a LIVE 1s
 * countdown; the moment [MessageMedia.RevealLocked.revealAtSec] is reached (a tick crossing it), the
 * bubble FLIPS to the real inner content with a reveal animation — no manual refresh, no round-trip.
 *
 * The 1s ticker derives remaining time from the device clock (never stored) and is lifecycle-scoped
 * (collectAsStateWithLifecycle stops it below STARTED) so there is no leaked coroutine / battery drain
 * — the same idiom as [CountdownOverlay] / ExpiryCountdownLine. The SENDER never reaches this
 * composable (the dispatch renders their inner content directly); only recipients before the reveal do.
 *
 * @param onRevealed rendered once the reveal instant passes — supplies the inner content (the caller
 *   dispatches [MessageMedia.RevealLocked.innerMedia] / innerText exactly like a normal message body).
 */
@Composable
fun RevealLockedBubble(
    media: MessageMedia.RevealLocked,
    isOwn: Boolean,
    modifier: Modifier = Modifier,
    nowProvider: () -> Long = { System.currentTimeMillis() / 1000L },
    onRevealed: @Composable () -> Unit,
) {
    // One conflated 1s ticker; lifecycle-scoped collection pauses it below STARTED (no battery drain).
    val now by remember(media.revealAtSec) {
        flow {
            while (true) {
                emit(nowProvider())
                delay(1_000L)
            }
        }
    }.collectAsStateWithLifecycle(initialValue = nowProvider())

    // The sender is never locked; recipients unlock at/after the reveal instant.
    val locked = RevealAtMath.isRevealLocked(media.revealAtSec, isSender = isOwn, nowSec = now)

    if (!locked) {
        // Auto-reveal (tick reached the target OR sender): render the inner content with a soft flip-in.
        AnimatedVisibility(
            visible = true,
            enter = fadeIn() + scaleIn(initialScale = 0.96f),
        ) {
            onRevealed()
        }
        return
    }

    val remaining = RevealAtMath.secondsUntilReveal(media.revealAtSec, now)
    val label = RevealAtMath.revealCountdownLabel(media.revealAtSec, now)
    val cd = "Scheduled reveal — unlocks in " +
        com.testlogon.android.data.messaging.CountdownLogic.accessibilityRemaining(remaining)

    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
        tonalElevation = 1.dp,
        modifier = modifier
            .widthIn(max = 280.dp)
            .testTag(RevealLockedTestTags.LOCKED_BUBBLE)
            .semantics { contentDescription = cd },
    ) {
        Box {
            // A blurred/greyed placeholder strip behind the lock — evokes hidden content without ever
            // carrying it (the inner body is NOT rendered while locked; only the lock chrome shows).
            Box(
                Modifier
                    .matchWidthPlaceholder()
                    .blur(16.dp)
                    .background(MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.12f)),
            )
            Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Filled.Lock,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                        tint = MaterialTheme.colorScheme.primary,
                    )
                    Text(
                        text = "Scheduled reveal",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(start = 6.dp),
                    )
                }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(top = 4.dp),
                ) {
                    Icon(
                        Icons.Filled.Schedule,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = "Unlocks in $label",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier
                            .padding(start = 6.dp)
                            .testTag(RevealLockedTestTags.COUNTDOWN),
                    )
                }
            }
        }
    }
}

/** A fixed placeholder footprint for the blurred strip behind the lock chrome. */
private fun Modifier.matchWidthPlaceholder(): Modifier = this
    .fillMaxWidth()
    .size(width = 220.dp, height = 44.dp)
