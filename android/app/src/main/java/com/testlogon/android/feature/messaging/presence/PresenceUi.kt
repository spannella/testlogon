package com.testlogon.android.feature.messaging.presence

import com.testlogon.android.data.messaging.presence.Presence
import com.testlogon.android.data.messaging.presence.PresenceStatus
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/**
 * AND-145 — presence dot. Online = a small filled tertiary dot; offline = a muted outline dot. The
 * dot is decorative (the textual state is carried by the adjacent label / contentDescription), so it
 * clears its own semantics. [stale] dims it while SSE is reconnecting rather than flipping to offline.
 */
@Composable
fun PresenceDot(
    status: PresenceStatus,
    modifier: Modifier = Modifier,
    stale: Boolean = false,
) {
    val color = when (status) {
        PresenceStatus.ONLINE -> MaterialTheme.colorScheme.tertiary
        PresenceStatus.OFFLINE -> MaterialTheme.colorScheme.outline
    }
    androidx.compose.foundation.layout.Box(
        modifier = modifier
            .size(10.dp)
            .clip(CircleShape)
            .background(color)
            .alpha(if (stale) 0.4f else 1f)
            .clearAndSetSemantics {},
    )
}

/**
 * AND-145 — compact presence line for the thread header: a dot + "Online" / "Last seen …" text. The
 * row carries a single non-color contentDescription so TalkBack announces the state textually.
 */
@Composable
fun PresenceHeaderLabel(
    presence: Presence,
    nowEpochSeconds: Long,
    modifier: Modifier = Modifier,
) {
    val text = presenceLabelText(presence, nowEpochSeconds)
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier,
    )
}

/** Localized presence label: "Online" or a relative "Last seen …" derived from last_seen_at. */
@Composable
fun presenceLabelText(presence: Presence, nowEpochSeconds: Long): String =
    when (presence.status) {
        PresenceStatus.ONLINE -> stringResource(R.string.presence_online)
        PresenceStatus.OFFLINE -> {
            val lastSeen = presence.lastSeenAtEpochSeconds
            if (lastSeen == null) {
                stringResource(R.string.presence_offline)
            } else {
                stringResource(R.string.presence_last_seen_at, relativeLastSeen(nowEpochSeconds, lastSeen))
            }
        }
    }

/**
 * AND-145 — pure relative "last seen" phrasing from epoch seconds, locale-independent and Android-free
 * so it is JVM-testable. Returns coarse buckets: "moments ago" / "Nm" / "Nh" / "Nd".
 */
fun relativeLastSeen(nowEpochSeconds: Long, lastSeenEpochSeconds: Long): String {
    val deltaSeconds = (nowEpochSeconds - lastSeenEpochSeconds).coerceAtLeast(0)
    return when {
        deltaSeconds < 60 -> "moments ago"
        deltaSeconds < 3_600 -> "${deltaSeconds / 60}m ago"
        deltaSeconds < 86_400 -> "${deltaSeconds / 3_600}h ago"
        else -> "${deltaSeconds / 86_400}d ago"
    }
}
