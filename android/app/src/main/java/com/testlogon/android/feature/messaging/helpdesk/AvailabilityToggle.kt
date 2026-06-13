package com.testlogon.android.feature.messaging.helpdesk

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.background
import com.testlogon.android.R
import com.testlogon.android.core.model.helpdesk.Availability

/** AND-379 — stable testTags for the availability toggle. */
object AvailabilityToggleTestTags {
    const val TOGGLE = "helpdesk_availability_toggle"
    const val SWITCH = "helpdesk_availability_switch"
}

/**
 * AND-379 — agent availability control: a Material 3 [Switch] + decorative status dot + text label
 * ("Online" / "Away"). State is conveyed by the text label (not color alone, WCAG 1.4.1); the dot is
 * decorative. The switch carries `stateDescription` "Online"/"Away" and a contentDescription of
 * "Agent availability" for TalkBack (AC-7). The toggle reads/writes the single source of truth via
 * its caller (the queue VM), so the UI can never diverge from the heartbeat status (AC-4).
 */
@Composable
fun AvailabilityToggle(
    value: Availability,
    onChange: (Availability) -> Unit,
    modifier: Modifier = Modifier,
) {
    val online = value == Availability.ONLINE
    val label = stringResource(
        if (online) R.string.helpdesk_availability_online else R.string.helpdesk_availability_away,
    )
    val stateDesc = label
    val cd = stringResource(R.string.helpdesk_availability_label)
    val dotColor = if (online) Color(0xFF2E7D32) else MaterialTheme.colorScheme.outline

    Row(
        modifier = modifier.testTag(AvailabilityToggleTestTags.TOGGLE),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        // Decorative status dot — state is also conveyed by the text label below.
        Spacer(
            Modifier
                .size(10.dp)
                .clip(CircleShape)
                .background(dotColor)
                .clearAndSetSemantics { },
        )
        Text(text = label, style = MaterialTheme.typography.labelLarge)
        Switch(
            checked = online,
            onCheckedChange = { checked ->
                onChange(if (checked) Availability.ONLINE else Availability.AWAY)
            },
            modifier = Modifier
                .padding(start = 4.dp)
                .testTag(AvailabilityToggleTestTags.SWITCH)
                .semantics {
                    // Merge (not clear): keep the Switch role + toggle action, add descriptions.
                    this.contentDescription = cd
                    this.stateDescription = stateDesc
                },
        )
    }
}
