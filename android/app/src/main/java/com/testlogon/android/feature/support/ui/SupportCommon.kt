@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.support.ui

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.testlogon.android.feature.support.data.SupportTicketStatus

/** B-SUP — shared testTags for the Support surface. */
object SupportTestTags {
    const val SCREEN = "support_screen"
    const val USER_SCREEN = "support_user_screen"
    const val ADMIN_SCREEN = "support_admin_screen"
    const val RESOLVING = "support_resolving"
    const val CREATE_FAB = "support_create_fab"
    const val TICKET_LIST = "support_ticket_list"
    const val TICKET_ROW = "support_ticket_row"
    const val EMPTY = "support_empty"
    const val CREATE_SUBJECT = "support_create_subject"
    const val CREATE_DESCRIPTION = "support_create_description"
    const val CREATE_SUBMIT = "support_create_submit"
    const val DETAIL_REPLY = "support_detail_reply"
    const val DETAIL_SEND = "support_detail_send"
    const val ADMIN_FORBIDDEN = "support_admin_forbidden"
    const val LIVE_CHAT_CARD = "support_live_chat_card"
    const val DETAIL_CLOSE = "support_detail_close"
    const val DETAIL_CANCEL = "support_detail_cancel"
}

/** Human label for a ticket status. */
fun SupportTicketStatus.label(): String = when (this) {
    SupportTicketStatus.OPEN -> "Open"
    SupportTicketStatus.IN_PROGRESS -> "In progress"
    SupportTicketStatus.WAITING_ON_USER -> "Waiting on you"
    SupportTicketStatus.DONE -> "Resolved"
    SupportTicketStatus.REOPENED -> "Reopened"
    SupportTicketStatus.CANCELLED -> "Cancelled"
    SupportTicketStatus.UNKNOWN -> "Status"
}

fun statusLabelFromWire(wire: String?): String = when (wire) {
    "open" -> "Open"
    "in_progress" -> "In progress"
    "waiting_on_user" -> "Waiting on user"
    "done" -> "Resolved"
    "reopened" -> "Reopened"
    else -> wire ?: "Status"
}

@Composable
fun StatusChip(status: SupportTicketStatus, modifier: Modifier = Modifier) {
    val container = when (status) {
        SupportTicketStatus.OPEN -> MaterialTheme.colorScheme.primaryContainer
        SupportTicketStatus.IN_PROGRESS -> MaterialTheme.colorScheme.tertiaryContainer
        SupportTicketStatus.WAITING_ON_USER -> MaterialTheme.colorScheme.secondaryContainer
        SupportTicketStatus.DONE -> MaterialTheme.colorScheme.surfaceVariant
        SupportTicketStatus.REOPENED -> MaterialTheme.colorScheme.errorContainer
        SupportTicketStatus.CANCELLED -> MaterialTheme.colorScheme.surfaceVariant
        SupportTicketStatus.UNKNOWN -> MaterialTheme.colorScheme.surfaceVariant
    }
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(status.label(), style = MaterialTheme.typography.labelSmall) },
        colors = AssistChipDefaults.assistChipColors(
            disabledContainerColor = container,
            disabledLabelColor = MaterialTheme.colorScheme.onSurface,
        ),
        modifier = modifier,
    )
}

fun relativeTime(epochSeconds: Long): String {
    if (epochSeconds <= 0L) return ""
    return DateUtils.getRelativeTimeSpanString(
        epochSeconds * 1000L,
        System.currentTimeMillis(),
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}

@Composable
fun CenteredText(text: String, tag: String, modifier: Modifier = Modifier) {
    Box(modifier.fillMaxSize(), Alignment.Center) {
        Text(
            text,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(24.dp),
        )
    }
}

@Suppress("unused")
private val unusedColor = Color.Transparent
