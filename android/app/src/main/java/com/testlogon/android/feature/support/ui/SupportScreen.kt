@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.support.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.feature.support.data.SupportTicket

/**
 * B-SUP (batch 7) - the role-branched Support entry point. Resolves GET /ui/me.is_admin then renders:
 *  - USER  -> a clean help experience: create a ticket + view my tickets/status/replies + FAQ/help links.
 *  - ADMIN -> the helpdesk/moderation queue (incoming tickets, filters, summary, drill-in to assign/respond).
 * While resolving (or on a failure) it degrades to the USER view so a non-admin NEVER sees admin controls.
 */
@Composable
fun SupportRoute(
    onBack: () -> Unit,
    onOpenTicket: (ticketId: String, isAdmin: Boolean) -> Unit,
    onCreateTicket: () -> Unit,
    viewModel: SupportHomeViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    when (state.role) {
        SupportRole.Resolving -> ResolvingScaffold(onBack)
        SupportRole.Admin -> SupportAdminScreen(
            onBack = onBack,
            onOpenTicket = { onOpenTicket(it, true) },
        )
        SupportRole.User -> SupportUserScreen(
            state = state,
            onBack = onBack,
            onRetry = viewModel::loadMyTickets,
            onOpenTicket = { onOpenTicket(it, false) },
            onCreateTicket = onCreateTicket,
        )
    }
}

@Composable
private fun ResolvingScaffold(onBack: () -> Unit) {
    Scaffold(
        modifier = Modifier.testTag(SupportTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Support") },
                navigationIcon = { BackButton(onBack) },
            )
        },
    ) { p ->
        Box(Modifier.fillMaxSize().padding(p), Alignment.Center) {
            CircularProgressIndicator(Modifier.testTag(SupportTestTags.RESOLVING))
        }
    }
}

@Composable
fun BackButton(onBack: () -> Unit) {
    IconButton(onClick = onBack) {
        Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = "Back")
    }
}

// ------------------------------- USER surface -------------------------------

@Composable
private fun SupportUserScreen(
    state: SupportHomeUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onOpenTicket: (String) -> Unit,
    onCreateTicket: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(SupportTestTags.USER_SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Help & support") },
                navigationIcon = { BackButton(onBack) },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onCreateTicket,
                icon = { Icon(Icons.Outlined.Add, contentDescription = null) },
                text = { Text("New ticket") },
                modifier = Modifier.testTag(SupportTestTags.CREATE_FAB),
            )
        },
    ) { p ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(p).testTag(SupportTestTags.TICKET_LIST),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            item {
                Text(
                    "Need a hand? Browse the help center or open a support ticket and our team will reply here.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                Text("Quick help", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            }
            items(faqLinks, key = { it.first }) { (q, _) ->
                FaqRow(q)
            }
            item {
                Spacer(Modifier.height(16.dp))
                HorizontalDivider()
                Spacer(Modifier.height(12.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text("My tickets", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    if (state.ticketsError != null) TextButton(onClick = onRetry) { Text("Retry") }
                }
            }
            when {
                state.ticketsLoading ->
                    item {
                        Box(Modifier.fillMaxWidth().padding(24.dp), Alignment.Center) { CircularProgressIndicator() }
                    }
                state.ticketsError != null ->
                    item { Text(state.ticketsError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                state.tickets.isEmpty() ->
                    item {
                        Text(
                            "You have no support tickets yet. Tap New ticket to get help.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.testTag(SupportTestTags.EMPTY).padding(vertical = 8.dp),
                        )
                    }
                else ->
                    items(state.tickets, key = { it.ticketId }) { t ->
                        TicketRow(t, showOwner = false, onClick = { onOpenTicket(t.ticketId) })
                    }
            }
        }
    }
}

private val faqLinks: List<Pair<String, String>> = listOf(
    "How do I reset my password?" to "faq_password",
    "Managing your payment methods" to "faq_payments",
    "Privacy, data export & account deletion" to "faq_privacy",
    "Reporting content or a user" to "faq_report",
)

@Composable
private fun FaqRow(question: String) {
    // Help-center content is stubbed (no in-app article endpoint); the row is informational for now.
    Row(
        Modifier.fillMaxWidth().padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(question, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Text("Help", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
    }
    HorizontalDivider()
}

@Composable
fun TicketRow(ticket: SupportTicket, showOwner: Boolean, onClick: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag(SupportTestTags.TICKET_ROW)
            .padding(vertical = 10.dp),
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text(
                ticket.subject.ifBlank { "(no subject)" },
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            StatusChip(ticket.status)
        }
        val sub = buildString {
            if (showOwner && ticket.ownerSub.isNotBlank()) append(ticket.ownerSub).append(" - ")
            if (!ticket.caseNumber.isNullOrBlank()) append(ticket.caseNumber).append(" - ")
            val rel = relativeTime(ticket.updatedAt)
            if (rel.isNotBlank()) append(rel)
            if (showOwner && !ticket.isAssigned) {
                if (isNotEmpty()) append(" - ")
                append("Unassigned")
            }
        }
        if (sub.isNotBlank()) {
            Text(sub, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        ticket.lastMessagePreview?.takeIf { it.isNotBlank() }?.let { preview ->
            Spacer(Modifier.height(2.dp))
            Text(preview, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.height(6.dp))
        HorizontalDivider()
    }
}
