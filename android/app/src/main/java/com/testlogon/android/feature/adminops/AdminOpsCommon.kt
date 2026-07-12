@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminops

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import java.text.NumberFormat
import java.util.Locale

/**
 * B6 admin-ops read dashboards (financials / payment-health / risk / compute / jobs / rate-limits /
 * audit-exports). Shared, PII-free error kind + reusable KPI tiles/rows. Mirrors the web admin pages;
 * every screen self-gates on a backend 403 -> Forbidden state (our admin account can drive the ADMIN
 * dashboards; the ROOT-only surfaces render Forbidden).
 */
enum class AdminOpsErrorType { NETWORK, SERVER, AUTH }

internal fun adminOpsErrorMessage(type: AdminOpsErrorType): String = when (type) {
    AdminOpsErrorType.AUTH -> "Your session expired. Please sign in again."
    AdminOpsErrorType.SERVER -> "Something went wrong on the server. Try again."
    AdminOpsErrorType.NETWORK -> "You appear to be offline. Check your connection."
}

/** Map an ApiResult failure status to the normalized error kind (403 handled separately -> Forbidden). */
internal fun adminOpsErrorFor(status: Int): AdminOpsErrorType =
    if (status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER

internal fun relativeSeconds(epochSeconds: Long): String = DateUtils.getRelativeTimeSpanString(
    epochSeconds * 1000L,
    System.currentTimeMillis(),
    DateUtils.MINUTE_IN_MILLIS,
).toString()

private val currencyFmt: NumberFormat = NumberFormat.getCurrencyInstance(Locale.US)

/** Cents -> "$1,234.56". */
internal fun cents(value: Long): String = currencyFmt.format(value / 100.0)

internal fun cents(value: Int): String = cents(value.toLong())

/** Basis points -> "20.00%" (2000 bps = 20%). */
internal fun bpsPct(bps: Int): String = String.format(Locale.US, "%.2f%%", bps / 100.0)

internal fun pct(fraction: Double): String = String.format(Locale.US, "%.1f%%", fraction)

@Composable
internal fun AdminOpsBackIcon(onBack: () -> Unit) {
    IconButton(onClick = onBack) {
        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
    }
}

/** A single KPI tile (label + value + optional sublabel). Fixed compact width for a wrapping grid. */
@Composable
internal fun KpiTile(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    sublabel: String? = null,
) {
    Card(modifier = modifier) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = label.uppercase(Locale.US),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = value,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (sublabel != null) {
                Text(
                    text = sublabel,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

/** Wrapping row of KPI tiles. Each tile takes ~half the width so two fit per line on a phone. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun KpiGrid(
    tiles: List<Pair<String, String>>,
    modifier: Modifier = Modifier,
    subs: Map<String, String> = emptyMap(),
) {
    FlowRow(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        tiles.forEach { (label, value) ->
            KpiTile(
                label = label,
                value = value,
                sublabel = subs[label],
                modifier = Modifier.fillMaxWidth(fraction = 0.47f),
            )
        }
    }
}

/** A simple label + value list row inside a section card. */
@Composable
internal fun StatRow(label: String, value: String, modifier: Modifier = Modifier) {
    androidx.compose.foundation.layout.Row(
        modifier = modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(end = 12.dp),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
            textAlign = androidx.compose.ui.text.style.TextAlign.End,
        )
    }
}

@Composable
internal fun SectionHeader(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.SemiBold,
        modifier = modifier.padding(top = 8.dp, bottom = 4.dp),
    )
}

@Composable
internal fun CardSection(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(bottom = 6.dp),
            )
            content()
        }
    }
}

/**
 * Shared scaffold for the read-only admin dashboards: TopAppBar + back, pull-to-refresh, and the
 * Loading / Forbidden / Error / Content branches. [content] renders the loaded body (already inside a
 * verticalScroll column with 16.dp padding is the caller's responsibility).
 */
@Composable
internal fun AdminOpsDashboardScaffold(
    title: String,
    branch: AdminOpsBranch,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    screenTag: String = "",
    forbiddenTag: String = "",
    retryTag: String = "",
    forbiddenBody: String = "You need platform-admin access to view this.",
    header: @Composable (() -> Unit)? = null,
    content: @Composable () -> Unit,
) {
    androidx.compose.material3.Scaffold(
        modifier = modifier.let { if (screenTag.isNotEmpty()) it.testTag(screenTag) else it },
        topBar = {
            androidx.compose.material3.TopAppBar(
                title = { Text(title) },
                navigationIcon = { AdminOpsBackIcon(onBack) },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxWidth().padding(padding)) {
            header?.invoke()
            androidx.compose.material3.pulltorefresh.PullToRefreshBox(
                isRefreshing = branch.isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.fillMaxSize(),
            ) {
                when (branch) {
                    is AdminOpsBranch.Loading -> com.testlogon.android.core.ui.state.LoadingState()
                    is AdminOpsBranch.Forbidden -> com.testlogon.android.core.ui.state.EmptyState(
                        modifier = if (forbiddenTag.isNotEmpty()) Modifier.testTag(forbiddenTag) else Modifier,
                        title = "Not authorised",
                        body = forbiddenBody,
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back",
                        onAction = onBack,
                    )
                    is AdminOpsBranch.Error -> com.testlogon.android.core.ui.state.ErrorState(
                        modifier = if (retryTag.isNotEmpty()) Modifier.testTag(retryTag) else Modifier,
                        message = adminOpsErrorMessage(branch.type),
                        onRetry = onRetry,
                    )
                    is AdminOpsBranch.Content -> content()
                }
            }
        }
    }
}

/** Simplified branch descriptor so the shared scaffold can render without knowing the concrete state. */
internal sealed interface AdminOpsBranch {
    val isRefreshing: Boolean get() = false
    data object Loading : AdminOpsBranch
    data class Content(override val isRefreshing: Boolean) : AdminOpsBranch
    data object Forbidden : AdminOpsBranch
    data class Error(val type: AdminOpsErrorType) : AdminOpsBranch
}
