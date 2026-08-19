@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.markets.alerts

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AddAlert
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.DoneAll
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.exchange.alerts.TradingAlert
import com.testlogon.android.data.exchange.alerts.TradingAlertKind
import com.testlogon.android.feature.markets.ui.MarketColors
import com.testlogon.android.feature.markets.ui.MarketSurface

/**
 * Trading Alerts (notifications) route. Lists the recent derived alerts (fills / liquidations /
 * funding / margin-distress / PM-resolutions) newest-first with per-kind colour + unread dot, plus
 * mark-all-read and clear actions. Reachable from the bell in the Markets header and the More hub.
 */
@Composable
fun TradingAlertsRoute(
    onBack: () -> Unit,
    onOpenPriceAlerts: () -> Unit = {},
    viewModel: TradingAlertsViewModel = hiltViewModel(),
) {
    val alerts by viewModel.alerts.collectAsStateWithLifecycle()
    val unread by viewModel.unreadCount.collectAsStateWithLifecycle()
    MarketSurface {
        Column(modifier = Modifier.fillMaxSize().statusBarsPadding()) {
            AlertsHeader(
                unread = unread,
                hasAlerts = alerts.isNotEmpty(),
                onBack = onBack,
                onOpenPriceAlerts = onOpenPriceAlerts,
                onMarkAllRead = viewModel::markAllRead,
                onClear = viewModel::clear,
            )
            Box(modifier = Modifier.fillMaxSize()) {
                if (alerts.isEmpty()) {
                    Column(
                        modifier = Modifier.fillMaxSize().padding(32.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center,
                    ) {
                        Text("No alerts yet", color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                        Spacer(Modifier.size(6.dp))
                        Text(
                            "Fills, liquidations, funding payments and market resolutions will show up here.",
                            color = MarketColors.TextSecondary,
                            fontSize = 13.sp,
                        )
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag("trading_alerts_list"),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(alerts, key = { it.id }) { alert ->
                            AlertCard(alert = alert, onClick = { viewModel.markRead(alert.id) })
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AlertsHeader(
    unread: Int,
    hasAlerts: Boolean,
    onBack: () -> Unit,
    onOpenPriceAlerts: () -> Unit,
    onMarkAllRead: () -> Unit,
    onClear: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 4.dp, end = 8.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onBack) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = MarketColors.TextPrimary)
        }
        Column(modifier = Modifier.weight(1f)) {
            Text("Alerts", color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 22.sp)
            Text(
                if (unread > 0) "$unread unread" else "up to date",
                color = if (unread > 0) MarketColors.Accent else MarketColors.TextSecondary,
                fontSize = 12.sp,
            )
        }
        IconButton(onClick = onOpenPriceAlerts, modifier = Modifier.testTag("open_price_alerts")) {
            Icon(Icons.Filled.AddAlert, contentDescription = "Price alerts", tint = MarketColors.TextSecondary)
        }
        if (hasAlerts) {
            IconButton(onClick = onMarkAllRead, modifier = Modifier.testTag("alerts_mark_read")) {
                Icon(Icons.Filled.DoneAll, contentDescription = "Mark all read", tint = MarketColors.TextSecondary)
            }
            IconButton(onClick = onClear, modifier = Modifier.testTag("alerts_clear")) {
                Icon(Icons.Filled.DeleteSweep, contentDescription = "Clear", tint = MarketColors.TextSecondary)
            }
        }
    }
}

@Composable
private fun AlertCard(alert: TradingAlert, onClick: () -> Unit) {
    val accent = kindColor(alert.kind)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(if (alert.read) MarketColors.Surface else MarketColors.SurfaceAlt)
            .border(1.dp, MarketColors.Border, RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier.size(8.dp).clip(CircleShape)
                .background(if (alert.read) Color.Transparent else accent),
        )
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    kindLabel(alert.kind),
                    color = accent,
                    fontWeight = FontWeight.Bold,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    alert.title,
                    color = MarketColors.TextPrimary,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 14.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    textAlign = TextAlign.End,
                    modifier = Modifier.weight(1f),
                )
            }
            Spacer(Modifier.size(3.dp))
            Text(alert.body, color = MarketColors.TextSecondary, fontSize = 13.sp)
        }
    }
}

private fun kindColor(kind: TradingAlertKind): Color = when (kind) {
    TradingAlertKind.FILL -> MarketColors.Up
    TradingAlertKind.LIQUIDATION -> MarketColors.Down
    TradingAlertKind.MARGIN_DISTRESS -> MarketColors.Down
    TradingAlertKind.FUNDING -> MarketColors.Accent
    TradingAlertKind.PM_RESOLVED -> MarketColors.Accent
    TradingAlertKind.PRICE -> MarketColors.Accent
}

private fun kindLabel(kind: TradingAlertKind): String = when (kind) {
    TradingAlertKind.FILL -> "FILL"
    TradingAlertKind.LIQUIDATION -> "LIQUIDATION"
    TradingAlertKind.MARGIN_DISTRESS -> "MARGIN"
    TradingAlertKind.FUNDING -> "FUNDING"
    TradingAlertKind.PM_RESOLVED -> "RESOLVED"
    TradingAlertKind.PRICE -> "PRICE"
}
