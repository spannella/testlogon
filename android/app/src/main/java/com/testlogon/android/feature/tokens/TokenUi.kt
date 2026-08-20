@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.tokens

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.data.tokens.AuctionStatus
import com.testlogon.android.data.tokens.TokenStatus
import com.testlogon.android.data.tokens.UpkeepStatus

/** Human label for a token lifecycle status. */
fun TokenStatus.label(): String = when (this) {
    TokenStatus.DRAFT -> "Draft"
    TokenStatus.MINTED -> "Minted"
    TokenStatus.LISTED -> "Listed"
    TokenStatus.FROZEN -> "Frozen"
    TokenStatus.DELISTED -> "Delisted"
    TokenStatus.UNKNOWN -> "—"
}

fun AuctionStatus.label(): String = when (this) {
    AuctionStatus.OPEN -> "Open"
    AuctionStatus.CLEARED -> "Cleared"
    AuctionStatus.CANCELLED -> "Cancelled"
    AuctionStatus.UNKNOWN -> "—"
}

fun UpkeepStatus.label(): String = when (this) {
    UpkeepStatus.COVERED -> "Covered"
    UpkeepStatus.DUE -> "Due"
    UpkeepStatus.PAID -> "Paid"
    UpkeepStatus.DELINQUENT -> "Delinquent"
    UpkeepStatus.FROZEN -> "FROZEN"
    UpkeepStatus.UNKNOWN -> "—"
}

/** A label/value row used across the token detail sections and confirm dialogs. */
@Composable
fun TokenKeyValueRow(label: String, value: String, emphasize: Boolean = false) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace,
            fontWeight = if (emphasize) FontWeight.Bold else FontWeight.Normal,
            color = if (emphasize) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
        )
    }
}

/** A small pill that renders a status string. */
@Composable
fun TokenStatusPill(text: String) {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        shape = MaterialTheme.shapes.small,
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
        )
    }
}
