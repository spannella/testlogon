@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.rewards

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.WorkspacePremium
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** Stable testTags for the Rewards status / loyalty tier screen. */
object StatusTierTestTags {
    const val SCREEN = "status_tier_screen"
    const val CONTENT = "status_tier_content"
    const val LOADING = "status_tier_loading"
    const val ERROR = "status_tier_error"
    const val COMING_SOON = "status_tier_coming_soon"
    const val CURRENT_CARD = "status_tier_current_card"
    const val PROGRESS = "status_tier_progress"
    const val LADDER = "status_tier_ladder"
    const val SOURCE_BADGE = "status_tier_source_badge"
    const val ROW_PREFIX = "status_tier_row_"
}

/** Route-level Rewards-status entry (reached from the Rewards screen / More -> Growth hub). */
@Composable
fun StatusTierRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: StatusTierViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    StatusTierScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        modifier = modifier,
    )
}

@Composable
fun StatusTierScreen(
    state: StatusTierUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.fillMaxSize().testTag(StatusTierTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Status & tiers") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("status_tier_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            val resolved = state.resolved
            when {
                state.loading -> LoadingState(modifier = Modifier.testTag(StatusTierTestTags.LOADING))

                state.offline -> ErrorState(
                    message = state.errorMessage ?: "Couldn't load your status.",
                    onRetry = onRetry,
                    modifier = Modifier.testTag(StatusTierTestTags.ERROR),
                )

                state.errorMessage != null && resolved == null -> ErrorState(
                    message = state.errorMessage,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(StatusTierTestTags.ERROR),
                )

                !state.available || resolved == null -> EmptyState(
                    title = "Status coming soon",
                    body = "Earn lifetime reward points to climb the loyalty tiers and unlock bigger points multipliers and perks. This lights up once rewards are enabled for your account.",
                    modifier = Modifier.testTag(StatusTierTestTags.COMING_SOON),
                )

                else -> StatusTierContent(resolved = resolved, ladder = state.ladder)
            }
        }
    }
}

@Composable
private fun StatusTierContent(
    resolved: StatusTierMath.ResolvedStatus,
    ladder: List<StatusTierMath.StatusTier>,
) {
    Column(
        modifier = Modifier
            .testTag(StatusTierTestTags.CONTENT)
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        CurrentTierCard(resolved)
        LadderCard(resolved = resolved, ladder = ladder)
        Text(
            "This is your loyalty membership status, based on lifetime reward points. It is separate from the maker/taker fee tiers, which are based on your trading volume.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun CurrentTierCard(resolved: StatusTierMath.ResolvedStatus) {
    ElevatedCard(modifier = Modifier.fillMaxWidth().testTag(StatusTierTestTags.CURRENT_CARD)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                TierBadge(imageVector = Icons.Outlined.WorkspacePremium)
                Column(modifier = Modifier.weight(1f)) {
                    Text("Your status", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(resolved.name, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
                }
                SourceBadge(resolved.isAuthoritative)
            }

            Row(horizontalArrangement = Arrangement.spacedBy(24.dp)) {
                StatCell("Lifetime points", formatPoints(resolved.lifetimePoints))
                StatCell("Points multiplier", StatusTierMath.multiplierLabel(resolved.multiplierBps))
            }

            // Progress to next tier (or a top-tier note).
            if (resolved.isTopTier) {
                Text(
                    "You've reached the top tier — enjoy every perk.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
                LinearProgressIndicator(
                    progress = { 1f },
                    modifier = Modifier.fillMaxWidth().height(8.dp).clip(RoundedCornerShape(4.dp)).testTag(StatusTierTestTags.PROGRESS),
                )
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    LinearProgressIndicator(
                        progress = { resolved.progressFraction },
                        modifier = Modifier.fillMaxWidth().height(8.dp).clip(RoundedCornerShape(4.dp)).testTag(StatusTierTestTags.PROGRESS),
                    )
                    val next = resolved.nextName ?: "next tier"
                    Text(
                        "${formatPoints(resolved.pointsToNext)} points to $next",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            if (resolved.perks.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Your perks", style = MaterialTheme.typography.labelLarge)
                    resolved.perks.forEach { perk -> PerkRow(perk) }
                }
            }
        }
    }
}

@Composable
private fun LadderCard(
    resolved: StatusTierMath.ResolvedStatus,
    ladder: List<StatusTierMath.StatusTier>,
) {
    ElevatedCard(modifier = Modifier.fillMaxWidth().testTag(StatusTierTestTags.LADDER)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("All tiers", style = MaterialTheme.typography.titleMedium)
            ladder.forEach { tier ->
                val achieved = resolved.lifetimePoints >= tier.thresholdPoints
                val isCurrent = tier.id == resolved.tierId
                LadderRow(tier = tier, achieved = achieved, isCurrent = isCurrent)
            }
        }
    }
}

@Composable
private fun LadderRow(
    tier: StatusTierMath.StatusTier,
    achieved: Boolean,
    isCurrent: Boolean,
) {
    val containerColor =
        if (isCurrent) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface
    val borderColor =
        if (isCurrent) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant
    Surface(
        color = containerColor,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, borderColor, RoundedCornerShape(12.dp))
            .testTag(StatusTierTestTags.ROW_PREFIX + tier.id),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(
                    imageVector = if (achieved) Icons.Filled.CheckCircle else Icons.Outlined.Lock,
                    contentDescription = if (achieved) "Achieved" else "Locked",
                    tint = if (achieved) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp),
                )
                Text(
                    tier.name,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = if (isCurrent) FontWeight.Bold else FontWeight.Medium,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    StatusTierMath.multiplierLabel(tier.multiplierBps),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            Text(
                if (tier.thresholdPoints <= 0L) "From day one" else "${formatPoints(tier.thresholdPoints)}+ lifetime points",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            tier.perks.forEach { perk ->
                Text("• $perk", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun TierBadge(imageVector: ImageVector) {
    Box(
        modifier = Modifier
            .size(44.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.primaryContainer),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = imageVector,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onPrimaryContainer,
            modifier = Modifier.size(26.dp),
        )
    }
}

@Composable
private fun SourceBadge(isAuthoritative: Boolean) {
    val label = if (isAuthoritative) "Live" else "Est"
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier.testTag(StatusTierTestTags.SOURCE_BADGE),
    ) {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
        )
    }
}

@Composable
private fun StatCell(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun PerkRow(perk: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Icon(
            Icons.Filled.CheckCircle,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(16.dp),
        )
        Text(perk, style = MaterialTheme.typography.bodyMedium)
    }
}

/** Group whole reward points with thousands separators (locale-agnostic grouping by comma). */
private fun formatPoints(points: Long): String {
    val negative = points < 0L
    val digits = kotlin.math.abs(points).toString()
    val sb = StringBuilder()
    val n = digits.length
    for (i in 0 until n) {
        if (i > 0 && (n - i) % 3 == 0) sb.append(',')
        sb.append(digits[i])
    }
    return (if (negative) "-" else "") + sb.toString()
}
