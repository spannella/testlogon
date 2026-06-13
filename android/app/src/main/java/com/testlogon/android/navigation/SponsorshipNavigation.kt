package com.testlogon.android.navigation

import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.R
import com.testlogon.android.feature.sponsorship.ui.SponsorshipInboxRoute

/**
 * AND-365 - the READ-ONLY sponsorship inbox destination (a single GET list of inbound brand deals with a
 * client-side status filter) plus a THIN placeholder for the deal-detail route.
 *
 * The inbox row taps through to sponsorship/deal/{dealId}. That detail destination is owned downstream by
 * AND-366; AND-365 registers only a "Coming soon" placeholder so the guarded tap-through (FR-6) does NOT
 * crash. AND-366 REPLACES [sponsorshipDealDestinationPlaceholder] with the real detail screen. Write actions
 * (accept / reject / counter / complete / cancel) are OUT OF SCOPE.
 */
data object SponsorshipInboxDest {
    const val ROUTE = "sponsorship/inbox"
}

data object SponsorshipDealDest {
    const val ARG_DEAL_ID = "dealId"
    const val ROUTE = "sponsorship/deal/{$ARG_DEAL_ID}"

    fun build(dealId: String): String = "sponsorship/deal/${Uri.encode(dealId)}"
}

/**
 * AND-365 - registers the sponsorship inbox + the thin deal-detail placeholder in the authenticated graph
 * (one shared nav graph; NOT forked). The inbox row taps through to the placeholder; both pop back.
 */
fun NavGraphBuilder.sponsorshipDestinations(navController: NavHostController) {
    composable(route = SponsorshipInboxDest.ROUTE) {
        SponsorshipInboxRoute(
            onBack = { navController.popBackStack() },
            onOpenDeal = { dealId ->
                navController.navigate(SponsorshipDealDest.build(dealId))
            },
        )
    }
    composable(
        route = SponsorshipDealDest.ROUTE,
        arguments = listOf(
            navArgument(SponsorshipDealDest.ARG_DEAL_ID) { type = NavType.StringType },
        ),
    ) { backStackEntry ->
        val dealId = backStackEntry.arguments?.getString(SponsorshipDealDest.ARG_DEAL_ID).orEmpty()
        SponsorshipDealPlaceholderScreen(
            dealId = dealId,
            onBack = { navController.popBackStack() },
        )
    }
}

/**
 * AND-365 - a thin "Coming soon" placeholder for the sponsorship deal detail. It exists ONLY so the inbox
 * tap-through (FR-6 guarded nav) does not crash on a missing route. AND-366 REPLACES this with the real
 * detail screen (accept / reject / negotiate live there, OUT OF SCOPE here). The dealId nav arg is shown for
 * manual verification of the hand-off.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SponsorshipDealPlaceholderScreen(
    dealId: String,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.sponsorship_deal_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.sponsorship_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            contentAlignment = Alignment.Center,
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = stringResource(R.string.sponsorship_deal_coming_soon),
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = stringResource(R.string.sponsorship_deal_id_label, dealId),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
