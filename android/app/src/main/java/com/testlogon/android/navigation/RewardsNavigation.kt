package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.rewards.ReferralHubRoute
import com.testlogon.android.feature.rewards.RewardsRoute

/**
 * The REFERRALS + REWARDS surfaces (feature/rewards), reached from the More -> Growth hub.
 *
 * [ReferralHubDest] wires GET me/referral + me/referral/list (share code / link + referral stats + list);
 * [RewardsDest] wires GET me/rewards (+ history + catalog) and POST me/rewards/redeem (redeem points for
 * cash into the USD wallet or perks, behind a money-safety confirm). The shared authenticated Retrofit
 * client attaches the session cookie / CSRF header. Reads degrade-on-404 to an honest coming-soon state.
 */
data object ReferralHubDest {
    const val ROUTE = "referral_hub"
}

data object RewardsDest {
    const val ROUTE = "rewards"
}

/** Registers the Referral hub + Rewards screens in the authenticated graph. Up / Back pops the stack. */
fun NavGraphBuilder.rewardsDestinations(navController: NavHostController) {
    composable(ReferralHubDest.ROUTE) {
        ReferralHubRoute(onBack = { navController.popBackStack() })
    }
    composable(RewardsDest.ROUTE) {
        RewardsRoute(onBack = { navController.popBackStack() })
    }
}
