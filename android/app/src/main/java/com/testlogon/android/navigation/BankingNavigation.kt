package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.banking.BankingAccountDetailRoute
import com.testlogon.android.feature.banking.BankingAccountsRoute
import com.testlogon.android.feature.banking.BankingTransactionRoute

/**
 * The native OpenBankProject banking-accounts surface (linked-accounts list -> account detail +
 * transactions -> transaction metadata editing), reached from the More -> Wallet hub. Wired to the
 * session-authed `/ui/banking` endpoints (the shared Retrofit client attaches the cookie). The whole
 * backend router is feature-flag-gated; reads degrade-on-404 to an honest "not available" empty state.
 */
data object BankingAccountsDest {
    const val ROUTE = "banking"
}

/** Account-detail route; the arg is the account_id path param. */
data object BankingAccountDetailDest {
    const val ARG_ACCOUNT_ID = "accountId"
    const val ROUTE = "banking/accounts/{$ARG_ACCOUNT_ID}"

    fun build(accountId: String): String = "banking/accounts/${Uri.encode(accountId)}"
}

/** Transaction-metadata route; the args are the account_id + transaction_id path params. */
data object BankingTransactionDest {
    const val ARG_ACCOUNT_ID = "accountId"
    const val ARG_TRANSACTION_ID = "transactionId"
    const val ROUTE = "banking/accounts/{$ARG_ACCOUNT_ID}/transactions/{$ARG_TRANSACTION_ID}"

    fun build(accountId: String, transactionId: String): String =
        "banking/accounts/${Uri.encode(accountId)}/transactions/${Uri.encode(transactionId)}"
}

/** Registers the three banking destinations in the authenticated graph. */
fun NavGraphBuilder.bankingDestinations(navController: NavHostController) {
    composable(BankingAccountsDest.ROUTE) {
        BankingAccountsRoute(
            onBack = { navController.popBackStack() },
            onOpenAccount = { accountId ->
                navController.navigate(BankingAccountDetailDest.build(accountId)) { launchSingleTop = true }
            },
        )
    }
    composable(
        route = BankingAccountDetailDest.ROUTE,
        arguments = listOf(
            navArgument(BankingAccountDetailDest.ARG_ACCOUNT_ID) { type = NavType.StringType },
        ),
    ) { backStackEntry ->
        val accountId = backStackEntry.arguments?.getString(BankingAccountDetailDest.ARG_ACCOUNT_ID).orEmpty()
        BankingAccountDetailRoute(
            accountId = accountId,
            onBack = { navController.popBackStack() },
            onOpenTransaction = { accId, txnId ->
                navController.navigate(BankingTransactionDest.build(accId, txnId)) { launchSingleTop = true }
            },
        )
    }
    composable(
        route = BankingTransactionDest.ROUTE,
        arguments = listOf(
            navArgument(BankingTransactionDest.ARG_ACCOUNT_ID) { type = NavType.StringType },
            navArgument(BankingTransactionDest.ARG_TRANSACTION_ID) { type = NavType.StringType },
        ),
    ) { backStackEntry ->
        val accountId = backStackEntry.arguments?.getString(BankingTransactionDest.ARG_ACCOUNT_ID).orEmpty()
        val transactionId = backStackEntry.arguments?.getString(BankingTransactionDest.ARG_TRANSACTION_ID).orEmpty()
        BankingTransactionRoute(
            accountId = accountId,
            transactionId = transactionId,
            onBack = { navController.popBackStack() },
        )
    }
}
