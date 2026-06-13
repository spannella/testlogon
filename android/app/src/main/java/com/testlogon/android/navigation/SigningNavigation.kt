package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.signing.PacketDetailRoute
import com.testlogon.android.feature.signing.PacketDetailViewModel
import com.testlogon.android.feature.signing.SigningEntryRoute

/**
 * AND-340 - the e-signature Signing ENTRY + packet DETAIL destinations.
 *
 * There is NO backend packet-list endpoint, so the entry (`signing/entry`) is a load-by-id /
 * create-draft surface (NOT a browse list); both paths open the detail (`signing/packet/{packetId}`)
 * which renders the status + signers + the field manifest placeholder (AND-341/342) + the events
 * timeline + the status-driven primary action. onOpenPdf (-> the PDF viewer) and onSign (the assigned-
 * signer deep flow -> AND-342/343) are defaulted no-ops for now.
 */
data object SigningEntryDest {
    const val ROUTE = "signing/entry"
}

/** The packet DETAIL destination; `packetId` is a required path arg. */
data object SigningPacketDetailDest {
    const val ROUTE = "signing/packet/{packetId}"

    fun build(packetId: String): String = "signing/packet/${Uri.encode(packetId)}"
}

/** AND-340 - registers the Signing entry + packet-detail screens in the authenticated graph. */
fun NavGraphBuilder.signingDestinations(navController: NavHostController) {
    composable(SigningEntryDest.ROUTE) {
        SigningEntryRoute(
            onBack = { navController.popBackStack() },
            onOpenPacket = { packetId ->
                navController.navigate(SigningPacketDetailDest.build(packetId))
            },
        )
    }
    composable(
        route = SigningPacketDetailDest.ROUTE,
        arguments = listOf(
            navArgument(PacketDetailViewModel.ARG_PACKET_ID) {
                type = NavType.StringType
            },
        ),
    ) {
        PacketDetailRoute(
            onBack = { navController.popBackStack() },
            // The PDF viewer + the assigned-signer deep capture flow are later tickets; no-op for now.
            onOpenPdf = {},
            onSign = {},
        )
    }
}
