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
import com.testlogon.android.feature.signing.document.DocumentViewerRoute
import com.testlogon.android.feature.signing.document.DocumentViewerViewModel

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

/**
 * AND-341 - the PDF document viewer destination, opened from the detail's "Open document" affordance.
 * `packetId` is a required path arg; the viewer streams that packet's PDF via SigningApi.downloadFinalPdf.
 */
data object SigningDocumentDest {
    const val ROUTE = "signing/packet/{packetId}/document"

    fun build(packetId: String): String = "signing/packet/${Uri.encode(packetId)}/document"
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
    ) { entry ->
        val packetId = entry.arguments?.getString(PacketDetailViewModel.ARG_PACKET_ID).orEmpty()
        PacketDetailRoute(
            onBack = { navController.popBackStack() },
            // AND-341 - the "Open document" affordance opens the PDF viewer for this packet. The viewer
            // streams the packet's PDF, so it navigates by packetId (NOT the source path argument).
            onOpenPdf = {
                if (packetId.isNotBlank()) {
                    navController.navigate(SigningDocumentDest.build(packetId))
                }
            },
            // The assigned-signer deep capture flow is a later ticket; no-op for now.
            onSign = {},
        )
    }
    composable(
        route = SigningDocumentDest.ROUTE,
        arguments = listOf(
            navArgument(DocumentViewerViewModel.ARG_PACKET_ID) {
                type = NavType.StringType
            },
        ),
    ) {
        DocumentViewerRoute(
            onBack = { navController.popBackStack() },
            // AND-342 will collect the per-page geometry to overlay signature fields; no-op for now.
            onPageLayout = {},
        )
    }
}
