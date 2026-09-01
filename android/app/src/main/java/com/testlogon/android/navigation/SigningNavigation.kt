package com.testlogon.android.navigation

import android.net.Uri
import androidx.compose.ui.platform.LocalContext
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.signing.PacketDetailRoute
import com.testlogon.android.feature.signing.PacketDetailViewModel
import com.testlogon.android.feature.signing.SigningEntryRoute
import com.testlogon.android.feature.signing.packetlist.SigningInboxRoute
import com.testlogon.android.feature.signing.capture.SigningRoute
import com.testlogon.android.feature.signing.capture.SigningViewModel
import com.testlogon.android.feature.signing.document.DocumentViewerRoute
import com.testlogon.android.feature.signing.document.DocumentViewerViewModel
import com.testlogon.android.feature.signing.submit.SignedDraftHandoff
import com.testlogon.android.feature.signing.submit.SubmitSignRoute
import com.testlogon.android.feature.signing.submit.SubmitSignViewModel
import dagger.hilt.android.EntryPointAccessors

/**
 * AND-340 - the e-signature Signing ENTRY + packet DETAIL destinations.
 *
 * There is NO backend packet-list endpoint, so the entry (`signing/entry`) is a load-by-id /
 * create-draft surface (NOT a browse list); both paths open the detail (`signing/packet/{packetId}`)
 * which renders the status + signers + the field manifest placeholder (AND-341/342) + the events
 * timeline + the status-driven primary action. onOpenPdf (-> the PDF viewer) and onSign (the assigned-
 * signer deep flow -> AND-342/343) are defaulted no-ops for now.
 */
/**
 * SUX-008 - the signing INBOX ("list packets") destination. Backed by the four browse endpoints
 * (awaiting / sent / completed-for-me / drafts) that shipped after AND-340's load-by-id-only entry.
 * Rows open the existing packet DETAIL. This is the More-hub entry point for the signing feature.
 */
data object SigningInboxDest {
    const val ROUTE = "signing/inbox"
}

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

/**
 * AND-342 - the signature CAPTURE + PLACEMENT destination. `packetId` + `documentId` are required path
 * args; the surface overlays signature fields on the AND-341 PDF viewer and builds a validated draft. NO
 * network submit (AND-343).
 */
data object SigningCaptureDest {
    // A distinct `capture/` prefix avoids any segment-count ambiguity with `signing/packet/{packetId}`.
    const val ROUTE = "signing/capture/{packetId}/{documentId}"

    fun build(packetId: String, documentId: String): String =
        "signing/capture/${Uri.encode(packetId)}/${Uri.encode(documentId)}"
}

/**
 * AND-343 - the TERMINAL e-sign (submit / sign + legal notice) destination, reached from the AND-342
 * capture surface's ContinueToSubmit. `packetId` is a required path arg; the validated draft is handed
 * over out-of-band via [SignedDraftHandoff] (a draft is not a primitive nav arg).
 */
data object SigningSubmitDest {
    const val ROUTE = "signing/submit/{packetId}"

    fun build(packetId: String): String = "signing/submit/${Uri.encode(packetId)}"
}

/** Hilt entry point so the capture route can resolve the singleton draft handoff in a composable. */
@dagger.hilt.EntryPoint
@dagger.hilt.InstallIn(dagger.hilt.components.SingletonComponent::class)
interface SignedDraftHandoffEntryPoint {
    fun signedDraftHandoff(): SignedDraftHandoff
}

/** AND-340 - registers the Signing entry + packet-detail screens in the authenticated graph. */
fun NavGraphBuilder.signingDestinations(navController: NavHostController) {
    composable(SigningInboxDest.ROUTE) {
        SigningInboxRoute(
            onBack = { navController.popBackStack() },
            onOpenPacket = { packetId ->
                navController.navigate(SigningPacketDetailDest.build(packetId))
            },
        )
    }
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
            // AND-342 - the assigned-signer deep flow opens the capture + placement surface. The PDF is
            // streamed by packetId (AND-341), so documentId == packetId here.
            onSign = {
                if (packetId.isNotBlank()) {
                    navController.navigate(SigningCaptureDest.build(packetId, packetId))
                }
            },
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
            // The AND-342 capture surface (SigningCaptureDest) overlays fields on its own viewer instance;
            // this standalone viewer is read-only, so no overlay is collected here.
            onPageLayout = {},
        )
    }
    composable(
        route = SigningCaptureDest.ROUTE,
        arguments = listOf(
            navArgument(SigningViewModel.ARG_PACKET_ID) { type = NavType.StringType },
            navArgument(SigningViewModel.ARG_DOCUMENT_ID) { type = NavType.StringType },
        ),
    ) {
        val context = LocalContext.current
        SigningRoute(
            onBack = { navController.popBackStack() },
            // AND-343 - deposit the validated draft into the process-scoped handoff (a draft is not a
            // primitive nav arg), then navigate to the terminal submit surface by packet id.
            onContinueToSubmit = { draft ->
                val handoff = EntryPointAccessors.fromApplication(
                    context.applicationContext,
                    SignedDraftHandoffEntryPoint::class.java,
                ).signedDraftHandoff()
                handoff.put(draft)
                if (draft.packetId.isNotBlank()) {
                    navController.navigate(SigningSubmitDest.build(draft.packetId))
                }
            },
        )
    }
    composable(
        route = SigningSubmitDest.ROUTE,
        arguments = listOf(
            navArgument(SubmitSignViewModel.ARG_PACKET_ID) { type = NavType.StringType },
        ),
    ) {
        SubmitSignRoute(
            // Terminal: dismiss back to the packet list / detail.
            onDismiss = { navController.popBackStack() },
        )
    }
}
