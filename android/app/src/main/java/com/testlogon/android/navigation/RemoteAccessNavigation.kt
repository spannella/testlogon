package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.connprofiles.ConnProfilesRoute
import com.testlogon.android.feature.instancetemplates.InstanceTemplatesRoute
import com.testlogon.android.feature.sshbastion.SshBastionRoute
import com.testlogon.android.feature.sshkeys.SshKeysRoute
import com.testlogon.android.feature.sshrecordings.SshRecordingsRoute
import com.testlogon.android.feature.vnc.RemoteDesktopRoute

/**
 * B7 web-parity: the REMOTE-ACCESS surfaces, registered in the AUTHENTICATED graph. Mirror the web
 * /remote (ssh-keys, recordings, bastion, connection-profiles, templates) + /remote-desktop pages. All
 * backends are owner-scoped require_ui_session control planes; a 403 (defence-in-depth) renders Forbidden.
 * Surfaced in the operator/Infra hub (operatorOnly). remote-desktop is FLAGGED on web
 * (VITE_VNC_REMOTE_DESKTOP_ENABLED, default ON) — the Android session broker is built; the live noVNC
 * viewer is an honest "open on desktop" state (RFB-over-WebSocket is not a mobile surface).
 */
data object SshKeysDest {
    const val ROUTE = "remote/ssh-keys"
}

data object SshRecordingsDest {
    const val ROUTE = "remote/ssh-recordings"
}

data object SshBastionDest {
    const val ROUTE = "remote/bastion"
}

data object ConnProfilesDest {
    const val ROUTE = "remote/connection-profiles"
}

data object InstanceTemplatesDest {
    const val ROUTE = "remote/templates"
}

data object RemoteDesktopDest {
    const val ROUTE = "remote/desktop"
}

fun NavGraphBuilder.remoteAccessDestinations(navController: NavHostController) {
    composable(SshKeysDest.ROUTE) {
        SshKeysRoute(onBack = { navController.popBackStack() })
    }
    composable(SshRecordingsDest.ROUTE) {
        SshRecordingsRoute(onBack = { navController.popBackStack() })
    }
    composable(SshBastionDest.ROUTE) {
        SshBastionRoute(onBack = { navController.popBackStack() })
    }
    composable(ConnProfilesDest.ROUTE) {
        ConnProfilesRoute(onBack = { navController.popBackStack() })
    }
    composable(InstanceTemplatesDest.ROUTE) {
        InstanceTemplatesRoute(onBack = { navController.popBackStack() })
    }
    composable(RemoteDesktopDest.ROUTE) {
        RemoteDesktopRoute(onBack = { navController.popBackStack() })
    }
}
