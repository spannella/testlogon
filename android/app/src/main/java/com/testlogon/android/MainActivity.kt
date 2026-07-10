package com.testlogon.android

import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.fragment.app.FragmentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import com.testlogon.android.core.network.AppThemeMode
import com.testlogon.android.core.network.ThemePreferencesStore
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.gcal.GoogleCalendarReturnHandler
import com.testlogon.android.data.payments.PaymentReturnDispatcher
import com.testlogon.android.data.payments.PaymentReturnHandler
import com.testlogon.android.feature.projects.provider.ProjectDriveReturnHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Composable
import androidx.activity.compose.LocalActivityResultRegistryOwner
import com.testlogon.android.testseam.TestHooks
import androidx.compose.runtime.mutableStateOf
import com.testlogon.android.feature.player.ActivityPipController
import com.testlogon.android.feature.player.LocalPipController
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.viewinterop.AndroidView
import androidx.media3.ui.PlayerView
import androidx.media3.common.util.UnstableApi
import com.testlogon.android.feature.health.HealthBannerHost
import com.testlogon.android.navigation.AppNavHost
import com.testlogon.android.navigation.applink.DeepLinkRouter
import com.testlogon.android.navigation.deeplink.DeepLinkParser
import com.testlogon.android.navigation.deeplink.NotificationDeepLink
import com.testlogon.android.navigation.deeplink.PushTapRouting
import com.testlogon.android.feature.messaging.nav.MessagingRoutes
import com.testlogon.android.feature.alerts.saleIdFromActionUrl
import com.testlogon.android.feature.alerts.shipGroupFromActionUrl
import com.testlogon.android.navigation.OrderTrackingDest
import com.testlogon.android.navigation.SellerSalesDest
import com.testlogon.android.navigation.navigateToNotificationTarget
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : FragmentActivity() {

    // Hoisted so onNewIntent can deliver warm/foreground deep links (AND-061, singleTask launchMode).
    // NavHostController so AND-108 push-tap routing can reuse the notification target extension.
    private var navController: NavHostController? = null

    // #8 — Picture-in-Picture controller backed by THIS Activity (single-activity app). Video players
    // call enterPip(); onUserLeaveHint auto-enters when a video is active. Lazily built in onCreate.
    private val pipController by lazy { ActivityPipController(this) }

    // #8 — observable PiP-mode flag the Compose tree reads (LocalPipController consumers can hide
    // chrome in PiP). Updated by onPictureInPictureModeChanged.
    private val inPipMode = mutableStateOf(false)

    // AND-108: a notification-tap deep link parsed from the launch/new intent, buffered until the
    // NavController is ready (cold start) and then routed exactly once. Survives the onCreate/first-
    // composition race; idempotent because the source Intent is marked consumed when parsed.
    private var pendingNotificationDeepLink: NotificationDeepLink? = null

    // AND-396: the central HTTP(S) App Link router. Observes a VIEW intent's URL, resolves it to a
    // typed route, and buffers it until the NavHost is ready / a session exists. Coexists with the
    // per-feature navDeepLink registrations (handleDeepLink below) — this seam adds the cold/warm
    // buffering + auth-deferral + telemetry the spec (FR-3..7) requires.
    @Inject
    lateinit var deepLinkRouter: DeepLinkRouter

    // AND-081: the device-local appearance preference drives TestLogonTheme at the app root.
    @Inject
    lateinit var themePreferencesStore: ThemePreferencesStore

    // AND-231: the provider-agnostic payment redirect/return handler + dispatcher. The handler dedupes,
    // correlates against the in-flight intent, and (via onParsed) hands the parsed return to the
    // provider sub-flows through the dispatcher.
    @Inject
    lateinit var paymentReturnHandler: PaymentReturnHandler

    @Inject
    lateinit var paymentReturnDispatcher: PaymentReturnDispatcher

    // AND-273: optional custom-scheme Google Calendar OAuth return handler (mirrors the AND-231 pattern).
    // The primary return path is Custom-Tab-return -> refreshStatus on the connect screen; this handles a
    // deep-link return if the backend registers the custom scheme as the redirect URI.
    @Inject
    lateinit var googleCalendarReturnHandler: GoogleCalendarReturnHandler

    // AND-374: custom-scheme project Google Drive OAuth return handler (mirrors the AND-273 pattern). Parses a
    // testlogon://projects/{id}/providers/google_drive/callback deep link and emits it to the detail ViewModel
    // via the ProjectDriveReturnDispatcher; the detail screen validates state + completes the connection.
    @Inject
    lateinit var projectDriveReturnHandler: ProjectDriveReturnHandler

    private val returnScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    @OptIn(UnstableApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // AND-108: parse a cold-start notification deep link before the NavHost composes; route it
        // once the NavController becomes available (onNavControllerReady below).
        handleNotificationDeepLink(intent)
        // AND-231: a cold-start payment return (provider -> browser -> app). Dispatched to the provider
        // sub-flow; generic terminal routing is handled there once the graph is ready.
        handlePaymentReturn(intent)
        // AND-273: a cold-start Google Calendar OAuth return (optional custom-scheme deep link).
        handleGoogleCalendarReturn(intent)
        // AND-374: a cold-start project Drive OAuth return (custom-scheme deep link).
        handleProjectDriveReturn(intent)
        // AND-396: record a cold-start HTTP(S) App Link so the central router can buffer an authed
        // target until a session exists and resume it after finalize (FR-4/6). Custom-scheme returns
        // above are handled by their own handlers; this is HTTP(S) App Links only.
        handleAppLink(intent, source = "cold")
        setContent {
            // AND-081: resolve the persisted appearance preference into TestLogonTheme inputs so the
            // whole app (incl. system bars) re-themes immediately when the user changes it.
            val appearance by themePreferencesStore.preferences.collectAsStateWithLifecycle()
            val darkTheme = when (appearance.mode) {
                AppThemeMode.LIGHT -> false
                AppThemeMode.DARK -> true
                AppThemeMode.SYSTEM -> isSystemInDarkTheme()
            }
            val dynamicColor = appearance.dynamicColor &&
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

            TestLogonTheme(darkTheme = darkTheme, dynamicColor = dynamicColor) {
                // Expose Compose testTags to UIAutomator as view resource-ids so on-device UI
                // automation (Maestro feature-demo capture, instrumented device tests) can target
                // every tagged node by id. Recommended by Google for production UI automation; no
                // runtime behaviour change beyond the semantics tree.
                // TEST SEAM (debug-only): if TestHooks supplies an intercepting
                // ActivityResultRegistryOwner, provide it so every rememberLauncherForActivityResult
                // (all media-pick sites) routes through it. Release/no-op -> null -> default owner.
                val testRegistryOwner = TestHooks.registryOwner(this@MainActivity)
                @OptIn(ExperimentalComposeUiApi::class)
                val pipContent = @Composable {
                CompositionLocalProvider(LocalPipController provides pipController) {
                Surface(
                    modifier = Modifier
                        .fillMaxSize()
                        .semantics { testTagsAsResourceId = true },
                ) {
                    // FAIL #7/#8 — when the system puts us in Picture-in-Picture, collapse the WHOLE
                    // Activity content to a video-ONLY surface bound to the currently-active player so
                    // the floating window shows the VIDEO (not the messaging thread / news feed behind
                    // an inline player). This mirrors the VOD detail player, whose PlayerView already
                    // fills the window. Outside PiP we render the normal app shell.
                    val activePlayer = pipController.pipPlayerState.value
                    if (inPipMode.value && activePlayer != null) {
                        Box(Modifier.fillMaxSize().background(Color.Black)) {
                            AndroidView(
                                modifier = Modifier.fillMaxSize(),
                                factory = { ctx ->
                                    PlayerView(ctx).apply {
                                        useController = false
                                        setShowBuffering(PlayerView.SHOW_BUFFERING_NEVER)
                                        player = activePlayer
                                    }
                                },
                                update = { it.player = activePlayer },
                                onReset = { it.player = null },
                                onRelease = { it.player = null },
                            )
                        }
                    } else {
                    Column(Modifier.fillMaxSize()) {
                        // AND-042: a single global health banner above all app content.
                        HealthBannerHost(modifier = Modifier.fillMaxWidth())
                        AppNavHost(
                            modifier = Modifier.fillMaxSize(),
                            // The NavHost handles the cold-start launch intent automatically; we keep a
                            // reference so onNewIntent can forward warm/foreground magic-link taps.
                            onNavControllerReady = {
                                navController = it
                                // AND-108: drain any buffered cold-start notification deep link now
                                // that the graph is ready.
                                routePendingNotificationDeepLink()
                            },
                        )
                    }
                    }
                }
                }
                }
                if (testRegistryOwner != null) {
                    CompositionLocalProvider(LocalActivityResultRegistryOwner provides testRegistryOwner) {
                        pipContent()
                    }
                } else {
                    pipContent()
                }
            }
        }
    }

    /**
     * #8 — auto-enter PiP when the user leaves the app (Home press) while a video is actively playing.
     * Players register their playing state via PipController.setVideoActive; this is the recommended
     * "keep playing in a floating window" UX (no extra tap needed).
     */
    override fun onUserLeaveHint() {
        super.onUserLeaveHint()
        if (pipController.videoActive && pipController.isPipSupported) {
            pipController.enterPip()
        }
    }

    /**
     * #8 — track PiP mode so the Compose tree can adapt (e.g. hide controls in the floating window).
     */
    override fun onPictureInPictureModeChanged(
        isInPictureInPictureMode: Boolean,
        newConfig: android.content.res.Configuration,
    ) {
        super.onPictureInPictureModeChanged(isInPictureInPictureMode, newConfig)
        inPipMode.value = isInPictureInPictureMode
        // FAIL #7/#8 — release the stable PiP snapshot + latch when leaving PiP so normal disposal
        // resumes; on enter, keep the snapshot captured at enterPip() time.
        pipController.onPipModeChanged(isInPictureInPictureMode)
    }

    /**
     * AND-061: with singleTask launchMode, re-tapping a magic link while the Activity is resident
     * delivers here instead of recreating it. Forward the VIEW intent into the NavController so the
     * deep link resolves to the verify destination.
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        // AND-108: a warm-start notification tap arrives here (singleTask). Route immediately.
        handleNotificationDeepLink(intent)
        routePendingNotificationDeepLink()
        // AND-231: a warm payment return arrives here when the Custom Tab bounces back into the task.
        handlePaymentReturn(intent)
        // AND-273: a warm Google Calendar OAuth return (optional custom-scheme deep link).
        handleGoogleCalendarReturn(intent)
        // AND-374: a warm project Drive OAuth return (custom-scheme deep link).
        handleProjectDriveReturn(intent)
        // AND-396: a warm HTTP(S) App Link (singleTask onNewIntent). Record it then let the central
        // router consume it against the live NavController + session.
        handleAppLink(intent, source = "warm")
        if (intent.data != null) {
            navController?.handleDeepLink(intent)
        }
    }

    /**
     * AND-396 — feeds a VIEW intent's HTTP(S) data URL to the central [DeepLinkRouter]. The router
     * parses (host-allowlisted, I/O-free), buffers an authed target until a session exists, and emits
     * path-template telemetry. Custom-scheme (`testlogon://`) links are out of scope here and continue
     * to flow through their per-feature handlers / navDeepLink registrations. Idempotent re-delivery is
     * harmless: the router only navigates once the NavController consumes the buffer.
     */
    private fun handleAppLink(intent: Intent?, source: String) {
        val data = intent?.data ?: return
        val scheme = data.scheme?.lowercase()
        if (scheme != "https" && scheme != "http") return
        deepLinkRouter.onIntent(data.toString(), host = data.host?.lowercase(), source = source)
    }

    /**
     * AND-231 — feeds a VIEW intent's data URL to the [PaymentReturnHandler]. The handler returns null
     * for non-billing URLs (so other deep-link handlers run) and for duplicate deliveries (idempotency);
     * for a recognized billing return it emits the parsed result to the [PaymentReturnDispatcher] so the
     * originating provider flow (PayPal/CCBill/hosted checkout) reacts. android.net.Uri parsing happens
     * only here — the pure parser logic uses java.net.URI.
     */
    private fun handlePaymentReturn(intent: Intent?) {
        val url = intent?.data?.toString() ?: return
        returnScope.launch {
            paymentReturnHandler.handle(url) { parsed -> paymentReturnDispatcher.emit(parsed) }
        }
    }

    /**
     * AND-273 — feeds a VIEW intent's data URL to the [GoogleCalendarReturnHandler]. Returns true (and
     * stops) only for a recognized Google-Calendar return URL; otherwise other deep-link handlers run.
     * android.net.Uri parsing happens only here — the pure parser uses java.net.URI.
     */
    private fun handleGoogleCalendarReturn(intent: Intent?): Boolean {
        val url = intent?.data?.toString() ?: return false
        return googleCalendarReturnHandler.handle(url)
    }

    /**
     * AND-374 — feeds a VIEW intent's data URL to the [ProjectDriveReturnHandler]. Returns true (and stops)
     * only for a recognized project-Drive return URL; otherwise other deep-link handlers run. android.net.Uri
     * parsing happens only here — the pure parser uses java.net.URI.
     */
    private fun handleProjectDriveReturn(intent: Intent?): Boolean {
        val url = intent?.data?.toString() ?: return false
        return projectDriveReturnHandler.handle(url)
    }

    override fun onDestroy() {
        super.onDestroy()
        returnScope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    /** AND-108: parse + buffer a notification deep link from [intent], marking it consumed (idempotent). */
    private fun handleNotificationDeepLink(intent: Intent?) {
        val link = DeepLinkParser.parse(intent) ?: return
        DeepLinkParser.markConsumed(intent)
        pendingNotificationDeepLink = link
    }

    /**
     * AND-108: navigate to the buffered notification deep link's resolved route, once.
     *
     * If unauthenticated, the [AppNavHost] auth gate keeps the user on the login graph and the
     * requested authenticated route is simply not reachable yet; the navigate call is a safe no-op in
     * that case. The buffered link is cleared after the attempt so rotation/recomposition never
     * re-routes (idempotency).
     */
    private fun routePendingNotificationDeepLink() {
        val controller = navController ?: return
        val link = pendingNotificationDeepLink ?: return
        pendingNotificationDeepLink = null
        // AND-108: reuse the notification feature's target routing (NotificationTargetResolver ->
        // navigateToNotificationTarget) so push taps land on the same destinations as in-app taps.
        runCatching {
            when (link) {
                is NotificationDeepLink.Message ->
                    controller.navigate(MessagingRoutes.thread(link.threadId, link.messageId)) {
                        // Force a fresh thread instance so it reloads history (picking up a message
                        // that arrived while backgrounded) and applies the new focus message, even if
                        // this conversation was already open underneath.
                        popUpTo(MessagingRoutes.THREAD) { inclusive = true }
                        launchSingleTop = true
                    }
                // ECOM-SELLER P1: an alert push carrying a deep-link resolves to a per-entity
                // destination via the SAME resolver the in-app Alerts row uses. A shop_item_sold
                // action_url (/seller/orders?sale={ship_group_id}) opens DIRECTLY to the sale detail
                // (SellerSalesDest) instead of the app home; any other alert falls back to the
                // notification target (alerts center).
                is NotificationDeepLink.Alert -> {
                    val saleId = saleIdFromActionUrl(link.actionUrl)
                    // D4: a buyer shipment alert (order_shipped/out_for_delivery/delivered) carries a
                    // ship_group in its action_url -> open the buyer order-tracking view directly.
                    val trackShipGroup = shipGroupFromActionUrl(link.actionUrl)
                    if (saleId != null) {
                        controller.navigate(SellerSalesDest.build(saleId)) { launchSingleTop = true }
                    } else if (trackShipGroup != null) {
                        controller.navigate(OrderTrackingDest.build(trackShipGroup)) { launchSingleTop = true }
                    } else {
                        controller.navigateToNotificationTarget(PushTapRouting.targetFor(link))
                    }
                }
                else ->
                    controller.navigateToNotificationTarget(PushTapRouting.targetFor(link))
            }
        }
    }
}
