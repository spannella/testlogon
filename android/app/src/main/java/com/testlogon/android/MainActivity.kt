package com.testlogon.android

import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
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
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import com.testlogon.android.core.network.AppThemeMode
import com.testlogon.android.core.network.ThemePreferencesStore
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.health.HealthBannerHost
import com.testlogon.android.navigation.AppNavHost
import com.testlogon.android.navigation.deeplink.DeepLinkParser
import com.testlogon.android.navigation.deeplink.NotificationDeepLink
import com.testlogon.android.navigation.deeplink.PushTapRouting
import com.testlogon.android.navigation.navigateToNotificationTarget
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    // Hoisted so onNewIntent can deliver warm/foreground deep links (AND-061, singleTask launchMode).
    // NavHostController so AND-108 push-tap routing can reuse the notification target extension.
    private var navController: NavHostController? = null

    // AND-108: a notification-tap deep link parsed from the launch/new intent, buffered until the
    // NavController is ready (cold start) and then routed exactly once. Survives the onCreate/first-
    // composition race; idempotent because the source Intent is marked consumed when parsed.
    private var pendingNotificationDeepLink: NotificationDeepLink? = null

    // AND-081: the device-local appearance preference drives TestLogonTheme at the app root.
    @Inject
    lateinit var themePreferencesStore: ThemePreferencesStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // AND-108: parse a cold-start notification deep link before the NavHost composes; route it
        // once the NavController becomes available (onNavControllerReady below).
        handleNotificationDeepLink(intent)
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
                Surface(modifier = Modifier.fillMaxSize()) {
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
        if (intent.data != null) {
            navController?.handleDeepLink(intent)
        }
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
            controller.navigateToNotificationTarget(PushTapRouting.targetFor(link))
        }
    }
}
