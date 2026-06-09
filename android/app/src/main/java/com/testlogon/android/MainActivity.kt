package com.testlogon.android

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.navigation.NavController
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.health.HealthBannerHost
import com.testlogon.android.navigation.AppNavHost
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    // Hoisted so onNewIntent can deliver warm/foreground deep links (AND-061, singleTask launchMode).
    private var navController: NavController? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            TestLogonTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    Column(Modifier.fillMaxSize()) {
                        // AND-042: a single global health banner above all app content.
                        HealthBannerHost(modifier = Modifier.fillMaxWidth())
                        AppNavHost(
                            modifier = Modifier.fillMaxSize(),
                            // The NavHost handles the cold-start launch intent automatically; we keep a
                            // reference so onNewIntent can forward warm/foreground magic-link taps.
                            onNavControllerReady = { navController = it },
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
        if (intent.data != null) {
            navController?.handleDeepLink(intent)
        }
    }
}
