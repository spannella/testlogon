package com.testlogon.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.health.HealthBannerHost
import com.testlogon.android.navigation.AppNavHost
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            TestLogonTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    Column(Modifier.fillMaxSize()) {
                        // AND-042: a single global health banner above all app content.
                        HealthBannerHost(modifier = Modifier.fillMaxWidth())
                        AppNavHost(modifier = Modifier.fillMaxSize())
                    }
                }
            }
        }
    }
}
