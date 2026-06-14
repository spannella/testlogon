package com.testlogon.android.core.ui.scaffold

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * App-level Material 3 [Scaffold] wrapper exposing slots for a top bar, snackbar host, an optional
 * banner region (above content, e.g. for [com.testlogon.android.core.ui.state.OfflineBanner]), and
 * a content lambda. The single scaffold entry point for feature screens.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TlScaffold(
    modifier: Modifier = Modifier,
    topBar: @Composable () -> Unit = {},
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
    banner: @Composable () -> Unit = {},
    floatingActionButton: @Composable () -> Unit = {},
    content: @Composable (PaddingValues) -> Unit,
) {
    Scaffold(
        modifier = modifier,
        topBar = topBar,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        floatingActionButton = floatingActionButton,
    ) { inner ->
        Column(Modifier.padding(inner)) {
            banner()
            content(PaddingValues(0.dp))
        }
    }
}
