@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.catalog

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState

/**
 * AND-205 — minimal placeholder for the product detail route (`shop/{categoryId}/{itemId}`). It exists
 * so the browse -> detail navigation contract is reachable end to end; AND-206 replaces it with the
 * real screen (item derived from the category-items list — there is no single-item GET).
 */
@Composable
fun ProductDetailPlaceholderRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag("product_detail_placeholder"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.catalog_item_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        EmptyState(
            title = stringResource(R.string.catalog_item_coming_soon),
            modifier = Modifier.fillMaxSize().padding(padding),
        )
    }
}
