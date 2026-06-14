@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.seo.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.BrokenImage
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.SubcomposeAsyncImage
import coil.request.ImageRequest
import androidx.compose.ui.platform.LocalContext
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.seo.data.SeoMetadata
import kotlinx.coroutines.launch

/** AND-400 - stable testTags for the read-only SEO inspector. */
object SeoTestTags {
    const val SCREEN = "seo_screen"
    const val LIST = "seo_list"
    const val EMPTY = "seo_empty"
    const val ERROR_RETRY = "seo_error_retry"
    const val IMAGE = "seo_image"
    const val JSON_LD = "seo_json_ld"

    /** Per-row copy button tag (suffix is the row key, e.g. seo_copy_canonical_url). */
    fun copy(key: String): String = "seo_copy_$key"

    /** Per-section header tag (suffix is the section key, e.g. seo_section_primary). */
    fun section(key: String): String = "seo_section_$key"
}

/** AND-400 - a single render-ready metadata row (a label, its value, and a stable copy key). */
private data class SeoRow(val key: String, val label: String, val value: String)

/**
 * AND-400 - route-level SEO inspector entry. The VM reads resourceType / id / secondaryId from
 * SavedStateHandle (the nav args). READ-ONLY diagnostic surface.
 */
@Composable
fun SeoRoute(
    onBack: () -> Unit,
    viewModel: SeoViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    SeoScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::load,
        onRetry = viewModel::load,
    )
}

/** AND-400 - the stateless SEO inspector. */
@Composable
fun SeoScreen(
    state: SeoUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()
    val copiedMessage = stringResource(R.string.seo_copied)

    val onCopy: (String) -> Unit = { value ->
        clipboard.setText(AnnotatedString(value))
        scope.launch { snackbarHostState.showSnackbar(copiedMessage) }
    }

    Scaffold(
        modifier = modifier.testTag(SeoTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.seo_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.seo_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                is SeoUiState.Loading -> LoadingState()
                is SeoUiState.Empty -> EmptyState(
                    title = stringResource(R.string.seo_empty_title),
                    body = stringResource(R.string.seo_empty_body),
                    modifier = Modifier.testTag(SeoTestTags.EMPTY),
                )
                is SeoUiState.Error -> if (state.retryable) {
                    ErrorState(
                        message = state.message,
                        onRetry = onRetry,
                        modifier = Modifier.testTag(SeoTestTags.ERROR_RETRY),
                    )
                } else {
                    EmptyState(
                        title = stringResource(R.string.seo_error_validation_title),
                        body = state.message,
                        modifier = Modifier.testTag(SeoTestTags.ERROR_RETRY),
                    )
                }
                is SeoUiState.Content -> SeoContent(
                    metadata = state.metadata,
                    onRefresh = onRefresh,
                    onCopy = onCopy,
                )
            }
        }
    }
}

@Composable
private fun SeoContent(
    metadata: SeoMetadata,
    onRefresh: () -> Unit,
    onCopy: (String) -> Unit,
) {
    val primaryRows = primaryRows(metadata)
    val ogRows = tagRows(metadata.og)
    val twitterRows = tagRows(metadata.twitter)

    PullToRefreshBox(
        isRefreshing = false,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize().testTag(SeoTestTags.LIST),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item {
                Text(
                    text = stringResource(R.string.seo_read_only_caption),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (primaryRows.isNotEmpty()) {
                item {
                    SeoSection(
                        key = "primary",
                        title = stringResource(R.string.seo_section_primary),
                        rows = primaryRows,
                        onCopy = onCopy,
                    )
                }
            }
            metadata.image?.let { imageUrl ->
                item { OgImageCard(imageUrl = imageUrl, onCopy = onCopy) }
            }
            if (ogRows.isNotEmpty()) {
                item {
                    SeoSection(
                        key = "og",
                        title = stringResource(R.string.seo_section_og),
                        rows = ogRows,
                        onCopy = onCopy,
                    )
                }
            }
            if (twitterRows.isNotEmpty()) {
                item {
                    SeoSection(
                        key = "twitter",
                        title = stringResource(R.string.seo_section_twitter),
                        rows = twitterRows,
                        onCopy = onCopy,
                    )
                }
            }
            metadata.jsonLd?.let { json ->
                item { JsonLdBlock(json = json, onCopy = onCopy) }
            }
        }
    }
}

/** Derives the ordered Primary section rows, dropping null/blank values. */
@Composable
private fun primaryRows(metadata: SeoMetadata): List<SeoRow> = buildList {
    addRow("title", stringResource(R.string.seo_label_title), metadata.title)
    addRow("description", stringResource(R.string.seo_label_description), metadata.description)
    addRow("canonical_url", stringResource(R.string.seo_label_canonical), metadata.canonicalUrl)
    addRow("site_name", stringResource(R.string.seo_label_site_name), metadata.siteName)
    addRow("locale", stringResource(R.string.seo_label_locale), metadata.locale)
}

/** Maps a flat prefixed-key tag map to ordered rows (the wire key doubles as label + copy key). */
private fun tagRows(tags: Map<String, String>): List<SeoRow> =
    tags.entries.map { (key, value) -> SeoRow(key = key, label = key, value = value) }

private fun MutableList<SeoRow>.addRow(key: String, label: String, value: String?) {
    if (!value.isNullOrBlank()) add(SeoRow(key = key, label = label, value = value))
}

@Composable
private fun SeoSection(
    key: String,
    title: String,
    rows: List<SeoRow>,
    onCopy: (String) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(SeoTestTags.section(key))) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(text = title, style = MaterialTheme.typography.titleMedium)
            rows.forEach { row ->
                MetaRow(row = row, onCopy = onCopy)
            }
        }
    }
}

@Composable
private fun MetaRow(row: SeoRow, onCopy: (String) -> Unit) {
    val copyCd = stringResource(R.string.seo_copy_label, row.label)
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = row.label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(text = row.value, style = MaterialTheme.typography.bodyMedium)
        }
        IconButton(
            onClick = { onCopy(row.value) },
            modifier = Modifier
                .size(48.dp)
                .testTag(SeoTestTags.copy(row.key)),
        ) {
            Icon(Icons.Outlined.ContentCopy, contentDescription = copyCd)
        }
    }
}

@Composable
private fun OgImageCard(imageUrl: String, onCopy: (String) -> Unit) {
    val context = LocalContext.current
    val imageCd = stringResource(R.string.seo_image_description)
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.seo_section_image),
                style = MaterialTheme.typography.titleMedium,
            )
            SubcomposeAsyncImage(
                model = ImageRequest.Builder(context).data(imageUrl).crossfade(true).build(),
                contentDescription = imageCd,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(180.dp)
                    .testTag(SeoTestTags.IMAGE),
                loading = {
                    Box(contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                },
                error = {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            Icons.Outlined.BrokenImage,
                            contentDescription = stringResource(R.string.seo_image_failed),
                            modifier = Modifier.size(48.dp),
                        )
                    }
                },
            )
            MetaRow(
                row = SeoRow(
                    key = "og_image",
                    label = stringResource(R.string.seo_label_image_url),
                    value = imageUrl,
                ),
                onCopy = onCopy,
            )
        }
    }
}

@Composable
private fun JsonLdBlock(json: String, onCopy: (String) -> Unit) {
    val regionCd = stringResource(R.string.seo_json_ld_description)
    val copyCd = stringResource(R.string.seo_copy_label, stringResource(R.string.seo_section_json_ld))
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = stringResource(R.string.seo_section_json_ld),
                    style = MaterialTheme.typography.titleMedium,
                )
                IconButton(
                    onClick = { onCopy(json) },
                    modifier = Modifier.size(48.dp).testTag(SeoTestTags.copy("json_ld")),
                ) {
                    Icon(Icons.Outlined.ContentCopy, contentDescription = copyCd)
                }
            }
            HorizontalDivider()
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(SeoTestTags.JSON_LD),
            ) {
                Text(
                    text = json,
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    modifier = Modifier
                        .padding(12.dp)
                        .horizontalScroll(rememberScrollState())
                        .semantics { contentDescription = regionCd },
                )
            }
        }
    }
}
