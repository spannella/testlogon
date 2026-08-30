@file:OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)

package com.testlogon.android.feature.messaging.thread

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Directions
import androidx.compose.material.icons.filled.Place
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import coil.compose.SubcomposeAsyncImage
import com.testlogon.android.feature.messaging.LocationCardModel

object LocationCardTestTags {
    const val CARD = "thread_location_card"
    const val THUMB = "thread_location_card_thumb"
    const val THUMB_FALLBACK = "thread_location_card_thumb_fallback"
    const val OPEN = "thread_location_card_open"
    const val DIRECTIONS = "thread_location_card_directions"
}

@Composable
fun LocationCard(
    card: LocationCardModel.LocationCard,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val coords = LocationCardModel.formatCoords(card.lat, card.lng)
    val primary = card.label?.takeIf { it.isNotBlank() }
        ?: card.placeName?.takeIf { it.isNotBlank() }
        ?: "Shared location"
    val secondary = when {
        card.label != null && card.placeName != null -> card.placeName
        else -> coords
    }
    val cd = "Location $primary, $secondary"

    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = modifier
            .widthIn(max = 260.dp)
            .testTag(LocationCardTestTags.CARD)
            .semantics { contentDescription = cd },
    ) {
        Column {
            SubcomposeAsyncImage(
                model = LocationCardModel.staticMapThumbUrl(card.lat, card.lng),
                contentDescription = null,
                contentScale = ContentScale.Crop,
                loading = { MapThumbPlaceholder() },
                error = { MapThumbPlaceholder() },
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(2f)
                    .testTag(LocationCardTestTags.THUMB),
            )
            Column(Modifier.padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Filled.Place,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp),
                    )
                    Text(
                        primary,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.padding(start = 6.dp),
                    )
                }
                Text(
                    secondary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 2.dp, start = 24.dp),
                )
                Row(
                    Modifier.fillMaxWidth().padding(top = 10.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedButton(
                        onClick = { openMaps(context, card) },
                        modifier = Modifier.weight(1f).testTag(LocationCardTestTags.OPEN),
                    ) { Text("Open in Maps") }
                    OutlinedButton(
                        onClick = {
                            openExternal(context, LocationCardModel.directionsUrl(card.lat, card.lng), fallback = null)
                        },
                        modifier = Modifier.testTag(LocationCardTestTags.DIRECTIONS),
                    ) {
                        Icon(Icons.Filled.Directions, contentDescription = "Directions", modifier = Modifier.size(18.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun MapThumbPlaceholder() {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.secondaryContainer)
            .testTag(LocationCardTestTags.THUMB_FALLBACK),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            Icons.Filled.Place,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(40.dp),
        )
    }
}

private fun openMaps(context: android.content.Context, card: LocationCardModel.LocationCard) {
    val geo = LocationCardModel.geoUri(card.lat, card.lng)
    val web = LocationCardModel.mapsOpenUrl(card.lat, card.lng, card.label)
    openExternal(context, geo, fallback = web)
}

private fun openExternal(context: android.content.Context, url: String, fallback: String?) {
    val ok = runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }.isSuccess
    if (!ok && fallback != null) {
        runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(fallback))) }
    }
}
