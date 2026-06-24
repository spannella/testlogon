package com.testlogon.android.feature.common

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImagePainter
import coil.compose.rememberAsyncImagePainter

/**
 * ID15 — shared circular avatar. Loads [photoUrl] via Coil (the app-wide ImageLoader resolves
 * server-relative "/..." urls against the API origin) when present and non-blank, and falls back to a
 * monogram of [name] only while loading, on error, or when no photo url is available.
 *
 * Used everywhere a person is represented (feed authors, conversation rows, the thread header, and the
 * Home greeting) so a real profile photo shows consistently instead of always-initials.
 */
@Composable
fun TlAvatar(
    name: String?,
    photoUrl: String?,
    modifier: Modifier = Modifier,
    size: Dp = 40.dp,
    containerColor: Color = MaterialTheme.colorScheme.primaryContainer,
    contentColor: Color = MaterialTheme.colorScheme.onPrimaryContainer,
    textStyle: TextStyle = MaterialTheme.typography.titleMedium,
) {
    val initials = remember(name) { avatarInitials(name) }
    val url = photoUrl?.takeIf { it.isNotBlank() }

    Box(
        modifier = modifier
            .size(size)
            .clip(CircleShape)
            .background(containerColor),
        contentAlignment = Alignment.Center,
    ) {
        // Initials sit underneath; the photo (once it loads) paints over them. While loading or on
        // error the initials remain visible, so there is never a blank circle.
        Text(text = initials, style = textStyle, color = contentColor)

        if (url != null) {
            val painter = rememberAsyncImagePainter(model = url)
            if (painter.state !is AsyncImagePainter.State.Error) {
                Image(
                    painter = painter,
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.size(size).clip(CircleShape),
                )
            }
        }
    }
}

/** First two letters of the best name token (two-word initials, else first two chars), upper-cased. */
fun avatarInitials(name: String?): String {
    val cleaned = name?.trim().orEmpty()
    if (cleaned.isEmpty()) return "?"
    val words = cleaned.split(Regex("\\s+")).filter { it.isNotBlank() }
    return when {
        words.size >= 2 -> (words[0].take(1) + words[1].take(1)).uppercase()
        else -> cleaned.filterNot { it.isWhitespace() }.take(2).uppercase().ifEmpty { "?" }
    }
}
