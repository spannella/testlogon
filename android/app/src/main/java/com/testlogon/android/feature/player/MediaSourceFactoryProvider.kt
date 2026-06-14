package com.testlogon.android.feature.player

import android.content.Context
import androidx.media3.common.MediaItem
import androidx.media3.common.MediaMetadata
import androidx.media3.common.util.UnstableApi
import androidx.media3.datasource.DataSource
import androidx.media3.datasource.DefaultDataSource
import androidx.media3.datasource.okhttp.OkHttpDataSource
import androidx.media3.exoplayer.hls.HlsMediaSource
import androidx.media3.exoplayer.source.DefaultMediaSourceFactory
import androidx.media3.exoplayer.source.MediaSource
import dagger.hilt.android.qualifiers.ApplicationContext
import okhttp3.OkHttpClient
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-167 — caller-facing media descriptor handed to the player. [type] AUTO resolves HLS vs
 * progressive from the URI; [headers] are per-source request headers attached only when the URI host
 * matches the configured API host (see [MediaSourceResolver.scopedHeaders]); [title] rides the
 * MediaMetadata. Pure data — no Media3 types — so it is safe in unit-tested code.
 */
data class MediaSourceSpec(
    val uri: String,
    val type: PlayerMediaType = PlayerMediaType.AUTO,
    val headers: Map<String, String> = emptyMap(),
    val title: String? = null,
)

/**
 * AND-167 — builds a Media3 [MediaSource] per [MediaSourceSpec], reusing the shared core-network
 * [OkHttpClient] (cookie jar + ~20s timeouts) via [OkHttpDataSource] instead of DefaultHttpDataSource,
 * so manifest/segment loads work against the flaky dev backend. HLS uses [HlsMediaSource] with
 * chunkless preparation (multi-variant ABR exposed up front); everything else uses the progressive
 * [DefaultMediaSourceFactory] path (preserves AND-131/AND-166 MP4 behavior).
 *
 * Hilt-provided cheap [Singleton]: it holds only the app [Context] + the shared client and builds the
 * base data-source factory lazily; it NEVER constructs an ExoPlayer. The actual player is created
 * per-screen by [VideoPlayerFactory]. All routing/auth DECISIONS live in the pure
 * [MediaSourceResolver]; this class only wires those decisions to Media3.
 */
@OptIn(UnstableApi::class)
@Singleton
class MediaSourceFactoryProvider @Inject constructor(
    @ApplicationContext private val context: Context,
    private val okHttpClient: OkHttpClient,
) {
    /** The configured API host; app-auth headers are scoped to it. null when not yet known. */
    var apiHost: String? = null

    /** Wraps the OkHttp data source with [DefaultDataSource] so asset:///, file:// etc. also work. */
    private fun baseFactory(headers: Map<String, String>): DataSource.Factory {
        val http = OkHttpDataSource.Factory(okHttpClient)
        if (headers.isNotEmpty()) http.setDefaultRequestProperties(headers)
        return DefaultDataSource.Factory(context, http)
    }

    /** Builds the [MediaSource] for [spec]; HLS vs progressive routed by [MediaSourceResolver]. */
    fun create(spec: MediaSourceSpec): MediaSource {
        val scoped = MediaSourceResolver.scopedHeaders(spec.uri, apiHost, spec.headers)
        val factory = baseFactory(scoped)
        val item = buildMediaItem(spec)
        return when (MediaSourceResolver.resolveType(spec.uri, spec.type)) {
            PlayerMediaType.HLS ->
                HlsMediaSource.Factory(factory)
                    .setAllowChunklessPreparation(true)
                    .createMediaSource(item)
            else ->
                DefaultMediaSourceFactory(factory).createMediaSource(item)
        }
    }

    private fun buildMediaItem(spec: MediaSourceSpec): MediaItem {
        val builder = MediaItem.Builder().setUri(spec.uri)
        spec.title?.let {
            builder.setMediaMetadata(MediaMetadata.Builder().setTitle(it).build())
        }
        if (MediaSourceResolver.resolveType(spec.uri, spec.type) == PlayerMediaType.HLS) {
            // Apply an app-default live target offset; ExoPlayer prefers the manifest hold-back when
            // present and ignores this for VOD timelines.
            builder.setLiveConfiguration(
                MediaItem.LiveConfiguration.Builder()
                    .setTargetOffsetMs(DEFAULT_LIVE_TARGET_OFFSET_MS)
                    .build(),
            )
        }
        return builder.build()
    }
}
