package com.testlogon.android.data.exchange

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.testlogon.android.core.network.SettingsStore
import com.testlogon.android.data.messaging.realtime.SseLineParser
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import okhttp3.Request
import java.io.IOException
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Markets (VIEW-ONLY) LIVE market-data stream over the SHARED core-network [OkHttpClient].
 *
 * Mirrors [com.testlogon.android.data.messaging.realtime.SseMessagingEventStream]: a raw streaming
 * `GET md/stream/{symbolId}?interval=1` whose response is `text/event-stream`. Cookies + CSRF ride
 * the shared OkHttp interceptor chain automatically (nothing extra to add). We stream the response
 * body and parse SSE frames with the reused [SseLineParser]; no okhttp-sse dependency is added.
 *
 * The server emits `event: md` frames whose `data:` JSON is [MdFrameDto]
 * `{symbol:Int, book:<OrderBookDto>, bars:<CandlesResponseDto>}` (NO trades). The stream ends after
 * ~5 min, so the cold [callbackFlow] keeps re-opening (short backoff) until the collector cancels.
 */
@Singleton
class ExchangeStream @Inject constructor(
    private val baseClient: OkHttpClient,
    private val settingsStore: SettingsStore,
    moshi: Moshi,
) {

    private val frameAdapter = moshi.adapter(MdFrameDto::class.java)

    /** A dedicated client view with no read timeout so the long-lived stream is not killed early. */
    private val streamClient: OkHttpClient by lazy {
        val builder = baseClient.newBuilder()
            .readTimeout(0, TimeUnit.MILLISECONDS)
            // Own pool: otherwise okhttp reuses baseClients pooled HTTP/2 connection and the
            // .protocols(HTTP_1_1) below never takes effect (the cpp edge resets long-lived h2).
            .connectionPool(ConnectionPool())
            .protocols(listOf(okhttp3.Protocol.HTTP_1_1))
        // CRITICAL: the shared baseClient carries a DEBUG-only HttpLoggingInterceptor at Level.BODY.
        // A BODY-level app interceptor buffers the ENTIRE response body before returning it — which
        // for an infinite text/event-stream never completes, so it blocks here forever and no frame
        // ever reaches the collector (the stream shows 200 OK but hangs). Strip it (and any body-
        // buffering okhttp-logging interceptor) from this streaming clients chain.
        builder.interceptors().removeAll { it is HttpLoggingInterceptor }
        builder.build()
    }

    /**
     * Cold flow of live [MdFrame]s for [symbolId]. Re-opens the stream on end/IO error after a short
     * backoff; cancelling the collector cancels the call and stops reconnecting.
     */
    fun marketData(symbolId: Int, intervalSec: Int = 60): Flow<MdEvent> = callbackFlow {
        var running = true
        val url = settingsStore.baseUrl.trimEnd('/') + "/" + STREAM_PATH_PREFIX + symbolId +
            "?interval=" + intervalSec

        val worker = Thread {
            while (running) {
                val lineParser = SseLineParser()
                val request = Request.Builder()
                    .url(url)
                    .header("Accept", "text/event-stream")
                    .header("Accept-Encoding", "identity")
                    .header("Cache-Control", "no-cache")
                    .build()
                val call = streamClient.newCall(request)
                try {
                    call.execute().use { response ->
                        if (!response.isSuccessful) error("stream HTTP ${response.code}")
                        val body = response.body ?: error("empty stream body")
                        lineParser.readFrames(body.source()) { frame ->
                            if (!running) return@readFrames false
                            if (frame.event == EVENT_MD) {
                                parseFrame(frame.data)?.let { trySend(MdEvent.Frame(it)) }
                            }
                            true
                        }
                    }
                } catch (_: IOException) {
                    // stream ended / network blip — reconnect after backoff below.
                } catch (_: IllegalStateException) {
                    // non-2xx / empty body — reconnect after backoff below.
                } finally {
                    call.cancel()
                }
                if (!running) break
                // The stream ended (server ~300s cap, network blip, or non-2xx). Tell the collector
                // so the UI can show "reconnecting" and lean on polling until the next frame lands.
                trySend(MdEvent.Disconnected)
                try {
                    Thread.sleep(RECONNECT_BACKOFF_MS)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }
        worker.isDaemon = true
        worker.start()

        awaitClose {
            running = false
            worker.interrupt()
        }
    }

    /**
     * Decode one SSE `data:` payload into an [MdFrame]. Package-visible (an [internal] test seam) so
     * the raw-JSON -> domain-frame mapping can be unit-tested: a well-formed frame decodes; a frame
     * with no order book, or malformed/non-JSON data, yields null (never throws).
     */
    internal fun parseFrame(data: String): MdFrame? {
        val dto = runCatching { frameAdapter.fromJson(data) }.getOrNull() ?: return null
        val book = dto.book?.toDomain() ?: return null
        val candle = dto.bars?.bars?.lastOrNull()?.toDomain()
        return MdFrame(orderBook = book, candle = candle)
    }

    private companion object {
        const val STREAM_PATH_PREFIX = "md/stream/"
        // interval is passed per-call so the live bars align with the selected timeframe grid
        // (same ts_start_ns), and mergeCandle replaces/appends bars correctly.
        const val EVENT_MD = "md"
        const val RECONNECT_BACKOFF_MS = 1_500L
    }
}

/** One decoded live market-data frame: the current order book and (optionally) the latest candle. */
data class MdFrame(
    val orderBook: OrderBook,
    val candle: Candle?,
)

/**
 * A live-stream event. [Frame] carries fresh book+candle data (stream is up); [Disconnected] is
 * emitted whenever the underlying stream ends before the next reconnect attempt, so the collector
 * can flip to a "reconnecting" indicator and keep the REST poll as the fallback.
 */
sealed interface MdEvent {
    data class Frame(val frame: MdFrame) : MdEvent
    data object Disconnected : MdEvent
}

/** Wire shape of the SSE `event: md` `data:` payload. Reuses [OrderBookDto] + [CandlesResponseDto]. */
@JsonClass(generateAdapter = true)
data class MdFrameDto(
    val symbol: Int = 0,
    @Json(name = "book") val book: OrderBookDto? = null,
    @Json(name = "bars") val bars: CandlesResponseDto? = null,
)
