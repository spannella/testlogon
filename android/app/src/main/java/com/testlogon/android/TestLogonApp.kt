package com.testlogon.android

import android.app.Application
import android.os.Build
import android.util.Log
import coil.ImageLoader
import coil.ImageLoaderFactory
import coil.decode.GifDecoder
import coil.decode.ImageDecoderDecoder
import com.google.firebase.FirebaseApp
import com.testlogon.android.data.push.FcmTokenRegistrar
import com.testlogon.android.notifications.NotificationChannelInitializer
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject

/**
 * Process-level entry point.
 *
 * [HiltAndroidApp] generates the SingletonComponent and the application-scoped graph that all
 * core-* and feature-* modules contribute to.
 *
 * AND-105/106/107: push bootstrap on cold start —
 *  - Gate Firebase init: we do NOT apply the com.google.gms.google-services Gradle plugin (no
 *    google-services.json is committed; applying it fails the build). Without that config Firebase
 *    cannot auto-initialize, so [FirebaseApp.getApps] is empty. We check it and skip push wiring
 *    rather than crash. Once a google-services.json (+ the gms plugin) is added, init succeeds and
 *    the push path activates with no further code change. The init is wrapped in try/catch as a
 *    second belt-and-braces guard.
 *  - Notification channels are created regardless (they are local and harmless), so they exist the
 *    moment push is configured.
 *  - The token registrar's auth-edge collector is started only when Firebase is available.
 */
@HiltAndroidApp
class TestLogonApp : Application(), ImageLoaderFactory {

    @Inject lateinit var channelInitializer: NotificationChannelInitializer

    @Inject lateinit var tokenRegistrar: FcmTokenRegistrar

    /** AND-145 — presence heartbeat + SSE presence collector wiring. */
    @Inject
    lateinit var presenceBootstrap: com.testlogon.android.data.messaging.presence.PresenceLifecycleBootstrap

    /**
     * AND-135 — the app-wide Coil [ImageLoader] with the animated-image decoder registered so GIF
     * messages and animated-WebP custom emoji animate. Coil picks this up via [ImageLoaderFactory]
     * (no per-call decoder wiring needed). `ImageDecoderDecoder` covers API 28+, `GifDecoder` the
     * minSdk 24-27 range.
     */
    override fun newImageLoader(): ImageLoader = ImageLoader.Builder(this)
        .components {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                add(ImageDecoderDecoder.Factory())
            } else {
                add(GifDecoder.Factory())
            }
        }
        .build()

    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            Log.d(TAG, "TestLogonApp.onCreate — process started")
        }

        // AND-107: channels are local; create them up front so push display works as soon as
        // Firebase is configured.
        runCatching { channelInitializer.ensureChannels() }

        // AND-145: start the foreground-bound presence heartbeat + SSE presence collector.
        runCatching { presenceBootstrap.start() }

        if (isFirebaseAvailable()) {
            // AND-106/109: start the auth-edge collector that registers the FCM token after login.
            runCatching { tokenRegistrar.start() }
            if (BuildConfig.DEBUG) Log.d(TAG, "fcm_init_ok — Firebase configured, push enabled")
        } else if (BuildConfig.DEBUG) {
            Log.d(
                TAG,
                "Firebase NOT configured (no google-services.json) — push runtime disabled; " +
                    "code compiles and channels exist. Add google-services.json + the gms plugin " +
                    "to receive pushes.",
            )
        }
    }

    /** True only when Firebase actually initialized (requires a committed google-services.json). */
    private fun isFirebaseAvailable(): Boolean = try {
        FirebaseApp.getApps(this).isNotEmpty()
    } catch (t: Throwable) {
        if (BuildConfig.DEBUG) Log.d(TAG, "FirebaseApp check failed: ${t.javaClass.simpleName}")
        false
    }

    companion object {
        private const val TAG = "TestLogonApp"
    }
}
