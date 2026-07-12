@file:Suppress("SetJavaScriptEnabled")

package com.testlogon.android.feature.vnc

import android.annotation.SuppressLint
import android.util.Log
import android.webkit.ConsoleMessage
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebView
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.viewinterop.AndroidView
import java.net.URLEncoder

/**
 * Live noVNC viewer hosted in a WebView. Loads the bundled noVNC 1.5.0 viewer
 * (assets/novnc/viewer.html) which attaches an RFB session to a <div> over the session's
 * WebSocket URL (with the connect token appended as ?token=, mirroring the web
 * RemoteDesktopPage.withConnectParams). Status transitions from the RFB lifecycle are relayed
 * back to Compose via the AndroidVnc JS bridge so the UI can show connected / unreachable.
 *
 * REAL, not stubbed: this is a genuine RFB client. Whether it renders pixels depends entirely on
 * the ws_url being reachable from the device (see the reachability gate in RemoteDesktopScreen).
 */
object VncViewerTestTags {
    const val WEBVIEW = "remotedesktop_webview"
}

/** Compose the full ws URL exactly as the web client does: append token as a query param. */
fun composeVncTargetUrl(wsUrl: String, connectParams: Map<String, String>): String {
    val token = connectParams["token"] ?: return wsUrl
    if (token.isBlank()) return wsUrl
    val sep = if (wsUrl.contains("?")) "&" else "?"
    return wsUrl + sep + "token=" + URLEncoder.encode(token, "UTF-8")
}

private class VncJsBridge(val onStatus: (String, String) -> Unit) {
    @JavascriptInterface
    fun onStatus(kind: String, message: String) {
        Log.i("VncWebView", "bridge kind=$kind msg=$message")
        onStatus.invoke(kind, message)
    }
}

@SuppressLint("SetJavaScriptEnabled")
@Composable
fun VncWebView(
    wsUrl: String,
    connectParams: Map<String, String>,
    onStatusChanged: (VncViewerStatus, String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val targetUrl = remember(wsUrl, connectParams) { composeVncTargetUrl(wsUrl, connectParams) }

    Box(modifier = modifier.fillMaxSize()) {
        AndroidView(
            modifier = Modifier.fillMaxSize().testTag(VncViewerTestTags.WEBVIEW),
            factory = { ctx ->
                WebView(ctx).apply {
                    // Force the WebView to fill the AndroidView box; without an explicit MATCH_PARENT
                    // height it wraps its (JS-only) content to 0px, so the page's 100vh resolves to 0
                    // and the noVNC canvas never gets a visible CSS size.
                    layoutParams = android.view.ViewGroup.LayoutParams(
                        android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                        android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                    )
                    settings.javaScriptEnabled = true
                    settings.domStorageEnabled = true
                    // noVNC uses ES-module imports across file:// — allow file->file access so the
                    // viewer.html's `import RFB from './core/rfb.js'` resolves.
                    settings.allowFileAccess = true
                    @Suppress("DEPRECATION")
                    settings.allowFileAccessFromFileURLs = true
                    @Suppress("DEPRECATION")
                    settings.allowUniversalAccessFromFileURLs = true
                    settings.mediaPlaybackRequiresUserGesture = false
                    settings.builtInZoomControls = true
                    settings.displayZoomControls = false
                    setBackgroundColor(0xFF0B0B0D.toInt())
                    webChromeClient = object : WebChromeClient() {
                        override fun onConsoleMessage(cm: ConsoleMessage): Boolean {
                            Log.i("VncWebView", "console: ${cm.message()} @${cm.sourceId()}:${cm.lineNumber()}")
                            return true
                        }
                    }
                    addJavascriptInterface(
                        VncJsBridge { kind, msg ->
                            post {
                                onStatusChanged(VncViewerStatus.fromKind(kind), msg)
                            }
                        },
                        "AndroidVnc",
                    )
                    val encoded = URLEncoder.encode(targetUrl, "UTF-8")
                    loadUrl("file:///android_asset/novnc/viewer.html?url=$encoded")
                }
            },
        )
    }

    DisposableEffect(Unit) {
        onDispose { /* WebView is torn down by AndroidView; no leak-prone singletons held. */ }
    }
}

enum class VncViewerStatus {
    Connecting, Connected, Disconnected, Error, Timeout, Unknown;

    companion object {
        fun fromKind(kind: String): VncViewerStatus = when (kind) {
            "connecting" -> Connecting
            "connected" -> Connected
            "disconnected" -> Disconnected
            "error" -> Error
            "timeout" -> Timeout
            else -> Unknown
        }
    }
}
