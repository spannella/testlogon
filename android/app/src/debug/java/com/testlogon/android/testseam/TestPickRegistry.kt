package com.testlogon.android.testseam

import android.app.Activity
import android.net.Uri
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.contract.ActivityResultContract
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.app.ActivityOptionsCompat
import java.util.concurrent.atomic.AtomicReference

/**
 * DEBUG-ONLY intercepting ActivityResultRegistry (app/src/debug).
 *
 * rememberLauncherForActivityResult reads LocalActivityResultRegistryOwner; MainActivity provides
 * an owner backed by THIS registry in debug (see TestHooks). Therefore ALL media-pick call sites
 * (PickVisualMedia / GetContent / OpenDocument / PickMultipleVisualMedia / OpenMultipleDocuments /
 * TakePicture) route their onLaunch through here with ZERO call-site edits.
 *
 * onLaunch behaviour:
 *  - If the seam is DISARMED or the gate is OFF -> delegate to the activitys REAL registry so the
 *    genuine system picker shows (seam totally inert).
 *  - If ARMED for the launched contracts category and the gate is ON -> synthesize a result from the
 *    bundled TestMediaProvider and dispatchResult() immediately, with no system UI.
 *
 * Arm state is one-shot per launch: an ARM is consumed by the next matching onLaunch.
 */
class TestPickRegistry(private val activity: ComponentActivity) : ActivityResultRegistry() {

    private val authority: String get() = "${activity.packageName}.testmedia"

    override fun <I, O> onLaunch(
        requestCode: Int,
        contract: ActivityResultContract<I, O>,
        input: I,
        options: ActivityOptionsCompat?,
    ) {
        val armed = TestSeamGate.enabled() && ArmState.peek() != null
        if (armed) {
            val handled = trySynthesize(requestCode, contract, input)
            if (handled) return
        }
        delegateToReal(requestCode, contract, input, options)
    }

    @Suppress("UNCHECKED_CAST")
    private fun <I, O> trySynthesize(
        requestCode: Int,
        contract: ActivityResultContract<I, O>,
        input: I,
    ): Boolean {
        val arm = ArmState.peek() ?: return false

        // Single-Uri pickers.
        val isSingleUri = contract is ActivityResultContracts.PickVisualMedia ||
            contract is ActivityResultContracts.GetContent ||
            contract is ActivityResultContracts.OpenDocument
        // Multi-Uri pickers.
        val isMultiUri = contract is ActivityResultContracts.PickMultipleVisualMedia ||
            contract is ActivityResultContracts.OpenMultipleDocuments
        // Camera capture writes to a caller-supplied target Uri and returns Boolean.
        val isTakePicture = contract is ActivityResultContracts.TakePicture

        return when {
            isTakePicture -> {
                val target = input as? Uri
                val ok = if (target != null) writeSampleImageInto(target) else false
                ArmState.consume()
                (this as ActivityResultRegistry).dispatchResult(requestCode, ok as O)
                Log.i(TAG, "synthesized TakePicture -> $ok into $target")
                true
            }
            isMultiUri -> {
                val uris = arm.uris(authority)
                ArmState.consume()
                (this as ActivityResultRegistry).dispatchResult(requestCode, uris as O)
                Log.i(TAG, "synthesized multi-uri -> $uris")
                true
            }
            isSingleUri -> {
                val uri = arm.uris(authority).firstOrNull()
                ArmState.consume()
                (this as ActivityResultRegistry).dispatchResult(requestCode, uri as O)
                Log.i(TAG, "synthesized single-uri -> $uri")
                true
            }
            else -> {
                // Unknown contract category (e.g. RequestPermission): do not intercept.
                false
            }
        }
    }

    /** Copy the bundled sample image bytes into the cameras target output Uri. */
    private fun writeSampleImageInto(target: Uri): Boolean = try {
        val src = TestMediaProvider.uriFor(authority, "sample.jpg")
        activity.contentResolver.openInputStream(src)!!.use { input ->
            activity.contentResolver.openOutputStream(target)!!.use { out ->
                input.copyTo(out)
            }
        }
        true
    } catch (t: Throwable) {
        Log.w(TAG, "writeSampleImageInto failed", t)
        false
    }

    /**
     * Delegate to the activitys REAL registry so the genuine system picker runs. We register a
     * transient launcher on activity.activityResultRegistry whose callback routes the real result
     * back through THIS registrys dispatchResult(requestCode, result), then launch it.
     */
    @Suppress("UNCHECKED_CAST")
    private fun <I, O> delegateToReal(
        requestCode: Int,
        contract: ActivityResultContract<I, O>,
        input: I,
        options: ActivityOptionsCompat?,
    ) {
        val real = activity.activityResultRegistry
        val key = "testseam-delegate-" + requestCode + "-" + (delegateCounter.incrementAndGet())
        val pending = AtomicReference<androidx.activity.result.ActivityResultLauncher<I>?>(null)
        val launcher = real.register(key, contract) { result: O ->
            (this as ActivityResultRegistry).dispatchResult(requestCode, result as O)
            pending.getAndSet(null)?.unregister()
        }
        pending.set(launcher)
        launcher.launch(input, options)
    }

    companion object {
        private const val TAG = "TestPickRegistry"
        private val delegateCounter = java.util.concurrent.atomic.AtomicInteger(0)
    }
}

/** What kind of media to synthesize for the next pick. */
enum class PickKind { IMAGE, VIDEO, PDF, PNG, MULTI_IMAGE, MULTI_AV, CAMERA }

/** A single pending arm: the kind + an optional count for multi pickers. */
data class Arm(val kind: PickKind, val count: Int = 2) {
    fun uris(authority: String): List<Uri> = when (kind) {
        PickKind.IMAGE -> listOf(TestMediaProvider.uriFor(authority, "sample.jpg"))
        PickKind.PNG -> listOf(TestMediaProvider.uriFor(authority, "sample.png"))
        PickKind.VIDEO -> listOf(TestMediaProvider.uriFor(authority, "sample.mp4"))
        PickKind.PDF -> listOf(TestMediaProvider.uriFor(authority, "sample.pdf"))
        PickKind.CAMERA -> listOf(TestMediaProvider.uriFor(authority, "sample.jpg"))
        PickKind.MULTI_IMAGE -> {
            val names = listOf("sample.jpg", "sample.png")
            (0 until count).map { i ->
                TestMediaProvider.uriFor(authority, names[i % names.size])
            }
        }
        PickKind.MULTI_AV -> listOf(
            TestMediaProvider.uriFor(authority, "sample.jpg"),
            TestMediaProvider.uriFor(authority, "sample.mp4"),
        )

    }
}

/** Process-global one-shot arm slot, set by the debug broadcast receiver, consumed on next pick. */
object ArmState {
    @Volatile private var pending: Arm? = null

    fun arm(arm: Arm) { pending = arm }
    fun peek(): Arm? = pending
    fun consume(): Arm? { val a = pending; pending = null; return a }
    fun clear() { pending = null }
}
