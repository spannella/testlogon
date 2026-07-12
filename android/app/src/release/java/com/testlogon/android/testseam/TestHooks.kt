package com.testlogon.android.testseam

import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultRegistryOwner

/**
 * RELEASE no-op shim for the test-seam facade. Same signature as the debug TestHooks so
 * MainActivity (src/main) compiles in BOTH variants, but here it ALWAYS returns null  there is
 * NO intercepting registry, no content provider, no broadcast receiver, no sample media in release
 * builds. MainActivity therefore installs no custom LocalActivityResultRegistryOwner in release and
 * all pickers use the genuine platform owner.
 */
object TestHooks {
    fun registryOwner(activity: ComponentActivity): ActivityResultRegistryOwner? = null
}
