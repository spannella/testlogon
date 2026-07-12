package com.testlogon.android.testseam

import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner

/**
 * DEBUG variant of the test-seam facade. MainActivity (src/main) calls TestHooks.registryOwner(this)
 * and, if non-null, wraps the Compose root in
 *   CompositionLocalProvider(LocalActivityResultRegistryOwner provides owner) { ... }
 *
 * In debug this returns an owner whose registry is the intercepting TestPickRegistry, so every
 * rememberLauncherForActivityResult in the app routes through the seam. The release variant
 * (app/src/release) returns null, so release builds use the platform default owner unchanged.
 *
 * IMPORTANT: this is still INERT until the runtime gate (debug.testlogon.testhooks==1) AND an arm
 * are both present  the intercepting registry delegates to the real registry otherwise. So even a
 * debug build with this owner installed behaves identically to stock until explicitly enabled.
 */
object TestHooks {
    fun registryOwner(activity: ComponentActivity): ActivityResultRegistryOwner? {
        val registry: ActivityResultRegistry = TestPickRegistry(activity)
        return object : ActivityResultRegistryOwner {
            override val activityResultRegistry: ActivityResultRegistry = registry
        }
    }
}
