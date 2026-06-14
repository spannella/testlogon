package com.testlogon.android.notifications

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-107 — reads the POST_NOTIFICATIONS runtime-permission state.
 *
 * The permission only exists on Android 13+ (API 33); below that, notifications post without a
 * runtime grant, so [isGranted] is unconditionally true on SDK < 33. All 33+ permission calls are
 * guarded by [Build.VERSION.SDK_INT]. The actual request UX (rationale dialog + system prompt) is a
 * UI concern triggered post-auth; this class only exposes the read so the presenter can drop
 * notifications gracefully when ungranted (FR-7).
 */
@Singleton
class NotificationPermissionState @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    fun isGranted(): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
}
