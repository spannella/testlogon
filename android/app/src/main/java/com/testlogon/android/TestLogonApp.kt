package com.testlogon.android

import android.app.Application
import android.util.Log
import dagger.hilt.android.HiltAndroidApp

/**
 * Process-level entry point.
 *
 * [HiltAndroidApp] generates the SingletonComponent and the application-scoped graph that all
 * core-* and feature-* modules contribute to. Networking singletons, DataStore, and the cookie
 * jar are installed in SingletonComponent in their own tickets (AND-009+).
 */
@HiltAndroidApp
class TestLogonApp : Application() {

    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            Log.d(TAG, "TestLogonApp.onCreate — process started")
        }
    }

    companion object {
        private const val TAG = "TestLogonApp"
    }
}
