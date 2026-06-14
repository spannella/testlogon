package com.testlogon.android.navigation.applink

import android.content.Context
import com.testlogon.android.R
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-396 — Hilt wiring for the App Link parser / router.
 *
 * The verified-host set is sourced from the per-flavor `@string/applink_host` resource (the same
 * resource the manifest `intent-filter` host references) so the parser allowlist and the verified
 * intent-filter host stay in lockstep, and a staging flavor cannot claim the prod host (R-4, SEC-1).
 */
@Module
@InstallIn(SingletonComponent::class)
object AppLinkProvidesModule {

    @Provides
    @Singleton
    @AppLinkHosts
    fun provideVerifiedHosts(@ApplicationContext context: Context): Set<String> =
        buildSet {
            // The verified App Link host (e.g. app.testlogon.com / staging.testlogon.com per flavor).
            context.getString(R.string.applink_host).lowercase().takeIf { it.isNotBlank() }?.let(::add)
            // The plaintext dev host carries non-auto-verified tap-through links during development; it
            // is accepted by the parser so a dev tap still routes (verification only removes the chooser).
            add(DEV_HOST)
        }

    private const val DEV_HOST = "18.222.237.167"
}

@Module
@InstallIn(SingletonComponent::class)
abstract class AppLinkBindsModule {

    @Binds
    @Singleton
    abstract fun bindDeepLinkParser(impl: DeepLinkParserImpl): DeepLinkParser

    @Binds
    @Singleton
    abstract fun bindDeepLinkTelemetry(impl: LogcatDeepLinkTelemetry): DeepLinkTelemetry
}
