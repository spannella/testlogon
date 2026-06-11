package com.testlogon.android.feature.calendar.detail

import android.content.Context
import com.testlogon.android.R
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-272 — supplies the published App Link host for building canonical https event share URLs (the
 * prod/staging web host), never the plaintext dev host. An interface so JVM tests can supply a fake
 * without a Context.
 */
interface PublicEventHostProvider {
    fun host(): String
}

/** Default impl that reads the `applink_host` string resource. */
@Singleton
class ResourcePublicEventHostProvider @Inject constructor(
    @ApplicationContext private val context: Context,
) : PublicEventHostProvider {
    override fun host(): String = context.getString(R.string.applink_host)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class PublicEventHostModule {
    @Binds
    abstract fun bindPublicEventHostProvider(impl: ResourcePublicEventHostProvider): PublicEventHostProvider
}
