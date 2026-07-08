package com.testlogon.android.core.network.msgprivacy

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * TIP-B4 — Hilt wiring for the message-privacy transport. Provides [MessagePrivacyApi] from the
 * shared singleton [Retrofit] (no new Retrofit/OkHttp/Moshi). Mirrors CallRateNetworkModule.
 */
@Module
@InstallIn(SingletonComponent::class)
object MessagePrivacyNetworkModule {

    @Provides
    @Singleton
    fun provideMessagePrivacyApi(retrofit: Retrofit): MessagePrivacyApi =
        retrofit.create(MessagePrivacyApi::class.java)
}
