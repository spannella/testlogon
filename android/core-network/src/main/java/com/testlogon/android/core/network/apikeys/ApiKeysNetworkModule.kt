package com.testlogon.android.core.network.apikeys

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * B-APIKEY (batch 7) - Hilt wiring for the API-keys transport layer.
 *
 * Provides [ApiKeysApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi / converter
 * config; no new Retrofit, OkHttp or Moshi is built, and no new dependency is introduced). The DTOs decode with
 * the reflective KotlinJsonAdapterFactory already on the shared Moshi (no enum adapter is needed). Mirrors the
 * AND-398 WebhooksNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object ApiKeysNetworkModule {

    @Provides
    @Singleton
    fun provideApiKeysApi(retrofit: Retrofit): ApiKeysApi =
        retrofit.create(ApiKeysApi::class.java)
}
