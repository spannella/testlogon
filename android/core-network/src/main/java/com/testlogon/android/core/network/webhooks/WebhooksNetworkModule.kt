package com.testlogon.android.core.network.webhooks

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-398 - Hilt wiring for the webhooks transport layer.
 *
 * Provides [WebhooksApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi / converter
 * config; no new Retrofit, OkHttp or Moshi is built, and no new dependency is introduced). The webhook DTOs
 * decode with the reflective KotlinJsonAdapterFactory already on the shared Moshi (no enum adapter is needed -
 * there are no enum-typed wire fields). Mirrors the AND-371 TicketsNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object WebhooksNetworkModule {

    @Provides
    @Singleton
    fun provideWebhooksApi(retrofit: Retrofit): WebhooksApi =
        retrofit.create(WebhooksApi::class.java)
}
