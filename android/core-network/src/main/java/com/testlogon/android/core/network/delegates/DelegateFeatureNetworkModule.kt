package com.testlogon.android.core.network.delegates

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-360 - Hilt wiring for the delegate-PATH feature transport (feed / messaging / broadcast).
 *
 * Provides the three AND-360 delegate APIs from the shared singleton [Retrofit] (reusing the production
 * OkHttp / Moshi / converter config; no new Retrofit, OkHttp or Moshi is built and no new dependency is
 * introduced). The shared CSRF / Bearer / 401-refresh interceptors on that client already cover these
 * calls - AND-360 adds NO header interceptor. This is SEPARATE from AND-359's DelegatesNetworkModule
 * (which provides the delegation-management DelegatesApi); mirrors the AND-353 OrgsNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object DelegateFeatureNetworkModule {

    @Provides
    @Singleton
    fun provideDelegateFeedApi(retrofit: Retrofit): DelegateFeedApi =
        retrofit.create(DelegateFeedApi::class.java)

    @Provides
    @Singleton
    fun provideDelegateMessagingApi(retrofit: Retrofit): DelegateMessagingApi =
        retrofit.create(DelegateMessagingApi::class.java)

    @Provides
    @Singleton
    fun provideDelegateBroadcastApi(retrofit: Retrofit): DelegateBroadcastApi =
        retrofit.create(DelegateBroadcastApi::class.java)
}
