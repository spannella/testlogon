package com.testlogon.android.core.network.delegates

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-359 - Hilt wiring for the delegate transport layer.
 *
 * Provides [DelegatesApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi /
 * converter config; no new Retrofit, OkHttp or Moshi is built, and no new dependency is introduced). The
 * delegate DTOs decode with the reflective KotlinJsonAdapterFactory already on the shared Moshi. Mirrors
 * the AND-353 OrgsNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object DelegatesNetworkModule {

    @Provides
    @Singleton
    fun provideDelegatesApi(retrofit: Retrofit): DelegatesApi =
        retrofit.create(DelegatesApi::class.java)
}
