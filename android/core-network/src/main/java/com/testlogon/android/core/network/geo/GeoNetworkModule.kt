package com.testlogon.android.core.network.geo

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * Hilt wiring for the geo-blocking settings transport layer. Provides [GeoApi] from the shared singleton
 * [Retrofit] (reusing the production OkHttp / Moshi / converter config; no new Retrofit, OkHttp or Moshi is
 * built). The DTOs decode with the reflective KotlinJsonAdapterFactory on the shared Moshi. Mirrors
 * ApiKeysNetworkModule.
 */
@Module
@InstallIn(SingletonComponent::class)
object GeoNetworkModule {

    @Provides
    @Singleton
    fun provideGeoApi(retrofit: Retrofit): GeoApi = retrofit.create(GeoApi::class.java)
}
