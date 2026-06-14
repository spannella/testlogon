package com.testlogon.android.core.network.syndicates

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-356 - Hilt wiring for the syndicate-overview transport layer.
 *
 * Provides [SyndicateApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi /
 * converter config; no new Retrofit, OkHttp or Moshi is built, and NO new dependency is introduced). The
 * syndicate DTOs decode with the reflective KotlinJsonAdapterFactory already on the shared Moshi. Mirrors
 * the AND-355 GroupsNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object SyndicateNetworkModule {

    @Provides
    @Singleton
    fun provideSyndicateApi(retrofit: Retrofit): SyndicateApi =
        retrofit.create(SyndicateApi::class.java)
}
