package com.testlogon.android.core.network.orgs

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-353 - Hilt wiring for the organizations transport layer.
 *
 * Provides [OrgsApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi /
 * converter config; no new Retrofit, OkHttp or Moshi is built, and no new dependency is introduced).
 * The org DTOs decode with the reflective KotlinJsonAdapterFactory already on the shared Moshi (org_role
 * is a plain String on the wire - the typed OrgRole enum + UNKNOWN fallback lives in core-model). Mirrors
 * the AND-339 SigningNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object OrgsNetworkModule {

    @Provides
    @Singleton
    fun provideOrgsApi(retrofit: Retrofit): OrgsApi =
        retrofit.create(OrgsApi::class.java)
}
