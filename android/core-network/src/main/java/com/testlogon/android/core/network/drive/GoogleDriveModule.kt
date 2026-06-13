package com.testlogon.android.core.network.drive

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-336 - Hilt wiring for the BACKEND-MEDIATED Google Drive transport layer.
 *
 * Provides [GoogleDriveApi] from the shared singleton AUTHED [Retrofit] (reusing the production OkHttp /
 * Moshi / converter config: session cookie + X-CSRF-Token + Bearer; no new Retrofit, OkHttp or Moshi is
 * built, and no new dependency is introduced). The Drive DTOs need no custom Moshi adapters - they decode
 * via the reflective KotlinJsonAdapterFactory already registered in NetworkModule.provideMoshi. Mirrors
 * the AND-331 FilesNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object GoogleDriveModule {

    @Provides
    @Singleton
    fun provideGoogleDriveApi(retrofit: Retrofit): GoogleDriveApi =
        retrofit.create(GoogleDriveApi::class.java)
}
