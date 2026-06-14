package com.testlogon.android.feature.share.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-335 - binds the share-link repository + the public downloader.
 *
 * [com.testlogon.android.core.network.share.FileShareLinksApi] (owner, authed Retrofit) and
 * [com.testlogon.android.core.network.share.PublicShareApi] (public, cookieless Retrofit) are provided by
 * the core-network ShareNetworkModule; [ApiErrorParser] and the application Context are already-available
 * singletons. No new dependency, no Room.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class ShareDataModule {

    @Binds
    @Singleton
    abstract fun bindShareRepository(impl: ShareRepositoryImpl): ShareRepository

    @Binds
    @Singleton
    abstract fun bindShareDownloader(impl: ShareDownloaderImpl): ShareDownloader
}
