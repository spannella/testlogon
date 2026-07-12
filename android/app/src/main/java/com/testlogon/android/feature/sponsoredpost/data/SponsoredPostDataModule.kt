package com.testlogon.android.feature.sponsoredpost.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * ADV2-E4 (F4) — Hilt wiring for the sponsored-as-creator feature. Binds the repository seam to its impl,
 * which consumes the ADV2-407 [com.testlogon.android.core.network.sponsoredpost.SponsoredPostApi], the
 * shared [com.testlogon.android.data.ads.AdTrackApi] (billing beacon) and the shared ApiErrorParser. No new
 * endpoint module, migration, or dependency is added.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class SponsoredPostDataModule {

    @Binds
    @Singleton
    abstract fun bindSponsoredPostRepository(impl: SponsoredPostRepositoryImpl): SponsoredPostRepository
}
