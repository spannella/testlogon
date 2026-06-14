package com.testlogon.android.data.discounts

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-267 — provides [AffiliateDiscountsApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object AffiliateDiscountsApiModule {

    @Provides
    @Singleton
    fun provideAffiliateDiscountsApi(retrofit: Retrofit): AffiliateDiscountsApi =
        retrofit.create(AffiliateDiscountsApi::class.java)
}

/** AND-267 — binds the affiliate-discounts data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AffiliateDiscountsDataModule {

    @Binds
    @Singleton
    abstract fun bindAffiliateDiscountsRepository(
        impl: AffiliateDiscountsRepositoryImpl,
    ): AffiliateDiscountsRepository
}
