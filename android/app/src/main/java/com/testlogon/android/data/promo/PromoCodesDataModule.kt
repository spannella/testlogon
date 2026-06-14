package com.testlogon.android.data.promo

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-266 — provides [PromoCodesApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object PromoCodesApiModule {

    @Provides
    @Singleton
    fun providePromoCodesApi(retrofit: Retrofit): PromoCodesApi =
        retrofit.create(PromoCodesApi::class.java)
}

/** AND-266 — binds the promo-codes data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class PromoCodesDataModule {

    @Binds
    @Singleton
    abstract fun bindPromoCodesRepository(impl: PromoCodesRepositoryImpl): PromoCodesRepository
}
