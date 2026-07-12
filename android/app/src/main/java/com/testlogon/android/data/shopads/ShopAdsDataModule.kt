package com.testlogon.android.data.shopads

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** ADV x ECOM (B2/B4) — provides [ShopAdsApi] on the shared Retrofit + binds the repository. */
@Module
@InstallIn(SingletonComponent::class)
object ShopAdsApiModule {

    @Provides
    @Singleton
    fun provideShopAdsApi(retrofit: Retrofit): ShopAdsApi =
        retrofit.create(ShopAdsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class ShopAdsDataModule {

    @Binds
    @Singleton
    abstract fun bindShopAdsRepository(impl: ShopAdsRepositoryImpl): ShopAdsRepository
}
