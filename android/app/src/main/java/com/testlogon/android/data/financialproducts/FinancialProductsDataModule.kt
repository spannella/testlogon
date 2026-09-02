package com.testlogon.android.data.financialproducts

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides [FinancialProductsApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object FinancialProductsApiModule {

    @Provides
    @Singleton
    fun provideFinancialProductsApi(retrofit: Retrofit): FinancialProductsApi =
        retrofit.create(FinancialProductsApi::class.java)
}

/** Binds the financial-products data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class FinancialProductsDataModule {

    @Binds
    @Singleton
    abstract fun bindFinancialProductsRepository(impl: FinancialProductsRepositoryImpl): FinancialProductsRepository
}
