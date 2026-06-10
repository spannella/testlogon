package com.testlogon.android.data.vod

import com.testlogon.android.data.vod.adsupported.VodAdSupportedApi
import com.testlogon.android.data.vod.adsupported.VodAdSupportedRepository
import com.testlogon.android.data.vod.adsupported.VodAdSupportedRepositoryImpl
import com.testlogon.android.data.vod.download.VodWatermarkDownloadApi
import com.testlogon.android.data.vod.download.WatermarkDownloadRepository
import com.testlogon.android.data.vod.download.WatermarkDownloadRepositoryImpl
import com.testlogon.android.data.vod.download.WatermarkDownloadScheduler
import com.testlogon.android.data.vod.download.WorkManagerWatermarkDownloadScheduler
import com.testlogon.android.data.vod.purchase.VodPurchaseApi
import com.testlogon.android.data.vod.purchase.VodPurchaseRepository
import com.testlogon.android.data.vod.purchase.VodPurchaseRepositoryImpl
import com.testlogon.android.data.vod.rental.VodRentalApi
import com.testlogon.android.data.vod.rental.VodRentalRepository
import com.testlogon.android.data.vod.rental.VodRentalRepositoryImpl
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-192/193/194/195 — provides the dedicated VOD-monetization Retrofit APIs on the shared Retrofit
 * and binds their repositories. Kept separate from the catalog ([VideosApiModule]) wiring so the
 * monetization work never touches the browse contracts.
 */
@Module
@InstallIn(SingletonComponent::class)
object VodMonetizationApiModule {

    @Provides
    @Singleton
    fun provideVodRentalApi(retrofit: Retrofit): VodRentalApi =
        retrofit.create(VodRentalApi::class.java)

    @Provides
    @Singleton
    fun provideVodPurchaseApi(retrofit: Retrofit): VodPurchaseApi =
        retrofit.create(VodPurchaseApi::class.java)

    @Provides
    @Singleton
    fun provideVodAdSupportedApi(retrofit: Retrofit): VodAdSupportedApi =
        retrofit.create(VodAdSupportedApi::class.java)

    @Provides
    @Singleton
    fun provideVodWatermarkDownloadApi(retrofit: Retrofit): VodWatermarkDownloadApi =
        retrofit.create(VodWatermarkDownloadApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class VodMonetizationDataModule {

    @Binds
    @Singleton
    abstract fun bindVodRentalRepository(impl: VodRentalRepositoryImpl): VodRentalRepository

    @Binds
    @Singleton
    abstract fun bindVodPurchaseRepository(impl: VodPurchaseRepositoryImpl): VodPurchaseRepository

    @Binds
    @Singleton
    abstract fun bindVodAdSupportedRepository(impl: VodAdSupportedRepositoryImpl): VodAdSupportedRepository

    @Binds
    @Singleton
    abstract fun bindWatermarkDownloadRepository(impl: WatermarkDownloadRepositoryImpl): WatermarkDownloadRepository

    @Binds
    @Singleton
    abstract fun bindWatermarkDownloadScheduler(impl: WorkManagerWatermarkDownloadScheduler): WatermarkDownloadScheduler
}
