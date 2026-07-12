package com.testlogon.android.data.videos

import com.testlogon.android.data.vod.VodApi
import com.testlogon.android.data.vod.VodRepository
import com.testlogon.android.data.vod.VodRepositoryImpl
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-189 / AND-190 / AND-191 — provides the dedicated [VideosApi] / [VodApi] on the shared Retrofit
 * and binds the videos + VOD repositories. Kept separate from the discover / messaging modules so this
 * feature never touches their wiring.
 */
@Module
@InstallIn(SingletonComponent::class)
object VideosApiModule {

    @Provides
    @Singleton
    fun provideVideosApi(retrofit: Retrofit): VideosApi =
        retrofit.create(VideosApi::class.java)

    @Provides
    @Singleton
    fun provideVodApi(retrofit: Retrofit): VodApi =
        retrofit.create(VodApi::class.java)

    @Provides
    @Singleton
    fun provideVideoCommentsApi(retrofit: Retrofit): VideoCommentsApi =
        retrofit.create(VideoCommentsApi::class.java)

    @Provides
    @Singleton
    fun provideVideoUploadApi(retrofit: Retrofit): VideoUploadApi =
        retrofit.create(VideoUploadApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class VideosDataModule {

    @Binds
    @Singleton
    abstract fun bindVideosRepository(impl: VideosRepositoryImpl): VideosRepository

    @Binds
    @Singleton
    abstract fun bindVodRepository(impl: VodRepositoryImpl): VodRepository
}
