package com.testlogon.android.data.upload

import android.content.ContentResolver
import android.content.Context
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import java.util.concurrent.TimeUnit
import javax.inject.Qualifier
import javax.inject.Singleton

/**
 * AND-129 — qualifies the COOKIELESS OkHttpClient used for the storage PUT. It deliberately omits
 * the app's cookie jar, CSRF interceptor and 401-authenticator: the presigned URL is a third-party
 * origin whose auth is in the signature, so app session credentials must never be attached.
 */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class StorageOkHttp

@Module
@InstallIn(SingletonComponent::class)
abstract class UploadModule {

    @Binds
    @Singleton
    abstract fun bindAttachmentUploader(impl: DefaultAttachmentUploader): AttachmentUploader

    companion object {

        @Provides
        @Singleton
        @StorageOkHttp
        fun provideStorageClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(STORAGE_CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(STORAGE_WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            // No overall call timeout: large media PUTs can exceed any fixed budget.
            .callTimeout(0, TimeUnit.SECONDS)
            .build()

        @Provides
        @Singleton
        fun provideAttachmentApi(retrofit: Retrofit): AttachmentApi =
            retrofit.create(AttachmentApi::class.java)

        @Provides
        fun provideContentResolver(@ApplicationContext context: Context): ContentResolver =
            context.contentResolver

        private const val STORAGE_CONNECT_TIMEOUT_SECONDS = 20L
        private const val STORAGE_WRITE_TIMEOUT_SECONDS = 120L
    }
}
