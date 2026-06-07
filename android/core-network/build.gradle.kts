plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
}

android {
    namespace = "com.testlogon.android.core.network"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
    }

    buildFeatures {
        // Exposes BuildConfig.DEBUG so logging is debug-only.
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":core-model"))

    // Networking
    implementation(libs.okhttp)
    implementation(libs.okhttp.logging)
    implementation(libs.retrofit)
    implementation(libs.retrofit.moshi)
    implementation(libs.moshi)
    implementation(libs.moshi.kotlin)

    // Coroutines
    implementation(libs.coroutines.core)
    implementation(libs.coroutines.android)

    // DI
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)

    // AndroidX
    implementation(libs.androidx.core.ktx)

    // Test
    testImplementation(libs.junit)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.coroutines.test)
}
