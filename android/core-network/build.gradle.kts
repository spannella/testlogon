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

        // AND-006 — the network layer reads its default base URL from BuildConfig so the flaky
        // plaintext dev host is never hard-coded in Kotlin source. SettingsStore seeds from this
        // and supports a runtime override. Keep this value in sync with the :app module.
        // (Library modules get their own BuildConfig; the field is re-declared here by design.)
        buildConfigField("String", "API_BASE_URL", "\"http://18.222.237.167:8000/\"")
    }

    buildFeatures {
        // Exposes BuildConfig.DEBUG so logging is debug-only; also carries API_BASE_URL (AND-006).
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
