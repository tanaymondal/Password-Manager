plugins {
    kotlin("multiplatform")
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.0"
    id("com.google.devtools.ksp")
}

kotlin {
    androidTarget {
        compilations.all {
            kotlinOptions {
                jvmTarget = "17"
                freeCompilerArgs += "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api"
            }
        }
    }
    
    iosX64 {}
    iosArm64 {}
    iosSimulatorArm64 {}
}

val commonMain by kotlin.sourceSets.getting
val androidMain by kotlin.sourceSets.getting

commonMain.dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.2")
    implementation("io.ktor:ktor-client-core:2.3.7")
    implementation("io.ktor:ktor-client-content-negotiation:2.3.7")
    implementation("io.ktor:ktor-serialization-kotlinx-json:2.3.7")
    implementation("com.russhwolf:multiplatform-settings:1.1.0")
}

androidMain.dependencies {
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation(platform("androidx.compose:compose-bom:2024.02.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.7.0")
    implementation("androidx.navigation:navigation-compose:2.8.0")
    implementation("io.insert-koin:koin-androidx-compose:3.5.3")
    implementation("androidx.datastore:datastore-preferences:1.0.0")
    
    // Ktor Client for Android
    implementation("io.ktor:ktor-client-android:2.3.7")
    
    // Room with SQLCipher for encrypted database
    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    implementation("net.zetetic:android-database-sqlcipher:4.5.4")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
}

android {
    namespace = "com.securevault.mobile"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.securevault.mobile"
        minSdk = 26
        targetSdk = 34
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}