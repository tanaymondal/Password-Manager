plugins {
    kotlin("multiplatform")
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("org.jetbrains.kotlin.plugin.compose") version "2.1.21"
    id("org.jetbrains.compose")
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

    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64()
    ).forEach { iosTarget ->
        iosTarget.binaries.framework {
            baseName = "SecureVault"
            isStatic = true
        }

        iosTarget.compilations.getByName("main") {
            cinterops {
                val securevault_crypto_core by creating {
                    defFile(project.file("src/iosMain/c_interop/securevault_crypto_core.def"))
                    includeDirs(project.file("src/iosMain/c_interop"))
                }
                val bio_keychain by creating {
                    defFile(project.file("src/iosMain/c_interop/bio_keychain.def"))
                    includeDirs(project.file("src/iosMain/c_interop"))
                }
            }
        }
        iosTarget.compilations.getByName("test") {
            cinterops {
                val securevault_crypto_core by creating {
                    defFile(project.file("src/iosMain/c_interop/securevault_crypto_core.def"))
                    includeDirs(project.file("src/iosMain/c_interop"))
                }
            }
        }
    }
}

val commonMain by kotlin.sourceSets.getting
val androidMain by kotlin.sourceSets.getting
val commonTest by kotlin.sourceSets.getting
val iosMain by kotlin.sourceSets.creating
iosMain.dependsOn(commonMain)
val iosTest by kotlin.sourceSets.creating
iosTest.dependsOn(commonTest)

kotlin.targets.matching { it.name.startsWith("ios") }.configureEach {
    compilations.getByName("main").defaultSourceSet.dependsOn(iosMain)
    compilations.getByName("test").defaultSourceSet.dependsOn(iosTest)
}

dependencies {
    add("kspAndroid", "androidx.room:room-compiler:2.7.2")
    add("kspIosSimulatorArm64", "androidx.room:room-compiler:2.7.2")
    add("kspIosArm64", "androidx.room:room-compiler:2.7.2")
    add("kspIosX64", "androidx.room:room-compiler:2.7.2")
}

commonMain.dependencies {
    implementation("org.jetbrains.compose.runtime:runtime:1.7.3")
    implementation("org.jetbrains.compose.foundation:foundation:1.7.3")
    implementation("org.jetbrains.compose.material3:material3:1.7.3")
    implementation("org.jetbrains.compose.material:material-icons-extended:1.7.3")
    implementation("org.jetbrains.androidx.navigation:navigation-compose:2.8.0-alpha10")
    implementation("org.jetbrains.androidx.lifecycle:lifecycle-viewmodel-compose:2.8.0")
    implementation("org.jetbrains.androidx.lifecycle:lifecycle-runtime-compose:2.8.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.2")
    implementation("io.ktor:ktor-client-core:3.5.0")
    implementation("io.ktor:ktor-client-content-negotiation:3.5.0")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.5.0")
    implementation("io.insert-koin:koin-core:3.5.3")
    implementation("androidx.room:room-runtime:2.7.2")
    implementation("androidx.sqlite:sqlite-bundled:2.5.0-SNAPSHOT")
    implementation("androidx.datastore:datastore-preferences:1.1.1")
}

iosMain.dependencies {
    implementation("io.insert-koin:koin-core:3.5.3")
    implementation("io.ktor:ktor-client-darwin:2.3.7")
}

commonTest.dependencies {
    implementation("junit:junit:4.13.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
}

iosTest.dependencies {
    implementation("junit:junit:4.13.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
}

androidMain.dependencies {
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("io.insert-koin:koin-androidx-compose:3.5.3")
    implementation("io.ktor:ktor-client-android:2.3.7")
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
}

iosMain.dependencies {
    implementation("io.insert-koin:koin-core:3.5.3")
    implementation("io.ktor:ktor-client-darwin:3.5.0")
}

commonTest.dependencies {
    implementation("junit:junit:4.13.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
}

iosTest.dependencies {
    implementation("junit:junit:4.13.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
}

androidMain.dependencies {
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("io.insert-koin:koin-androidx-compose:3.5.3")
    implementation("androidx.datastore:datastore-preferences:1.0.0")
    implementation("io.ktor:ktor-client-android:3.5.0")
    implementation("androidx.room:room-runtime-android:2.7.2")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
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
            isMinifyEnabled = true
            isShrinkResources = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}
