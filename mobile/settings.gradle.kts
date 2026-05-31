pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
    plugins {
        id("com.google.devtools.ksp") version "2.1.20-1.0.31" apply false
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "SecureVault"
include(":app")