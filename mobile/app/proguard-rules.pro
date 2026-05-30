# Kotlin serialization
-keepattributes *Annotation*, InnerClasses
-keepclassmembers class kotlinx.serialization.json.** { *; }
-keep class kotlinx.serialization.** { *; }

# Ktor client
-keep class io.ktor.** { *; }
-dontwarn io.ktor.**

# Room
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-dontwarn androidx.room.**

# SecureVault app
-keep class com.securevault.mobile.** { *; }

# JNI native methods (Rust crypto-core)
-keepclasseswithmembernames class * {
    native <methods>;
}

# Coroutines
-dontwarn kotlinx.coroutines.**

# Kotlin stdlib
-dontwarn kotlin.**

# Compose
-dontwarn androidx.compose.**
