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

# Argon2
-keep class com.lambdapioneer.argon2kt.** { *; }

# SecureVault app
-keep class com.securevault.mobile.** { *; }

# Coroutines
-dontwarn kotlinx.coroutines.**

# Kotlin stdlib
-dontwarn kotlin.**

# Compose
-dontwarn androidx.compose.**
