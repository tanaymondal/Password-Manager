package com.securevault.mobile.data.local

import android.content.Context
import androidx.room.Room
import androidx.sqlite.driver.bundled.BundledSQLiteDriver

fun createSecureVaultDatabase(context: Context): SecureVaultDatabase {
    return Room.databaseBuilder<SecureVaultDatabase>(
        context = context.applicationContext,
        name = context.getDatabasePath(SecureVaultDatabase.DATABASE_NAME).absolutePath
    )
        .setDriver(BundledSQLiteDriver())
        .build()
}
