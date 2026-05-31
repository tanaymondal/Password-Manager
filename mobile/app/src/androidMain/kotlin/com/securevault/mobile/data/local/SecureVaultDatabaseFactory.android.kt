package com.securevault.mobile.data.local

import android.content.Context
import androidx.room.Room
import androidx.sqlite.driver.bundled.BundledSQLiteDriver
import net.sqlcipher.database.SupportFactory

fun createSecureVaultDatabase(context: Context): SecureVaultDatabase {
    val keyManager = DatabaseKeyManager(context)
    val passphrase = keyManager.getOrCreatePassphrase()
    val factory = SupportFactory(passphrase)
    return Room.databaseBuilder<SecureVaultDatabase>(
        context = context.applicationContext,
        name = context.getDatabasePath(SecureVaultDatabase.DATABASE_NAME).absolutePath
    )
        .openHelperFactory(factory)
        .setDriver(BundledSQLiteDriver())
        .build()
}
