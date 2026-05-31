package com.securevault.mobile.data.local

import androidx.room.Room
import androidx.sqlite.driver.bundled.BundledSQLiteDriver
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSUserDomainMask

@OptIn(ExperimentalForeignApi::class)
fun createSecureVaultDatabase(): SecureVaultDatabase {
    val documentDirectory = NSFileManager.defaultManager.URLForDirectory(
        directory = NSDocumentDirectory,
        inDomain = NSUserDomainMask,
        appropriateForURL = null,
        create = false,
        error = null,
    )
    val dbPath = requireNotNull(documentDirectory?.path) + "/${SecureVaultDatabase.DATABASE_NAME}"
    return Room.databaseBuilder<SecureVaultDatabase>(
        name = dbPath
    ).setDriver(BundledSQLiteDriver()).build()
}
