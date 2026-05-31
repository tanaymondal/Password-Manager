package com.securevault.mobile.data.local

import androidx.room.Room
import androidx.sqlite.driver.bundled.BundledSQLiteDriver
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSFileProtectionComplete
import platform.Foundation.NSUserDomainMask
import platform.Foundation.NSFileProtectionKey

@OptIn(ExperimentalForeignApi::class)
fun createSecureVaultDatabase(): SecureVaultDatabase {
    val documentDirectory = NSFileManager.defaultManager.URLForDirectory(
        directory = NSDocumentDirectory,
        inDomain = NSUserDomainMask,
        appropriateForURL = null,
        create = false,
        error = null,
    )
    val dbDir = requireNotNull(documentDirectory?.path)
    val dbPath = "$dbDir/${SecureVaultDatabase.DATABASE_NAME}"

    val db = Room.databaseBuilder<SecureVaultDatabase>(
        name = dbPath
    ).setDriver(BundledSQLiteDriver()).build()

    // Apply NSFileProtectionComplete to the database file and related files
    val fm = NSFileManager.defaultManager
    val protection = mapOf<Any?, Any?>(NSFileProtectionKey to NSFileProtectionComplete)
    for (suffix in listOf("", "-wal", "-shm", "-journal")) {
        fm.setAttributes(protection, ofItemAtPath = "$dbPath$suffix", error = null)
    }

    return db
}
