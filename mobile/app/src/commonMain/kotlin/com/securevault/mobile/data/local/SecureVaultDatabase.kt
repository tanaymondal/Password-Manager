package com.securevault.mobile.data.local

import androidx.room.ConstructedBy
import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.RoomDatabaseConstructor

@Database(
    entities = [VaultEntryEntity::class],
    version = 1,
    exportSchema = false
)
@ConstructedBy(SecureVaultDatabaseConstructor::class)
abstract class SecureVaultDatabase : RoomDatabase() {
    abstract fun vaultEntryDao(): VaultEntryDao

    companion object {
        const val DATABASE_NAME = "secure_vault.db"
    }
}

@Suppress("NO_ACTUAL_FOR_EXPECT")
expect object SecureVaultDatabaseConstructor : RoomDatabaseConstructor<SecureVaultDatabase> {
    override fun initialize(): SecureVaultDatabase
}
