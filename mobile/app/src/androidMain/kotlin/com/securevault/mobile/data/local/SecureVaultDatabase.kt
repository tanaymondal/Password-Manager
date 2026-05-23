package com.securevault.mobile.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import net.sqlcipher.database.SupportFactory

@Database(
    entities = [VaultEntryEntity::class],
    version = 1,
    exportSchema = false
)
abstract class SecureVaultDatabase : RoomDatabase() {

    abstract fun vaultEntryDao(): VaultEntryDao

    companion object {
        const val DATABASE_NAME = "secure_vault.db"

        @Volatile
        private var INSTANCE: SecureVaultDatabase? = null

        fun getInstance(context: Context, passphrase: ByteArray): SecureVaultDatabase {
            return INSTANCE ?: synchronized(this) {
                val factory = SupportFactory(passphrase)
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    SecureVaultDatabase::class.java,
                    DATABASE_NAME
                )
                    .openHelperFactory(factory)
                    .fallbackToDestructiveMigration()
                    .build()
                INSTANCE = instance
                instance
            }
        }

        fun getInstance(context: Context): SecureVaultDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    SecureVaultDatabase::class.java,
                    DATABASE_NAME
                )
                    .fallbackToDestructiveMigration()
                    .build()
                INSTANCE = instance
                instance
            }
        }

        fun clearInstance() {
            synchronized(this) {
                INSTANCE?.close()
                INSTANCE = null
            }
        }
    }
}