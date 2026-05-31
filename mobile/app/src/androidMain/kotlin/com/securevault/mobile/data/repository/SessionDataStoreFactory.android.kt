package com.securevault.mobile.data.repository

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStore

private val Context.preferences by preferencesDataStore(name = "sv_session")

fun createPlatformDataStore(context: Context): DataStore<Preferences> {
    return context.preferences
}
