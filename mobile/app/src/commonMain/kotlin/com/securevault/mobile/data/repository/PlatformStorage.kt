package com.securevault.mobile.data.repository

expect class PlatformStorage() {
    val isReady: Boolean
    fun init(context: Any)
    fun getString(key: String, default: String): String
    fun putString(key: String, value: String)
    fun getInt(key: String, default: Int): Int
    fun putInt(key: String, value: Int)
    fun getBoolean(key: String, default: Boolean): Boolean
    fun putBoolean(key: String, value: Boolean)
    fun clear()
}
