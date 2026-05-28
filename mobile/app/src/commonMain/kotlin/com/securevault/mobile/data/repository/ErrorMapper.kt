package com.securevault.mobile.data.repository

object ErrorMapper {

    fun map(rawMessage: String?, defaultMessage: String): String {
        val msg = rawMessage ?: return defaultMessage
        return when {
            msg.contains("locked", ignoreCase = true) -> "Account is temporarily locked. Please try again later."
            msg.contains("rate", ignoreCase = true) -> "Too many attempts. Please wait before trying again."
            msg.contains("expired", ignoreCase = true) -> "Session expired. Please log in again."
            msg.contains("Unauthorized") || msg.contains("unauthorized") -> "Please log in again."
            msg.contains("not found", ignoreCase = true) -> "Resource not found."
            msg.contains("already", ignoreCase = true) -> msg
            msg.length > 120 -> defaultMessage
            else -> msg
        }
    }
}
