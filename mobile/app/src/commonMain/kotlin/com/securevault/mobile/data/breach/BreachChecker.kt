package com.securevault.mobile.data.breach

import com.securevault.mobile.domain.crypto.CryptoEngine
import io.ktor.client.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.statement.*

object BreachChecker {

    private const val HIBP_URL = "https://api.pwnedpasswords.com/range/"
    private val client = HttpClient {
        install(HttpTimeout) {
            requestTimeoutMillis = 10_000
            connectTimeoutMillis = 5_000
        }
    }

    suspend fun checkBreach(password: String, cryptoEngine: CryptoEngine): Boolean {
        val hash = cryptoEngine.sha1Hex(password)
        val prefix = hash.substring(0, 5)
        val suffix = hash.substring(5)

        return try {
            val response: HttpResponse = client.get("$HIBP_URL$prefix")
            if (response.status.value !in 200..299) return false
            val body = response.bodyAsText()
            body.lines().any { line -> line.startsWith(suffix) }
        } catch (e: Exception) {
            false
        }
    }
}
